use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use object::{Object, ObjectSection};
use tracing::debug;

/// A detected jump table in .rodata
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// Virtual address of the table base in the shared library
    pub table_vaddr: u64,
    /// Target virtual addresses, one per 4-byte table entry
    pub targets: Vec<u64>,
}

/// Abstract value tracked per register during symbolic execution.
#[derive(Debug, Clone)]
enum AbstractValue {
    /// A known .rodata address loaded via LEA [rip+disp]
    RodataAddr(u64),
    /// A value loaded from a jump table (i32 sign-extended offset)
    TableEntry { table_base: u64 },
    /// Sum of RodataAddr + TableEntry — a computed jump target
    ComputedTarget { table_base: u64 },
}

/// Abstract values currently held by the 64-bit GP registers. Sub-registers
/// share their parent's entry, so `AL`, `EAX` and `RAX` are all `RAX`.
type RegState = HashMap<Register, AbstractValue>;

/// The 64-bit GP register whose state `reg` is part of, e.g. `CL`/`CX`/`ECX` →
/// `RCX`. `None` for anything that is not a GP register: `RIP`, `XMM0`, or the
/// `Register::None` of an operand that names no register at all.
fn to_gpr64(reg: Register) -> Option<Register> {
    reg.is_gpr().then(|| reg.full_register())
}

/// The abstract value tracked for whichever 64-bit register `reg` is part of.
fn value_of(regs: &RegState, reg: Register) -> Option<&AbstractValue> {
    regs.get(&to_gpr64(reg)?)
}

/// The 64-bit GP register named by operand `op`, if it names one.
fn operand_gpr(instr: &Instruction, op: u32) -> Option<Register> {
    if op >= instr.op_count() || instr.op_kind(op) != OpKind::Register {
        return None;
    }
    to_gpr64(instr.op_register(op))
}

/// The abstract value tracked for operand `op`, if it names a GP register.
fn operand_value<'a>(
    instr: &Instruction,
    regs: &'a RegState,
    op: u32,
) -> Option<&'a AbstractValue> {
    regs.get(&operand_gpr(instr, op)?)
}

/// The base and index registers of the instruction's memory operand, or
/// `Register::None` for each when it has no memory operand.
fn memory_regs(instr: &Instruction) -> (Register, Register) {
    if instr.op_count() >= 2 && instr.op_kind(1) == OpKind::Memory {
        (instr.memory_base(), instr.memory_index())
    } else {
        (Register::None, Register::None)
    }
}

/// Detects jump tables in a function using symbolic execution with iced-x86.
///
/// Decodes instructions and tracks register state to identify the pattern:
///   LEA reg, [rip+disp]  (load .rodata table base)
///   MOVSXD reg, [base+idx*4]  (read i32 offset from table)
///   ADD reg, reg  (compute target = base + offset)
///   JMP reg  (indirect jump through computed address)
pub fn detect_jump_tables(
    code: &[u8],
    base_vaddr: u64,
    symbol_name: &str,
    elf: &object::read::elf::ElfFile64<'_>,
) -> Result<Vec<JumpTable>> {
    if code.len() < 16 {
        return Ok(Vec::new());
    }

    debug!(symbol = symbol_name, "Scanning for jump tables");

    // Symbolic execution pass
    let mut instr = Instruction::default();
    let mut regs = RegState::new();
    let mut confirmed_bases: HashSet<u64> = HashSet::new();

    let mut decoder = Decoder::with_ip(64, code, base_vaddr, DecoderOptions::NONE);
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);

        // An indirect branch through a register holding table base + entry is
        // what confirms a table.
        if instr.flow_control() == FlowControl::IndirectBranch
            && let Some(gpr) = operand_gpr(&instr, 0)
            && let Some(AbstractValue::ComputedTarget { table_base }) = regs.get(&gpr)
        {
            debug!(
                table_base = format_args!("{:#x}", table_base),
                jmp_addr = format_args!("{:#x}", instr.ip()),
                "Confirmed jump table"
            );
            confirmed_bases.insert(*table_base);
        }

        // Every instruction this scanner models writes its first operand, and
        // whatever it leaves there replaces what we were tracking. An
        // instruction we cannot interpret invalidates its destination instead
        // of letting a stale value survive the write.
        if let Some(dst) = operand_gpr(&instr, 0) {
            match transfer(&instr, elf, &regs) {
                Some(value) => regs.insert(dst, value),
                None => regs.remove(&dst),
            };
        }
    }

    if confirmed_bases.is_empty() {
        return Ok(Vec::new());
    }

    // Sort bases so we can truncate each table at the start of the next one
    let mut sorted_bases: Vec<u64> = confirmed_bases.into_iter().collect();
    sorted_bases.sort();

    // Validate each confirmed table base
    let mut jump_tables = Vec::new();
    for (i, &table_addr) in sorted_bases.iter().enumerate() {
        let next_table = sorted_bases.get(i + 1).copied();
        match identify_table_bounds(elf, table_addr, base_vaddr, code.len() as u64, next_table) {
            Ok(table) => {
                debug!(
                    vaddr = format_args!("{:#x}", table.table_vaddr),
                    entries = table.targets.len(),
                    "Validated jump table"
                );
                jump_tables.push(table);
            }
            Err(e) => {
                debug!(
                    vaddr=format_args!("{:#x}", table_addr),
                    error=%e,
                    "Jump table validation failed"
                );
            }
        }
    }

    Ok(jump_tables)
}

/// The abstract value an instruction leaves in its first operand, or `None`
/// when the instruction is not one of the forms this scanner understands — in
/// which case the caller discards whatever that register held.
///
/// Every form below is one step of the switch-dispatch sequence; the register
/// state is only ever these three values, so one function covers all of them.
fn transfer(
    instr: &Instruction,
    elf: &object::read::elf::ElfFile64<'_>,
    regs: &RegState,
) -> Option<AbstractValue> {
    match instr.mnemonic() {
        // `lea dst, [rip+disp]` pointing into read-only data: a candidate
        // table base.
        Mnemonic::Lea if instr.is_ip_rel_memory_operand() => {
            let table = instr.ip_rel_memory_address();
            is_rodata_address(elf, table).then_some(AbstractValue::RodataAddr(table))
        }
        // `lea dst, [base+index]` and `add dst, src` both add a table base to
        // an entry read out of that table, which is the branch target.
        Mnemonic::Lea => {
            let (base, index) = memory_regs(instr);
            combine(value_of(regs, base), value_of(regs, index))
        }
        Mnemonic::Add => combine(operand_value(instr, regs, 0), operand_value(instr, regs, 1)),
        // `movsxd dst, [table+idx*4]` reads a signed 32-bit entry out of a
        // tracked table.
        Mnemonic::Movsxd => {
            let (table, _) = memory_regs(instr);
            match value_of(regs, table)? {
                &AbstractValue::RodataAddr(table_base) => {
                    Some(AbstractValue::TableEntry { table_base })
                }
                _ => None,
            }
        }
        // `mov dst, src` carries whatever `src` held.
        Mnemonic::Mov => operand_value(instr, regs, 1).cloned(),
        _ => None,
    }
}

/// Add a table base to an entry read out of that same table, in either operand
/// order, giving the jump target the dispatch branches to. Any other pair of
/// values is not part of the pattern.
fn combine(a: Option<&AbstractValue>, b: Option<&AbstractValue>) -> Option<AbstractValue> {
    match (a?, b?) {
        (AbstractValue::RodataAddr(addr), AbstractValue::TableEntry { table_base })
        | (AbstractValue::TableEntry { table_base }, AbstractValue::RodataAddr(addr))
            if addr == table_base =>
        {
            Some(AbstractValue::ComputedTarget {
                table_base: *table_base,
            })
        }
        _ => None,
    }
}

/// Check if an address falls within a read-only data section (.rodata, .data.rel.ro, etc.)
fn is_rodata_address(elf: &object::read::elf::ElfFile64<'_>, addr: u64) -> bool {
    for section in elf.sections() {
        let section_addr = section.address();
        let section_size = section.size();
        if addr >= section_addr && addr < section_addr + section_size {
            let kind = section.kind();
            return matches!(
                kind,
                object::SectionKind::ReadOnlyData | object::SectionKind::Data
            );
        }
    }
    false
}

/// Determine jump table bounds by reading consecutive i32 values and validating targets.
///
/// Algorithm:
/// 1. Read section containing table_base address
/// 2. Starting at table_base, read consecutive i32 values
/// 3. For each i32 offset value:
///    - Compute target = table_base + i32_value
///    - Validate the target lands inside `func_base .. func_base + func_size`
/// 4. Stop at the first entry that fails, at the next detected table, or at the
///    end of the section
fn identify_table_bounds(
    elf: &object::read::elf::ElfFile64<'_>,
    table_base: u64,
    func_base: u64,
    func_size: u64,
    next_table: Option<u64>,
) -> Result<JumpTable> {
    // Find section containing the table
    let section = elf
        .sections()
        .find(|s| {
            let addr = s.address();
            let size = s.size();
            table_base >= addr && table_base < addr + size
        })
        .context("Could not find section containing jump table")?;

    let section_data = section.data().context("Could not read section data")?;

    let targets = scan_table_entries(
        section_data,
        section.address(),
        table_base,
        func_base,
        func_size,
        next_table,
    )
    .context("Table base offset exceeds section bounds")?;

    if targets.len() < 2 {
        bail!(
            "Too few entries ({}) to be confident it's a jump table",
            targets.len()
        );
    }

    Ok(JumpTable {
        table_vaddr: table_base,
        targets,
    })
}

/// Tables with more entries than this are almost certainly a misdetection.
const MAX_TABLE_ENTRIES: usize = 256;

/// Read consecutive i32 entries starting at `table_base` and turn them into
/// target addresses, stopping at the first entry that cannot belong to this
/// table. Returns `None` if `table_base` isn't inside the section at all.
fn scan_table_entries(
    section_data: &[u8],
    section_addr: u64,
    table_base: u64,
    func_base: u64,
    func_size: u64,
    next_table: Option<u64>,
) -> Option<Vec<u64>> {
    let offset_in_section = usize::try_from(table_base.checked_sub(section_addr)?).ok()?;
    if offset_in_section + 4 > section_data.len() {
        return None;
    }

    let mut targets = Vec::new();
    for entry_idx in 0..MAX_TABLE_ENTRIES {
        let entry_offset = offset_in_section + entry_idx * 4;
        if entry_offset + 4 > section_data.len() {
            break;
        }

        // Stop before the next table starts (avoid overlapping relocations)
        let entry_vaddr = table_base + (entry_idx * 4) as u64;
        if next_table.is_some_and(|next| entry_vaddr >= next) {
            break;
        }

        // target = table_base + i32_value, matching the code pattern:
        //   lea base, [rip+table]; movsxd off, [base+idx*4]; add off, base; jmp off
        let i32_offset = i32::from_le_bytes(
            section_data[entry_offset..entry_offset + 4]
                .try_into()
                .expect("4-byte window"),
        );
        let target = (table_base as i64 + i32_offset as i64) as u64;

        // A switch table only ever branches to blocks of the function that owns
        // it, so that function's extent is the table's real end marker. The
        // tables of consecutive functions sit back to back in .rodata, and the
        // first entry of the next one still looks plausible on its own (a nearby
        // address in some text section), so without this bound a table runs on
        // into its neighbour and claims the neighbour's entries as its own.
        // Those stolen entries get relocated against the wrong function, and the
        // real owner's table is then dropped as a duplicate — leaving its
        // dispatch to jump through offsets that only made sense in the original
        // library.
        if target < func_base || target >= func_base.saturating_add(func_size) {
            break;
        }

        targets.push(target);
    }

    Some(targets)
}

#[cfg(test)]
mod tests {
    use super::{MAX_TABLE_ENTRIES, detect_jump_tables, scan_table_entries};
    use object::{Object, ObjectSection, ObjectSymbol};

    /// A function's machine code, with the virtual address it was linked at.
    fn function_code(elf: &object::read::elf::ElfFile64<'_>, symbol: &str) -> (Vec<u8>, u64) {
        let sym = elf
            .dynamic_symbols()
            .find(|s| s.name() == Ok(symbol))
            .unwrap_or_else(|| panic!("no symbol '{symbol}'"));
        let object::SymbolSection::Section(si) = sym.section() else {
            panic!("'{symbol}' is not in a section");
        };
        let section = elf.section_by_index(si).expect("symbol section");
        let data = section.data().expect("section data");
        let start = (sym.address() - section.address()) as usize;
        (
            data[start..start + sym.size() as usize].to_vec(),
            sym.address(),
        )
    }

    /// The symbolic executor has to recognise the dispatch sequence a real
    /// compiler emits — `lea` of the table in `.rodata`, `movsxd` of an entry,
    /// `add` to fold the two together, indirect `jmp` — across the register
    /// shuffling that sits between those four instructions in optimized code.
    ///
    /// `pcre2_config_8` is a plain `switch` over its first argument, compiled
    /// into two such tables of sixteen entries each. Recovering them is what
    /// lets the merged copy of the function dispatch at all: the entries are
    /// offsets relative to the table, so without a relocation per entry the
    /// copied table still points where the library used to be loaded.
    #[test]
    fn recovers_the_switch_tables_of_a_real_function() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test/libs/libpcre2-8.so.0"
        ))
        .expect("read library");
        let file = object::File::parse(&*bytes).expect("parse library");
        let object::File::Elf64(elf) = &file else {
            panic!("not ELF64")
        };

        let (code, base) = function_code(elf, "pcre2_config_8");
        let tables = detect_jump_tables(&code, base, "pcre2_config_8", elf).expect("detect");
        assert_eq!(tables.len(), 2, "{tables:#x?}");

        let rodata = elf.section_by_name(".rodata").expect(".rodata");
        let rodata = rodata.address()..rodata.address() + rodata.size();
        for table in &tables {
            assert_eq!(table.targets.len(), 16, "{table:#x?}");
            assert!(
                rodata.contains(&table.table_vaddr),
                "table at {:#x} is not in .rodata",
                table.table_vaddr
            );
            // Every entry must branch into the function that owns the table;
            // an entry outside it would be a neighbouring table's, relocated
            // against the wrong function.
            assert!(
                table
                    .targets
                    .iter()
                    .all(|t| (base..base + code.len() as u64).contains(t)),
                "{table:#x?}"
            );
        }
    }

    const SECTION_ADDR: u64 = 0x7e000;
    const FUNC_BASE: u64 = 0x3350;
    const FUNC_SIZE: u64 = 0x100;

    /// Build a section holding one table of `in_func` entries pointing into
    /// `FUNC_BASE`, immediately followed by a second table belonging to a
    /// function that starts at `other_func`.
    fn section_with_two_tables(table_base: u64, in_func: usize, other_func: u64) -> Vec<u8> {
        let mut data = vec![0u8; 0x1000];
        let mut write = |idx: usize, target: u64| {
            let off = (table_base - SECTION_ADDR) as usize + idx * 4;
            let rel = (target as i64 - table_base as i64) as i32;
            data[off..off + 4].copy_from_slice(&rel.to_le_bytes());
        };
        for idx in 0..in_func {
            write(idx, FUNC_BASE + 0x10 + (idx as u64 % (FUNC_SIZE - 0x10)));
        }
        for idx in in_func..in_func + 32 {
            write(idx, other_func + (idx - in_func) as u64 * 2);
        }
        data
    }

    #[test]
    fn stops_at_the_end_of_the_owning_function() {
        let table_base = SECTION_ADDR + 0x914;
        let data = section_with_two_tables(table_base, 32, 0xd254);
        let targets =
            scan_table_entries(&data, SECTION_ADDR, table_base, FUNC_BASE, FUNC_SIZE, None)
                .unwrap();
        // Without the bound this would run on into the neighbouring function's
        // table and report 64 entries.
        assert_eq!(targets.len(), 32);
        assert!(
            targets
                .iter()
                .all(|&t| (FUNC_BASE..FUNC_BASE + FUNC_SIZE).contains(&t)),
            "{targets:#x?}"
        );
    }

    #[test]
    fn a_table_owned_by_another_function_yields_nothing() {
        // The same .rodata run, but scanned on behalf of the function that owns
        // the *first* table: the second table's entries must not be claimed.
        let table_base = SECTION_ADDR + 0x914;
        let data = section_with_two_tables(table_base, 32, 0xd254);
        let second = table_base + 32 * 4;
        let targets =
            scan_table_entries(&data, SECTION_ADDR, second, FUNC_BASE, FUNC_SIZE, None).unwrap();
        assert!(targets.is_empty(), "{targets:#x?}");
    }

    #[test]
    fn stops_at_the_next_detected_table() {
        let table_base = SECTION_ADDR + 0x100;
        let data = section_with_two_tables(table_base, 64, 0xd254);
        let targets = scan_table_entries(
            &data,
            SECTION_ADDR,
            table_base,
            FUNC_BASE,
            FUNC_SIZE,
            Some(table_base + 10 * 4),
        )
        .unwrap();
        assert_eq!(targets.len(), 10);
    }

    #[test]
    fn stops_at_the_end_of_the_section() {
        // Table starts 12 bytes before the end of the section.
        let mut data = vec![0u8; 0x100];
        let table_base = SECTION_ADDR + 0xf4;
        for idx in 0..3 {
            let off = 0xf4 + idx * 4;
            let rel = (FUNC_BASE as i64 - table_base as i64) as i32;
            data[off..off + 4].copy_from_slice(&rel.to_le_bytes());
        }
        let targets =
            scan_table_entries(&data, SECTION_ADDR, table_base, FUNC_BASE, FUNC_SIZE, None)
                .unwrap();
        assert_eq!(targets.len(), 3);
    }

    #[test]
    fn caps_the_entry_count() {
        // Every entry is in range, so only MAX_TABLE_ENTRIES stops the walk.
        let table_base = SECTION_ADDR;
        let mut data = Vec::new();
        for _ in 0..MAX_TABLE_ENTRIES * 2 {
            let rel = (FUNC_BASE as i64 - table_base as i64) as i32;
            data.extend_from_slice(&rel.to_le_bytes());
        }
        let targets =
            scan_table_entries(&data, SECTION_ADDR, table_base, FUNC_BASE, FUNC_SIZE, None)
                .unwrap();
        assert_eq!(targets.len(), MAX_TABLE_ENTRIES);
    }

    #[test]
    fn rejects_a_table_base_outside_the_section() {
        let data = vec![0u8; 0x100];
        assert!(
            scan_table_entries(
                &data,
                SECTION_ADDR,
                SECTION_ADDR - 4,
                FUNC_BASE,
                FUNC_SIZE,
                None
            )
            .is_none()
        );
        assert!(
            scan_table_entries(
                &data,
                SECTION_ADDR,
                SECTION_ADDR + 0xfe,
                FUNC_BASE,
                FUNC_SIZE,
                None
            )
            .is_none()
        );
    }
}
