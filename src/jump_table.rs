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
    /// Number of entries (targets) in the table
    pub num_entries: usize,
    /// Target virtual addresses for each table entry
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

/// Map a sub-register to its full 64-bit GP register for state tracking.
fn to_gpr64(reg: Register) -> Option<Register> {
    match reg {
        Register::AL | Register::AH | Register::AX | Register::EAX | Register::RAX => {
            Some(Register::RAX)
        }
        Register::BL | Register::BH | Register::BX | Register::EBX | Register::RBX => {
            Some(Register::RBX)
        }
        Register::CL | Register::CH | Register::CX | Register::ECX | Register::RCX => {
            Some(Register::RCX)
        }
        Register::DL | Register::DH | Register::DX | Register::EDX | Register::RDX => {
            Some(Register::RDX)
        }
        Register::SIL | Register::SI | Register::ESI | Register::RSI => Some(Register::RSI),
        Register::DIL | Register::DI | Register::EDI | Register::RDI => Some(Register::RDI),
        Register::BPL | Register::BP | Register::EBP | Register::RBP => Some(Register::RBP),
        Register::SPL | Register::SP | Register::ESP | Register::RSP => Some(Register::RSP),
        Register::R8L | Register::R8W | Register::R8D | Register::R8 => Some(Register::R8),
        Register::R9L | Register::R9W | Register::R9D | Register::R9 => Some(Register::R9),
        Register::R10L | Register::R10W | Register::R10D | Register::R10 => Some(Register::R10),
        Register::R11L | Register::R11W | Register::R11D | Register::R11 => Some(Register::R11),
        Register::R12L | Register::R12W | Register::R12D | Register::R12 => Some(Register::R12),
        Register::R13L | Register::R13W | Register::R13D | Register::R13 => Some(Register::R13),
        Register::R14L | Register::R14W | Register::R14D | Register::R14 => Some(Register::R14),
        Register::R15L | Register::R15W | Register::R15D | Register::R15 => Some(Register::R15),
        _ => None,
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
    _lib_bytes: &[u8],
) -> Result<Vec<JumpTable>> {
    if code.len() < 16 {
        return Ok(Vec::new());
    }

    // Quick check: does this function contain any indirect branches?
    let mut decoder = Decoder::with_ip(64, code, base_vaddr, DecoderOptions::NONE);
    let mut has_indirect = false;
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.flow_control() == FlowControl::IndirectBranch {
            has_indirect = true;
            break;
        }
    }

    if !has_indirect {
        return Ok(Vec::new());
    }

    debug!(symbol = symbol_name, "Scanning for jump tables");

    // Symbolic execution pass
    let mut regs: HashMap<Register, AbstractValue> = HashMap::new();
    let mut confirmed_bases: HashSet<u64> = HashSet::new();

    let mut decoder = Decoder::with_ip(64, code, base_vaddr, DecoderOptions::NONE);
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);

        match instr.mnemonic() {
            Mnemonic::Lea => {
                handle_lea(&instr, elf, &mut regs);
            }
            Mnemonic::Movsxd => {
                handle_movsxd(&instr, &mut regs);
            }
            Mnemonic::Add => {
                handle_add(&instr, &mut regs);
            }
            Mnemonic::Mov => {
                handle_mov(&instr, &mut regs);
            }
            _ => {
                // Check for indirect jump with a computed target
                if instr.flow_control() == FlowControl::IndirectBranch
                    && instr.op_count() >= 1
                    && instr.op_kind(0) == OpKind::Register
                    && let Some(gpr) = to_gpr64(instr.op_register(0))
                    && let Some(AbstractValue::ComputedTarget { table_base }) = regs.get(&gpr)
                {
                    debug!(
                        table_base = format_args!("{:#x}", table_base),
                        jmp_addr = format_args!("{:#x}", instr.ip()),
                        "Confirmed jump table"
                    );
                    confirmed_bases.insert(*table_base);
                }

                // Kill destination register for any other instruction that writes to a GP register
                kill_dest_register(&instr, &mut regs);
            }
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
                    entries = table.num_entries,
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

/// Handle LEA instruction: if it's a RIP-relative LEA targeting .rodata, track the value.
fn handle_lea(
    instr: &Instruction,
    elf: &object::read::elf::ElfFile64<'_>,
    regs: &mut HashMap<Register, AbstractValue>,
) {
    // LEA reg, [rip+disp] — destination is always op0 (register)
    if instr.op_count() < 2 {
        return;
    }
    let dst = match instr.op_kind(0) {
        OpKind::Register => instr.op_register(0),
        _ => return,
    };
    let Some(gpr) = to_gpr64(dst) else {
        return;
    };

    if instr.is_ip_rel_memory_operand() {
        let target = instr.ip_rel_memory_address();
        if is_rodata_address(elf, target) {
            regs.insert(gpr, AbstractValue::RodataAddr(target));
            return;
        }
    }

    // LEA used for arithmetic (e.g., lea rax, [rbx+rcx]) — check if it combines base+offset
    if instr.op_kind(1) == OpKind::Memory {
        let base_reg = instr.memory_base();
        let index_reg = instr.memory_index();

        if base_reg != Register::None
            && index_reg != Register::None
            && let (Some(gpr_base), Some(gpr_index)) = (to_gpr64(base_reg), to_gpr64(index_reg))
        {
            let base_val = regs.get(&gpr_base).cloned();
            let index_val = regs.get(&gpr_index).cloned();
            if let Some(table_base) = try_combine(&base_val, &index_val) {
                regs.insert(gpr, AbstractValue::ComputedTarget { table_base });
                return;
            }
        }
    }

    // Unrecognized LEA pattern — kill the destination
    regs.remove(&gpr);
}

/// Handle MOVSXD instruction: if base register holds a RodataAddr, this is a table entry load.
fn handle_movsxd(instr: &Instruction, regs: &mut HashMap<Register, AbstractValue>) {
    if instr.op_count() < 2 {
        return;
    }
    let dst = match instr.op_kind(0) {
        OpKind::Register => instr.op_register(0),
        _ => return,
    };
    let Some(gpr_dst) = to_gpr64(dst) else {
        return;
    };

    // Source is a memory operand — check if base register is a tracked RodataAddr
    if instr.op_kind(1) == OpKind::Memory {
        let base_reg = instr.memory_base();
        if base_reg != Register::None
            && let Some(gpr_base) = to_gpr64(base_reg)
            && let Some(AbstractValue::RodataAddr(addr)) = regs.get(&gpr_base)
        {
            regs.insert(gpr_dst, AbstractValue::TableEntry { table_base: *addr });
            return;
        }
    }

    regs.remove(&gpr_dst);
}

/// Handle ADD instruction: if one operand is RodataAddr and other is TableEntry, produce ComputedTarget.
fn handle_add(instr: &Instruction, regs: &mut HashMap<Register, AbstractValue>) {
    if instr.op_count() < 2 {
        return;
    }

    // ADD reg, reg
    if instr.op_kind(0) == OpKind::Register && instr.op_kind(1) == OpKind::Register {
        let dst = instr.op_register(0);
        let src = instr.op_register(1);
        let (Some(gpr_dst), Some(gpr_src)) = (to_gpr64(dst), to_gpr64(src)) else {
            return;
        };

        let dst_val = regs.get(&gpr_dst).cloned();
        let src_val = regs.get(&gpr_src).cloned();

        if let Some(table_base) = try_combine(&dst_val, &src_val) {
            regs.insert(gpr_dst, AbstractValue::ComputedTarget { table_base });
            return;
        }
    }

    // Any other ADD pattern — kill destination
    if instr.op_kind(0) == OpKind::Register
        && let Some(gpr) = to_gpr64(instr.op_register(0))
    {
        regs.remove(&gpr);
    }
}

/// Handle MOV reg, reg: copy abstract value.
fn handle_mov(instr: &Instruction, regs: &mut HashMap<Register, AbstractValue>) {
    if instr.op_count() < 2 {
        return;
    }

    if instr.op_kind(0) == OpKind::Register && instr.op_kind(1) == OpKind::Register {
        let dst = instr.op_register(0);
        let src = instr.op_register(1);
        if let (Some(gpr_dst), Some(gpr_src)) = (to_gpr64(dst), to_gpr64(src)) {
            if let Some(val) = regs.get(&gpr_src).cloned() {
                regs.insert(gpr_dst, val);
            } else {
                regs.remove(&gpr_dst);
            }
            return;
        }
    }

    // MOV reg, mem or MOV reg, imm — kill destination
    if instr.op_kind(0) == OpKind::Register
        && let Some(gpr) = to_gpr64(instr.op_register(0))
    {
        regs.remove(&gpr);
    }
}

/// Try to combine two abstract values into a ComputedTarget.
/// Returns Some(table_base) if one is RodataAddr and the other is TableEntry with matching base.
fn try_combine(a: &Option<AbstractValue>, b: &Option<AbstractValue>) -> Option<u64> {
    match (a, b) {
        (Some(AbstractValue::RodataAddr(addr)), Some(AbstractValue::TableEntry { table_base }))
        | (Some(AbstractValue::TableEntry { table_base }), Some(AbstractValue::RodataAddr(addr)))
            if addr == table_base =>
        {
            Some(*table_base)
        }
        _ => None,
    }
}

/// Kill the destination register of an instruction that writes to a GP register.
fn kill_dest_register(instr: &Instruction, regs: &mut HashMap<Register, AbstractValue>) {
    if instr.op_count() >= 1
        && instr.op_kind(0) == OpKind::Register
        && let Some(gpr) = to_gpr64(instr.op_register(0))
    {
        regs.remove(&gpr);
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
pub fn identify_table_bounds(
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
        num_entries: targets.len(),
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
    use super::{MAX_TABLE_ENTRIES, scan_table_entries};

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
