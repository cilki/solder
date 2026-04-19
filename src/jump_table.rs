use std::collections::{HashMap, HashSet};

use anyhow::{bail, Context, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use object::{Object, ObjectSection, ObjectSymbol};

/// A detected jump table in .rodata
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// Virtual address of the table base in the shared library
    pub table_vaddr: u64,
    /// Number of entries (targets) in the table
    pub num_entries: usize,
    /// Target virtual addresses for each table entry
    pub targets: Vec<u64>,
    /// Section name where table resides (usually .rodata)
    pub section_name: String,
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

    eprintln!(
        "DEBUG: Scanning {} for jump tables (has indirect branch)",
        symbol_name
    );

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
                if instr.flow_control() == FlowControl::IndirectBranch {
                    if instr.op_count() >= 1 && instr.op_kind(0) == OpKind::Register {
                        if let Some(gpr) = to_gpr64(instr.op_register(0)) {
                            if let Some(AbstractValue::ComputedTarget { table_base }) =
                                regs.get(&gpr)
                            {
                                eprintln!(
                                    "DEBUG:   Confirmed jump table at {:#x} via indirect jmp at {:#x}",
                                    table_base,
                                    instr.ip()
                                );
                                confirmed_bases.insert(*table_base);
                            }
                        }
                    }
                }

                // Kill destination register for any other instruction that writes to a GP register
                kill_dest_register(&instr, &mut regs);
            }
        }
    }

    if confirmed_bases.is_empty() {
        return Ok(Vec::new());
    }

    // Validate each confirmed table base
    let mut jump_tables = Vec::new();
    for table_addr in confirmed_bases {
        match identify_table_bounds(elf, table_addr, base_vaddr, code.len() as u64) {
            Ok(table) => {
                eprintln!(
                    "DEBUG:   Validated jump table at {:#x} with {} entries",
                    table.table_vaddr, table.num_entries
                );
                jump_tables.push(table);
            }
            Err(e) => {
                eprintln!(
                    "DEBUG:   Table at {:#x} failed validation: {}",
                    table_addr, e
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
            eprintln!(
                "DEBUG:   LEA loading rodata address {:#x} at {:#x}",
                target,
                instr.ip()
            );
            regs.insert(gpr, AbstractValue::RodataAddr(target));
            return;
        }
    }

    // LEA used for arithmetic (e.g., lea rax, [rbx+rcx]) — check if it combines base+offset
    if instr.op_kind(1) == OpKind::Memory {
        let base_reg = instr.memory_base();
        let index_reg = instr.memory_index();

        if base_reg != Register::None && index_reg != Register::None {
            if let (Some(gpr_base), Some(gpr_index)) =
                (to_gpr64(base_reg), to_gpr64(index_reg))
            {
                let base_val = regs.get(&gpr_base).cloned();
                let index_val = regs.get(&gpr_index).cloned();
                if let Some(table_base) = try_combine(&base_val, &index_val) {
                    regs.insert(gpr, AbstractValue::ComputedTarget { table_base });
                    return;
                }
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
        if base_reg != Register::None {
            if let Some(gpr_base) = to_gpr64(base_reg) {
                if let Some(AbstractValue::RodataAddr(addr)) = regs.get(&gpr_base) {
                    regs.insert(
                        gpr_dst,
                        AbstractValue::TableEntry { table_base: *addr },
                    );
                    return;
                }
            }
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
    if instr.op_kind(0) == OpKind::Register {
        if let Some(gpr) = to_gpr64(instr.op_register(0)) {
            regs.remove(&gpr);
        }
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
    if instr.op_kind(0) == OpKind::Register {
        if let Some(gpr) = to_gpr64(instr.op_register(0)) {
            regs.remove(&gpr);
        }
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
    if instr.op_count() >= 1 && instr.op_kind(0) == OpKind::Register {
        if let Some(gpr) = to_gpr64(instr.op_register(0)) {
            regs.remove(&gpr);
        }
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
///    - Validate target is valid code address
///    - Check if target is "nearby" (within ±1MB of func_base)
/// 4. Stop when we hit invalid target or sentinel value
pub fn identify_table_bounds(
    elf: &object::read::elf::ElfFile64<'_>,
    table_base: u64,
    func_base: u64,
    _func_size: u64,
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

    let section_name = section.name().unwrap_or("<unknown>").to_string();

    let section_data = section.data().context("Could not read section data")?;

    let section_addr = section.address();

    let offset_in_section = (table_base - section_addr) as usize;

    if offset_in_section + 4 > section_data.len() {
        bail!("Table base offset exceeds section bounds");
    }

    let mut targets = Vec::new();
    let mut current_offset = offset_in_section;

    // Maximum reasonable table size (256 entries for switch statements)
    let max_entries = 256;

    eprintln!(
        "DEBUG:     Identifying table bounds at {:#x} in {}",
        table_base, section_name
    );

    for entry_idx in 0..max_entries {
        if current_offset + 4 > section_data.len() {
            break;
        }

        // Read i32 offset
        let offset_bytes = &section_data[current_offset..current_offset + 4];
        let i32_offset = i32::from_le_bytes([
            offset_bytes[0],
            offset_bytes[1],
            offset_bytes[2],
            offset_bytes[3],
        ]);

        // Compute target address
        // Formula: target = table_base + i32_value
        // This matches the code pattern: lea base, [rip+table]; movsxd off, [base+idx*4]; add off, base; jmp off
        let target = (table_base as i64 + i32_offset as i64) as u64;

        // Validation: target should be nearby (within ±1MB) and in a code section
        let distance = if target >= func_base {
            target - func_base
        } else {
            func_base - target
        };

        if distance > 1024 * 1024 {
            eprintln!(
                "DEBUG:     Entry {} target {:#x} too far from function ({}MB), stopping",
                entry_idx,
                target,
                distance / 1024 / 1024
            );
            break;
        }

        // Validate target is in a text section
        let in_text = elf.sections().any(|s| {
            let addr = s.address();
            let size = s.size();
            let kind = s.kind();
            matches!(kind, object::SectionKind::Text) && target >= addr && target < addr + size
        });

        if !in_text {
            eprintln!(
                "DEBUG:     Entry {} target {:#x} not in text section, stopping",
                entry_idx, target
            );
            break;
        }

        targets.push(target);
        current_offset += 4;
    }

    if targets.is_empty() {
        bail!("No valid jump table entries found");
    }

    if targets.len() < 2 {
        bail!(
            "Too few entries ({}) to be confident it's a jump table",
            targets.len()
        );
    }

    eprintln!("DEBUG:     Found {} valid entries", targets.len());

    Ok(JumpTable {
        table_vaddr: table_base,
        num_entries: targets.len(),
        targets,
        section_name,
    })
}

/// Find the symbol name at a given virtual address, if any exists.
/// Checks if address falls within the symbol's range (address to address+size).
pub fn find_symbol_at_address(
    elf: &object::read::elf::ElfFile64<'_>,
    addr: u64,
) -> Option<String> {
    // First check .symtab (has local symbols)
    for sym in elf.symbols() {
        let sym_addr = sym.address();
        let sym_size = sym.size();
        if addr >= sym_addr && addr < sym_addr + sym_size && !sym.is_undefined() {
            if let Ok(name) = sym.name() {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    // Fall back to .dynsym
    for sym in elf.dynamic_symbols() {
        let sym_addr = sym.address();
        let sym_size = sym.size();
        if addr >= sym_addr && addr < sym_addr + sym_size && !sym.is_undefined() {
            if let Ok(name) = sym.name() {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}
