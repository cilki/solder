use std::collections::{HashMap, HashSet};

use anyhow::{bail, Context, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use object::{Object, ObjectSection, ObjectSymbol};
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

    debug!(symbol=symbol_name, "Scanning for jump tables");

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
                                debug!(
                                    table_base=format_args!("{:#x}", table_base),
                                    jmp_addr=format_args!("{:#x}", instr.ip()),
                                    "Confirmed jump table"
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
                    vaddr=format_args!("{:#x}", table.table_vaddr),
                    entries=table.num_entries,
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

/// Run symbolic execution on raw code bytes, returning the set of confirmed jump table base
/// addresses. This is the core detection logic extracted for testability — it does not require
/// an ELF file, so it cannot validate that LEA targets actually land in .rodata. Instead, every
/// RIP-relative LEA is treated as a potential table base, and `rodata_filter` (if provided) can
/// reject addresses that aren't in .rodata.
fn symbolic_execution_scan(
    code: &[u8],
    base_vaddr: u64,
    rodata_filter: Option<&dyn Fn(u64) -> bool>,
) -> HashSet<u64> {
    let mut regs: HashMap<Register, AbstractValue> = HashMap::new();
    let mut confirmed_bases: HashSet<u64> = HashSet::new();
    let mut instr = Instruction::default();
    let mut decoder = Decoder::with_ip(64, code, base_vaddr, DecoderOptions::NONE);

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);

        match instr.mnemonic() {
            Mnemonic::Lea => {
                // Inline LEA handling without ELF dependency
                if instr.op_count() >= 2 {
                    if let OpKind::Register = instr.op_kind(0) {
                        let dst = instr.op_register(0);
                        if let Some(gpr) = to_gpr64(dst) {
                            if instr.is_ip_rel_memory_operand() {
                                let target = instr.ip_rel_memory_address();
                                let accept =
                                    rodata_filter.map_or(true, |f| f(target));
                                if accept {
                                    regs.insert(gpr, AbstractValue::RodataAddr(target));
                                    continue;
                                }
                            }

                            // LEA as arithmetic (base+index)
                            if instr.op_kind(1) == OpKind::Memory {
                                let base_reg = instr.memory_base();
                                let index_reg = instr.memory_index();
                                if base_reg != Register::None && index_reg != Register::None {
                                    if let (Some(gpr_base), Some(gpr_index)) =
                                        (to_gpr64(base_reg), to_gpr64(index_reg))
                                    {
                                        let base_val = regs.get(&gpr_base).cloned();
                                        let index_val = regs.get(&gpr_index).cloned();
                                        if let Some(table_base) =
                                            try_combine(&base_val, &index_val)
                                        {
                                            regs.insert(
                                                gpr,
                                                AbstractValue::ComputedTarget { table_base },
                                            );
                                            continue;
                                        }
                                    }
                                }
                            }

                            regs.remove(&gpr);
                        }
                    }
                }
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
                if instr.flow_control() == FlowControl::IndirectBranch {
                    if instr.op_count() >= 1 && instr.op_kind(0) == OpKind::Register {
                        if let Some(gpr) = to_gpr64(instr.op_register(0)) {
                            if let Some(AbstractValue::ComputedTarget { table_base }) =
                                regs.get(&gpr)
                            {
                                confirmed_bases.insert(*table_base);
                            }
                        }
                    }
                }
                kill_dest_register(&instr, &mut regs);
            }
        }
    }

    confirmed_bases
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

    for entry_idx in 0..max_entries {
        if current_offset + 4 > section_data.len() {
            break;
        }

        // Stop before the next table starts (avoid overlapping relocations)
        let entry_vaddr = table_base + (entry_idx * 4) as u64;
        if let Some(next) = next_table {
            if entry_vaddr >= next {
                break;
            }
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

    Ok(JumpTable {
        table_vaddr: table_base,
        num_entries: targets.len(),
        targets,
        section_name,
    })
}

/// Find the symbol name at a given virtual address, if any exists.
/// Checks if address falls within the symbol's range (address to address+size).
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: assemble a classic jump table pattern at a given base VA.
    ///
    /// Produces:
    ///   lea rax, [rip + disp]       ; rax = table_addr (in .rodata)
    ///   movsxd rcx, [rax + rdx*4]   ; rcx = sign-extended i32 from table
    ///   add rax, rcx                ; rax = table_base + offset = target
    ///   jmp rax                     ; indirect jump
    ///
    /// `code_base` is the VA where the code starts.
    /// `table_addr` is the VA of the jump table in .rodata.
    fn assemble_classic_jump_table(code_base: u64, table_addr: u64) -> Vec<u8> {
        let mut code = Vec::new();

        // LEA RAX, [RIP + disp32]
        // Encoding: 48 8D 05 <disp32>
        // The displacement is relative to the NEXT instruction's IP.
        // LEA is 7 bytes, so next_ip = code_base + 7.
        // disp = table_addr - next_ip
        let lea_next_ip = code_base + 7;
        let disp = (table_addr as i64 - lea_next_ip as i64) as i32;
        code.extend_from_slice(&[0x48, 0x8D, 0x05]);
        code.extend_from_slice(&disp.to_le_bytes());

        // MOVSXD RCX, [RAX + RDX*4]
        // Encoding: 48 63 0C 90
        code.extend_from_slice(&[0x48, 0x63, 0x0C, 0x90]);

        // ADD RAX, RCX
        // Encoding: 48 01 C8
        code.extend_from_slice(&[0x48, 0x01, 0xC8]);

        // JMP RAX
        // Encoding: FF E0
        code.extend_from_slice(&[0xFF, 0xE0]);

        code
    }

    #[test]
    fn test_classic_jump_table_detected() {
        let code_base = 0x1000u64;
        let table_addr = 0x5000u64;
        let code = assemble_classic_jump_table(code_base, table_addr);

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert_eq!(bases.len(), 1);
        assert!(bases.contains(&table_addr));
    }

    #[test]
    fn test_classic_jump_table_with_rodata_filter_accepts() {
        let code_base = 0x1000u64;
        let table_addr = 0x5000u64;
        let code = assemble_classic_jump_table(code_base, table_addr);

        // Filter that accepts the table address
        let bases = symbolic_execution_scan(&code, code_base, Some(&|addr| addr == table_addr));
        assert_eq!(bases.len(), 1);
        assert!(bases.contains(&table_addr));
    }

    #[test]
    fn test_classic_jump_table_with_rodata_filter_rejects() {
        let code_base = 0x1000u64;
        let table_addr = 0x5000u64;
        let code = assemble_classic_jump_table(code_base, table_addr);

        // Filter that rejects all addresses (not in .rodata)
        let bases = symbolic_execution_scan(&code, code_base, Some(&|_| false));
        assert!(bases.is_empty());
    }

    #[test]
    fn test_no_indirect_branch_no_detection() {
        // Just some arithmetic, no JMP reg
        //   lea rax, [rip+0x3000]
        //   movsxd rcx, [rax+rdx*4]
        //   add rax, rcx
        //   ret
        let code_base = 0x1000u64;
        let mut code = Vec::new();

        // LEA RAX, [RIP+disp32]
        let disp = (0x5000i64 - (code_base as i64 + 7)) as i32;
        code.extend_from_slice(&[0x48, 0x8D, 0x05]);
        code.extend_from_slice(&disp.to_le_bytes());

        // MOVSXD RCX, [RAX + RDX*4]
        code.extend_from_slice(&[0x48, 0x63, 0x0C, 0x90]);

        // ADD RAX, RCX
        code.extend_from_slice(&[0x48, 0x01, 0xC8]);

        // RET (not an indirect branch through register)
        code.push(0xC3);

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert!(bases.is_empty());
    }

    #[test]
    fn test_indirect_jmp_without_table_pattern_not_detected() {
        // JMP to a register that was loaded from memory (not a jump table pattern)
        //   mov rax, [rbx]
        //   jmp rax
        let code_base = 0x1000u64;
        let code: Vec<u8> = vec![
            0x48, 0x8B, 0x03, // MOV RAX, [RBX]
            0xFF, 0xE0, // JMP RAX
        ];

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert!(bases.is_empty());
    }

    #[test]
    fn test_lea_overwritten_before_use() {
        // LEA loads table address, but register is overwritten before the jump table pattern
        //   lea rax, [rip+table]
        //   xor rax, rax          ; kills the RodataAddr
        //   movsxd rcx, [rax+rdx*4]
        //   add rax, rcx
        //   jmp rax
        let code_base = 0x1000u64;
        let table_addr = 0x5000u64;
        let mut code = Vec::new();

        // LEA RAX, [RIP+disp32] (7 bytes)
        let disp = (table_addr as i64 - (code_base as i64 + 7)) as i32;
        code.extend_from_slice(&[0x48, 0x8D, 0x05]);
        code.extend_from_slice(&disp.to_le_bytes());

        // XOR RAX, RAX (3 bytes) — kills RAX
        code.extend_from_slice(&[0x48, 0x31, 0xC0]);

        // MOVSXD RCX, [RAX+RDX*4]
        code.extend_from_slice(&[0x48, 0x63, 0x0C, 0x90]);

        // ADD RAX, RCX
        code.extend_from_slice(&[0x48, 0x01, 0xC8]);

        // JMP RAX
        code.extend_from_slice(&[0xFF, 0xE0]);

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert!(bases.is_empty());
    }

    #[test]
    fn test_movsxd_without_rodata_base_not_detected() {
        // MOVSXD from a register that does NOT hold a RodataAddr
        //   mov rax, rbx           ; RAX = unknown
        //   movsxd rcx, [rax+rdx*4]
        //   add rax, rcx
        //   jmp rax
        let code_base = 0x1000u64;
        let code: Vec<u8> = vec![
            0x48, 0x89, 0xD8, // MOV RAX, RBX
            0x48, 0x63, 0x0C, 0x90, // MOVSXD RCX, [RAX+RDX*4]
            0x48, 0x01, 0xC8, // ADD RAX, RCX
            0xFF, 0xE0, // JMP RAX
        ];

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert!(bases.is_empty());
    }

    #[test]
    fn test_add_mismatched_table_bases_not_detected() {
        // LEA loads two different .rodata addresses, MOVSXD uses one, ADD combines with the other
        //   lea rax, [rip+table_a]   ; rax = RodataAddr(table_a)
        //   lea rbx, [rip+table_b]   ; rbx = RodataAddr(table_b)
        //   movsxd rcx, [rax+rdx*4]  ; rcx = TableEntry{table_base: table_a}
        //   add rbx, rcx             ; try_combine(RodataAddr(table_b), TableEntry{table_a}) → None
        //   jmp rbx
        let code_base = 0x1000u64;
        let table_a = 0x5000u64;
        let table_b = 0x6000u64;
        let mut code = Vec::new();

        // LEA RAX, [RIP+disp_a] (7 bytes)
        let disp_a = (table_a as i64 - (code_base as i64 + 7)) as i32;
        code.extend_from_slice(&[0x48, 0x8D, 0x05]);
        code.extend_from_slice(&disp_a.to_le_bytes());

        // LEA RBX, [RIP+disp_b] (7 bytes) at offset 7
        let disp_b = (table_b as i64 - (code_base as i64 + 14)) as i32;
        code.extend_from_slice(&[0x48, 0x8D, 0x1D]);
        code.extend_from_slice(&disp_b.to_le_bytes());

        // MOVSXD RCX, [RAX+RDX*4] (4 bytes)
        code.extend_from_slice(&[0x48, 0x63, 0x0C, 0x90]);

        // ADD RBX, RCX (3 bytes)
        code.extend_from_slice(&[0x48, 0x01, 0xCB]);

        // JMP RBX (2 bytes)
        code.extend_from_slice(&[0xFF, 0xE3]);

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert!(bases.is_empty(), "mismatched table bases should not be detected");
    }

    #[test]
    fn test_mov_propagates_computed_target() {
        // MOV copies a ComputedTarget to another register, then jumps through it
        //   lea rax, [rip+table]
        //   movsxd rcx, [rax+rdx*4]
        //   add rax, rcx
        //   mov rbx, rax             ; copy ComputedTarget to RBX
        //   jmp rbx                  ; jump through RBX
        let code_base = 0x1000u64;
        let table_addr = 0x5000u64;
        let mut code = Vec::new();

        // LEA RAX, [RIP+disp32]
        let disp = (table_addr as i64 - (code_base as i64 + 7)) as i32;
        code.extend_from_slice(&[0x48, 0x8D, 0x05]);
        code.extend_from_slice(&disp.to_le_bytes());

        // MOVSXD RCX, [RAX+RDX*4]
        code.extend_from_slice(&[0x48, 0x63, 0x0C, 0x90]);

        // ADD RAX, RCX
        code.extend_from_slice(&[0x48, 0x01, 0xC8]);

        // MOV RBX, RAX
        code.extend_from_slice(&[0x48, 0x89, 0xC3]);

        // JMP RBX
        code.extend_from_slice(&[0xFF, 0xE3]);

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert_eq!(bases.len(), 1);
        assert!(bases.contains(&table_addr));
    }

    #[test]
    fn test_multiple_jump_tables_detected() {
        // Two independent jump table patterns in the same function
        let code_base = 0x1000u64;
        let table_a = 0x5000u64;
        let table_b = 0x6000u64;

        let mut code = Vec::new();

        // First jump table pattern
        let first_code = assemble_classic_jump_table(code_base, table_a);
        code.extend_from_slice(&first_code);

        // Second jump table pattern
        let second_base = code_base + first_code.len() as u64;
        let second_code = assemble_classic_jump_table(second_base, table_b);
        code.extend_from_slice(&second_code);

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert_eq!(bases.len(), 2);
        assert!(bases.contains(&table_a));
        assert!(bases.contains(&table_b));
    }

    #[test]
    fn test_lea_to_text_section_not_detected() {
        // LEA to a text address (not .rodata) should not produce a jump table
        // when rodata_filter rejects it
        let code_base = 0x1000u64;
        let text_addr = 0x2000u64; // in .text, not .rodata
        let code = assemble_classic_jump_table(code_base, text_addr);

        // Filter rejects text addresses
        let bases = symbolic_execution_scan(&code, code_base, Some(&|addr| addr >= 0x5000));
        assert!(bases.is_empty());
    }

    #[test]
    fn test_code_too_short() {
        let code: Vec<u8> = vec![0xC3]; // just RET
        let bases = symbolic_execution_scan(&code, 0x1000, None);
        assert!(bases.is_empty());
    }

    #[test]
    fn test_empty_code() {
        let code: Vec<u8> = vec![];
        let bases = symbolic_execution_scan(&code, 0x1000, None);
        assert!(bases.is_empty());
    }

    #[test]
    fn test_32bit_subreg_lea_detected() {
        // LEA EAX, [RIP+disp] — writes to 32-bit sub-register, should be tracked as RAX
        // Then use RAX in the standard pattern
        let code_base = 0x1000u64;
        let table_addr = 0x5000u64;
        let mut code = Vec::new();

        // LEA EAX, [RIP+disp32] (6 bytes: 8D 05 <disp32>)
        // Note: no REX.W prefix — this is a 32-bit LEA
        let lea_next_ip = code_base + 6; // 6 bytes, not 7
        let disp = (table_addr as i64 - lea_next_ip as i64) as i32;
        code.extend_from_slice(&[0x8D, 0x05]);
        code.extend_from_slice(&disp.to_le_bytes());

        // MOVSXD RCX, [RAX+RDX*4]
        code.extend_from_slice(&[0x48, 0x63, 0x0C, 0x90]);

        // ADD RAX, RCX
        code.extend_from_slice(&[0x48, 0x01, 0xC8]);

        // JMP RAX
        code.extend_from_slice(&[0xFF, 0xE0]);

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert_eq!(bases.len(), 1);
        assert!(bases.contains(&table_addr));
    }

    #[test]
    fn test_lea_used_for_address_calc_not_detected() {
        // LEA used for simple address calculation (not a jump table):
        //   lea rax, [rip+data]     ; load some .rodata address
        //   mov rcx, [rax]          ; load a value from that address (kills tracked state)
        //   jmp rcx                 ; indirect jump through loaded value
        let code_base = 0x1000u64;
        let data_addr = 0x5000u64;
        let mut code = Vec::new();

        // LEA RAX, [RIP+disp32]
        let disp = (data_addr as i64 - (code_base as i64 + 7)) as i32;
        code.extend_from_slice(&[0x48, 0x8D, 0x05]);
        code.extend_from_slice(&disp.to_le_bytes());

        // MOV RCX, [RAX] — loads a value from memory, NOT movsxd from table
        code.extend_from_slice(&[0x48, 0x8B, 0x08]);

        // JMP RCX
        code.extend_from_slice(&[0xFF, 0xE1]);

        let bases = symbolic_execution_scan(&code, code_base, None);
        assert!(bases.is_empty());
    }
}
