use anyhow::{bail, Context, Result};

use crate::layout::align_up;
use crate::types::{MergePlan, RelativeReloc};

/// Build the merged segment bytes (all units + trampoline stubs) in one flat buffer.
///
/// Each unit is placed at its `assigned_vaddr - plan.load_address` offset.
/// Gaps between units are zero-filled.
///
/// For PIE executables, this also populates `plan.relative_relocs` with entries
/// for the trampoline GOT address slots that need R_X86_64_RELATIVE relocations.
pub fn build_merged_segment(plan: &mut MergePlan) -> Result<Vec<u8>> {
    let size = plan.segment_size();
    let mut seg = vec![0u8; size];

    for au in plan.all_units() {
        let off = (au.assigned_vaddr - plan.load_address) as usize;
        let end = off + au.unit.bytes.len();
        if end > seg.len() {
            bail!(
                "unit '{}' at offset 0x{:x} + {} overflows segment of size {}",
                au.unit.name,
                off,
                au.unit.bytes.len(),
                seg.len()
            );
        }
        seg[off..end].copy_from_slice(&au.unit.bytes);
    }

    for stub in &plan.trampoline_stubs {
        let off = (stub.vaddr - plan.load_address) as usize;
        // Write: FF 25 00 00 00 00  (jmp [rip+0])
        //        <8 bytes: target GOT VA>
        // At runtime: [rip+0] = the 8 bytes immediately after this instruction.
        // The RIP after the instruction = stub.vaddr + 6, so:
        //   [rip + 0] = *(stub.vaddr + 6) = target_got_vaddr
        // But this is an *indirect* jump — it reads a 64-bit address from
        // stub.vaddr+6 and jumps to that address.  We store the target GOT *VA*
        // directly (the GOT slot holds the resolved function pointer at runtime).
        //
        // Actually: FF 25 imm32 means jmp QWORD PTR [rip + imm32].
        // The imm32 encodes the offset from (rip after this 6-byte instruction)
        // to the 8-byte target slot.  We place the target slot immediately after
        // the instruction, so imm32 = 0.
        if off + 14 > seg.len() {
            bail!("trampoline for '{}' overflows segment", stub.symbol_name);
        }
        seg[off] = 0xFF;
        seg[off + 1] = 0x25;
        seg[off + 2..off + 6].copy_from_slice(&0u32.to_le_bytes()); // RIP+0
        seg[off + 6..off + 14].copy_from_slice(&stub.target_got_vaddr.to_le_bytes());

        // For PIE: the 8-byte GOT address at offset+6 needs runtime fixup
        if plan.is_pie {
            plan.relative_relocs.push(RelativeReloc {
                vaddr: stub.vaddr + 6,
                addend: stub.target_got_vaddr as i64,
            });
        }
    }

    Ok(seg)
}

/// Write the final output ELF file.
///
/// Structure:
///   [patched original ELF bytes]
///   [merged segment bytes]
///   [new program header table (old PHT + new PT_LOAD entry)]
///
/// The ELF header is updated in-place to point e_phoff at the new PHT location.
pub fn write_output(
    patched_exe: &[u8],
    plan: &MergePlan,
    merged_seg: &[u8],
    output_path: &std::path::Path,
) -> Result<()> {
    use object::elf::{PF_R, PF_W, PF_X, PT_LOAD, PT_PHDR};
    use object::read::elf::{ElfFile64, ProgramHeader};

    let exe = ElfFile64::<object::Endianness>::parse(patched_exe)
        .context("parsing patched executable for output")?;
    let endian = exe.endian();

    // Collect existing program headers.
    let old_phdrs: Vec<object::elf::ProgramHeader64<object::Endianness>> =
        exe.elf_program_headers().to_vec();
    let phdr_entry_size = std::mem::size_of::<object::elf::ProgramHeader64<object::Endianness>>();

    // File offset where the merged segment will start.
    let seg_file_offset = patched_exe.len() as u64;
    // Page-align the offset (required by the kernel for PT_LOAD).
    let seg_file_offset = align_up(seg_file_offset, 0x1000);

    // File offset where the new PHT will start (after the merged segment, page-aligned).
    let pht_file_offset = align_up(seg_file_offset + merged_seg.len() as u64, 8);
    let new_phnum = old_phdrs.len() + 1;
    let pht_size = (new_phnum * phdr_entry_size) as u64;

    // Build the output buffer.
    let total_size = pht_file_offset + pht_size;
    let mut out = vec![0u8; total_size as usize];

    // Copy patched exe bytes.
    out[..patched_exe.len()].copy_from_slice(patched_exe);
    // Copy merged segment.
    let seg_start = seg_file_offset as usize;
    let seg_end = seg_start + merged_seg.len();
    out[seg_start..seg_end].copy_from_slice(merged_seg);

    // Build the new PHT.
    let pht_start = pht_file_offset as usize;

    // Copy old entries, updating PT_PHDR if present.
    let mut written = 0usize;
    for phdr in &old_phdrs {
        let p_type = phdr.p_type(endian);
        let entry_bytes: &[u8] = as_bytes(phdr);
        let dst = pht_start + written;
        out[dst..dst + phdr_entry_size].copy_from_slice(entry_bytes);

        // If this is PT_PHDR, update p_offset and p_vaddr to new location.
        if p_type == PT_PHDR {
            // p_offset is at offset 8 in Phdr64 (after p_type + p_flags)
            // Actually layout: p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8) p_filesz(8) p_memsz(8) p_align(8)
            write_u64_le(&mut out, dst + 8, pht_file_offset);
            // p_vaddr: we can't know the mapping VA for the PHT without knowing the
            // load bias. For ET_EXEC, set p_vaddr = p_paddr = 0 (PHT is not mapped
            // as its own segment in typical executables; PT_PHDR is informational).
            // Leave p_vaddr unchanged (it was likely wrong anyway in the original
            // for our purposes).
        }

        written += phdr_entry_size;
    }

    // Write the new PT_LOAD entry for the merged segment.
    // Layout of Elf64_Phdr:
    //   p_type   u32  offset 0
    //   p_flags  u32  offset 4
    //   p_offset u64  offset 8
    //   p_vaddr  u64  offset 16
    //   p_paddr  u64  offset 24
    //   p_filesz u64  offset 32
    //   p_memsz  u64  offset 40
    //   p_align  u64  offset 48
    let dst = pht_start + written;
    write_u32_le(&mut out, dst, PT_LOAD);
    write_u32_le(&mut out, dst + 4, PF_R | PF_W | PF_X); // rwx — MVP
    write_u64_le(&mut out, dst + 8, seg_file_offset);
    write_u64_le(&mut out, dst + 16, plan.load_address);
    write_u64_le(&mut out, dst + 24, plan.load_address); // p_paddr = p_vaddr
    write_u64_le(&mut out, dst + 32, merged_seg.len() as u64);
    write_u64_le(&mut out, dst + 40, merged_seg.len() as u64);
    write_u64_le(&mut out, dst + 48, 0x1000); // p_align = 4 KiB

    // Update ELF header: e_phoff (offset 32 in Elf64 header) and e_phnum (offset 56).
    write_u64_le(&mut out, 32, pht_file_offset);
    write_u16_le(&mut out, 56, new_phnum as u16);

    // For PIE executables, extend .rela.dyn with RELATIVE relocations
    if plan.is_pie && !plan.relative_relocs.is_empty() {
        extend_rela_dyn(&mut out, plan)?;
    }

    // Write output file.
    std::fs::write(output_path, &out)
        .with_context(|| format!("writing output {}", output_path.display()))?;

    // Make executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(output_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(output_path, perms)?;
    }

    Ok(())
}

// Helper: view a value as bytes.
fn as_bytes<T: Sized>(val: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) }
}

fn write_u64_le(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn write_u32_le(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u16_le(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

fn write_i64_le(buf: &mut [u8], offset: usize, val: i64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

/// R_X86_64_RELATIVE relocation type
const R_X86_64_RELATIVE: u32 = 8;

/// Size of an Elf64_Rela entry
const RELA_ENTRY_SIZE: usize = 24;

/// Extend .rela.dyn with R_X86_64_RELATIVE entries for PIE executables.
///
/// This function appends new RELATIVE relocation entries to the file and updates
/// DT_RELASZ in .dynamic to include them. For simplicity, we relocate the entire
/// .rela.dyn section to the end of the file (after the PHT).
fn extend_rela_dyn(out: &mut Vec<u8>, plan: &MergePlan) -> Result<()> {
    if plan.relative_relocs.is_empty() {
        return Ok(());
    }

    // Parse the current state to find .rela.dyn info
    let goblin_elf = goblin::elf::Elf::parse(out).context("parsing ELF for rela.dyn extension")?;

    // Find DT_RELA, DT_RELASZ, DT_RELAENT, DT_RELACOUNT in .dynamic
    let dynamic = goblin_elf
        .dynamic
        .as_ref()
        .context("no .dynamic section for PIE rela.dyn extension")?;

    let mut dt_rela_offset: Option<u64> = None;
    let mut dt_relasz: Option<u64> = None;
    let mut dt_relacount: Option<u64> = None;
    let mut dt_rela_dyn_idx: Option<usize> = None;
    let mut dt_relasz_dyn_idx: Option<usize> = None;
    let mut dt_relacount_dyn_idx: Option<usize> = None;

    for (i, entry) in dynamic.dyns.iter().enumerate() {
        match entry.d_tag {
            goblin::elf::dynamic::DT_RELA => {
                dt_rela_offset = Some(entry.d_val);
                dt_rela_dyn_idx = Some(i);
            }
            goblin::elf::dynamic::DT_RELASZ => {
                dt_relasz = Some(entry.d_val);
                dt_relasz_dyn_idx = Some(i);
            }
            goblin::elf::dynamic::DT_RELACOUNT => {
                dt_relacount = Some(entry.d_val);
                dt_relacount_dyn_idx = Some(i);
            }
            _ => {}
        }
    }

    let old_rela_va = dt_rela_offset.context("PIE executable missing DT_RELA")?;
    let old_relasz = dt_relasz.context("PIE executable missing DT_RELASZ")?;

    // Convert old rela VA to file offset to read existing entries
    let old_rela_file_offset = {
        let elf = object::read::elf::ElfFile64::<object::Endianness>::parse(out.as_slice())
            .context("parsing ELF for va_to_file_offset")?;
        crate::elf_reader::va_to_file_offset(&elf, old_rela_va)
            .context("DT_RELA VA not in any PT_LOAD segment")?
    };

    // Read existing .rela.dyn entries
    let num_existing = (old_relasz as usize) / RELA_ENTRY_SIZE;
    let mut existing_rela = Vec::with_capacity(num_existing * RELA_ENTRY_SIZE);
    let start = old_rela_file_offset as usize;
    let end = start + old_relasz as usize;
    if end > out.len() {
        bail!("existing .rela.dyn extends past end of file");
    }
    existing_rela.extend_from_slice(&out[start..end]);

    // Build new RELATIVE entries
    let num_new = plan.relative_relocs.len();
    let new_entries_size = num_new * RELA_ENTRY_SIZE;
    let mut new_rela = vec![0u8; new_entries_size];

    for (i, reloc) in plan.relative_relocs.iter().enumerate() {
        let off = i * RELA_ENTRY_SIZE;
        // r_offset: VA where the runtime fixup applies
        write_u64_le(&mut new_rela, off, reloc.vaddr);
        // r_info: (sym_idx << 32) | type  — for RELATIVE, sym_idx = 0, type = 8
        write_u64_le(&mut new_rela, off + 8, R_X86_64_RELATIVE as u64);
        // r_addend: the value to add to load base
        write_i64_le(&mut new_rela, off + 16, reloc.addend);
    }

    // Append combined rela.dyn (existing + new) to end of file
    let new_rela_file_offset = out.len() as u64;
    out.extend_from_slice(&existing_rela);
    out.extend_from_slice(&new_rela);

    // Now we need to update .dynamic entries. Re-parse to get fresh offsets.
    // Find .dynamic section file offset
    let dyn_section_offset = find_dynamic_section_offset(out)?;

    // Update DT_RELA to point to new location (as VA)
    // The new rela section is at file offset new_rela_file_offset, but DT_RELA wants a VA.
    // Since we're appending past the end of the original file, we need to figure out
    // what VA this maps to. For PIE, VAs are offsets from load base.
    // The new rela.dyn is in our new merged segment area, so its VA is based on the
    // last PT_LOAD's coverage. Actually, it's simplest to just use the file offset
    // as the VA for PIE (they're equivalent at load base 0).
    //
    // Actually for PIE, the dynamic linker uses the load bias. The file offset equals
    // the VA when mapped at the file's base. So new_rela_file_offset is the VA.
    let new_rela_va = new_rela_file_offset;
    let new_relasz = old_relasz + new_entries_size as u64;

    // Each Elf64_Dyn entry is 16 bytes: d_tag(8) + d_val(8)
    const DYN_ENTRY_SIZE: usize = 16;

    if let Some(idx) = dt_rela_dyn_idx {
        let entry_offset = dyn_section_offset as usize + idx * DYN_ENTRY_SIZE;
        // d_val is at offset 8 within the entry
        write_u64_le(out, entry_offset + 8, new_rela_va);
    }

    if let Some(idx) = dt_relasz_dyn_idx {
        let entry_offset = dyn_section_offset as usize + idx * DYN_ENTRY_SIZE;
        write_u64_le(out, entry_offset + 8, new_relasz);
    }

    // Update DT_RELACOUNT if present (count of RELATIVE relocations)
    if let Some(idx) = dt_relacount_dyn_idx {
        let old_count = dt_relacount.unwrap_or(0);
        let new_count = old_count + num_new as u64;
        let entry_offset = dyn_section_offset as usize + idx * DYN_ENTRY_SIZE;
        write_u64_le(out, entry_offset + 8, new_count);
    }

    Ok(())
}

/// Find the file offset of the .dynamic section.
fn find_dynamic_section_offset(bytes: &[u8]) -> Result<u64> {
    let goblin_elf = goblin::elf::Elf::parse(bytes).context("goblin parse for .dynamic lookup")?;
    for sh in &goblin_elf.section_headers {
        if goblin_elf.shdr_strtab.get_at(sh.sh_name) == Some(".dynamic") {
            return Ok(sh.sh_offset);
        }
    }
    bail!(".dynamic section not found")
}
