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

    // Write init/fini arrays if present
    if let Some(ref init_fini) = plan.init_fini {
        // Write init_array entries
        if !init_fini.combined_init_entries.is_empty() {
            let base_off = (init_fini.combined_init_vaddr - plan.load_address) as usize;
            for (i, &func_va) in init_fini.combined_init_entries.iter().enumerate() {
                let off = base_off + i * 8;
                if off + 8 > seg.len() {
                    bail!("init_array entry {} overflows segment", i);
                }
                seg[off..off + 8].copy_from_slice(&func_va.to_le_bytes());

                // For PIE: each function pointer needs an R_X86_64_RELATIVE relocation
                if plan.is_pie {
                    plan.relative_relocs.push(RelativeReloc {
                        vaddr: init_fini.combined_init_vaddr + (i * 8) as u64,
                        addend: func_va as i64,
                    });
                }
            }
        }

        // Write fini_array entries
        if !init_fini.combined_fini_entries.is_empty() {
            let base_off = (init_fini.combined_fini_vaddr - plan.load_address) as usize;
            for (i, &func_va) in init_fini.combined_fini_entries.iter().enumerate() {
                let off = base_off + i * 8;
                if off + 8 > seg.len() {
                    bail!("fini_array entry {} overflows segment", i);
                }
                seg[off..off + 8].copy_from_slice(&func_va.to_le_bytes());

                // For PIE: each function pointer needs an R_X86_64_RELATIVE relocation
                if plan.is_pie {
                    plan.relative_relocs.push(RelativeReloc {
                        vaddr: init_fini.combined_fini_vaddr + (i * 8) as u64,
                        addend: func_va as i64,
                    });
                }
            }
        }
    }

    Ok(seg)
}

/// Write the final output ELF file.
///
/// Structure:
///   [patched original ELF bytes]
///   [merged segment bytes + rela.dyn extension + PHT]
///
/// The PHT is embedded within the new PT_LOAD segment so PT_PHDR can point to it.
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

    // Pre-compute .dynamic section info from the ORIGINAL exe before we modify headers.
    let dynamic_info = parse_dynamic_info(patched_exe)?;

    // Collect existing program headers.
    let old_phdrs: Vec<object::elf::ProgramHeader64<object::Endianness>> =
        exe.elf_program_headers().to_vec();
    let phdr_entry_size = std::mem::size_of::<object::elf::ProgramHeader64<object::Endianness>>();

    // File offset where the merged segment will start.
    let seg_file_offset = patched_exe.len() as u64;
    // Page-align the offset (required by the kernel for PT_LOAD).
    let seg_file_offset = align_up(seg_file_offset, 0x1000);

    // Build the extended merged segment: original segment + rela.dyn data (if PIE).
    // We need to include rela.dyn in the segment so it's mapped by PT_LOAD.
    let (extended_seg, rela_info) = if plan.is_pie && !plan.relative_relocs.is_empty() {
        build_extended_segment_with_rela(
            patched_exe,
            merged_seg,
            plan,
            &dynamic_info,
            seg_file_offset,
        )?
    } else {
        (merged_seg.to_vec(), None)
    };

    // Calculate sizes for embedding PHT within the new PT_LOAD segment.
    // We need 1 extra entry for the new PT_LOAD itself.
    let new_phnum = old_phdrs.len() + 1;
    let pht_size = (new_phnum * phdr_entry_size) as u64;

    // PHT will be placed at the end of the extended segment, aligned to 8 bytes.
    // This makes it part of the new PT_LOAD's mapped memory.
    let pht_offset_in_seg = align_up(extended_seg.len() as u64, 8);
    let pht_file_offset = seg_file_offset + pht_offset_in_seg;
    let pht_vaddr = plan.load_address + pht_offset_in_seg;

    // Total size of the extended segment including PHT
    let total_seg_size = pht_offset_in_seg + pht_size;

    // Build the output buffer.
    let total_file_size = seg_file_offset + total_seg_size;
    let mut out = vec![0u8; total_file_size as usize];

    // Copy patched exe bytes.
    out[..patched_exe.len()].copy_from_slice(patched_exe);
    // Copy extended merged segment.
    let seg_start = seg_file_offset as usize;
    let seg_end = seg_start + extended_seg.len();
    out[seg_start..seg_end].copy_from_slice(&extended_seg);

    // Build the new PHT at its location within the segment.
    let pht_start = pht_file_offset as usize;

    // Copy old entries, updating PT_PHDR to point to the new PHT location.
    let mut written = 0usize;
    for phdr in &old_phdrs {
        let dst = pht_start + written;
        let entry_bytes: &[u8] = as_bytes(phdr);
        out[dst..dst + phdr_entry_size].copy_from_slice(entry_bytes);

        // Update PT_PHDR to point to the new PHT location
        if phdr.p_type(endian) == PT_PHDR {
            write_u64_le(&mut out, dst + 8, pht_file_offset);    // p_offset
            write_u64_le(&mut out, dst + 16, pht_vaddr);          // p_vaddr
            write_u64_le(&mut out, dst + 24, pht_vaddr);          // p_paddr
            write_u64_le(&mut out, dst + 32, pht_size);           // p_filesz
            write_u64_le(&mut out, dst + 40, pht_size);           // p_memsz
        }

        written += phdr_entry_size;
    }

    // Write the new PT_LOAD entry for the extended merged segment (including PHT).
    let dst = pht_start + written;
    write_u32_le(&mut out, dst, PT_LOAD);
    write_u32_le(&mut out, dst + 4, PF_R | PF_W | PF_X); // rwx — MVP
    write_u64_le(&mut out, dst + 8, seg_file_offset);
    write_u64_le(&mut out, dst + 16, plan.load_address);
    write_u64_le(&mut out, dst + 24, plan.load_address); // p_paddr = p_vaddr
    write_u64_le(&mut out, dst + 32, total_seg_size);     // p_filesz includes PHT
    write_u64_le(&mut out, dst + 40, total_seg_size);     // p_memsz includes PHT
    write_u64_le(&mut out, dst + 48, 0x1000); // p_align = 4 KiB

    // Update ELF header: e_phoff and e_phnum.
    write_u64_le(&mut out, 32, pht_file_offset);
    write_u16_le(&mut out, 56, new_phnum as u16);

    // Update .dynamic entries for rela.dyn if we extended it
    if let Some((rela_va, rela_size, rela_count)) = rela_info {
        let dyn_section_offset = dynamic_info.section_offset as usize;
        if let Some(idx) = dynamic_info.dt_rela_idx {
            let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
            write_u64_le(&mut out, entry_offset + 8, rela_va);
        }
        if let Some(idx) = dynamic_info.dt_relasz_idx {
            let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
            write_u64_le(&mut out, entry_offset + 8, rela_size);
        }
        if let Some(idx) = dynamic_info.dt_relacount_idx {
            let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
            write_u64_le(&mut out, entry_offset + 8, rela_count);
        }
    }

    // Update DT_INIT_ARRAY and DT_FINI_ARRAY to point to our combined arrays
    if plan.init_fini.is_some() {
        update_dynamic_init_fini(&mut out, plan, &dynamic_info)?;
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

/// Size of an Elf64_Dyn entry
const DYN_ENTRY_SIZE: usize = 16;

/// Pre-parsed .dynamic section info to avoid re-parsing modified ELF.
#[derive(Debug, Default)]
struct DynamicInfo {
    /// File offset of the .dynamic section
    section_offset: u64,
    /// Index and value of various DT_* entries
    dt_rela_idx: Option<usize>,
    dt_rela_val: Option<u64>,
    dt_relasz_idx: Option<usize>,
    dt_relasz_val: Option<u64>,
    dt_relacount_idx: Option<usize>,
    dt_relacount_val: Option<u64>,
    dt_init_array_idx: Option<usize>,
    dt_init_arraysz_idx: Option<usize>,
    dt_fini_array_idx: Option<usize>,
    dt_fini_arraysz_idx: Option<usize>,
    dt_null_indices: Vec<usize>,
}

/// Parse .dynamic section info from an unmodified ELF.
fn parse_dynamic_info(bytes: &[u8]) -> Result<DynamicInfo> {
    let goblin_elf = goblin::elf::Elf::parse(bytes).context("goblin parse for .dynamic info")?;

    let mut info = DynamicInfo::default();

    // Find .dynamic section offset
    for sh in &goblin_elf.section_headers {
        if goblin_elf.shdr_strtab.get_at(sh.sh_name) == Some(".dynamic") {
            info.section_offset = sh.sh_offset;
            break;
        }
    }

    if info.section_offset == 0 {
        // Try to find via PT_DYNAMIC program header
        for ph in &goblin_elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_DYNAMIC {
                info.section_offset = ph.p_offset;
                break;
            }
        }
    }

    if info.section_offset == 0 {
        bail!(".dynamic section not found");
    }

    // Parse dynamic entries
    if let Some(dynamic) = &goblin_elf.dynamic {
        for (i, entry) in dynamic.dyns.iter().enumerate() {
            match entry.d_tag {
                goblin::elf::dynamic::DT_RELA => {
                    info.dt_rela_idx = Some(i);
                    info.dt_rela_val = Some(entry.d_val);
                }
                goblin::elf::dynamic::DT_RELASZ => {
                    info.dt_relasz_idx = Some(i);
                    info.dt_relasz_val = Some(entry.d_val);
                }
                goblin::elf::dynamic::DT_RELACOUNT => {
                    info.dt_relacount_idx = Some(i);
                    info.dt_relacount_val = Some(entry.d_val);
                }
                goblin::elf::dynamic::DT_INIT_ARRAY => {
                    info.dt_init_array_idx = Some(i);
                }
                goblin::elf::dynamic::DT_INIT_ARRAYSZ => {
                    info.dt_init_arraysz_idx = Some(i);
                }
                goblin::elf::dynamic::DT_FINI_ARRAY => {
                    info.dt_fini_array_idx = Some(i);
                }
                goblin::elf::dynamic::DT_FINI_ARRAYSZ => {
                    info.dt_fini_arraysz_idx = Some(i);
                }
                goblin::elf::dynamic::DT_NULL => {
                    info.dt_null_indices.push(i);
                }
                _ => {}
            }
        }
    }

    Ok(info)
}

/// Build the merged segment with rela.dyn data appended.
/// Returns (extended_segment, Some((rela_va, rela_size, rela_count))) or (segment, None).
///
/// The rela.dyn section has a specific layout: R_X86_64_RELATIVE entries come first
/// (DT_RELACOUNT specifies how many), followed by other relocation types (R_X86_64_64,
/// R_X86_64_GLOB_DAT, etc.). We must insert our new RELATIVE entries after the existing
/// RELATIVE entries but before the non-RELATIVE entries to maintain this invariant.
fn build_extended_segment_with_rela(
    patched_exe: &[u8],
    merged_seg: &[u8],
    plan: &MergePlan,
    dyn_info: &DynamicInfo,
    _seg_file_offset: u64,
) -> Result<(Vec<u8>, Option<(u64, u64, u64)>)> {
    let old_rela_va = dyn_info.dt_rela_val.context("PIE executable missing DT_RELA")?;
    let old_relasz = dyn_info.dt_relasz_val.context("PIE executable missing DT_RELASZ")?;
    let old_relacount = dyn_info.dt_relacount_val.unwrap_or(0);

    // Read existing .rela.dyn entries from the original exe
    // For PIE, VA == file offset when loaded at base 0.
    let start = old_rela_va as usize;
    let end = start + old_relasz as usize;
    if end > patched_exe.len() {
        bail!("existing .rela.dyn extends past end of file");
    }

    // Split existing rela into RELATIVE entries (first `old_relacount`) and non-RELATIVE entries
    let relative_end = start + (old_relacount as usize * RELA_ENTRY_SIZE);
    let existing_relative = &patched_exe[start..relative_end];
    let existing_non_relative = &patched_exe[relative_end..end];

    // Build new RELATIVE entries
    let num_new = plan.relative_relocs.len();
    let new_entries_size = num_new * RELA_ENTRY_SIZE;
    let mut new_rela = vec![0u8; new_entries_size];

    for (i, reloc) in plan.relative_relocs.iter().enumerate() {
        let off = i * RELA_ENTRY_SIZE;
        write_u64_le(&mut new_rela, off, reloc.vaddr);
        write_u64_le(&mut new_rela, off + 8, R_X86_64_RELATIVE as u64);
        write_i64_le(&mut new_rela, off + 16, reloc.addend);
    }

    // Build extended segment: merged_seg + [existing RELATIVE + new RELATIVE + existing non-RELATIVE]
    let total_rela_size = existing_relative.len() + new_rela.len() + existing_non_relative.len();
    let mut extended = Vec::with_capacity(merged_seg.len() + total_rela_size);
    extended.extend_from_slice(merged_seg);

    // Align to 8 bytes before rela data
    while extended.len() % 8 != 0 {
        extended.push(0);
    }

    let rela_offset_in_seg = extended.len();
    // Order: existing RELATIVE, new RELATIVE, existing non-RELATIVE
    extended.extend_from_slice(existing_relative);
    extended.extend_from_slice(&new_rela);
    extended.extend_from_slice(existing_non_relative);

    // Calculate the VA of the rela section in the extended segment
    let rela_va = plan.load_address + rela_offset_in_seg as u64;
    let new_relasz = total_rela_size as u64;
    let new_count = old_relacount + num_new as u64;

    Ok((extended, Some((rela_va, new_relasz, new_count))))
}

/// Update DT_INIT_ARRAY/DT_INIT_ARRAYSZ and DT_FINI_ARRAY/DT_FINI_ARRAYSZ in .dynamic
/// to point to our combined init/fini arrays in the merged segment.
fn update_dynamic_init_fini(
    out: &mut [u8],
    plan: &MergePlan,
    dyn_info: &DynamicInfo,
) -> Result<()> {
    let init_fini = match &plan.init_fini {
        Some(p) => p,
        None => return Ok(()),
    };

    let dyn_section_offset = dyn_info.section_offset as usize;

    // We need a mutable copy of the null indices since we consume them
    let mut dt_null_indices = dyn_info.dt_null_indices.clone();

    // Helper to write a dynamic entry
    let write_dyn_entry = |out: &mut [u8], idx: usize, tag: u64, val: u64| {
        let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
        write_u64_le(out, entry_offset, tag);
        write_u64_le(out, entry_offset + 8, val);
    };

    // Update or create DT_INIT_ARRAY entries
    if !init_fini.combined_init_entries.is_empty() {
        let init_array_size = (init_fini.combined_init_entries.len() * 8) as u64;

        if let Some(idx) = dyn_info.dt_init_array_idx {
            // Update existing DT_INIT_ARRAY
            let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
            write_u64_le(out, entry_offset + 8, init_fini.combined_init_vaddr);
        } else if !dt_null_indices.is_empty() {
            // Use a DT_NULL slot
            let idx = dt_null_indices.remove(0);
            write_dyn_entry(
                out,
                idx,
                goblin::elf::dynamic::DT_INIT_ARRAY,
                init_fini.combined_init_vaddr,
            );
        } else {
            bail!("no DT_INIT_ARRAY entry and no DT_NULL slots available in .dynamic");
        }

        if let Some(idx) = dyn_info.dt_init_arraysz_idx {
            // Update existing DT_INIT_ARRAYSZ
            let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
            write_u64_le(out, entry_offset + 8, init_array_size);
        } else if !dt_null_indices.is_empty() {
            // Use a DT_NULL slot
            let idx = dt_null_indices.remove(0);
            write_dyn_entry(
                out,
                idx,
                goblin::elf::dynamic::DT_INIT_ARRAYSZ,
                init_array_size,
            );
        } else {
            bail!("no DT_INIT_ARRAYSZ entry and no DT_NULL slots available in .dynamic");
        }
    }

    // Update or create DT_FINI_ARRAY entries
    if !init_fini.combined_fini_entries.is_empty() {
        let fini_array_size = (init_fini.combined_fini_entries.len() * 8) as u64;

        if let Some(idx) = dyn_info.dt_fini_array_idx {
            // Update existing DT_FINI_ARRAY
            let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
            write_u64_le(out, entry_offset + 8, init_fini.combined_fini_vaddr);
        } else if !dt_null_indices.is_empty() {
            // Use a DT_NULL slot
            let idx = dt_null_indices.remove(0);
            write_dyn_entry(
                out,
                idx,
                goblin::elf::dynamic::DT_FINI_ARRAY,
                init_fini.combined_fini_vaddr,
            );
        } else {
            bail!("no DT_FINI_ARRAY entry and no DT_NULL slots available in .dynamic");
        }

        if let Some(idx) = dyn_info.dt_fini_arraysz_idx {
            // Update existing DT_FINI_ARRAYSZ
            let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
            write_u64_le(out, entry_offset + 8, fini_array_size);
        } else if !dt_null_indices.is_empty() {
            // Use a DT_NULL slot
            let idx = dt_null_indices.remove(0);
            write_dyn_entry(
                out,
                idx,
                goblin::elf::dynamic::DT_FINI_ARRAYSZ,
                fini_array_size,
            );
        } else {
            bail!("no DT_FINI_ARRAYSZ entry and no DT_NULL slots available in .dynamic");
        }
    }

    Ok(())
}
