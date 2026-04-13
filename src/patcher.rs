use anyhow::{bail, Context, Result};

use crate::types::{MergePlan, RelativeReloc};

/// Apply all in-place patches to a mutable copy of the executable bytes:
///   1. Pre-fill GOT entries with resolved merged symbol addresses.
///   2. Zero out JUMP_SLOT relocation entries so ld.so won't overwrite our patches.
///   3. Remove DT_NEEDED entries for fully-merged libraries.
///   4. Remove PT_INTERP if no DT_NEEDED entries remain.
///
/// For PIE executables, this also populates `plan.relative_relocs` with entries
/// for the patched GOT slots that need R_X86_64_RELATIVE relocations.
pub fn apply_patches(exe_bytes: &mut Vec<u8>, plan: &mut MergePlan) -> Result<()> {
    patch_got(exe_bytes, plan)?;
    zero_jump_slot_relocs(exe_bytes, plan)?;
    remove_dt_needed(exe_bytes, plan)?;
    Ok(())
}

/// Write each resolved symbol address into the executable's GOT.
/// For PIE, also record RELATIVE relocations for each patched slot.
fn patch_got(bytes: &mut Vec<u8>, plan: &mut MergePlan) -> Result<()> {
    for patch in &plan.got_patches {
        let off = patch.got_file_offset as usize;
        if off + 8 > bytes.len() {
            bail!(
                "GOT patch offset 0x{:x} + 8 out of bounds (file size {})",
                off,
                bytes.len()
            );
        }
        bytes[off..off + 8].copy_from_slice(&patch.value.to_le_bytes());

        // For PIE: the patched GOT slot holds an absolute address that needs runtime fixup
        if plan.is_pie {
            plan.relative_relocs.push(RelativeReloc {
                vaddr: patch.got_vaddr,
                addend: patch.value as i64,
            });
        }
    }
    Ok(())
}

/// Zero out r_info and r_addend for JUMP_SLOT relocations of merged symbols,
/// so ld.so won't re-resolve them and overwrite our GOT entries.
/// Each reloc entry file offset points to the r_info field (8 bytes into the entry).
/// We zero both r_info (8 bytes) and r_addend (8 bytes) = 16 bytes total.
fn zero_jump_slot_relocs(bytes: &mut Vec<u8>, plan: &MergePlan) -> Result<()> {
    for &off in &plan.jump_slot_reloc_offsets {
        let off = off as usize;
        if off + 16 > bytes.len() {
            bail!("JUMP_SLOT reloc offset 0x{:x} out of bounds", off);
        }
        bytes[off..off + 16].fill(0);
    }
    Ok(())
}

/// Remove DT_NEEDED entries from the .dynamic section for fully-merged libraries.
///
/// Strategy: find the entry in .dynamic matching the soname, then shift all
/// subsequent entries up by one slot, zeroing the last slot.
fn remove_dt_needed(bytes: &mut Vec<u8>, plan: &MergePlan) -> Result<()> {
    if plan.remove_needed.is_empty() {
        return Ok(());
    }

    // Parse goblin to collect the entry indices and section offset, then drop
    // the borrow before mutating `bytes`.
    let (dyn_section_offset, num_entries, removal_indices): (u64, usize, Vec<usize>) = {
        let goblin_elf =
            goblin::elf::Elf::parse(bytes).context("goblin parse for DT_NEEDED removal")?;

        let dynamic = match &goblin_elf.dynamic {
            Some(d) => d,
            None => return Ok(()),
        };

        let dyn_section_offset = find_section_file_offset(bytes, ".dynamic")?;
        if dyn_section_offset == 0 {
            return Ok(());
        }

        let num_entries = dynamic.dyns.len();

        let mut indices = Vec::new();
        for soname in &plan.remove_needed {
            if let Some(idx) = dynamic.dyns.iter().position(|entry| {
                entry.d_tag == goblin::elf::dynamic::DT_NEEDED
                    && goblin_elf
                        .dynstrtab
                        .get_at(entry.d_val as usize)
                        .map(|s| s == soname)
                        .unwrap_or(false)
            }) {
                indices.push(idx);
            }
        }
        (dyn_section_offset, num_entries, indices)
        // goblin_elf + borrow of bytes is dropped here
    };

    // Each Elf64_Dyn entry is 16 bytes: d_tag(8) + d_val/d_ptr(8)
    const ENTRY_SIZE: usize = 16;
    let base = dyn_section_offset as usize;

    // Process removals in reverse index order so earlier removals don't shift later indices.
    let mut sorted_indices = removal_indices;
    sorted_indices.sort_unstable_by(|a, b| b.cmp(a)); // descending

    for idx in sorted_indices {
        // Shift entries [idx+1 .. num_entries) up by one slot.
        let src_start = base + (idx + 1) * ENTRY_SIZE;
        let dst_start = base + idx * ENTRY_SIZE;
        let move_count = (num_entries - idx - 1) * ENTRY_SIZE;
        bytes.copy_within(src_start..src_start + move_count, dst_start);

        // Zero the last entry.
        let last_start = base + (num_entries - 1) * ENTRY_SIZE;
        bytes[last_start..last_start + ENTRY_SIZE].fill(0);
    }

    Ok(())
}

/// Find the file offset of an ELF section by name.
/// Returns 0 if the section is not found.
fn find_section_file_offset(bytes: &[u8], name: &str) -> Result<u64> {
    let goblin_elf = goblin::elf::Elf::parse(bytes).context("goblin parse for section lookup")?;
    for sh in &goblin_elf.section_headers {
        if goblin_elf.shdr_strtab.get_at(sh.sh_name) == Some(name) {
            return Ok(sh.sh_offset);
        }
    }
    Ok(0)
}
