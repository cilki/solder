use anyhow::{bail, Context, Result};

use crate::types::{MergePlan, RelativeReloc};

/// Apply all in-place patches to a mutable copy of the executable bytes:
///   1. Pre-fill GOT entries with resolved merged symbol addresses.
///   2. Zero out JUMP_SLOT relocation entries so ld.so won't overwrite our patches.
///   3. Remove DT_NEEDED entries for fully-merged libraries.
///   4. Remove version requirements (.gnu.version_r) for fully-merged libraries.
///
/// For PIE executables, this also populates `plan.relative_relocs` with entries
/// for the patched GOT slots that need R_X86_64_RELATIVE relocations.
pub fn apply_patches(exe_bytes: &mut Vec<u8>, plan: &mut MergePlan) -> Result<()> {
    patch_got(exe_bytes, plan)?;
    zero_jump_slot_relocs(exe_bytes, plan)?;
    remove_dt_needed(exe_bytes, plan)?;
    remove_verneed_entries(exe_bytes, plan)?;
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

/// Remove version requirement entries (.gnu.version_r) for fully-merged libraries.
///
/// The .gnu.version_r section is a linked list of Verneed entries. Each entry
/// references a library (via vn_file -> .dynstr) and contains version requirements.
/// When we remove a DT_NEEDED entry, we must also remove the corresponding Verneed
/// entry, or the dynamic linker will fail with "Assertion `needed != NULL' failed".
///
/// Strategy:
/// 1. Find entries to remove by matching vn_file against plan.remove_needed
/// 2. Update vn_next pointers to skip removed entries (linked list surgery)
/// 3. Decrement DT_VERNEEDNUM in .dynamic
fn remove_verneed_entries(bytes: &mut Vec<u8>, plan: &MergePlan) -> Result<()> {
    if plan.remove_needed.is_empty() {
        return Ok(());
    }

    // Verneed entry structure (16 bytes):
    //   vn_version: u16  (offset 0)
    //   vn_cnt:     u16  (offset 2)
    //   vn_file:    u32  (offset 4) - offset into .dynstr for library name
    //   vn_aux:     u32  (offset 8) - offset to first Vernaux (relative to this entry)
    //   vn_next:    u32  (offset 12) - offset to next Verneed (relative to this entry), 0 if last
    const VERNEED_SIZE: usize = 16;

    // Collect info we need before mutating bytes
    let (verneed_offset, verneednum_dyn_idx, dyn_section_offset, entries_to_remove): (
        u64,
        Option<usize>,
        u64,
        Vec<u64>,
    ) = {
        let goblin_elf =
            goblin::elf::Elf::parse(bytes).context("goblin parse for verneed removal")?;

        let dynamic = match &goblin_elf.dynamic {
            Some(d) => d,
            None => return Ok(()),
        };

        // Find DT_VERNEED value (VA of .gnu.version_r) and DT_VERNEEDNUM index
        let mut verneed_va: Option<u64> = None;
        let mut verneednum_idx: Option<usize> = None;

        for (i, entry) in dynamic.dyns.iter().enumerate() {
            match entry.d_tag {
                goblin::elf::dynamic::DT_VERNEED => {
                    verneed_va = Some(entry.d_val);
                }
                goblin::elf::dynamic::DT_VERNEEDNUM => {
                    verneednum_idx = Some(i);
                }
                _ => {}
            }
        }

        let _verneed_va = match verneed_va {
            Some(va) => va,
            None => return Ok(()), // No version requirements section
        };

        // Find .gnu.version_r section offset
        let verneed_file_offset = find_section_file_offset(bytes, ".gnu.version_r")?;
        if verneed_file_offset == 0 {
            return Ok(());
        }

        let dyn_offset = find_section_file_offset(bytes, ".dynamic")?;

        // Walk the Verneed linked list to find entries matching libraries to remove
        let mut entries_to_remove = Vec::new();
        let mut offset = verneed_file_offset as usize;

        loop {
            if offset + VERNEED_SIZE > bytes.len() {
                break;
            }

            let vn_file = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
            let vn_next = u32::from_le_bytes(bytes[offset + 12..offset + 16].try_into().unwrap());

            // Check if this entry's library matches one we're removing
            if let Some(lib_name) = goblin_elf.dynstrtab.get_at(vn_file as usize) {
                if plan.remove_needed.iter().any(|s| s == lib_name) {
                    entries_to_remove.push(offset as u64);
                }
            }

            if vn_next == 0 {
                break;
            }
            offset += vn_next as usize;
        }

        (
            verneed_file_offset,
            verneednum_idx,
            dyn_offset,
            entries_to_remove,
        )
    };

    if entries_to_remove.is_empty() {
        return Ok(());
    }

    // Now perform the linked list surgery
    // We need to update vn_next pointers of entries that precede removed entries
    // to skip over them.

    let mut offset = verneed_offset as usize;
    let mut prev_offset: Option<usize> = None;
    let mut removed_count = 0u64;

    loop {
        if offset + VERNEED_SIZE > bytes.len() {
            break;
        }

        let vn_next = u32::from_le_bytes(bytes[offset + 12..offset + 16].try_into().unwrap());
        let is_last = vn_next == 0;
        let next_offset = if is_last { None } else { Some(offset + vn_next as usize) };

        if entries_to_remove.contains(&(offset as u64)) {
            // This entry should be removed
            removed_count += 1;

            if let Some(prev) = prev_offset {
                // Update previous entry's vn_next to skip this entry
                if let Some(next) = next_offset {
                    // Point to next entry: calculate relative offset from prev to next
                    let new_vn_next = (next - prev) as u32;
                    bytes[prev + 12..prev + 16].copy_from_slice(&new_vn_next.to_le_bytes());
                } else {
                    // This was the last entry, make prev the new last
                    bytes[prev + 12..prev + 16].copy_from_slice(&0u32.to_le_bytes());
                }
            }
            // If prev_offset is None, this is the first entry - we handle this by
            // keeping the first entry in place but zeroing it, or we'd need to update
            // DT_VERNEED which is more complex. For now, zero the entry's vn_cnt.
            if prev_offset.is_none() && next_offset.is_some() {
                // First entry being removed but there are more entries after.
                // We can't easily move the section start, so we'll zero vn_cnt
                // to make this entry have no version requirements.
                bytes[offset + 2..offset + 4].copy_from_slice(&0u16.to_le_bytes());
                // Keep vn_next intact so the list continues
                // Don't count this as fully removed since we still traverse it
                removed_count -= 1;
            } else if prev_offset.is_none() && next_offset.is_none() {
                // Only entry, just zero it
                bytes[offset + 2..offset + 4].copy_from_slice(&0u16.to_le_bytes());
            }

            // Don't update prev_offset for removed entries
        } else {
            // Keep this entry, it becomes the new "previous"
            prev_offset = Some(offset);
        }

        if is_last {
            break;
        }
        offset = next_offset.unwrap();
    }

    // Update DT_VERNEEDNUM in .dynamic
    if removed_count > 0 {
        if let Some(idx) = verneednum_dyn_idx {
            let entry_offset = dyn_section_offset as usize + idx * 16 + 8; // d_val is at offset 8
            if entry_offset + 8 <= bytes.len() {
                let current = u64::from_le_bytes(bytes[entry_offset..entry_offset + 8].try_into().unwrap());
                let new_count = current.saturating_sub(removed_count);
                bytes[entry_offset..entry_offset + 8].copy_from_slice(&new_count.to_le_bytes());
            }
        }
    }

    Ok(())
}
