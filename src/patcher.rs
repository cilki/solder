use anyhow::{Context, Result, bail};

use crate::types::{MergePlan, RelativeReloc};

/// Apply all in-place patches to a mutable copy of the executable bytes:
///   1. Pre-fill GOT entries with resolved merged symbol addresses.
///   2. Zero out JUMP_SLOT relocation entries so ld.so won't overwrite our patches.
///   3. Remove DT_NEEDED entries for fully-merged libraries.
///   4. Remove version requirements (.gnu.version_r) for fully-merged libraries.
///   5. Force eager binding so the loader processes the zeroed (R_X86_64_NONE)
///      PLT relocations through the eager path, which accepts NONE.
///
/// For PIE executables, this also populates `plan.relative_relocs` with entries
/// for the patched GOT slots that need R_X86_64_RELATIVE relocations.
pub fn apply_patches(exe_bytes: &mut [u8], plan: &mut MergePlan) -> Result<()> {
    patch_got(exe_bytes, plan)?;
    zero_jump_slot_relocs(exe_bytes, plan)?;
    zero_copy_relocs(exe_bytes, plan)?;
    remove_dt_needed(exe_bytes, plan)?;
    remove_verneed_entries(exe_bytes, plan)?;
    ensure_bind_now(exe_bytes)?;
    Ok(())
}

/// Write each resolved symbol address into the executable's GOT.
/// For PIE, also record RELATIVE relocations for each patched slot.
fn patch_got(bytes: &mut [u8], plan: &mut MergePlan) -> Result<()> {
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
fn zero_jump_slot_relocs(bytes: &mut [u8], plan: &MergePlan) -> Result<()> {
    for &off in &plan.jump_slot_reloc_offsets {
        let off = off as usize;
        if off + 16 > bytes.len() {
            bail!("JUMP_SLOT reloc offset 0x{:x} out of bounds", off);
        }
        bytes[off..off + 16].fill(0);
    }
    Ok(())
}

/// Zero out r_info and r_addend for R_X86_64_COPY relocations whose symbol was
/// provided by a merged-away library, turning each into R_X86_64_NONE so ld.so
/// skips it instead of failing to resolve the now-absent symbol. Each offset
/// points to the entry's r_info field.
fn zero_copy_relocs(bytes: &mut [u8], plan: &MergePlan) -> Result<()> {
    for &off in &plan.copy_reloc_offsets {
        let off = off as usize;
        if off + 16 > bytes.len() {
            bail!("COPY reloc offset 0x{:x} out of bounds", off);
        }
        bytes[off..off + 16].fill(0);
    }
    Ok(())
}

/// Remove DT_NEEDED entries from the .dynamic section for fully-merged libraries.
///
/// Strategy: find the entry in .dynamic matching the soname, then shift all
/// subsequent entries up by one slot, zeroing the last slot.
fn remove_dt_needed(bytes: &mut [u8], plan: &MergePlan) -> Result<()> {
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

/// Force eager symbol binding on the modified executable by ensuring a
/// `DF_BIND_NOW` flag (or equivalent) is set in the dynamic section.
///
/// Why this matters: `zero_jump_slot_relocs` rewrites the PLT relocations for
/// merged symbols as `R_X86_64_NONE` (r_info = 0). Some glibc versions reject
/// `R_X86_64_NONE` in the lazy PLT path (`elf_machine_lazy_rel`) and fail with
/// "unexpected PLT reloc type 0x00". The eager path (`elf_machine_rela`) always
/// treats NONE as a no-op, so forcing BIND_NOW makes the binary load reliably
/// regardless of glibc version or binding mode.
fn ensure_bind_now(bytes: &mut [u8]) -> Result<()> {
    // DT_* tag values not all exposed by goblin as constants we want, hardcode:
    const DT_NULL: u64 = 0;
    const DT_FLAGS: u64 = 30;
    const DT_BIND_NOW: u64 = 24;
    const DT_FLAGS_1: u64 = 0x6ffffffb;
    const DF_BIND_NOW: u64 = 0x8;
    const DF_1_NOW: u64 = 0x1;
    const ENTRY_SIZE: usize = 16;

    let dyn_section_offset = find_section_file_offset(bytes, ".dynamic")?;
    if dyn_section_offset == 0 {
        return Ok(());
    }

    // Parse to discover current state, then drop the borrow before mutating.
    let (already_now, flags_idx, num_entries, dyn_segment_filesz): (
        bool,
        Option<usize>,
        usize,
        u64,
    ) = {
        let goblin_elf = goblin::elf::Elf::parse(bytes).context("goblin parse for BIND_NOW")?;

        let dyn_filesz = goblin_elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == goblin::elf::program_header::PT_DYNAMIC)
            .map(|ph| ph.p_filesz)
            .unwrap_or(0);

        let dynamic = match &goblin_elf.dynamic {
            Some(d) => d,
            None => return Ok(()),
        };

        let mut already = false;
        let mut flags_at: Option<usize> = None;
        for (i, e) in dynamic.dyns.iter().enumerate() {
            if e.d_tag == DT_BIND_NOW {
                already = true;
            } else if e.d_tag == DT_FLAGS {
                flags_at = Some(i);
                if e.d_val & DF_BIND_NOW != 0 {
                    already = true;
                }
            } else if e.d_tag == DT_FLAGS_1 && e.d_val & DF_1_NOW != 0 {
                already = true;
            }
        }

        (already, flags_at, dynamic.dyns.len(), dyn_filesz)
    };

    if already_now {
        return Ok(());
    }

    let base = dyn_section_offset as usize;

    if let Some(idx) = flags_idx {
        // OR DF_BIND_NOW into the existing DT_FLAGS entry.
        let val_off = base + idx * ENTRY_SIZE + 8;
        let current = u64::from_le_bytes(bytes[val_off..val_off + 8].try_into().unwrap());
        let new = current | DF_BIND_NOW;
        bytes[val_off..val_off + 8].copy_from_slice(&new.to_le_bytes());
        return Ok(());
    }

    // Append a new DT_FLAGS entry. Goblin includes the DT_NULL terminator in
    // `dynamic.dyns`, so the terminator lives at index `num_entries - 1`. We
    // overwrite that slot with our new entry; the slot after becomes the new
    // DT_NULL terminator.
    if num_entries == 0 {
        anyhow::bail!("empty dynamic section");
    }
    let new_entry_off = base + (num_entries - 1) * ENTRY_SIZE;
    let next_off = new_entry_off + ENTRY_SIZE;

    if (next_off + ENTRY_SIZE) > base + dyn_segment_filesz as usize {
        anyhow::bail!(
            "no room in PT_DYNAMIC to add DT_FLAGS=DF_BIND_NOW entry \
             (segment filesz=0x{:x}, would need offset 0x{:x})",
            dyn_segment_filesz,
            next_off + ENTRY_SIZE - base
        );
    }

    // Sanity: the slot we're overwriting should currently be DT_NULL.
    let cur_tag = u64::from_le_bytes(bytes[new_entry_off..new_entry_off + 8].try_into().unwrap());
    if cur_tag != DT_NULL {
        anyhow::bail!(
            "expected DT_NULL at .dynamic offset 0x{:x}, found tag 0x{:x}",
            new_entry_off - base,
            cur_tag
        );
    }

    bytes[new_entry_off..new_entry_off + 8].copy_from_slice(&DT_FLAGS.to_le_bytes());
    bytes[new_entry_off + 8..new_entry_off + 16].copy_from_slice(&DF_BIND_NOW.to_le_bytes());
    bytes[next_off..next_off + ENTRY_SIZE].fill(0);

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
fn remove_verneed_entries(bytes: &mut [u8], plan: &MergePlan) -> Result<()> {
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
    let (
        verneed_offset,
        verneed_va,
        verneed_dyn_idx,
        verneednum_dyn_idx,
        dyn_section_offset,
        entries_to_remove,
    ): (u64, u64, Option<usize>, Option<usize>, u64, Vec<u64>) = {
        let goblin_elf =
            goblin::elf::Elf::parse(bytes).context("goblin parse for verneed removal")?;

        let dynamic = match &goblin_elf.dynamic {
            Some(d) => d,
            None => return Ok(()),
        };

        // Find DT_VERNEED value (VA of .gnu.version_r) and DT_VERNEEDNUM index
        let mut verneed_va: Option<u64> = None;
        let mut verneed_idx: Option<usize> = None;
        let mut verneednum_idx: Option<usize> = None;

        for (i, entry) in dynamic.dyns.iter().enumerate() {
            match entry.d_tag {
                goblin::elf::dynamic::DT_VERNEED => {
                    verneed_va = Some(entry.d_val);
                    verneed_idx = Some(i);
                }
                goblin::elf::dynamic::DT_VERNEEDNUM => {
                    verneednum_idx = Some(i);
                }
                _ => {}
            }
        }

        let verneed_va = match verneed_va {
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
            if let Some(lib_name) = goblin_elf.dynstrtab.get_at(vn_file as usize)
                && plan.remove_needed.iter().any(|s| s == lib_name)
            {
                entries_to_remove.push(offset as u64);
            }

            if vn_next == 0 {
                break;
            }
            offset += vn_next as usize;
        }

        (
            verneed_file_offset,
            verneed_va,
            verneed_idx,
            verneednum_idx,
            dyn_offset,
            entries_to_remove,
        )
    };

    if entries_to_remove.is_empty() {
        return Ok(());
    }

    // Now perform the linked list surgery.
    //
    // glibc's `_dl_check_map_versions` calls `find_needed(vn_file)` for *every*
    // Verneed entry and asserts the result is non-NULL *before* it ever looks at
    // `vn_cnt`.  So a removed library's entry cannot merely be zeroed in place —
    // it must be unlinked from the list entirely, including when it is the head
    // (in which case DT_VERNEED itself must be advanced to the next entry).
    let removed: std::collections::HashSet<usize> =
        entries_to_remove.iter().map(|&o| o as usize).collect();

    let (new_head, kept_count) = relink_verneed_list(bytes, verneed_offset as usize, &removed);

    // If the head entry was removed, point DT_VERNEED at the first kept entry.
    // (Its VA tracks the file offset since the section is contiguous.)
    if kept_count > 0 {
        if new_head as u64 != verneed_offset
            && let Some(idx) = verneed_dyn_idx
        {
            let new_va = verneed_va + (new_head as u64 - verneed_offset);
            let entry_offset = dyn_section_offset as usize + idx * 16 + 8; // d_val at +8
            if entry_offset + 8 <= bytes.len() {
                bytes[entry_offset..entry_offset + 8].copy_from_slice(&new_va.to_le_bytes());
            }
        }
    } else {
        // No requirements remain at all. Drop DT_VERNEED so ld.so doesn't walk a
        // now-empty section (rare: only if every needed library was merged).
        if let Some(idx) = verneed_dyn_idx {
            let entry_offset = dyn_section_offset as usize + idx * 16;
            if entry_offset + 16 <= bytes.len() {
                // Rewrite tag to a runtime no-op (DT_DEBUG is ignored by ld.so).
                let dt_debug = goblin::elf::dynamic::DT_DEBUG.to_le_bytes();
                bytes[entry_offset..entry_offset + 8].copy_from_slice(&dt_debug);
                bytes[entry_offset + 8..entry_offset + 16].copy_from_slice(&0u64.to_le_bytes());
            }
        }
    }

    // Update DT_VERNEEDNUM to the number of surviving entries.
    if let Some(idx) = verneednum_dyn_idx {
        let entry_offset = dyn_section_offset as usize + idx * 16 + 8; // d_val is at offset 8
        if entry_offset + 8 <= bytes.len() {
            bytes[entry_offset..entry_offset + 8]
                .copy_from_slice(&(kept_count as u64).to_le_bytes());
        }
    }

    Ok(())
}

/// Rewrite the Verneed linked list in `bytes` starting at `verneed_offset`,
/// unlinking every entry whose file offset is contained in `removed`.
///
/// Each Verneed entry's `vn_next` (at byte offset +12) is a *relative* byte
/// offset to the next entry, or 0 to terminate the list. This walks the chain,
/// drops the removed offsets, and rewrites `vn_next` across the survivors so the
/// removed entries are skipped. Returns `(new_head_offset, surviving_count)`;
/// `new_head_offset` equals `verneed_offset` unless the original head was removed.
fn relink_verneed_list(
    bytes: &mut [u8],
    verneed_offset: usize,
    removed: &std::collections::HashSet<usize>,
) -> (usize, usize) {
    const VERNEED_SIZE: usize = 16;

    // Pass 1: collect every entry offset in list order.
    let mut all_offsets: Vec<usize> = Vec::new();
    let mut offset = verneed_offset;
    loop {
        if offset + VERNEED_SIZE > bytes.len() {
            break;
        }
        all_offsets.push(offset);
        let vn_next = u32::from_le_bytes(bytes[offset + 12..offset + 16].try_into().unwrap());
        if vn_next == 0 {
            break;
        }
        offset += vn_next as usize;
    }

    let kept: Vec<usize> = all_offsets
        .into_iter()
        .filter(|o| !removed.contains(o))
        .collect();

    // Pass 2: rebuild the vn_next chain across the kept entries.
    for (i, &off) in kept.iter().enumerate() {
        let new_vn_next = match kept.get(i + 1) {
            Some(&next) => (next - off) as u32,
            None => 0, // last kept entry terminates the list
        };
        bytes[off + 12..off + 16].copy_from_slice(&new_vn_next.to_le_bytes());
    }

    (kept.first().copied().unwrap_or(verneed_offset), kept.len())
}

#[cfg(test)]
mod verneed_tests {
    use super::relink_verneed_list;
    use std::collections::HashSet;

    /// Build `n` consecutive 16-byte Verneed entries. `vn_file` (byte +4) is set
    /// to the entry index so entries are distinguishable; `vn_next` chains them.
    fn make_list(n: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; n * 16];
        for i in 0..n {
            let off = i * 16;
            bytes[off + 4..off + 8].copy_from_slice(&(i as u32).to_le_bytes());
            let vn_next: u32 = if i + 1 < n { 16 } else { 0 };
            bytes[off + 12..off + 16].copy_from_slice(&vn_next.to_le_bytes());
        }
        bytes
    }

    fn walk(bytes: &[u8], head: usize) -> Vec<u32> {
        let mut out = Vec::new();
        let mut off = head;
        loop {
            out.push(u32::from_le_bytes(
                bytes[off + 4..off + 8].try_into().unwrap(),
            ));
            let nn = u32::from_le_bytes(bytes[off + 12..off + 16].try_into().unwrap());
            if nn == 0 {
                break;
            }
            off += nn as usize;
        }
        out
    }

    #[test]
    fn remove_head_advances_to_next() {
        // This is the case that crashed ld.so: the merged library was the first
        // Verneed entry, so DT_VERNEED must move to the second entry.
        let mut bytes = make_list(3);
        let (head, count) = relink_verneed_list(&mut bytes, 0, &HashSet::from([0]));
        assert_eq!((head, count), (16, 2));
        assert_eq!(walk(&bytes, head), vec![1, 2]);
    }

    #[test]
    fn remove_middle_relinks_around() {
        let mut bytes = make_list(3);
        let (head, count) = relink_verneed_list(&mut bytes, 0, &HashSet::from([16]));
        assert_eq!((head, count), (0, 2));
        assert_eq!(walk(&bytes, head), vec![0, 2]);
    }

    #[test]
    fn remove_tail_terminates_list() {
        let mut bytes = make_list(3);
        let (head, count) = relink_verneed_list(&mut bytes, 0, &HashSet::from([32]));
        assert_eq!((head, count), (0, 2));
        assert_eq!(walk(&bytes, head), vec![0, 1]);
    }

    #[test]
    fn remove_head_and_middle() {
        let mut bytes = make_list(4);
        let (head, count) = relink_verneed_list(&mut bytes, 0, &HashSet::from([0, 32]));
        assert_eq!((head, count), (16, 2));
        assert_eq!(walk(&bytes, head), vec![1, 3]);
    }

    #[test]
    fn remove_all_reports_empty() {
        let mut bytes = make_list(2);
        let (_head, count) = relink_verneed_list(&mut bytes, 0, &HashSet::from([0, 16]));
        assert_eq!(count, 0);
    }
}
