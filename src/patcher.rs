use anyhow::{Context, Result, bail};

use crate::elf_reader::{DYN_ENTRY_SIZE, DynamicTable};
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
    use goblin::elf::dynamic::DT_NEEDED;

    if plan.remove_needed.is_empty() {
        return Ok(());
    }

    let dynamic = DynamicTable::parse(bytes).context("reading .dynamic for DT_NEEDED removal")?;

    let mut removal_indices: Vec<usize> = plan
        .remove_needed
        .iter()
        .filter_map(|soname| {
            dynamic
                .entries_of(DT_NEEDED)
                .find(|&(_, val)| dynamic.string_at(bytes, val) == Some(soname.as_str()))
                .map(|(idx, _)| idx)
        })
        .collect();

    // The DT_NULL terminator shifts up along with the entries behind the one
    // being dropped, so it is part of the range that moves.
    let slots = (dynamic.used() + 1).min(dynamic.capacity());

    // Process removals in reverse index order so earlier removals don't shift later indices.
    removal_indices.sort_unstable_by(|a, b| b.cmp(a)); // descending

    for idx in removal_indices {
        // Shift entries [idx+1 .. slots) up by one slot.
        let src = dynamic.entry_offset(idx + 1);
        let moved = (slots - idx - 1) * DYN_ENTRY_SIZE;
        bytes.copy_within(src..src + moved, dynamic.entry_offset(idx));

        // Zero the last entry.
        let last = dynamic.entry_offset(slots - 1);
        bytes[last..last + DYN_ENTRY_SIZE].fill(0);
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
    use goblin::elf::dynamic::{DF_1_NOW, DF_BIND_NOW, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1};

    let dynamic = DynamicTable::parse(bytes).context("reading .dynamic for BIND_NOW")?;

    let already_now = dynamic.value_of(DT_BIND_NOW).is_some()
        || dynamic
            .value_of(DT_FLAGS)
            .is_some_and(|flags| flags & DF_BIND_NOW != 0)
        || dynamic
            .value_of(DT_FLAGS_1)
            .is_some_and(|flags| flags & DF_1_NOW != 0);
    if already_now {
        return Ok(());
    }

    if let Some(idx) = dynamic.index_of(DT_FLAGS) {
        // OR DF_BIND_NOW into the existing DT_FLAGS entry.
        let at = dynamic.value_offset(idx);
        let current = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        bytes[at..at + 8].copy_from_slice(&(current | DF_BIND_NOW).to_le_bytes());
        return Ok(());
    }

    // Append a new DT_FLAGS entry over the DT_NULL terminator; the slot after
    // it becomes the new terminator, so PT_DYNAMIC needs one spare slot.
    let terminator = dynamic.used();
    if terminator + 1 >= dynamic.capacity() {
        bail!(
            "no room in PT_DYNAMIC to add DT_FLAGS=DF_BIND_NOW entry \
             ({} slots, {terminator} used)",
            dynamic.capacity()
        );
    }

    let at = dynamic.entry_offset(terminator);
    bytes[at..at + 8].copy_from_slice(&DT_FLAGS.to_le_bytes());
    bytes[at + 8..at + 16].copy_from_slice(&DF_BIND_NOW.to_le_bytes());
    // Zeroing the following slot makes it the new DT_NULL terminator; slots
    // past the old one may hold garbage.
    let next = dynamic.entry_offset(terminator + 1);
    bytes[next..next + DYN_ENTRY_SIZE].fill(0);

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
    use goblin::elf::dynamic::{DT_DEBUG, DT_VERNEED, DT_VERNEEDNUM};

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

    let dynamic = DynamicTable::parse(bytes).context("reading .dynamic for verneed removal")?;

    // No version requirements section: nothing to unlink.
    let Some((verneed_dyn_idx, verneed_va)) = dynamic.entries_of(DT_VERNEED).next() else {
        return Ok(());
    };
    let verneed_offset = find_section_file_offset(bytes, ".gnu.version_r")? as usize;
    if verneed_offset == 0 {
        return Ok(());
    }

    // Walk the Verneed linked list to find entries matching libraries to remove
    let mut removed: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut offset = verneed_offset;
    while offset + VERNEED_SIZE <= bytes.len() {
        let vn_file = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let vn_next = u32::from_le_bytes(bytes[offset + 12..offset + 16].try_into().unwrap());

        // Check if this entry's library matches one we're removing
        if let Some(lib_name) = dynamic.string_at(bytes, vn_file as u64)
            && plan.remove_needed.iter().any(|s| s == lib_name)
        {
            removed.insert(offset);
        }

        if vn_next == 0 {
            break;
        }
        offset += vn_next as usize;
    }

    if removed.is_empty() {
        return Ok(());
    }

    // Now perform the linked list surgery.
    //
    // glibc's `_dl_check_map_versions` calls `find_needed(vn_file)` for *every*
    // Verneed entry and asserts the result is non-NULL *before* it ever looks at
    // `vn_cnt`.  So a removed library's entry cannot merely be zeroed in place —
    // it must be unlinked from the list entirely, including when it is the head
    // (in which case DT_VERNEED itself must be advanced to the next entry).
    let (new_head, kept_count) = relink_verneed_list(bytes, verneed_offset, &removed);

    let tag_at = dynamic.entry_offset(verneed_dyn_idx);
    let val_at = dynamic.value_offset(verneed_dyn_idx);
    if kept_count == 0 {
        // No requirements remain at all. Drop DT_VERNEED so ld.so doesn't walk a
        // now-empty section (rare: only if every needed library was merged).
        // Rewrite the tag to a runtime no-op (DT_DEBUG is ignored by ld.so).
        bytes[tag_at..tag_at + 8].copy_from_slice(&DT_DEBUG.to_le_bytes());
        bytes[val_at..val_at + 8].fill(0);
    } else if new_head != verneed_offset {
        // The head entry was removed, so point DT_VERNEED at the first kept
        // one. (Its VA tracks the file offset since the section is contiguous.)
        let new_va = verneed_va + (new_head - verneed_offset) as u64;
        bytes[val_at..val_at + 8].copy_from_slice(&new_va.to_le_bytes());
    }

    // Update DT_VERNEEDNUM to the number of surviving entries.
    if let Some(idx) = dynamic.index_of(DT_VERNEEDNUM) {
        let at = dynamic.value_offset(idx);
        bytes[at..at + 8].copy_from_slice(&(kept_count as u64).to_le_bytes());
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
