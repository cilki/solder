use std::path::Path;

use anyhow::{Context, Result, bail};
use tracing::warn;

use crate::elf_reader::{DYN_ENTRY_SIZE, DynamicTable, SectionTable};
use crate::types::{MergePlan, RelativeReloc};

/// Apply all in-place patches to a mutable copy of the executable bytes:
///   1. Pre-fill GOT entries with resolved merged symbol addresses.
///   2. Zero out JUMP_SLOT relocation entries so ld.so won't overwrite our patches.
///   3. Remove DT_NEEDED entries for fully-merged libraries.
///   4. Remove version requirements (.gnu.version_r) for fully-merged libraries.
///   5. Force eager binding so the loader processes the zeroed (R_X86_64_NONE)
///      PLT relocations through the eager path, which accepts NONE.
///   6. Re-derive the `.note.gnu.property` entries that describe the whole
///      program over the merged-in code as well.
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
    update_gnu_properties(exe_bytes, plan)?;
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

/// `NT_GNU_PROPERTY_TYPE_0`: the note type whose descriptor is the GNU
/// property array.
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
/// `GNU_PROPERTY_X86_FEATURE_1_AND`: the CET features *every* object making up
/// the process has to support before the loader turns them on.
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
/// `GNU_PROPERTY_X86_ISA_1_NEEDED`: the x86-64 ISA levels the code needs, which
/// `ld.so` refuses to run on a CPU that lacks.
const GNU_PROPERTY_X86_ISA_1_NEEDED: u32 = 0xc000_8002;
/// The `GNU_PROPERTY_X86_FEATURE_1_*` bits, for naming the ones being dropped.
const X86_FEATURE_1_BITS: [(u32, &str); 4] = [
    (1 << 0, "IBT"),
    (1 << 1, "SHSTK"),
    (1 << 2, "LAM_U48"),
    (1 << 3, "LAM_U57"),
];
/// A GNU property's `pr_data` is padded to this in an ELF64 object.
const PROPERTY_ALIGN: usize = 8;

/// Re-derive the `.note.gnu.property` entries that describe the program as a
/// whole, now that code from the merged libraries is part of it.
///
/// Two properties stop being true the moment foreign code is merged in, and
/// both are exactly what a static link recomputes across its inputs:
///
///   * `GNU_PROPERTY_X86_FEATURE_1_AND` advertises the CET features — IBT and
///     the shadow stack — that the whole program supports, and `ld.so` turns
///     them on for the process when the executable claims them. Merging a
///     library built without `-fcf-protection` leaves the claim standing over
///     code that never got an `endbr64`, and solder routes calls into that code
///     through GOT slots, i.e. as indirect branches — precisely what IBT
///     faults on. The claim is the AND of every contributing object's, so each
///     feature the merged library does not have is cleared here.
///   * `GNU_PROPERTY_X86_ISA_1_NEEDED` is the union of the ISA levels the code
///     requires. Without the merged library's levels folded in, a binary
///     carrying, say, AVX-512 library code looks runnable on a baseline CPU and
///     dies with SIGILL there instead of `ld.so`'s "CPU ISA level is lower than
///     required".
///
/// Both are a fixed-size `u32` inside an existing note, so they are patched in
/// place. A property the executable does not already carry cannot be added
/// without growing the note — there is nothing to grow into between the notes
/// and the rest of the first mapping — so that case is reported instead.
fn update_gnu_properties(bytes: &mut [u8], plan: &MergePlan) -> Result<()> {
    let exe_features = find_property(bytes, GNU_PROPERTY_X86_FEATURE_1_AND)
        .context("reading the executable's .note.gnu.property")?;
    let exe_isa = find_property(bytes, GNU_PROPERTY_X86_ISA_1_NEEDED)
        .context("reading the executable's .note.gnu.property")?;
    if exe_features.is_none() && exe_isa.is_none() {
        return Ok(());
    }

    let mut libs: Vec<&Path> = plan
        .units
        .iter()
        .map(|au| au.unit.source_lib.as_path())
        .collect();
    libs.sort_unstable();
    libs.dedup();

    let mut features = exe_features.map_or(0, |(_, mask)| mask);
    let mut isa = exe_isa.map_or(0, |(_, mask)| mask);
    for lib in libs {
        let data = std::fs::read(lib)
            .with_context(|| format!("reading {} for its GNU property note", lib.display()))?;
        let lib_features = find_property(&data, GNU_PROPERTY_X86_FEATURE_1_AND)
            .with_context(|| format!("reading .note.gnu.property of {}", lib.display()))?
            .map_or(0, |(_, mask)| mask);
        let lib_isa = find_property(&data, GNU_PROPERTY_X86_ISA_1_NEEDED)
            .with_context(|| format!("reading .note.gnu.property of {}", lib.display()))?
            .map_or(0, |(_, mask)| mask);

        if features & !lib_features != 0 {
            warn!(
                library = %lib.display(),
                dropped = %feature_names(features & !lib_features),
                "merged library does not support the CET features the executable \
                 advertises; clearing them so the loader does not enable them over \
                 code that cannot take them"
            );
        }
        if lib_isa & !isa != 0 && exe_isa.is_none() {
            warn!(
                library = %lib.display(),
                needed = format_args!("0x{:x}", lib_isa),
                "merged library needs x86-64 ISA levels the executable's \
                 .note.gnu.property has no entry to record; on a CPU without them \
                 the merged code will fault instead of being refused by ld.so"
            );
        }

        features &= lib_features;
        isa |= lib_isa;
    }

    if let Some((at, mask)) = exe_features
        && mask != features
    {
        bytes[at..at + 4].copy_from_slice(&features.to_le_bytes());
    }
    if let Some((at, mask)) = exe_isa
        && mask != isa
    {
        bytes[at..at + 4].copy_from_slice(&isa.to_le_bytes());
    }

    Ok(())
}

/// Name the `GNU_PROPERTY_X86_FEATURE_1_*` bits set in `mask`.
fn feature_names(mask: u32) -> String {
    let mut names: Vec<String> = X86_FEATURE_1_BITS
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect();
    let known: u32 = X86_FEATURE_1_BITS.iter().fold(0, |acc, (bit, _)| acc | bit);
    if mask & !known != 0 {
        names.push(format!("0x{:x}", mask & !known));
    }
    names.join(", ")
}

/// File offset of `pr_type`'s 4-byte value in `bytes`, and the value, if the
/// object carries that property.
///
/// Only `PT_NOTE` segments are searched: those are the notes the loader itself
/// reads, and a property note outside one would not reach it.
fn find_property(bytes: &[u8], pr_type: u32) -> Result<Option<(usize, u32)>> {
    let elf = goblin::elf::Elf::parse(bytes).context("goblin parse for GNU property notes")?;
    for ph in &elf.program_headers {
        if ph.p_type != goblin::elf::program_header::PT_NOTE {
            continue;
        }
        let start = ph.p_offset as usize;
        let Some(notes) = bytes.get(start..start.saturating_add(ph.p_filesz as usize)) else {
            continue;
        };
        if let Some((at, value)) = find_property_in_notes(notes, ph.p_align as usize, pr_type) {
            return Ok(Some((start + at, value)));
        }
    }
    Ok(None)
}

/// Walk a note array, returning the offset *relative to `notes`* of the 4-byte
/// value of property `pr_type`, together with that value.
///
/// `align` is the containing segment's `p_align`, which is what decides where
/// each note's descriptor starts and where the next note begins — a GNU
/// property note is 8-aligned where the build-id and ABI-tag notes beside it
/// are 4-aligned. A malformed note ends the walk rather than failing the merge:
/// an unreadable property is one we cannot say anything about, and the rest of
/// the output does not depend on it.
fn find_property_in_notes(notes: &[u8], align: usize, pr_type: u32) -> Option<(usize, u32)> {
    let align = align.max(4);
    let mut pos = 0usize;

    while pos + 12 <= notes.len() {
        let namesz = u32_at(notes, pos)? as usize;
        let descsz = u32_at(notes, pos + 4)? as usize;
        let n_type = u32_at(notes, pos + 8)?;
        let name = notes.get(pos + 12..(pos + 12).checked_add(namesz)?)?;

        // The name starts right after the 12-byte header and the descriptor
        // starts after it, both padded out to `align`.
        let desc_at =
            pos.checked_add((12usize.checked_add(namesz)?).checked_next_multiple_of(align)?)?;
        let next = desc_at.checked_add(descsz.checked_next_multiple_of(align)?)?;

        if n_type == NT_GNU_PROPERTY_TYPE_0 && name == b"GNU\0" {
            let props = notes.get(desc_at..desc_at.checked_add(descsz)?)?;
            if let Some((at, value)) = find_in_property_array(props, pr_type) {
                return Some((desc_at + at, value));
            }
        }

        pos = next;
    }

    None
}

/// Walk one `NT_GNU_PROPERTY_TYPE_0` descriptor — a sequence of
/// `(pr_type: u32, pr_datasz: u32, pr_data, padding to 8)` — for `pr_type`.
fn find_in_property_array(props: &[u8], pr_type: u32) -> Option<(usize, u32)> {
    let mut at = 0usize;
    while at + 8 <= props.len() {
        let this_type = u32_at(props, at)?;
        let datasz = u32_at(props, at + 4)? as usize;
        let data_at = at + 8;
        if data_at.checked_add(datasz)? > props.len() {
            return None;
        }
        if this_type == pr_type && datasz == 4 {
            return Some((data_at, u32_at(props, data_at)?));
        }
        at = data_at.checked_add(datasz.checked_next_multiple_of(PROPERTY_ALIGN)?)?;
    }
    None
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(field.try_into().expect("4 bytes")))
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
    // `.gnu.version_r` has no `DT_*` tag for its extent, so the only way to
    // find the list is through its section header.
    let verneed_offset = SectionTable::parse(bytes)?
        .and_then(|sections| sections.by_name(".gnu.version_r").map(|s| s.offset));
    let Some(verneed_offset) = verneed_offset.map(|off| off as usize) else {
        return Ok(());
    };

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

#[cfg(test)]
mod gnu_property_tests {
    use super::*;
    use crate::types::{AssignedUnit, ExtractedUnit, SectionKind, UnitId};
    use std::path::PathBuf;

    const GREP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/grep");
    /// Built without `-fcf-protection`, like every library in `test/libs`: it
    /// carries no `.note.gnu.property` at all.
    const PCRE2: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs/libpcre2-8.so.0");

    const IBT: u32 = 1 << 0;
    const SHSTK: u32 = 1 << 1;

    /// One note: `namesz`/`descsz`/`n_type`, the name `GNU\0`, then `desc`
    /// padded out to `align`.
    fn note(n_type: u32, desc: &[u8], align: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        out.extend_from_slice(&n_type.to_le_bytes());
        out.extend_from_slice(b"GNU\0");
        out.resize(16usize.next_multiple_of(align), 0);
        out.extend_from_slice(desc);
        out.resize(out.len().next_multiple_of(align), 0);
        out
    }

    /// One `(pr_type, pr_datasz, pr_data)` property holding a `u32`, padded to
    /// the 8-byte property alignment.
    fn property(pr_type: u32, value: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&pr_type.to_le_bytes());
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        out.resize(out.len().next_multiple_of(PROPERTY_ALIGN), 0);
        out
    }

    /// The property note is not necessarily the first note in its segment, nor
    /// the sought property the first in the note, and the preceding notes carry
    /// descriptors of sizes that are not multiples of the alignment.
    #[test]
    fn a_property_is_found_behind_other_notes_and_properties() {
        const NT_GNU_BUILD_ID: u32 = 3;
        let mut desc = property(GNU_PROPERTY_X86_ISA_1_NEEDED, 0x4);
        desc.extend_from_slice(&property(GNU_PROPERTY_X86_FEATURE_1_AND, IBT | SHSTK));

        let mut notes = note(NT_GNU_BUILD_ID, &[0xab; 20], 4);
        let property_note_at = notes.len();
        notes.extend_from_slice(&note(NT_GNU_PROPERTY_TYPE_0, &desc, 4));

        let (at, value) = find_property_in_notes(&notes, 4, GNU_PROPERTY_X86_FEATURE_1_AND)
            .expect("the CET property is in there");
        // Second property of the note: 16 bytes of note header and name, then
        // the ISA property — 8 bytes of `pr_type`/`pr_datasz`, a `u32` and the
        // padding out to 8 — then 8 bytes into the feature property.
        assert_eq!(at, property_note_at + 16 + 16 + 8);
        assert_eq!(value, IBT | SHSTK);

        assert_eq!(
            find_property_in_notes(&notes, 4, GNU_PROPERTY_X86_ISA_1_NEEDED),
            Some((property_note_at + 16 + 8, 0x4))
        );
    }

    /// A note whose sizes run past the end of the segment is where the walk
    /// stops: the loader would not read it either, and a merge must not fall
    /// over on it.
    #[test]
    fn a_truncated_note_ends_the_walk() {
        let desc = property(GNU_PROPERTY_X86_FEATURE_1_AND, IBT);
        let whole = note(NT_GNU_PROPERTY_TYPE_0, &desc, 8);
        for cut in 1..whole.len() {
            let truncated = &whole[..whole.len() - cut];
            assert_eq!(
                find_property_in_notes(truncated, 8, GNU_PROPERTY_X86_FEATURE_1_AND),
                None,
                "a note cut {cut} bytes short should not be read"
            );
        }

        // A nonsense namesz must not be trusted to stay in bounds either.
        let mut bogus = whole.clone();
        bogus[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            find_property_in_notes(&bogus, 8, GNU_PROPERTY_X86_FEATURE_1_AND),
            None
        );
    }

    /// Anchor the segment walk against a real binary: `test/grep` carries a
    /// single `GNU_PROPERTY_X86_ISA_1_NEEDED` property of `x86-64-baseline` and
    /// no CET property.
    #[test]
    fn a_real_executables_property_is_located_in_its_note_segment() {
        let bytes = std::fs::read(GREP).expect("read test/grep");
        assert_eq!(
            find_property(&bytes, GNU_PROPERTY_X86_ISA_1_NEEDED).expect("parse test/grep"),
            Some((0x350, 1))
        );
        assert_eq!(
            find_property(&bytes, GNU_PROPERTY_X86_FEATURE_1_AND).expect("parse test/grep"),
            None
        );
        assert_eq!(
            find_property(&std::fs::read(PCRE2).expect("read libpcre2"), 0xc000_0002)
                .expect("parse libpcre2"),
            None
        );
    }

    /// A plan that merged one unit out of `lib`.
    fn plan_merging(lib: &str) -> MergePlan {
        MergePlan {
            is_pie: true,
            load_address: 0x10_0000,
            exec_size: 0x1000,
            rodata_end: 0x1000,
            writable_end: 0x1000,
            units: vec![AssignedUnit {
                unit: ExtractedUnit {
                    id: UnitId(0),
                    name: "pcre2_match_8".to_owned(),
                    source_lib: PathBuf::from(lib),
                    bytes: vec![0x90; 16],
                    section_kind: SectionKind::Text,
                    alignment: 16,
                    relocations: Vec::new(),
                },
                assigned_vaddr: 0x10_0000,
            }],
            trampoline_stubs: Vec::new(),
            got_patches: Vec::new(),
            jump_slot_reloc_offsets: Vec::new(),
            copy_reloc_offsets: Vec::new(),
            remove_needed: Vec::new(),
            add_needed: Vec::new(),
            relative_relocs: Vec::new(),
            new_externals: Vec::new(),
            got_imports: Vec::new(),
            init_fini: None,
        }
    }

    /// `test/grep` with its ISA property rewritten into a CET property claiming
    /// IBT and the shadow stack — i.e. the binary a distribution that builds
    /// with `-fcf-protection=full` ships.
    fn grep_claiming_cet() -> (Vec<u8>, usize) {
        let mut bytes = std::fs::read(GREP).expect("read test/grep");
        let (at, _) = find_property(&bytes, GNU_PROPERTY_X86_ISA_1_NEEDED)
            .expect("parse test/grep")
            .expect("test/grep has an ISA property");
        // Same shape, so the note keeps its size: only pr_type and the value
        // change.
        bytes[at - 8..at - 4].copy_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        bytes[at..at + 4].copy_from_slice(&(IBT | SHSTK).to_le_bytes());
        (bytes, at)
    }

    /// The case this is all for: merging code that was built without CET into
    /// an executable that advertises it has to withdraw the advertisement, or
    /// the loader turns IBT on over code with no `endbr64` at the indirect
    /// branch targets solder itself routes calls through.
    #[test]
    fn merging_a_library_without_cet_withdraws_the_cet_claim() {
        let (mut bytes, at) = grep_claiming_cet();
        update_gnu_properties(&mut bytes, &plan_merging(PCRE2)).expect("update properties");
        assert_eq!(
            find_property(&bytes, GNU_PROPERTY_X86_FEATURE_1_AND).expect("reparse"),
            Some((at, 0)),
            "the executable still claims CET features the merged code does not have"
        );
    }

    /// The other half of the AND: a feature both sides support survives.
    #[test]
    fn a_feature_the_merged_library_also_has_is_kept() {
        let (mut bytes, at) = grep_claiming_cet();
        // Stand in for a CET-built library: the shadow stack but not IBT.
        let (lib, _) = grep_claiming_cet();
        let lib_path = tempfile::NamedTempFile::new().expect("tempfile");
        let mut lib_bytes = lib;
        let lib_at = find_property(&lib_bytes, GNU_PROPERTY_X86_FEATURE_1_AND)
            .expect("parse")
            .expect("property")
            .0;
        lib_bytes[lib_at..lib_at + 4].copy_from_slice(&SHSTK.to_le_bytes());
        std::fs::write(lib_path.path(), &lib_bytes).expect("write library");

        update_gnu_properties(
            &mut bytes,
            &plan_merging(lib_path.path().to_str().expect("utf-8 path")),
        )
        .expect("update properties");
        assert_eq!(
            find_property(&bytes, GNU_PROPERTY_X86_FEATURE_1_AND).expect("reparse"),
            Some((at, SHSTK))
        );
    }

    /// The ISA levels the merged code needs are the union, not the
    /// executable's alone: a baseline binary that merges AVX-512 library code
    /// must say so, so `ld.so` refuses to run it on a CPU without it instead of
    /// letting it fault.
    #[test]
    fn the_isa_levels_of_merged_code_are_folded_in() {
        const V4: u32 = 1 << 3;
        let mut bytes = std::fs::read(GREP).expect("read test/grep");
        let (at, baseline) = find_property(&bytes, GNU_PROPERTY_X86_ISA_1_NEEDED)
            .expect("parse test/grep")
            .expect("test/grep has an ISA property");

        let mut lib_bytes = bytes.clone();
        lib_bytes[at..at + 4].copy_from_slice(&V4.to_le_bytes());
        let lib_path = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(lib_path.path(), &lib_bytes).expect("write library");

        update_gnu_properties(
            &mut bytes,
            &plan_merging(lib_path.path().to_str().expect("utf-8 path")),
        )
        .expect("update properties");
        assert_eq!(
            find_property(&bytes, GNU_PROPERTY_X86_ISA_1_NEEDED).expect("reparse"),
            Some((at, baseline | V4))
        );
    }

    /// An executable with no property note of its own is left alone: there is
    /// nothing to intersect and no room to add a note.
    #[test]
    fn an_executable_without_properties_is_untouched() {
        let mut bytes = std::fs::read(PCRE2).expect("read libpcre2");
        let before = bytes.clone();
        update_gnu_properties(&mut bytes, &plan_merging(GREP)).expect("update properties");
        assert_eq!(bytes, before);
    }

    #[test]
    fn dropped_features_are_named_in_the_warning() {
        assert_eq!(feature_names(IBT | SHSTK), "IBT, SHSTK");
        assert_eq!(feature_names(1 << 9), "0x200");
    }
}
