use std::path::Path;

use anyhow::{Context, Result, bail};
use tracing::warn;

use crate::elf_reader::{
    DYN_ENTRY_SIZE, DynamicTable, SH_ADDR, SH_INFO, SH_OFFSET, SH_SIZE, SHDR_SIZE, SectionTable,
    VER_NDX_GLOBAL,
};
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

/// `sizeof (Elf64_Verneed)`, one entry of the `.gnu.version_r` list:
///   vn_version: u16  (offset 0)
///   vn_cnt:     u16  (offset 2) - Vernaux entries hanging off this one
///   vn_file:    u32  (offset 4) - offset into .dynstr for the library name
///   vn_aux:     u32  (offset 8) - offset to first Vernaux, relative to here
///   vn_next:    u32  (offset 12) - offset to next Verneed, relative to here,
///                                  0 if last
const VERNEED_SIZE: usize = 16;

/// `sizeof (Elf64_Vernaux)`, one version required of the library its Verneed
/// names:
///   vna_hash:  u32  (offset 0)
///   vna_flags: u16  (offset 4)
///   vna_other: u16  (offset 6) - the version index `.gnu.version` uses
///   vna_name:  u32  (offset 8) - offset into .dynstr for the version name
///   vna_next:  u32  (offset 12) - offset to next Vernaux, relative to here,
///                                 0 if last
const VERNAUX_SIZE: usize = 16;

/// `VERSYM_HIDDEN`, the top bit of a `.gnu.version` entry; the index is the
/// rest.
const VERSYM_HIDDEN: u16 = 0x8000;

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
/// 4. Point every `.gnu.version` index that named one of the unlinked entries'
///    versions at `VER_NDX_GLOBAL`, so no symbol is left requiring a version
///    that is no longer described
/// 5. Keep `.gnu.version_r`'s own section header describing the list the loader
///    now walks, so section-header-based tools see the same requirements
fn remove_verneed_entries(bytes: &mut [u8], plan: &MergePlan) -> Result<()> {
    use goblin::elf::dynamic::{DT_DEBUG, DT_VERNEED, DT_VERNEEDNUM};

    if plan.remove_needed.is_empty() {
        return Ok(());
    }

    let dynamic = DynamicTable::parse(bytes).context("reading .dynamic for verneed removal")?;

    // No version requirements section: nothing to unlink.
    let Some((verneed_dyn_idx, verneed_va)) = dynamic.entries_of(DT_VERNEED).next() else {
        return Ok(());
    };
    // `.gnu.version_r` has no `DT_*` tag for its extent, so the only way to
    // find the list — and the header that has to keep describing it — is
    // through the section header table. `.gnu.version` is reached the same way
    // rather than through `DT_VERSYM`, so that the array being rewritten and
    // the header naming it cannot be two different ranges.
    let Some(sections) = SectionTable::parse(bytes)? else {
        return Ok(());
    };
    let Some(verneed) = sections.by_name(".gnu.version_r") else {
        return Ok(());
    };
    let verneed_offset = verneed.offset as usize;
    let verneed_hdr_at = sections.offset + verneed.index * SHDR_SIZE;
    let verneed_extent = verneed.size;
    let versym = sections
        .by_name(".gnu.version")
        .map(|s| (s.offset as usize, s.size as usize));

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

    // The versions those entries required, before the surgery takes them off
    // the list: every `.gnu.version` index naming one of them is about to
    // describe nothing.
    let dropped_versions = required_version_indices(bytes, &removed);

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

    // The symbols that required those versions came from the merged-away
    // library, so they are undefined and unreferenced now: every relocation
    // against them has been rewritten to R_X86_64_NONE. Their version indices,
    // though, still name Vernaux entries no longer on the list, which is what
    // `readelf` reports as `sym@@<corrupt>` and what leaves glibc sizing
    // `l_versions` around a slot it never fills in. VER_NDX_GLOBAL — "no
    // version required" — is what the writer stamps on the externals it
    // injects, and the right answer for these too.
    //
    // The writer rebuilds `.gnu.version` in the merged region by copying the
    // array from here, so fixing the original fixes the copy the loader reads.
    if let Some((versym_at, versym_size)) = versym {
        clear_dropped_versyms(bytes, versym_at, versym_size, &dropped_versions);
    }

    // Finally, keep `.gnu.version_r`'s section header describing what
    // DT_VERNEED and DT_VERNEEDNUM now say. `sh_info` is the entry count, and
    // the extent has to start at the first entry still on the list: otherwise
    // every tool that reads section headers rather than PT_DYNAMIC goes on
    // reporting a requirement against a library that is no longer needed.
    let head_delta = (new_head - verneed_offset) as u64;
    let (extent, addr_delta) = if kept_count == 0 {
        (0, 0)
    } else {
        (verneed_extent.saturating_sub(head_delta), head_delta)
    };
    let hdr = &mut bytes[verneed_hdr_at..verneed_hdr_at + SHDR_SIZE];
    for (field, value) in [
        (SH_ADDR, verneed.addr + addr_delta),
        (SH_OFFSET, verneed.offset + addr_delta),
        (SH_SIZE, extent),
    ] {
        hdr[field..field + 8].copy_from_slice(&value.to_le_bytes());
    }
    hdr[SH_INFO..SH_INFO + 4].copy_from_slice(&(kept_count as u32).to_le_bytes());

    Ok(())
}

/// The version indices the Verneed entries at `offsets` require: the
/// `vna_other` of every Vernaux hanging off each of them.
///
/// `vn_cnt` bounds the walk along with `vna_next`, so a chain that lies about
/// its own length cannot run past the entries it claims.
fn required_version_indices(
    bytes: &[u8],
    offsets: &std::collections::HashSet<usize>,
) -> std::collections::HashSet<u16> {
    let mut indices = std::collections::HashSet::new();
    for &verneed_at in offsets {
        let Some(entry) = bytes.get(verneed_at..verneed_at + VERNEED_SIZE) else {
            continue;
        };
        let vn_cnt = u16::from_le_bytes(entry[2..4].try_into().expect("2 bytes"));
        let vn_aux = u32::from_le_bytes(entry[8..12].try_into().expect("4 bytes")) as usize;

        let mut at = verneed_at + vn_aux;
        for _ in 0..vn_cnt {
            let Some(aux) = bytes.get(at..at + VERNAUX_SIZE) else {
                break;
            };
            indices.insert(u16::from_le_bytes(aux[6..8].try_into().expect("2 bytes")));
            let vna_next = u32::from_le_bytes(aux[12..16].try_into().expect("4 bytes")) as usize;
            if vna_next == 0 {
                break;
            }
            at += vna_next;
        }
    }
    indices
}

/// Rewrite every entry of the `.gnu.version` array at `versym_at` whose index
/// is in `dropped` to `VER_NDX_GLOBAL`, and return how many were rewritten.
///
/// The array is one `u16` per `.dynsym` entry: the index of the version that
/// symbol requires, with `VERSYM_HIDDEN` set when the symbol is not to be
/// matched by an unversioned reference. A dropped version takes the hidden bit
/// with it — an undefined symbol with no version requirement left has nothing
/// to hide.
fn clear_dropped_versyms(
    bytes: &mut [u8],
    versym_at: usize,
    versym_size: usize,
    dropped: &std::collections::HashSet<u16>,
) -> usize {
    if dropped.is_empty() {
        return 0;
    }
    let end = (versym_at + versym_size).min(bytes.len());
    let mut cleared = 0;
    for at in (versym_at..end.saturating_sub(1)).step_by(2) {
        let entry = u16::from_le_bytes(bytes[at..at + 2].try_into().expect("2 bytes"));
        if dropped.contains(&(entry & !VERSYM_HIDDEN)) {
            bytes[at..at + 2].copy_from_slice(&VER_NDX_GLOBAL.to_le_bytes());
            cleared += 1;
        }
    }
    cleared
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
    use super::*;
    use std::collections::HashSet;

    /// `test/bash` requires `NCURSES6_TINFO_5.0.19991023` of
    /// `libtinfo.so.6` — the first entry of its `.gnu.version_r` list — so
    /// merging libtinfo away is the case where both the head of the list and
    /// the version indices pointing into it have to be dealt with.
    const BASH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/bash");
    const TINFO: &str = "libtinfo.so.6";

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

    /// One Verneed entry at `at` requiring each of `versions`, one Vernaux
    /// behind it per index. `vn_aux` and `vna_next` are offsets relative to the
    /// entry they sit in, which is the part worth getting wrong.
    fn make_entry_with_aux(at: usize, versions: &[u16]) -> Vec<u8> {
        let mut bytes = vec![0u8; at + VERNEED_SIZE + versions.len() * VERNAUX_SIZE];
        bytes[at + 2..at + 4].copy_from_slice(&(versions.len() as u16).to_le_bytes()); // vn_cnt
        bytes[at + 8..at + 12].copy_from_slice(&(VERNEED_SIZE as u32).to_le_bytes()); // vn_aux
        for (i, &index) in versions.iter().enumerate() {
            let aux = at + VERNEED_SIZE + i * VERNAUX_SIZE;
            bytes[aux + 6..aux + 8].copy_from_slice(&index.to_le_bytes()); // vna_other
            let vna_next = if i + 1 < versions.len() {
                VERNAUX_SIZE as u32
            } else {
                0
            };
            bytes[aux + 12..aux + 16].copy_from_slice(&vna_next.to_le_bytes());
        }
        bytes
    }

    /// A library can be required at more than one version, so unlinking its
    /// entry drops every index on its Vernaux chain, not just the first.
    #[test]
    fn every_version_an_entry_requires_is_collected() {
        let bytes = make_entry_with_aux(32, &[4, 7, 9]);
        assert_eq!(
            required_version_indices(&bytes, &HashSet::from([32])),
            HashSet::from([4, 7, 9])
        );
        // An entry that is not being removed contributes nothing.
        assert!(required_version_indices(&bytes, &HashSet::new()).is_empty());
    }

    /// `vn_cnt` and `vna_next` both bound the walk, and neither may be trusted
    /// to stay inside the file: a chain that claims more entries than are there
    /// must not panic the merge.
    #[test]
    fn a_vernaux_chain_running_past_the_end_is_not_followed() {
        let mut bytes = make_entry_with_aux(0, &[4, 7]);
        bytes[2..4].copy_from_slice(&9u16.to_le_bytes()); // vn_cnt lies: 9 entries
        assert_eq!(
            required_version_indices(&bytes, &HashSet::from([0])),
            HashSet::from([4, 7]),
            "the walk read past the entries that are there"
        );

        // A truncated entry is not read at all, nor is one past the end.
        let short = &bytes[..VERNEED_SIZE - 1];
        assert!(required_version_indices(short, &HashSet::from([0])).is_empty());
        assert!(required_version_indices(&bytes, &HashSet::from([0x1000])).is_empty());
    }

    /// The hidden bit is part of the entry but not of the index, so a hidden
    /// symbol's dropped version has to be recognised — and loses the bit along
    /// with the requirement.
    #[test]
    fn a_dropped_version_is_cleared_through_the_hidden_bit() {
        let versym: Vec<u16> = vec![0, 1, 2, 6, 6 | VERSYM_HIDDEN, 7];
        let mut bytes: Vec<u8> = versym.iter().flat_map(|v| v.to_le_bytes()).collect();
        let size = bytes.len();

        assert_eq!(
            clear_dropped_versyms(&mut bytes, 0, size, &HashSet::from([6])),
            2
        );
        let after: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().expect("2 bytes")))
            .collect();
        assert_eq!(after, vec![0, 1, 2, VER_NDX_GLOBAL, VER_NDX_GLOBAL, 7]);
    }

    /// The array's size bounds the rewrite: `.gnu.version` is parallel to
    /// `.dynsym`, and whatever follows it in the file is somebody else's.
    #[test]
    fn clearing_stays_inside_the_array() {
        let mut bytes = vec![6u8, 0, 6, 0, 6, 0];
        assert_eq!(
            clear_dropped_versyms(&mut bytes, 0, 2, &HashSet::from([6])),
            1
        );
        assert_eq!(bytes, vec![1u8, 0, 6, 0, 6, 0]);

        // No dropped version, and a size running past the end: both leave the
        // bytes alone rather than reading out of bounds.
        let before = bytes.clone();
        assert_eq!(clear_dropped_versyms(&mut bytes, 0, 6, &HashSet::new()), 0);
        assert_eq!(
            clear_dropped_versyms(&mut bytes, 4, 0x1000, &HashSet::new()),
            0
        );
        assert_eq!(bytes, before);
    }

    /// A plan that merges `soname` away entirely, which is what puts its
    /// soname on `remove_needed`.
    fn plan_removing(soname: &str) -> MergePlan {
        MergePlan {
            is_pie: true,
            load_address: 0x10_0000,
            exec_size: 0x1000,
            rodata_end: 0x1000,
            writable_end: 0x1000,
            units: Vec::new(),
            trampoline_stubs: Vec::new(),
            got_patches: Vec::new(),
            jump_slot_reloc_offsets: Vec::new(),
            copy_reloc_offsets: Vec::new(),
            remove_needed: vec![soname.to_owned()],
            add_needed: Vec::new(),
            relative_relocs: Vec::new(),
            new_externals: Vec::new(),
            got_imports: Vec::new(),
            init_fini: None,
        }
    }

    fn section(bytes: &[u8], name: &str) -> crate::elf_reader::SectionHeader {
        let table = SectionTable::parse(bytes)
            .expect("read the section headers")
            .expect("the fixture has no section headers");
        table
            .sections
            .into_iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("the fixture has no '{name}' section"))
    }

    /// The `.gnu.version` array: one version index per `.dynsym` entry.
    fn version_indices(bytes: &[u8]) -> Vec<u16> {
        let header = section(bytes, ".gnu.version");
        let at = header.offset as usize;
        bytes[at..at + header.size as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().expect("2 bytes")))
            .collect()
    }

    /// The Verneed entries the `.gnu.version_r` section header lists, reached
    /// the way `readelf` reaches them: from where the header says the list
    /// starts, following `vn_next`.
    fn listed_entries(bytes: &[u8]) -> HashSet<usize> {
        let header = section(bytes, ".gnu.version_r");
        if header.size == 0 {
            return HashSet::new();
        }
        let mut entries = HashSet::new();
        let mut at = header.offset as usize;
        loop {
            entries.insert(at);
            let vn_next = u32::from_le_bytes(bytes[at + 12..at + 16].try_into().expect("4 bytes"));
            if vn_next == 0 {
                break;
            }
            at += vn_next as usize;
        }
        entries
    }

    /// Every version index those entries still require.
    fn described_versions(bytes: &[u8]) -> HashSet<u16> {
        required_version_indices(bytes, &listed_entries(bytes))
    }

    /// `.gnu.version_r`'s `sh_info`: the number of entries the section header
    /// claims are on the list.
    fn listed_count(bytes: &[u8]) -> u32 {
        let table = SectionTable::parse(bytes)
            .expect("read the section headers")
            .expect("the fixture has no section headers");
        let at = table.offset + section(bytes, ".gnu.version_r").index * SHDR_SIZE + SH_INFO;
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
    }

    /// The symbols whose version requirement came from the merged-away library
    /// are undefined and unreferenced afterwards, but their `.gnu.version`
    /// indices used to be left pointing into the entry that was unlinked —
    /// which is what `readelf` reports as `tputs@@<corrupt>`, and what left
    /// glibc sizing `l_versions` around a slot it never fills in.
    #[test]
    fn a_merged_away_librarys_symbols_stop_requiring_its_versions() {
        let before = std::fs::read(BASH).expect("read test/bash");
        let mut after = before.clone();
        remove_verneed_entries(&mut after, &plan_removing(TINFO)).expect("remove verneed entries");

        let (was, now) = (version_indices(&before), version_indices(&after));
        assert_eq!(was.len(), now.len(), ".gnu.version changed length");

        let changed: Vec<usize> = (0..was.len()).filter(|&i| was[i] != now[i]).collect();
        assert!(
            !changed.is_empty(),
            "no symbol required a version of {TINFO}, so this proves nothing"
        );
        for i in changed {
            assert_eq!(
                now[i], VER_NDX_GLOBAL,
                "symbol {i} went from version {} to {}",
                was[i], now[i]
            );
        }

        // tputs is the one from the issue: it is imported at
        // NCURSES6_TINFO_5.0.19991023, a version only libtinfo provides.
        let elf = goblin::elf::Elf::parse(&before).expect("parse test/bash");
        let tputs = elf
            .dynsyms
            .iter()
            .position(|sym| elf.dynstrtab.get_at(sym.st_name) == Some("tputs"))
            .expect("test/bash imports tputs");
        assert_ne!(was[tputs], VER_NDX_GLOBAL, "tputs was unversioned already");
        assert_eq!(now[tputs], VER_NDX_GLOBAL);

        // And nothing is left requiring a version no entry describes.
        let described = described_versions(&after);
        for (i, &index) in now.iter().enumerate() {
            assert!(
                index <= VER_NDX_GLOBAL || described.contains(&(index & !VERSYM_HIDDEN)),
                "symbol {i} requires version {index}, which nothing describes"
            );
        }
    }

    /// The loader walks the Verneed list from `DT_VERNEED` and every other tool
    /// from the `.gnu.version_r` section header. Unlinking the head entry
    /// advanced the first and left the second behind, so `readelf` went on
    /// listing a requirement against a library that is no longer in
    /// `DT_NEEDED`.
    #[test]
    fn the_verneed_section_header_follows_the_list_the_loader_walks() {
        use goblin::elf::dynamic::{DT_VERNEED, DT_VERNEEDNUM};

        let before = std::fs::read(BASH).expect("read test/bash");
        let mut after = before.clone();
        remove_verneed_entries(&mut after, &plan_removing(TINFO)).expect("remove verneed entries");

        let was = section(&before, ".gnu.version_r");
        let now = section(&after, ".gnu.version_r");
        let dynamic = DynamicTable::parse(&after).expect("parse .dynamic");

        // The loader's view and every other tool's view have to be the same
        // list: same first entry, same number of entries on it.
        let head = dynamic.value_of(DT_VERNEED).expect("DT_VERNEED");
        assert_eq!(
            now.addr, head,
            "the section starts at {:#x} but the loader starts at {head:#x}",
            now.addr
        );
        let count = dynamic.value_of(DT_VERNEEDNUM).expect("DT_VERNEEDNUM");
        assert_eq!(u64::from(listed_count(&after)), count, "sh_info is stale");
        assert_eq!(
            listed_entries(&after).len() as u64,
            count,
            "the list the header points at is not {count} entries long"
        );

        // libtinfo heads the list in this fixture, so the extent starts one
        // entry further in and shrinks by as much, while still ending where it
        // did — inside the file, covering every entry left on the list.
        assert!(
            now.addr > was.addr,
            "the unlinked head entry is still described"
        );
        assert_eq!(now.offset - was.offset, now.addr - was.addr);
        assert_eq!(now.size, was.size - (now.offset - was.offset));
        assert!(now.offset + now.size <= after.len() as u64);
        for entry in listed_entries(&after) {
            assert!(
                (now.offset..now.offset + now.size).contains(&(entry as u64)),
                "the entry at {entry:#x} is outside the section that lists it"
            );
        }
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
