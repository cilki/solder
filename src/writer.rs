use anyhow::{Context, Result, bail};

use crate::elf_reader::{
    DynamicTable, SH_ADDR, SH_ADDRALIGN, SH_FLAGS, SH_NAME, SH_OFFSET, SH_SIZE, SH_TYPE, SHDR_SIZE,
    SectionTable, va_to_file_offset,
};
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

    for au in &plan.units {
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
        // Real PLT stub encoding: `FF 25 <imm32>` = `jmp qword ptr [rip + imm32]`.
        // The CPU computes effective address (rip_after + imm32), reads the
        // 8-byte function pointer the loader wrote into that GOT slot, and
        // jumps there. We use a RIP-relative offset so the loader's load-base
        // offset doesn't matter (PIE and non-PIE both work without extra
        // RELATIVE relocs).
        if off + 14 > seg.len() {
            bail!("trampoline for '{}' overflows segment", stub.symbol_name);
        }
        let rip_after = stub.vaddr + 6;
        let rel = (stub.target_got_vaddr as i64) - (rip_after as i64);
        if !(i32::MIN as i64..=i32::MAX as i64).contains(&rel) {
            bail!(
                "trampoline for '{}': GOT slot offset 0x{:x} does not fit in i32 \
                 (stub at 0x{:x}, target at 0x{:x})",
                stub.symbol_name,
                rel,
                stub.vaddr,
                stub.target_got_vaddr
            );
        }
        seg[off] = 0xFF;
        seg[off + 1] = 0x25;
        seg[off + 2..off + 6].copy_from_slice(&(rel as i32).to_le_bytes());
        // The remaining 8 bytes of the reserved 14-byte slot are unused; leave
        // them zeroed. (Kept at 14 bytes total so the layout calculation that
        // reserves 14-byte trampolines stays correct.)
    }

    // Write the preinit and fini arrays if present. Each entry is a link-time
    // VA in the output image, so under PIE each one also needs an
    // R_X86_64_RELATIVE relocation for ld.so to rebase it.
    if let Some(init_fini) = &plan.init_fini {
        for (kind, array) in init_fini.arrays() {
            for (i, &func_va) in array.entries.iter().enumerate() {
                let vaddr = array.vaddr + (i * 8) as u64;
                let off = (vaddr - plan.load_address) as usize;
                if off + 8 > seg.len() {
                    bail!("{} entry {i} overflows segment", kind.name());
                }
                seg[off..off + 8].copy_from_slice(&func_va.to_le_bytes());
                if plan.is_pie {
                    plan.relative_relocs.push(RelativeReloc {
                        vaddr,
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

    check_runtime_writes_are_writable(plan)?;

    let exe = ElfFile64::<object::Endianness>::parse(patched_exe)
        .context("parsing patched executable for output")?;
    let endian = exe.endian();

    // Read .dynamic from the ORIGINAL exe before we modify headers.
    let dynamic = DynamicTable::parse(patched_exe).context("reading .dynamic for output")?;

    // Collect existing program headers.
    let old_phdrs: Vec<object::elf::ProgramHeader64<object::Endianness>> =
        exe.elf_program_headers().to_vec();
    let phdr_entry_size = std::mem::size_of::<object::elf::ProgramHeader64<object::Endianness>>();

    // File offset where the merged segment will start. It is pinned to
    // `load_address` so that `p_vaddr - p_offset` comes out the same for the
    // merged mappings as for the executable's own — `PT_PHDR` lands inside the
    // merged region, and tools read its difference as the whole image's (see
    // `merged_load_address`). Everything between the end of the executable and
    // here is unmapped zero padding.
    let base_delta = crate::elf_reader::image_base_delta(&exe);
    let seg_file_offset = plan
        .load_address
        .checked_sub(base_delta)
        .filter(|offset| *offset >= patched_exe.len() as u64)
        .with_context(|| {
            format!(
                "merged region at {:#x} would start at file offset {:#x}, inside the \
                 {:#x}-byte executable (image base delta {base_delta:#x})",
                plan.load_address,
                plan.load_address.wrapping_sub(base_delta),
                patched_exe.len()
            )
        })?;

    // Build the extended merged segment: original segment + any sections we
    // need to grow (.dynstr/.dynsym/.gnu.version when injecting new external
    // symbols; .rela.dyn whenever PIE relocs or new GLOB_DATs are added).
    let needs_rela_extension = plan.is_pie && !plan.relative_relocs.is_empty();
    let needs_symbol_extension = !plan.new_externals.is_empty()
        || !plan.got_imports.is_empty()
        || !plan.add_needed.is_empty();
    let (extended_seg, ext_info) = if needs_rela_extension || needs_symbol_extension {
        build_extended_segment(patched_exe, merged_seg, plan, &dynamic, &exe)?
    } else {
        (merged_seg.to_vec(), ExtensionInfo::default())
    };

    // The merged region is described by up to four PT_LOADs rather than one
    // read-write-execute mapping: the code and trampolines, then the merged
    // constants, then everything ld.so writes to at startup, then the rebuilt
    // symbol/relocation tables and the new program header table. `layout`
    // page-aligned the boundaries so each mapping starts on a page, and
    // `seg_file_offset` and `plan.load_address` are both page-aligned, which
    // keeps p_offset and p_vaddr congruent modulo the page size for all of
    // them.
    //
    // Each element is the start offset of a mapping within the region; the
    // mapping runs to the next element's start, or to the end of the region.
    let mut regions: Vec<(u64, u32)> = Vec::with_capacity(4);
    if plan.exec_size > 0 {
        regions.push((0, (PF_R | PF_X).0));
    }
    if plan.rodata_end > plan.exec_size {
        regions.push((plan.exec_size, PF_R.0));
    }
    if plan.writable_end > plan.rodata_end {
        regions.push((plan.rodata_end, (PF_R | PF_W).0));
    }
    regions.push((plan.writable_end, PF_R.0));

    // Calculate sizes for embedding PHT within the new PT_LOAD segments.
    let new_phnum = old_phdrs.len() + regions.len();
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
            write_u64_le(&mut out, dst + 8, pht_file_offset); // p_offset
            write_u64_le(&mut out, dst + 16, pht_vaddr); // p_vaddr
            write_u64_le(&mut out, dst + 24, pht_vaddr); // p_paddr
            write_u64_le(&mut out, dst + 32, pht_size); // p_filesz
            write_u64_le(&mut out, dst + 40, pht_size); // p_memsz
        }

        written += phdr_entry_size;
    }

    // Write one PT_LOAD per mapping of the merged region. The last one runs to
    // the end of the region, so it is the one that covers the PHT.
    for (i, (start, flags)) in regions.iter().enumerate() {
        let end = regions
            .get(i + 1)
            .map(|(next, _)| *next)
            .unwrap_or(total_seg_size);
        let size = end - start;
        let dst = pht_start + written;
        write_u32_le(&mut out, dst, PT_LOAD.0);
        write_u32_le(&mut out, dst + 4, *flags);
        write_u64_le(&mut out, dst + 8, seg_file_offset + start);
        write_u64_le(&mut out, dst + 16, plan.load_address + start);
        write_u64_le(&mut out, dst + 24, plan.load_address + start); // p_paddr = p_vaddr
        write_u64_le(&mut out, dst + 32, size);
        write_u64_le(&mut out, dst + 40, size);
        write_u64_le(&mut out, dst + 48, crate::layout::PAGE_SIZE);
        written += phdr_entry_size;
    }

    // Update ELF header: e_phoff and e_phnum.
    write_u64_le(&mut out, 32, pht_file_offset);
    write_u16_le(&mut out, 56, new_phnum as u16);

    // Update .dynamic entries for any sections we relocated into the merged
    // segment. Each update writes only the d_val field (offset +8 from the
    // entry start); d_tag is untouched.
    apply_extension_info(&mut out, &dynamic, &ext_info);

    // Point DT_PREINIT_ARRAY/DT_FINI_ARRAY at our arrays and add a DT_NEEDED
    // entry per inherited soname.
    if plan.init_fini.is_some() || !plan.add_needed.is_empty() {
        update_dynamic_entries(&mut out, plan, &dynamic, &ext_info)?;
    }

    // Everything above describes the merge to the dynamic loader, which reads
    // PT_DYNAMIC. Now describe it to everything that reads section headers.
    rewrite_section_headers(
        &mut out,
        plan,
        &ext_info,
        seg_file_offset,
        &regions,
        total_seg_size,
    )?;

    // `output_path` is the input executable, so read its mode before the write
    // replaces the file: the merge must not change who is allowed to read or
    // run the binary.
    #[cfg(unix)]
    let original_mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(output_path)
            .map(|m| m.permissions().mode() & 0o7777)
            .ok()
    };

    // Write output file.
    std::fs::write(output_path, &out)
        .with_context(|| format!("writing output {}", output_path.display()))?;

    // Restore the mode the input had, adding owner-execute if it somehow
    // lacked it. Unconditionally chmod'ing 0o755 here widened a 0o700 binary
    // to world-readable and world-executable and silently dropped any
    // setuid/setgid bit, neither of which is the merge's business.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = original_mode.unwrap_or(0o755) | 0o100;
        std::fs::set_permissions(output_path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("restoring mode on {}", output_path.display()))?;
    }

    Ok(())
}

/// Make the section header table describe the merged binary.
///
/// The merge moves `.dynstr`, `.dynsym`, `.gnu.version` and `.rela.dyn` into
/// the merged region (rebuilt larger) and repoints the matching `DT_*` tags at
/// the new copies, but their section headers kept describing the pre-merge
/// file. Everything that reads section headers instead of `PT_DYNAMIC` — and
/// that is every binutils tool, plus gdb and patchelf — therefore saw the
/// executable as it was before the merge: the old relocation and symbol tables,
/// and no trace at all of the merged code and data.
///
/// `solder` is itself one of those readers: `read_dynsym_tables` takes the
/// `.dynsym` and `.gnu.version` sizes from their section headers, because
/// `.dynamic` has no tag that gives them. Left stale, a second merge over an
/// already-merged executable copied only as many symbols as the *first* merge
/// started with, dropping the ones it had injected while the `GLOB_DAT`
/// relocations still referenced them by index.
///
/// So: repoint the headers of the rebuilt sections, add one covering each
/// mapping of the merged region, and write a fresh section header table and
/// `.shstrtab` at the end of the file.
fn rewrite_section_headers(
    out: &mut Vec<u8>,
    plan: &MergePlan,
    ext: &ExtensionInfo,
    seg_file_offset: u64,
    regions: &[(u64, u32)],
    total_seg_size: u64,
) -> Result<()> {
    use object::elf::{PF_W, PF_X, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_PROGBITS};

    // An executable whose section header table was already stripped has nothing
    // to keep in sync; the loader never needed it.
    let Some(table) = SectionTable::parse(out)? else {
        return Ok(());
    };

    let mut shdrs = out[table.byte_range()].to_vec();
    let shstrtab_hdr = table.shstrndx * SHDR_SIZE;
    let shstrtab = table.shstrtab();
    let names_at = shstrtab.offset as usize;
    let mut names = out[names_at..names_at + shstrtab.size as usize].to_vec();

    // Repoint the sections the merge rebuilt. A section the executable does not
    // have is skipped: nothing described the old table either.
    for &(section, vaddr, size) in &ext.rebuilt_sections {
        let Some(header) = table.by_name(section) else {
            continue;
        };
        let base = header.index * SHDR_SIZE;
        write_u64_le(&mut shdrs, base + SH_ADDR, vaddr);
        write_u64_le(
            &mut shdrs,
            base + SH_OFFSET,
            seg_file_offset + (vaddr - plan.load_address),
        );
        write_u64_le(&mut shdrs, base + SH_SIZE, size);
    }

    // One section per mapping of the merged region, so tools that rebuild a
    // file from its sections (`strip`, `objcopy`) carry the merged code and
    // data along instead of dropping everything no section claimed. The last
    // mapping is skipped: it holds the rebuilt tables repointed above plus the
    // program header table, which no section describes in a linker's output
    // either.
    let append_name = |names: &mut Vec<u8>, s: &str| -> u32 {
        let offset = names.len() as u32;
        names.extend_from_slice(s.as_bytes());
        names.push(0);
        offset
    };
    let mut added = 0usize;
    for (i, &(start, flags)) in regions.iter().enumerate().take(regions.len() - 1) {
        let end = regions
            .get(i + 1)
            .map(|(next, _)| *next)
            .unwrap_or(total_seg_size);
        let (name, sh_flags) = if flags & PF_X.0 != 0 {
            (".solder.text", (SHF_ALLOC | SHF_EXECINSTR).0)
        } else if flags & PF_W.0 != 0 {
            (".solder.data", (SHF_ALLOC | SHF_WRITE).0)
        } else {
            (".solder.rodata", SHF_ALLOC.0)
        };
        let name_off = append_name(&mut names, name);

        let mut shdr = [0u8; SHDR_SIZE];
        write_u32_le(&mut shdr, SH_NAME, name_off);
        write_u32_le(&mut shdr, SH_TYPE, SHT_PROGBITS.0);
        write_u64_le(&mut shdr, SH_FLAGS, sh_flags);
        write_u64_le(&mut shdr, SH_ADDR, plan.load_address + start);
        write_u64_le(&mut shdr, SH_OFFSET, seg_file_offset + start);
        write_u64_le(&mut shdr, SH_SIZE, end - start);
        write_u64_le(&mut shdr, SH_ADDRALIGN, crate::layout::PAGE_SIZE);
        shdrs.extend_from_slice(&shdr);
        added += 1;
    }

    // Lay the rebuilt `.shstrtab` and section header table past the last
    // PT_LOAD, where a linker puts them: neither is mapped at runtime.
    let names_offset = out.len() as u64;
    write_u64_le(&mut shdrs, shstrtab_hdr + SH_OFFSET, names_offset);
    write_u64_le(&mut shdrs, shstrtab_hdr + SH_SIZE, names.len() as u64);
    out.extend_from_slice(&names);
    pad_to(out, 8);
    let new_shoff = out.len() as u64;
    out.extend_from_slice(&shdrs);

    write_u64_le(out, 0x28, new_shoff);
    write_u16_le(out, 0x3c, (table.sections.len() + added) as u16);
    Ok(())
}

/// Fail before writing anything if a slot the dynamic loader has to write at
/// startup landed outside the writable run of the merged region.
///
/// Only one of the merged region's mappings is writable, so a layout that puts
/// an `R_X86_64_RELATIVE` target or a `GLOB_DAT` GOT slot among the code or
/// among the read-only constants would make ld.so fault while relocating.
/// Refusing to emit such a binary beats shipping one that cannot start.
///
/// `plan.load_address` sits past the end of every original `PT_LOAD`, so any
/// target at or above it belongs to the merged region; the ones below it are
/// slots in the executable's own GOT, which keep whatever permissions the
/// executable already gave them.
fn check_runtime_writes_are_writable(plan: &MergePlan) -> Result<()> {
    let writable = plan.load_address + plan.rodata_end..plan.load_address + plan.writable_end;
    let misplaced = |vaddr: u64| vaddr >= plan.load_address && !writable.contains(&vaddr);

    let slots = plan
        .relative_relocs
        .iter()
        .map(|r| ("R_X86_64_RELATIVE target", r.vaddr, String::new()))
        .chain(
            plan.new_externals
                .iter()
                .map(|e| ("GOT slot", e.got_vaddr, format!(" for '{}'", e.name))),
        )
        .chain(
            plan.got_imports
                .iter()
                .map(|g| ("copied GOT slot", g.got_vaddr, format!(" for '{}'", g.name))),
        );
    for (what, vaddr, which) in slots {
        if misplaced(vaddr) {
            bail!(
                "{what}{which} at 0x{vaddr:x} falls outside the writable part of the \
                 merged segment (0x{:x}..0x{:x}); ld.so cannot write it",
                writable.start,
                writable.end
            );
        }
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

/// Name of `.dynsym` entry `index`, resolved through `.dynstr`. `None` for an
/// entry whose `st_name` is out of range or names the empty string, neither of
/// which identifies a symbol.
fn symbol_name<'s>(dynsym: &[u8], dynstr: &'s [u8], index: usize) -> Option<&'s str> {
    let at = index * SYM_ENTRY_SIZE;
    let st_name = u32::from_le_bytes(dynsym.get(at..at + 4)?.try_into().expect("4 bytes"));
    crate::elf_reader::cstr_at(dynstr, st_name as usize).filter(|name| !name.is_empty())
}

/// R_X86_64_RELATIVE relocation type
const R_X86_64_RELATIVE: u32 = 8;

/// Size of an Elf64_Rela entry
const RELA_ENTRY_SIZE: usize = 24;

/// What `build_extended_segment` rebuilt in the merged segment, as the
/// `.dynamic` edits that make the loader read the new copies.
#[derive(Debug, Default)]
struct ExtensionInfo {
    /// `(d_tag, new d_val)` per entry to repoint. An entry the executable does
    /// not have is skipped: there is nothing pointing at the old table either,
    /// so nothing to redirect.
    dyn_updates: Vec<(u64, u64)>,
    /// Offset into the rebuilt `.dynstr` of each `plan.add_needed` soname, in
    /// the same order, for the `DT_NEEDED` entries that reference them.
    needed_name_offsets: Vec<u32>,
    /// `(section name, vaddr, size)` for each section rebuilt in the merged
    /// region, so `rewrite_section_headers` can repoint its section header at
    /// the copy the loader will actually read.
    rebuilt_sections: Vec<(&'static str, u64, u64)>,
}

/// R_X86_64_GLOB_DAT relocation type.
const R_X86_64_GLOB_DAT: u32 = 6;
/// Size of an Elf64_Sym entry.
const SYM_ENTRY_SIZE: usize = 24;
/// STB_GLOBAL | STT_FUNC — for the new undefined function symbols we inject.
const ST_INFO_GLOBAL_FUNC: u8 = (1 << 4) | 2;
/// STB_WEAK | STT_FUNC — for injected symbols that may legitimately stay
/// unresolved (their GOT slots then hold 0, which the code null-checks).
const ST_INFO_WEAK_FUNC: u8 = (2 << 4) | 2;
/// VER_NDX_GLOBAL — accept any version of the symbol.
const VER_NDX_GLOBAL: u16 = 1;

/// Build the merged segment with any extended sections appended. The result
/// always covers the existing PIE-rela extension; when `plan.new_externals` is
/// non-empty it also rebuilds `.dynstr`, `.dynsym`, and `.gnu.version` (placed
/// in the merged segment) and stitches new GLOB_DAT relocs into the rebuilt
/// `.rela.dyn`.
///
/// The original `.rela.dyn` layout requires that R_X86_64_RELATIVE entries come
/// first (DT_RELACOUNT bytes' worth), followed by everything else. We preserve
/// that ordering: existing RELATIVE → new RELATIVE → existing non-RELATIVE →
/// new GLOB_DAT.
fn build_extended_segment(
    patched_exe: &[u8],
    merged_seg: &[u8],
    plan: &MergePlan,
    dynamic: &DynamicTable,
    exe: &object::read::elf::ElfFile64<'_, object::Endianness>,
) -> Result<(Vec<u8>, ExtensionInfo)> {
    use goblin::elf::dynamic::{
        DT_RELA, DT_RELACOUNT, DT_RELASZ, DT_STRSZ, DT_STRTAB, DT_SYMTAB, DT_VERSYM,
    };

    let mut extended = Vec::from(merged_seg);
    let mut info = ExtensionInfo::default();

    // ---- 1. Inject new external symbols (extends .dynstr / .dynsym / .gnu.version)
    //
    // We do this first so we know the final symbol indices before writing the
    // GLOB_DAT relocations into the rebuilt .rela.dyn. The new sections are
    // placed back-to-back at the end of the segment; existing strings/syms
    // are copied verbatim so that all pre-existing offsets and indices stay
    // valid for unchanged consumers (hash tables, verneed entries, etc.).

    let mut new_sym_idx_base: usize = 0;
    // Existing .dynsym name → index, for GLOB_DATs against already-present symbols.
    let mut existing_sym_idx: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    // Symbols to inject: (name, weak). new_externals first (strong), then any
    // got_imports whose symbol is in neither the exe's .dynsym nor this list.
    let mut injects: Vec<(String, bool)> = Vec::new();

    if !plan.new_externals.is_empty() || !plan.got_imports.is_empty() || !plan.add_needed.is_empty()
    {
        let (old_dynstr, old_dynsym, old_versym) = read_dynsym_tables(patched_exe, exe, dynamic)?;
        let old_num_syms = old_dynsym.len() / SYM_ENTRY_SIZE;
        new_sym_idx_base = old_num_syms;

        for i in 0..old_num_syms {
            if let Some(name) = symbol_name(&old_dynsym, &old_dynstr, i) {
                existing_sym_idx.entry(name.to_owned()).or_insert(i);
            }
        }

        for ext in &plan.new_externals {
            injects.push((ext.name.clone(), false));
        }
        for gi in &plan.got_imports {
            if !existing_sym_idx.contains_key(&gi.name)
                && !injects.iter().any(|(n, _)| n == &gi.name)
            {
                injects.push((gi.name.clone(), gi.weak));
            }
        }

        if !injects.is_empty() || !plan.add_needed.is_empty() {
            // .dynstr: copy existing bytes (preserves all existing offsets), then
            // append a NUL-terminated name per new symbol, and one per inherited
            // soname. Track the byte offset each name lands at so we can wire
            // st_name and the new DT_NEEDED values correctly.
            pad_to(&mut extended, 8);
            let dynstr_offset_in_seg = extended.len();
            extended.extend_from_slice(&old_dynstr);
            let append_string = |extended: &mut Vec<u8>, s: &str| -> u32 {
                let offset = extended.len() as u32 - dynstr_offset_in_seg as u32;
                extended.extend_from_slice(s.as_bytes());
                extended.push(0);
                offset
            };
            let mut new_name_offsets: Vec<u32> = Vec::with_capacity(injects.len());
            for (name, _) in &injects {
                new_name_offsets.push(append_string(&mut extended, name));
            }
            for soname in &plan.add_needed {
                let offset = append_string(&mut extended, soname);
                info.needed_name_offsets.push(offset);
            }
            let dynstr_size = extended.len() - dynstr_offset_in_seg;

            // .dynsym: copy existing entries (preserves all existing indices), then
            // append one undefined function entry per new symbol.
            pad_to(&mut extended, 8);
            let dynsym_offset_in_seg = extended.len();
            extended.extend_from_slice(&old_dynsym);
            for (name_off, (_, weak)) in new_name_offsets.iter().zip(&injects) {
                let mut sym = [0u8; SYM_ENTRY_SIZE];
                sym[0..4].copy_from_slice(&name_off.to_le_bytes()); // st_name
                sym[4] = if *weak {
                    ST_INFO_WEAK_FUNC
                } else {
                    ST_INFO_GLOBAL_FUNC
                }; // st_info
                sym[5] = 0; // st_other = STV_DEFAULT
                sym[6..8].copy_from_slice(&0u16.to_le_bytes()); // st_shndx = SHN_UNDEF
                // st_value (8 bytes) and st_size (8 bytes) stay zero
                extended.extend_from_slice(&sym);
            }

            // .gnu.version: copy existing u16-per-symbol array, then append one
            // VER_NDX_GLOBAL entry per new symbol. This array must stay parallel
            // to .dynsym, so its length tracks the new symbol count.
            pad_to(&mut extended, 2);
            let versym_offset_in_seg = extended.len();
            extended.extend_from_slice(&old_versym);
            for _ in &injects {
                extended.extend_from_slice(&VER_NDX_GLOBAL.to_le_bytes());
            }

            let dynsym_size = old_dynsym.len() + injects.len() * SYM_ENTRY_SIZE;
            let versym_size = old_versym.len() + injects.len() * 2;

            info.dyn_updates.extend([
                (DT_STRTAB, plan.load_address + dynstr_offset_in_seg as u64),
                (DT_STRSZ, dynstr_size as u64),
                (DT_SYMTAB, plan.load_address + dynsym_offset_in_seg as u64),
                (DT_VERSYM, plan.load_address + versym_offset_in_seg as u64),
            ]);
            info.rebuilt_sections.extend([
                (
                    ".dynstr",
                    plan.load_address + dynstr_offset_in_seg as u64,
                    dynstr_size as u64,
                ),
                (
                    ".dynsym",
                    plan.load_address + dynsym_offset_in_seg as u64,
                    dynsym_size as u64,
                ),
                (
                    ".gnu.version",
                    plan.load_address + versym_offset_in_seg as u64,
                    versym_size as u64,
                ),
            ]);
        }
    }

    // Final symbol index for `name`, whether pre-existing or injected.
    let sym_index_of = |name: &str| -> Option<usize> {
        existing_sym_idx.get(name).copied().or_else(|| {
            injects
                .iter()
                .position(|(n, _)| n == name)
                .map(|i| new_sym_idx_base + i)
        })
    };

    // ---- 2. Rebuild .rela.dyn (always when there's anything new to write).

    let need_new_rela = !plan.relative_relocs.is_empty()
        || !plan.new_externals.is_empty()
        || !plan.got_imports.is_empty();
    if need_new_rela {
        let (existing_relative, existing_non_relative, old_relacount) =
            read_existing_rela_dyn(patched_exe, exe, dynamic)?;

        // New RELATIVE entries for PIE (trampolines, GOT patches, init/fini).
        let mut new_relative = Vec::with_capacity(plan.relative_relocs.len() * RELA_ENTRY_SIZE);
        for reloc in &plan.relative_relocs {
            let mut entry = [0u8; RELA_ENTRY_SIZE];
            entry[0..8].copy_from_slice(&reloc.vaddr.to_le_bytes());
            entry[8..16].copy_from_slice(&(R_X86_64_RELATIVE as u64).to_le_bytes());
            entry[16..24].copy_from_slice(&reloc.addend.to_le_bytes());
            new_relative.extend_from_slice(&entry);
        }

        // New GLOB_DAT entries: one per freshly injected external's GOT slot,
        // plus one per copied GOT slot that ld.so must re-resolve. r_info packs
        // the symbol index and the relocation type.
        let glob_dat_slots = plan
            .new_externals
            .iter()
            .map(|ext| (ext.got_vaddr, ext.name.as_str()))
            .chain(
                plan.got_imports
                    .iter()
                    .map(|gi| (gi.got_vaddr, gi.name.as_str())),
            );
        let mut new_glob_dat = Vec::new();
        for (got_vaddr, name) in glob_dat_slots {
            let sym_idx = sym_index_of(name)
                .with_context(|| format!("no .dynsym index for GLOB_DAT symbol '{name}'"))?;
            let r_info: u64 = ((sym_idx as u64) << 32) | (R_X86_64_GLOB_DAT as u64);
            let mut entry = [0u8; RELA_ENTRY_SIZE];
            entry[0..8].copy_from_slice(&got_vaddr.to_le_bytes());
            entry[8..16].copy_from_slice(&r_info.to_le_bytes());
            // r_addend stays zero
            new_glob_dat.extend_from_slice(&entry);
        }

        pad_to(&mut extended, 8);
        let rela_offset_in_seg = extended.len();
        extended.extend_from_slice(&existing_relative);
        extended.extend_from_slice(&new_relative);
        extended.extend_from_slice(&existing_non_relative);
        extended.extend_from_slice(&new_glob_dat);

        let total_size = existing_relative.len()
            + new_relative.len()
            + existing_non_relative.len()
            + new_glob_dat.len();
        let new_count = old_relacount + (plan.relative_relocs.len() as u64);

        info.dyn_updates.extend([
            (DT_RELA, plan.load_address + rela_offset_in_seg as u64),
            (DT_RELASZ, total_size as u64),
            (DT_RELACOUNT, new_count),
        ]);
        info.rebuilt_sections.push((
            ".rela.dyn",
            plan.load_address + rela_offset_in_seg as u64,
            total_size as u64,
        ));
    }

    Ok((extended, info))
}

/// Read .dynstr, .dynsym, and .gnu.version contents from the patched exe.
/// The DT_STRTAB/DT_SYMTAB/DT_VERSYM VAs are resolved to file offsets via the
/// existing PT_LOAD segments, so this works for both ET_EXEC and PIE.
fn read_dynsym_tables(
    patched_exe: &[u8],
    exe: &object::read::elf::ElfFile64<'_, object::Endianness>,
    dynamic: &DynamicTable,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use goblin::elf::dynamic::{DT_STRSZ, DT_STRTAB, DT_SYMTAB, DT_VERSYM};

    let strtab_va = dynamic
        .value_of(DT_STRTAB)
        .context("executable missing DT_STRTAB")?;
    let strsz = dynamic
        .value_of(DT_STRSZ)
        .context("executable missing DT_STRSZ")? as usize;
    let symtab_va = dynamic
        .value_of(DT_SYMTAB)
        .context("executable missing DT_SYMTAB")?;
    let versym_va = dynamic
        .value_of(DT_VERSYM)
        .context("executable missing DT_VERSYM")?;

    let strtab_off =
        va_to_file_offset(exe, strtab_va).context("DT_STRTAB not in any PT_LOAD")? as usize;

    // The .dynsym and .gnu.version sizes have to come from their section
    // headers — DT_SYMENT only gives the per-entry width, and there is no
    // DT_SYMSZ or DT_VERSYMSZ at all.
    let sections = SectionTable::parse(patched_exe)?.context(
        "executable has no usable section header table, which is the only place the \
                  .dynsym and .gnu.version sizes are recorded",
    )?;
    let size_of = |name: &str| -> Result<usize> {
        Ok(sections
            .by_name(name)
            .with_context(|| format!("{name} section header not found"))?
            .size as usize)
    };
    let dynsym_size = size_of(".dynsym")?;
    let versym_size = size_of(".gnu.version")?;

    let symtab_off =
        va_to_file_offset(exe, symtab_va).context("DT_SYMTAB not in any PT_LOAD")? as usize;
    let versym_off =
        va_to_file_offset(exe, versym_va).context("DT_VERSYM not in any PT_LOAD")? as usize;

    if strtab_off + strsz > patched_exe.len() {
        bail!(".dynstr extends past end of file");
    }
    if symtab_off + dynsym_size > patched_exe.len() {
        bail!(".dynsym extends past end of file");
    }
    if versym_off + versym_size > patched_exe.len() {
        bail!(".gnu.version extends past end of file");
    }

    Ok((
        patched_exe[strtab_off..strtab_off + strsz].to_vec(),
        patched_exe[symtab_off..symtab_off + dynsym_size].to_vec(),
        patched_exe[versym_off..versym_off + versym_size].to_vec(),
    ))
}

/// Slice the existing .rela.dyn into its RELATIVE prefix and everything else,
/// returning the two halves plus the original RELATIVE count.
fn read_existing_rela_dyn(
    patched_exe: &[u8],
    exe: &object::read::elf::ElfFile64<'_, object::Endianness>,
    dynamic: &DynamicTable,
) -> Result<(Vec<u8>, Vec<u8>, u64)> {
    use goblin::elf::dynamic::{DT_RELA, DT_RELACOUNT, DT_RELASZ};

    let rela_va = dynamic
        .value_of(DT_RELA)
        .context("executable missing DT_RELA")?;
    let relasz = dynamic
        .value_of(DT_RELASZ)
        .context("executable missing DT_RELASZ")? as usize;
    let relacount = dynamic.value_of(DT_RELACOUNT).unwrap_or(0);

    let rela_off = va_to_file_offset(exe, rela_va).context("DT_RELA not in any PT_LOAD")? as usize;
    if rela_off + relasz > patched_exe.len() {
        bail!(".rela.dyn extends past end of file");
    }

    let relative_end = rela_off + (relacount as usize) * RELA_ENTRY_SIZE;
    if relative_end > rela_off + relasz {
        bail!(
            "DT_RELACOUNT ({relacount}) implies more bytes than DT_RELASZ ({relasz}) — \
             corrupted .rela.dyn"
        );
    }
    Ok((
        patched_exe[rela_off..relative_end].to_vec(),
        patched_exe[relative_end..rela_off + relasz].to_vec(),
        relacount,
    ))
}

fn pad_to(buf: &mut Vec<u8>, alignment: usize) {
    while !buf.len().is_multiple_of(alignment) {
        buf.push(0);
    }
}

/// Write any updated DT_* d_val fields back into the in-memory .dynamic image.
fn apply_extension_info(out: &mut [u8], dynamic: &DynamicTable, ext: &ExtensionInfo) {
    for &(tag, val) in &ext.dyn_updates {
        if let Some(idx) = dynamic.index_of(tag) {
            write_u64_le(out, dynamic.value_offset(idx), val);
        }
    }
}

/// Rewrite the `.dynamic` entries that the merge changes:
///   * `DT_PREINIT_ARRAY`/`DT_FINI_ARRAY` (and their sizes) to point at the
///     combined init/fini arrays in the merged segment, and
///   * one `DT_NEEDED` per soname inherited from a merged-away library.
///
/// Both kinds of update share a single cursor over the spare `.dynamic` slots,
/// since a tag that the executable does not already have can only be added by
/// pushing the `DT_NULL` terminator down.
fn update_dynamic_entries(
    out: &mut [u8],
    plan: &MergePlan,
    dynamic: &DynamicTable,
    ext: &ExtensionInfo,
) -> Result<()> {
    use goblin::elf::dynamic::{DT_NEEDED, DT_NULL};

    // New entries are appended at the DT_NULL terminator, pushing it down.
    // The last slot must stay DT_NULL so ld.so's scan terminates.
    let mut next_free = dynamic.used();

    let write_dyn_entry = |out: &mut [u8], idx: usize, tag: u64, val: u64| {
        write_u64_le(out, dynamic.entry_offset(idx), tag);
        write_u64_le(out, dynamic.value_offset(idx), val);
    };

    // Update the existing entry for `tag`, or append a new one at the
    // terminator. `force_new` is for DT_NEEDED, which repeats rather than
    // being overwritten.
    let mut set_dyn_entry = |out: &mut [u8], tag: u64, val: u64, force_new: bool| -> Result<()> {
        match dynamic.index_of(tag).filter(|_| !force_new) {
            Some(idx) => write_u64_le(out, dynamic.value_offset(idx), val),
            None if next_free + 1 < dynamic.capacity() => {
                write_dyn_entry(out, next_free, tag, val);
                next_free += 1;
                // Re-terminate (slots after the old terminator may be garbage).
                write_dyn_entry(out, next_free, DT_NULL, 0);
            }
            None => bail!(
                ".dynamic has no spare capacity to append dynamic tag {tag:#x} \
                 ({} slots, {} used)",
                dynamic.capacity(),
                dynamic.used()
            ),
        }
        Ok(())
    };

    // Point each rebuilt array's DT_* pair at the merged copy, creating the
    // pair if the executable did not have one (a binary with no constructors
    // of its own has no DT_PREINIT_ARRAY to update).
    if let Some(init_fini) = &plan.init_fini {
        for (kind, array) in init_fini.arrays() {
            if array.entries.is_empty() {
                continue;
            }
            let (array_tag, size_tag) = kind.dynamic_tags();
            set_dyn_entry(out, array_tag, array.vaddr, false)?;
            set_dyn_entry(out, size_tag, array.size(), false)?;
        }
    }

    // One fresh DT_NEEDED per inherited soname. These always append — an
    // existing entry would mean the executable already linked the library, in
    // which case `inherited_needed` would not have returned it.
    if !plan.add_needed.is_empty() {
        if ext.needed_name_offsets.len() != plan.add_needed.len() {
            bail!(
                "{} sonames to add to DT_NEEDED but {} were written to .dynstr — internal error",
                plan.add_needed.len(),
                ext.needed_name_offsets.len()
            );
        }
        for (soname, &name_offset) in plan.add_needed.iter().zip(&ext.needed_name_offsets) {
            set_dyn_entry(out, DT_NEEDED, name_offset as u64, true).with_context(|| {
                format!("adding DT_NEEDED '{soname}' inherited from a merged library")
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod runtime_write_tests {
    use super::*;
    use crate::types::{GotSlotImport, NewExternalSym};

    const LOAD: u64 = 0x10_0000;
    const EXEC_END: u64 = LOAD + 0x1000;
    const RODATA_END: u64 = LOAD + 0x2000;
    const WRITABLE_END: u64 = LOAD + 0x3000;

    /// An otherwise empty plan whose merged region has all three runs:
    /// read-execute, read-only and read-write, one page each.
    fn plan() -> MergePlan {
        MergePlan {
            is_pie: true,
            load_address: LOAD,
            exec_size: EXEC_END - LOAD,
            rodata_end: RODATA_END - LOAD,
            writable_end: WRITABLE_END - LOAD,
            units: Vec::new(),
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

    #[test]
    fn a_rebased_pointer_in_the_writable_run_is_accepted() {
        let mut plan = plan();
        plan.relative_relocs.push(RelativeReloc {
            vaddr: RODATA_END,
            addend: 0,
        });
        plan.got_imports.push(GotSlotImport {
            got_vaddr: WRITABLE_END - 8,
            name: "memcpy".to_owned(),
            weak: false,
        });
        check_runtime_writes_are_writable(&plan).expect("the writable run is writable");
    }

    #[test]
    fn a_rebased_pointer_in_the_read_only_run_is_rejected() {
        let mut plan = plan();
        plan.relative_relocs.push(RelativeReloc {
            vaddr: RODATA_END - 8,
            addend: 0,
        });
        let err = check_runtime_writes_are_writable(&plan)
            .expect_err("ld.so would fault writing a read-only page");
        assert!(
            format!("{err}").contains("R_X86_64_RELATIVE"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn a_got_slot_among_the_code_is_rejected() {
        let mut plan = plan();
        plan.new_externals.push(NewExternalSym {
            name: "solder_absent_symbol".to_owned(),
            got_vaddr: EXEC_END - 8,
        });
        let err = check_runtime_writes_are_writable(&plan)
            .expect_err("ld.so would fault writing an executable page");
        assert!(
            format!("{err}").contains("solder_absent_symbol"),
            "unhelpful error: {err}"
        );
    }

    /// The patcher records a RELATIVE relocation for every GOT slot it
    /// pre-fills in the executable itself. Those sit below the merged region
    /// entirely, under whatever permissions the executable already had, and are
    /// none of this check's business.
    #[test]
    fn a_rebased_pointer_in_the_executable_itself_is_accepted() {
        let mut plan = plan();
        plan.relative_relocs.push(RelativeReloc {
            vaddr: LOAD - 0x100,
            addend: 0,
        });
        check_runtime_writes_are_writable(&plan).expect("the executable's own GOT is writable");
    }
}

#[cfg(test)]
mod section_header_tests {
    use super::*;
    use crate::elf_reader::MappedElf;
    use crate::layout::plan_layout;
    use crate::types::{
        ExtractedReloc, ExtractedUnit, InitFiniArrays, RelocTarget, SectionKind, UnitId,
    };
    use std::path::{Path, PathBuf};

    const GREP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/grep");

    fn unit(
        id: u32,
        name: &str,
        kind: SectionKind,
        len: usize,
        externals: &[&str],
    ) -> ExtractedUnit {
        ExtractedUnit {
            id: UnitId(id),
            name: name.to_owned(),
            source_lib: PathBuf::from("/nonexistent/libtest.so.1"),
            bytes: vec![0x90; len],
            section_kind: kind,
            alignment: 16,
            relocations: externals
                .iter()
                .enumerate()
                .map(|(i, sym)| ExtractedReloc {
                    offset_within_unit: (i * 8) as u64,
                    kind: object::RelocationKind::Relative,
                    encoding: object::RelocationEncoding::Generic,
                    size: 32,
                    addend: -4,
                    target: RelocTarget::External((*sym).to_owned()),
                })
                .collect(),
        }
    }

    /// Merge a code, a read-only and a data unit into a copy of `test/grep` and
    /// return the plan alongside the bytes that were written.
    ///
    /// `solder_absent_symbol` is not in the executable's `.dynsym`, so the
    /// writer has to rebuild `.dynstr`/`.dynsym`/`.gnu.version` to inject it —
    /// which is what moves those tables out of the sections that described them.
    fn merged_grep() -> (MergePlan, Vec<u8>) {
        let mapped = MappedElf::open(Path::new(GREP)).expect("open test/grep");
        let exe = mapped.parse().expect("parse test/grep");
        let units = vec![
            unit(
                0,
                "fn_a",
                SectionKind::Text,
                64,
                &["memcpy", "solder_absent_symbol"],
            ),
            unit(1, "ro_a", SectionKind::ReadOnlyData, 32, &[]),
            unit(2, "data_a", SectionKind::Data, 48, &[]),
        ];
        let mut plan = plan_layout(
            units,
            &exe,
            &[],
            true,
            InitFiniArrays::default(),
            &[],
            Vec::new(),
        )
        .expect("plan layout");

        let seg = build_merged_segment(&mut plan).expect("build merged segment");
        let out = tempfile::NamedTempFile::new().expect("temp output");
        std::fs::copy(GREP, out.path()).expect("seed the output with the fixture");
        write_output(mapped.bytes(), &plan, &seg, out.path()).expect("write output");
        let bytes = std::fs::read(out.path()).expect("read the merged output back");
        (plan, bytes)
    }

    fn section_table(bytes: &[u8]) -> SectionTable {
        SectionTable::parse(bytes)
            .expect("read the output's section headers")
            .expect("the output has no section headers")
    }

    fn section<'t>(table: &'t SectionTable, name: &str) -> &'t crate::elf_reader::SectionHeader {
        table
            .by_name(name)
            .unwrap_or_else(|| panic!("the merged output has no '{name}' section"))
    }

    /// The tables the loader reads and the sections that claim to describe them
    /// have to be the same bytes. They were not: the merge rebuilt the tables in
    /// the merged region and repointed `DT_*` at them while the section headers
    /// kept describing the pre-merge copies, so every section-header-based tool
    /// reported the executable as it was before the merge.
    #[test]
    fn the_rebuilt_dynamic_tables_and_their_section_headers_agree() {
        use goblin::elf::dynamic::{DT_RELA, DT_RELASZ, DT_STRSZ, DT_STRTAB, DT_SYMTAB, DT_VERSYM};

        let (_, bytes) = merged_grep();
        let table = section_table(&bytes);
        let dynamic = DynamicTable::parse(&bytes).expect("parse .dynamic of the merged output");

        for (tag, name) in [
            (DT_STRTAB, ".dynstr"),
            (DT_SYMTAB, ".dynsym"),
            (DT_VERSYM, ".gnu.version"),
            (DT_RELA, ".rela.dyn"),
        ] {
            let va = dynamic.value_of(tag).expect("dynamic tag");
            let addr = section(&table, name).addr;
            assert_eq!(
                addr, va,
                "'{name}' describes {addr:#x} but the loader reads {va:#x}"
            );
        }

        for (tag, name) in [(DT_STRSZ, ".dynstr"), (DT_RELASZ, ".rela.dyn")] {
            let size = dynamic.value_of(tag).expect("dynamic size tag");
            assert_eq!(
                section(&table, name).size,
                size,
                "'{name}' is the wrong size"
            );
        }

        // `.gnu.version` is one u16 per `.dynsym` entry, and the injected
        // symbols have to be covered by both or ld.so reads a version index
        // from past the end of the array.
        assert_eq!(
            section(&table, ".dynsym").size / SYM_ENTRY_SIZE as u64 * 2,
            section(&table, ".gnu.version").size,
            ".gnu.version is not parallel to .dynsym"
        );
    }

    /// `read_dynsym_tables` has to take the `.dynsym` and `.gnu.version` sizes
    /// from their section headers — `.dynamic` carries no tag for either. So a
    /// second merge over an already-merged executable reads back exactly what
    /// the first one recorded: with stale headers it copied only the symbols the
    /// first merge *started* with, silently dropping the ones it injected while
    /// the `GLOB_DAT` relocations still referred to them by index.
    #[test]
    fn a_second_merge_sees_the_symbols_the_first_one_injected() {
        let (_, bytes) = merged_grep();
        let exe = object::read::elf::ElfFile64::<object::Endianness>::parse(&*bytes)
            .expect("parse the merged output");
        let dynamic = DynamicTable::parse(&bytes).expect("parse .dynamic of the merged output");

        let (dynstr, dynsym, versym) =
            read_dynsym_tables(&bytes, &exe, &dynamic).expect("re-read the merged symbol tables");

        let count = dynsym.len() / SYM_ENTRY_SIZE;
        assert_eq!(versym.len(), count * 2, ".gnu.version is short of .dynsym");

        let names: Vec<&str> = (0..count)
            .filter_map(|i| symbol_name(&dynsym, &dynstr, i))
            .collect();
        assert!(
            names.contains(&"solder_absent_symbol"),
            "the injected symbol is missing from the re-read .dynsym ({count} symbols)"
        );
    }

    /// Tools that rebuild a file from its sections (`strip`, `objcopy`) drop
    /// anything no section claims, which was all of the merged code and data.
    #[test]
    fn each_mapping_of_the_merged_region_has_a_section() {
        let (plan, bytes) = merged_grep();
        let table = section_table(&bytes);

        for (name, start, end) in [
            (".solder.text", 0, plan.exec_size),
            (".solder.rodata", plan.exec_size, plan.rodata_end),
            (".solder.data", plan.rodata_end, plan.writable_end),
        ] {
            let header = section(&table, name);
            assert_eq!(
                header.addr,
                plan.load_address + start,
                "'{name}' is misplaced"
            );
            assert_eq!(header.size, end - start, "'{name}' is the wrong size");
        }
    }

    /// The merge rebuilds the program header table inside the merged region, so
    /// `PT_PHDR` takes on that region's `p_vaddr - p_offset`. A linker only ever
    /// puts that table in the first `PT_LOAD`, and `patchelf` relies on it:
    /// rewriting the table, it moves it to file offset `sizeof(Elf64_Ehdr)` and
    /// claims `(PT_PHDR.p_vaddr - PT_PHDR.p_offset) + sizeof(Elf64_Ehdr)` as its
    /// address. With the merged region at the end of the memory image but its
    /// bytes at the end of the file, those differed by the size of the
    /// executable's `.bss` — so `patchelf --set-rpath` over a merged binary
    /// produced a `PT_PHDR` that much too high, and glibc, which takes the main
    /// map's load address to be `AT_PHDR - PT_PHDR.p_vaddr`, relocated the whole
    /// executable by the error and crashed before `main`.
    #[test]
    fn the_rebuilt_program_header_table_keeps_the_executables_address_to_offset_difference() {
        use object::read::elf::ProgramHeader;

        let (plan, bytes) = merged_grep();
        let out = object::read::elf::ElfFile64::<object::Endianness>::parse(&*bytes)
            .expect("parse the merged output");
        let endian = out.endian();

        // The input and the output agree on it: the merge appends mappings
        // rather than touching the one that starts the image.
        let expected = crate::elf_reader::image_base_delta(&out);
        let mapped = MappedElf::open(Path::new(GREP)).expect("open test/grep");
        assert_eq!(
            expected,
            crate::elf_reader::image_base_delta(&mapped.parse().expect("parse test/grep")),
            "the merge moved the mapping that starts the image"
        );

        let phdr = out
            .elf_program_headers()
            .iter()
            .find(|seg| seg.p_type(endian) == object::elf::PT_PHDR)
            .expect("the merged output has no PT_PHDR");
        assert_eq!(
            phdr.p_vaddr(endian) - phdr.p_offset(endian),
            expected,
            "PT_PHDR at {:#x} maps file offset {:#x}",
            phdr.p_vaddr(endian),
            phdr.p_offset(endian)
        );

        // PT_PHDR inherits it from the merged region, so the region's own
        // mappings carry it too — including the executable one, which is where
        // `load_address` is.
        for seg in out.elf_program_headers() {
            let vaddr = seg.p_vaddr(endian);
            if seg.p_type(endian) != object::elf::PT_LOAD || vaddr < plan.load_address {
                continue;
            }
            assert_eq!(
                vaddr - seg.p_offset(endian),
                expected,
                "a merged mapping at {vaddr:#x} maps file offset {:#x}",
                seg.p_offset(endian)
            );
        }
    }

    /// Repointing a section header is only an improvement if the range it names
    /// is actually in the file — including `.shstrtab` and the section header
    /// table itself, which the merge moves to the end.
    #[test]
    fn every_section_stays_inside_the_file() {
        let (_, bytes) = merged_grep();
        for header in section_table(&bytes).sections {
            // `.bss` is SHT_NOBITS: it occupies no file bytes, and its
            // sh_offset is only a hint at where it would have started.
            if header.name == ".bss" {
                continue;
            }
            let end = header.offset + header.size;
            assert!(
                end <= bytes.len() as u64,
                "'{}' runs to {end:#x}, past the {:#x}-byte file",
                header.name,
                bytes.len()
            );
        }
    }
}
