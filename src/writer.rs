use anyhow::{Context, Result, bail};

use crate::elf_reader::va_to_file_offset;
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

    // Write preinit/fini arrays if present
    if let Some(ref init_fini) = plan.init_fini {
        // Write preinit array entries
        if !init_fini.preinit_entries.is_empty() {
            let base_off = (init_fini.preinit_vaddr - plan.load_address) as usize;
            for (i, &func_va) in init_fini.preinit_entries.iter().enumerate() {
                let off = base_off + i * 8;
                if off + 8 > seg.len() {
                    bail!("preinit array entry {} overflows segment", i);
                }
                seg[off..off + 8].copy_from_slice(&func_va.to_le_bytes());

                // For PIE: each function pointer needs an R_X86_64_RELATIVE relocation
                if plan.is_pie {
                    plan.relative_relocs.push(RelativeReloc {
                        vaddr: init_fini.preinit_vaddr + (i * 8) as u64,
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

    // Build the extended merged segment: original segment + any sections we
    // need to grow (.dynstr/.dynsym/.gnu.version when injecting new external
    // symbols; .rela.dyn whenever PIE relocs or new GLOB_DATs are added).
    let needs_rela_extension = plan.is_pie && !plan.relative_relocs.is_empty();
    let needs_symbol_extension = !plan.new_externals.is_empty() || !plan.got_imports.is_empty();
    let (extended_seg, ext_info) = if needs_rela_extension || needs_symbol_extension {
        build_extended_segment(patched_exe, merged_seg, plan, &dynamic_info, &exe)?
    } else {
        (merged_seg.to_vec(), ExtensionInfo::default())
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
            write_u64_le(&mut out, dst + 8, pht_file_offset); // p_offset
            write_u64_le(&mut out, dst + 16, pht_vaddr); // p_vaddr
            write_u64_le(&mut out, dst + 24, pht_vaddr); // p_paddr
            write_u64_le(&mut out, dst + 32, pht_size); // p_filesz
            write_u64_le(&mut out, dst + 40, pht_size); // p_memsz
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
    write_u64_le(&mut out, dst + 32, total_seg_size); // p_filesz includes PHT
    write_u64_le(&mut out, dst + 40, total_seg_size); // p_memsz includes PHT
    write_u64_le(&mut out, dst + 48, 0x1000); // p_align = 4 KiB

    // Update ELF header: e_phoff and e_phnum.
    write_u64_le(&mut out, 32, pht_file_offset);
    write_u16_le(&mut out, 56, new_phnum as u16);

    // Update .dynamic entries for any sections we relocated into the merged
    // segment. Each update writes only the d_val field (offset +8 from the
    // entry start); d_tag is untouched.
    apply_extension_info(&mut out, &dynamic_info, &ext_info)?;

    // Update DT_PREINIT_ARRAY and DT_FINI_ARRAY to point to our arrays
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
    dt_preinit_array_idx: Option<usize>,
    dt_preinit_arraysz_idx: Option<usize>,
    dt_fini_array_idx: Option<usize>,
    dt_fini_arraysz_idx: Option<usize>,
    dt_strtab_idx: Option<usize>,
    dt_strtab_val: Option<u64>,
    dt_strsz_idx: Option<usize>,
    dt_strsz_val: Option<u64>,
    dt_symtab_idx: Option<usize>,
    dt_symtab_val: Option<u64>,
    dt_versym_idx: Option<usize>,
    dt_versym_val: Option<u64>,
    /// Number of entries before the DT_NULL terminator.
    used_entries: usize,
    /// Total 16-byte slots in the .dynamic section.
    capacity: usize,
}

/// Summary of which sections were rebuilt in the merged segment and the new
/// VAs / sizes that need to land in .dynamic.
#[derive(Debug, Default)]
struct ExtensionInfo {
    rela_va: Option<u64>,
    rela_size: Option<u64>,
    rela_count: Option<u64>,
    strtab_va: Option<u64>,
    strtab_size: Option<u64>,
    symtab_va: Option<u64>,
    versym_va: Option<u64>,
}

/// Parse .dynamic section info from an unmodified ELF.
fn parse_dynamic_info(bytes: &[u8]) -> Result<DynamicInfo> {
    let goblin_elf = goblin::elf::Elf::parse(bytes).context("goblin parse for .dynamic info")?;

    let mut info = DynamicInfo::default();

    // Find .dynamic section offset and size
    let mut section_size: u64 = 0;
    for sh in &goblin_elf.section_headers {
        if goblin_elf.shdr_strtab.get_at(sh.sh_name) == Some(".dynamic") {
            info.section_offset = sh.sh_offset;
            section_size = sh.sh_size;
            break;
        }
    }

    if info.section_offset == 0 {
        // Try to find via PT_DYNAMIC program header
        for ph in &goblin_elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_DYNAMIC {
                info.section_offset = ph.p_offset;
                section_size = ph.p_filesz;
                break;
            }
        }
    }

    if info.section_offset == 0 {
        bail!(".dynamic section not found");
    }

    // How many 16-byte slots the section holds, and how many precede the
    // DT_NULL terminator. New entries are appended at the terminator (pushing
    // it down into spare capacity) — slots after the terminator are invisible
    // to ld.so, so they can't be written directly.
    info.capacity = (section_size / DYN_ENTRY_SIZE as u64) as usize;
    info.used_entries = info.capacity; // assume full unless a terminator is found
    for i in 0..info.capacity {
        let off = info.section_offset as usize + i * DYN_ENTRY_SIZE;
        if off + DYN_ENTRY_SIZE <= bytes.len()
            && u64::from_le_bytes(bytes[off..off + 8].try_into().expect("8 bytes")) == 0
        {
            info.used_entries = i;
            break;
        }
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
                goblin::elf::dynamic::DT_PREINIT_ARRAY => {
                    info.dt_preinit_array_idx = Some(i);
                }
                goblin::elf::dynamic::DT_PREINIT_ARRAYSZ => {
                    info.dt_preinit_arraysz_idx = Some(i);
                }
                goblin::elf::dynamic::DT_FINI_ARRAY => {
                    info.dt_fini_array_idx = Some(i);
                }
                goblin::elf::dynamic::DT_FINI_ARRAYSZ => {
                    info.dt_fini_arraysz_idx = Some(i);
                }
                goblin::elf::dynamic::DT_STRTAB => {
                    info.dt_strtab_idx = Some(i);
                    info.dt_strtab_val = Some(entry.d_val);
                }
                goblin::elf::dynamic::DT_STRSZ => {
                    info.dt_strsz_idx = Some(i);
                    info.dt_strsz_val = Some(entry.d_val);
                }
                goblin::elf::dynamic::DT_SYMTAB => {
                    info.dt_symtab_idx = Some(i);
                    info.dt_symtab_val = Some(entry.d_val);
                }
                0x6ffffff0u64 => {
                    // DT_VERSYM
                    info.dt_versym_idx = Some(i);
                    info.dt_versym_val = Some(entry.d_val);
                }
                _ => {}
            }
        }
    }

    Ok(info)
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
    dyn_info: &DynamicInfo,
    exe: &object::read::elf::ElfFile64<'_, object::Endianness>,
) -> Result<(Vec<u8>, ExtensionInfo)> {
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

    if !plan.new_externals.is_empty() || !plan.got_imports.is_empty() {
        let (old_dynstr, old_dynsym, old_versym) = read_dynsym_tables(patched_exe, exe, dyn_info)?;
        let old_num_syms = old_dynsym.len() / SYM_ENTRY_SIZE;
        new_sym_idx_base = old_num_syms;

        for i in 0..old_num_syms {
            let st_name =
                u32::from_le_bytes(old_dynsym[i * SYM_ENTRY_SIZE..i * SYM_ENTRY_SIZE + 4].try_into()?)
                    as usize;
            if st_name < old_dynstr.len()
                && let Some(end) = old_dynstr[st_name..].iter().position(|&b| b == 0)
                && end > 0
                && let Ok(name) = std::str::from_utf8(&old_dynstr[st_name..st_name + end])
            {
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

        if !injects.is_empty() {
            // .dynstr: copy existing bytes (preserves all existing offsets), then
            // append a NUL-terminated name per new symbol. Track the byte offset
            // each name lands at so we can wire st_name correctly.
            pad_to(&mut extended, 8);
            let dynstr_offset_in_seg = extended.len();
            extended.extend_from_slice(&old_dynstr);
            let mut new_name_offsets: Vec<u32> = Vec::with_capacity(injects.len());
            for (name, _) in &injects {
                new_name_offsets.push(extended.len() as u32 - dynstr_offset_in_seg as u32);
                extended.extend_from_slice(name.as_bytes());
                extended.push(0);
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

            info.strtab_va = Some(plan.load_address + dynstr_offset_in_seg as u64);
            info.strtab_size = Some(dynstr_size as u64);
            info.symtab_va = Some(plan.load_address + dynsym_offset_in_seg as u64);
            info.versym_va = Some(plan.load_address + versym_offset_in_seg as u64);
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
            read_existing_rela_dyn(patched_exe, exe, dyn_info)?;

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

        info.rela_va = Some(plan.load_address + rela_offset_in_seg as u64);
        info.rela_size = Some(total_size as u64);
        info.rela_count = Some(new_count);
    }

    Ok((extended, info))
}

/// Read .dynstr, .dynsym, and .gnu.version contents from the patched exe.
/// The DT_STRTAB/DT_SYMTAB/DT_VERSYM VAs are resolved to file offsets via the
/// existing PT_LOAD segments, so this works for both ET_EXEC and PIE.
fn read_dynsym_tables(
    patched_exe: &[u8],
    exe: &object::read::elf::ElfFile64<'_, object::Endianness>,
    dyn_info: &DynamicInfo,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let strtab_va = dyn_info
        .dt_strtab_val
        .context("executable missing DT_STRTAB")?;
    let strsz = dyn_info
        .dt_strsz_val
        .context("executable missing DT_STRSZ")? as usize;
    let symtab_va = dyn_info
        .dt_symtab_val
        .context("executable missing DT_SYMTAB")?;
    let versym_va = dyn_info
        .dt_versym_val
        .context("executable missing DT_VERSYM")?;

    let strtab_off = va_to_file_offset(exe, strtab_va).context("DT_STRTAB not in any PT_LOAD")?
        as usize;

    // .dynsym size has to come from the section header — DT_SYMENT only gives
    // the per-entry width, and there is no DT_SYMSZ.
    let goblin_elf =
        goblin::elf::Elf::parse(patched_exe).context("goblin parse for dynsym/versym sizes")?;
    let mut dynsym_size: Option<usize> = None;
    let mut versym_size: Option<usize> = None;
    for sh in &goblin_elf.section_headers {
        match goblin_elf.shdr_strtab.get_at(sh.sh_name) {
            Some(".dynsym") => dynsym_size = Some(sh.sh_size as usize),
            Some(".gnu.version") => versym_size = Some(sh.sh_size as usize),
            _ => {}
        }
    }
    let dynsym_size = dynsym_size.context(".dynsym section header not found")?;
    let versym_size = versym_size.context(".gnu.version section header not found")?;

    let symtab_off = va_to_file_offset(exe, symtab_va).context("DT_SYMTAB not in any PT_LOAD")?
        as usize;
    let versym_off = va_to_file_offset(exe, versym_va).context("DT_VERSYM not in any PT_LOAD")?
        as usize;

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
    dyn_info: &DynamicInfo,
) -> Result<(Vec<u8>, Vec<u8>, u64)> {
    let rela_va = dyn_info
        .dt_rela_val
        .context("executable missing DT_RELA")?;
    let relasz = dyn_info
        .dt_relasz_val
        .context("executable missing DT_RELASZ")? as usize;
    let relacount = dyn_info.dt_relacount_val.unwrap_or(0);

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
fn apply_extension_info(
    out: &mut [u8],
    dyn_info: &DynamicInfo,
    ext: &ExtensionInfo,
) -> Result<()> {
    let dyn_section_offset = dyn_info.section_offset as usize;
    let write_val = |out: &mut [u8], idx: usize, val: u64| {
        let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
        write_u64_le(out, entry_offset + 8, val);
    };

    if let Some(va) = ext.rela_va
        && let Some(idx) = dyn_info.dt_rela_idx
    {
        write_val(out, idx, va);
    }
    if let Some(sz) = ext.rela_size
        && let Some(idx) = dyn_info.dt_relasz_idx
    {
        write_val(out, idx, sz);
    }
    if let Some(c) = ext.rela_count
        && let Some(idx) = dyn_info.dt_relacount_idx
    {
        write_val(out, idx, c);
    }
    if let Some(va) = ext.strtab_va
        && let Some(idx) = dyn_info.dt_strtab_idx
    {
        write_val(out, idx, va);
    }
    if let Some(sz) = ext.strtab_size
        && let Some(idx) = dyn_info.dt_strsz_idx
    {
        write_val(out, idx, sz);
    }
    if let Some(va) = ext.symtab_va
        && let Some(idx) = dyn_info.dt_symtab_idx
    {
        write_val(out, idx, va);
    }
    if let Some(va) = ext.versym_va
        && let Some(idx) = dyn_info.dt_versym_idx
    {
        write_val(out, idx, va);
    }

    Ok(())
}

/// Update DT_PREINIT_ARRAY/DT_PREINIT_ARRAYSZ and DT_FINI_ARRAY/DT_FINI_ARRAYSZ in .dynamic
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

    // New entries are appended at the DT_NULL terminator, pushing it down.
    // The last slot must stay DT_NULL so ld.so's scan terminates.
    let mut next_free = dyn_info.used_entries;

    // Helper to write a dynamic entry
    let write_dyn_entry = |out: &mut [u8], idx: usize, tag: u64, val: u64| {
        let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
        write_u64_le(out, entry_offset, tag);
        write_u64_le(out, entry_offset + 8, val);
    };

    // Update the existing entry for `tag`, or append a new one at the terminator.
    let mut set_dyn_entry =
        |out: &mut [u8], existing_idx: Option<usize>, tag: u64, val: u64| -> Result<()> {
            if let Some(idx) = existing_idx {
                let entry_offset = dyn_section_offset + idx * DYN_ENTRY_SIZE;
                write_u64_le(out, entry_offset + 8, val);
            } else if next_free + 1 < dyn_info.capacity {
                write_dyn_entry(out, next_free, tag, val);
                next_free += 1;
                // Re-terminate (slots after the old terminator may be garbage).
                write_dyn_entry(out, next_free, 0, 0);
            } else {
                bail!(
                    ".dynamic has no spare capacity to append dynamic tag {tag:#x} \
                     ({} slots, {} used)",
                    dyn_info.capacity,
                    dyn_info.used_entries
                );
            }
            Ok(())
        };

    // Update or create DT_PREINIT_ARRAY entries for merged constructors
    if !init_fini.preinit_entries.is_empty() {
        let preinit_array_size = (init_fini.preinit_entries.len() * 8) as u64;
        set_dyn_entry(
            out,
            dyn_info.dt_preinit_array_idx,
            goblin::elf::dynamic::DT_PREINIT_ARRAY,
            init_fini.preinit_vaddr,
        )?;
        set_dyn_entry(
            out,
            dyn_info.dt_preinit_arraysz_idx,
            goblin::elf::dynamic::DT_PREINIT_ARRAYSZ,
            preinit_array_size,
        )?;
    }

    // Update or create DT_FINI_ARRAY entries
    if !init_fini.combined_fini_entries.is_empty() {
        let fini_array_size = (init_fini.combined_fini_entries.len() * 8) as u64;
        set_dyn_entry(
            out,
            dyn_info.dt_fini_array_idx,
            goblin::elf::dynamic::DT_FINI_ARRAY,
            init_fini.combined_fini_vaddr,
        )?;
        set_dyn_entry(
            out,
            dyn_info.dt_fini_arraysz_idx,
            goblin::elf::dynamic::DT_FINI_ARRAYSZ,
            fini_array_size,
        )?;
    }

    Ok(())
}
