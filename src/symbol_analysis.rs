use std::path::PathBuf;

use anyhow::{Context, Result};
use object::read::elf::ElfFile64;
use object::{Object, ObjectSection};

use crate::elf_reader::va_to_file_offset;
use crate::lib_discovery::{is_excluded, resolve_library, LdsoCache};
use crate::types::{ImportKind, ImportedSymbol};

/// Parse the dynamic section of an ELF to extract DT_NEEDED, DT_RPATH, and DT_RUNPATH.
pub struct DynamicInfo {
    pub needed: Vec<String>,
    pub rpath: Vec<PathBuf>,
    pub runpath: Vec<PathBuf>,
}

pub fn parse_dynamic(elf: &ElfFile64<'_>) -> Result<DynamicInfo> {
    use goblin::elf::dynamic::{DT_NEEDED, DT_RPATH, DT_RUNPATH};

    let bytes = elf.data();
    let goblin_elf = goblin::elf::Elf::parse(bytes).context("goblin parse for dynamic section")?;

    let mut needed = Vec::new();
    let mut rpath = Vec::new();
    let mut runpath = Vec::new();

    if let Some(dynamic) = &goblin_elf.dynamic {
        for entry in &dynamic.dyns {
            let tag = entry.d_tag as u64;
            if tag == DT_NEEDED {
                if let Some(s) = goblin_elf.dynstrtab.get_at(entry.d_val as usize) {
                    needed.push(s.to_owned());
                }
            } else if tag == DT_RPATH {
                if let Some(s) = goblin_elf.dynstrtab.get_at(entry.d_val as usize) {
                    rpath.extend(s.split(':').filter(|p| !p.is_empty()).map(PathBuf::from));
                }
            } else if tag == DT_RUNPATH {
                if let Some(s) = goblin_elf.dynstrtab.get_at(entry.d_val as usize) {
                    runpath.extend(s.split(':').filter(|p| !p.is_empty()).map(PathBuf::from));
                }
            }
        }
    }

    Ok(DynamicInfo {
        needed,
        rpath,
        runpath,
    })
}

/// Collect all symbols the executable imports from shared libraries, resolving
/// each to an absolute library path and a GOT file offset.
pub fn collect_imports(
    elf: &ElfFile64<'_>,
    dyn_info: &DynamicInfo,
    ldso_cache: &LdsoCache,
    extra_lib_paths: &[PathBuf],
    merge_filter: Option<&[String]>,
) -> Result<Vec<ImportedSymbol>> {
    let bytes = elf.data();

    // Build a map from symbol name → source library path.
    // For each DT_NEEDED entry (in order), find the library, parse its .dynsym,
    // and record which symbols it exports.  The first library providing a symbol wins.
    let mut sym_to_lib: std::collections::HashMap<String, PathBuf> =
        std::collections::HashMap::new();

    let mut search_rpath = dyn_info.rpath.clone();
    search_rpath.extend_from_slice(extra_lib_paths);
    let search_runpath = dyn_info.runpath.as_slice();

    for needed in &dyn_info.needed {
        if is_excluded(needed) {
            continue;
        }
        if let Some(filter) = merge_filter {
            if !filter
                .iter()
                .any(|f| f == needed || needed.starts_with(f.as_str()))
            {
                continue;
            }
        }

        let lib_path = resolve_library(needed, &search_rpath, search_runpath, ldso_cache)
            .with_context(|| format!("resolving DT_NEEDED '{needed}'"))?;

        let lib_bytes =
            std::fs::read(&lib_path).with_context(|| format!("reading {}", lib_path.display()))?;
        let lib_goblin = goblin::elf::Elf::parse(&lib_bytes)
            .with_context(|| format!("parsing {}", lib_path.display()))?;

        for sym in lib_goblin.dynsyms.iter() {
            if sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize && sym.st_shndx != 0
            {
                if let Some(name) = lib_goblin.dynstrtab.get_at(sym.st_name) {
                    sym_to_lib
                        .entry(name.to_owned())
                        .or_insert_with(|| lib_path.clone());
                }
            }
        }
    }

    // Now walk .rela.plt (JUMP_SLOT) and .rela.dyn (GLOB_DAT) to find GOT offsets.
    let goblin_exe = goblin::elf::Elf::parse(bytes).context("goblin parse of executable")?;

    // Build a name→index map for .dynsym so we can look up each relocation's symbol name.
    let mut dynidx_to_name: std::collections::HashMap<usize, String> =
        std::collections::HashMap::new();
    for (i, sym) in goblin_exe.dynsyms.iter().enumerate() {
        if let Some(name) = goblin_exe.dynstrtab.get_at(sym.st_name) {
            dynidx_to_name.insert(i, name.to_owned());
        }
    }

    let mut imports: Vec<ImportedSymbol> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Helper: get the file offset of a GOT slot from its virtual address.
    let got_file_offset = |va: u64| -> Result<u64> {
        va_to_file_offset(elf, va)
            .with_context(|| format!("GOT VA 0x{va:x} not in any PT_LOAD segment"))
    };

    // Process .rela.plt → JUMP_SLOT
    for rela in &goblin_exe.pltrelocs {
        let sym_idx = rela.r_sym;
        let sym_name = match dynidx_to_name.get(&sym_idx) {
            Some(n) => n.clone(),
            None => continue,
        };
        if seen.contains(&sym_name) {
            continue;
        }
        let source_library = match sym_to_lib.get(&sym_name) {
            Some(p) => p.clone(),
            None => continue, // external (glibc) symbol — not importing from a mergeable lib
        };
        let gfo = got_file_offset(rela.r_offset)?;
        imports.push(ImportedSymbol {
            name: sym_name.clone(),
            source_library,
            got_file_offset: gfo,
            kind: ImportKind::JumpSlot,
        });
        seen.insert(sym_name);
    }

    // Process .rela.dyn → GLOB_DAT
    for rela in &goblin_exe.dynrelas {
        use goblin::elf64::reloc::R_X86_64_GLOB_DAT;
        if rela.r_type != R_X86_64_GLOB_DAT {
            continue;
        }
        let sym_idx = rela.r_sym;
        let sym_name = match dynidx_to_name.get(&sym_idx) {
            Some(n) => n.clone(),
            None => continue,
        };
        if seen.contains(&sym_name) {
            continue;
        }
        let source_library = match sym_to_lib.get(&sym_name) {
            Some(p) => p.clone(),
            None => continue,
        };
        let gfo = got_file_offset(rela.r_offset)?;
        imports.push(ImportedSymbol {
            name: sym_name.clone(),
            source_library,
            got_file_offset: gfo,
            kind: ImportKind::GlobDat,
        });
        seen.insert(sym_name);
    }

    Ok(imports)
}

/// For a given set of imported symbols, find the file offsets of their JUMP_SLOT
/// relocation entries (so we can zero them out later to prevent ld.so from
/// overwriting our pre-patched GOT entries).
pub fn find_jump_slot_reloc_offsets(
    elf: &ElfFile64<'_>,
    imported_names: &std::collections::HashSet<String>,
) -> Result<Vec<u64>> {
    let bytes = elf.data();
    let goblin_exe = goblin::elf::Elf::parse(bytes).context("goblin parse")?;

    let mut offsets = Vec::new();

    // Find the .rela.plt section to get its file offset.
    // Each Rela64 entry is 24 bytes: r_offset(8) + r_info(8) + r_addend(8)
    // We need the file offset of the r_info field (offset +8) and r_addend (offset+16)
    // to zero them out.
    //
    // goblin gives us the VAs of relocations; we need file offsets.
    // Find the .rela.plt section by name.
    for section in elf.sections() {
        if section.name() != Ok(".rela.plt") {
            continue;
        }
        let sh_offset = section.file_range().map(|(off, _)| off).unwrap_or(0);

        // Parse entries manually: each is 24 bytes
        let data = section.data().context(".rela.plt data")?;
        let n = data.len() / 24;

        let dynidx_to_name: std::collections::HashMap<usize, String> = goblin_exe
            .dynsyms
            .iter()
            .enumerate()
            .filter_map(|(i, sym)| {
                goblin_exe
                    .dynstrtab
                    .get_at(sym.st_name)
                    .map(|n| (i, n.to_owned()))
            })
            .collect();

        for i in 0..n {
            let entry = &data[i * 24..(i + 1) * 24];
            let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            // r_info encodes: sym_index (upper 32 bits) | reloc_type (lower 32 bits)
            let sym_idx = (r_info >> 32) as usize;
            let name = match dynidx_to_name.get(&sym_idx) {
                Some(n) => n,
                None => continue,
            };
            if imported_names.contains(name) {
                // File offset of this entry's r_info (to zero r_info + r_addend)
                offsets.push(sh_offset + (i as u64) * 24 + 8);
            }
        }
        break;
    }

    Ok(offsets)
}
