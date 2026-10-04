use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use object::read::elf::ElfFile64;
use object::{Object, ObjectSection};
use tracing::{debug, warn};

use crate::elf_reader::va_to_file_offset;
use crate::lib_discovery::{LdsoCache, is_excluded, resolve_library};
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
            let tag = entry.d_tag;
            if tag == DT_NEEDED {
                if let Some(s) = goblin_elf.dynstrtab.get_at(entry.d_val as usize) {
                    needed.push(s.to_owned());
                }
            } else if tag == DT_RPATH {
                if let Some(s) = goblin_elf.dynstrtab.get_at(entry.d_val as usize) {
                    rpath.extend(s.split(':').filter(|p| !p.is_empty()).map(PathBuf::from));
                }
            } else if tag == DT_RUNPATH
                && let Some(s) = goblin_elf.dynstrtab.get_at(entry.d_val as usize)
            {
                runpath.extend(s.split(':').filter(|p| !p.is_empty()).map(PathBuf::from));
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
/// Result of `collect_imports`: the symbols the executable imports, plus a
/// map of every symbol exported by any mergeable library (used by the
/// extractor to resolve cross-library PLT calls).
pub struct ImportInfo {
    pub imports: Vec<ImportedSymbol>,
    pub merged_lib_syms: std::collections::HashMap<String, PathBuf>,
}

/// Whether a `-m` filter entry selects the given DT_NEEDED soname. A filter
/// entry may be the full soname (`libz.so.1`) or a prefix of it (`libz.so`,
/// `libz`), so that callers don't have to know the exact version suffix.
fn filter_selects(filter_entry: &str, needed: &str) -> bool {
    needed == filter_entry || needed.starts_with(filter_entry)
}

/// Reject `-m` entries that cannot possibly take effect.
///
/// Without this, a mistyped soname (or one the executable doesn't actually link
/// against) is silently dropped: solder reports success having merged nothing,
/// or — worse, when several `-m` flags are given — having merged only the
/// subset that happened to match.
fn validate_merge_filter(needed: &[String], filter: &[String]) -> Result<()> {
    for entry in filter {
        let matched: Vec<&str> = needed
            .iter()
            .filter(|n| filter_selects(entry, n))
            .map(|n| n.as_str())
            .collect();

        if matched.is_empty() {
            anyhow::bail!(
                "no DT_NEEDED entry matches '{entry}'; this executable needs: {}",
                needed.join(", ")
            );
        }
        if matched.iter().all(|n| is_excluded(n)) {
            anyhow::bail!(
                "'{entry}' only matches never-mergeable libraries ({}); \
                 they are part of the libc/kernel ABI and must stay dynamic",
                matched.join(", ")
            );
        }
    }
    Ok(())
}

pub fn collect_imports(
    elf: &ElfFile64<'_>,
    dyn_info: &DynamicInfo,
    ldso_cache: &LdsoCache,
    extra_lib_paths: &[PathBuf],
    merge_filter: Option<&[String]>,
) -> Result<ImportInfo> {
    if let Some(filter) = merge_filter {
        validate_merge_filter(&dyn_info.needed, filter)?;
    }

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
        if let Some(filter) = merge_filter
            && !filter.iter().any(|f| filter_selects(f, needed))
        {
            continue;
        }

        let lib_path = resolve_library(needed, &search_rpath, search_runpath, ldso_cache)
            .with_context(|| format!("resolving DT_NEEDED '{needed}'"))?;

        for name in exported_symbols(&lib_path)? {
            sym_to_lib.entry(name).or_insert_with(|| lib_path.clone());
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

    Ok(ImportInfo {
        imports,
        merged_lib_syms: sym_to_lib,
    })
}

/// Names of every symbol `lib_path` defines in its `.dynsym` — i.e. everything
/// it can satisfy an undefined reference with.
pub fn exported_symbols(lib_path: &Path) -> Result<HashSet<String>> {
    let bytes =
        std::fs::read(lib_path).with_context(|| format!("reading {}", lib_path.display()))?;
    let elf = goblin::elf::Elf::parse(&bytes)
        .with_context(|| format!("parsing {}", lib_path.display()))?;

    Ok(elf
        .dynsyms
        .iter()
        .filter(|sym| sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize)
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name).map(str::to_owned))
        .collect())
}

/// Sonames the executable has to inherit from the libraries being merged away.
///
/// Merging a library moves its code into the executable but not its
/// dependencies: `libcrypto.so.3` resolves `ZSTD_compress` through its own
/// `DT_NEEDED` on `libzstd.so.1`, and once libcrypto is gone from the
/// executable's `DT_NEEDED` nothing in the link chain provides that symbol any
/// more. `solder` injects those references as undefined `.dynsym` entries with
/// `GLOB_DAT` relocations, so with `DF_BIND_NOW` set the loader rejects the
/// binary outright ("symbol lookup error: undefined symbol"). The executable
/// therefore has to take over the dependencies that still carry its weight.
///
/// A merged library's soname is inherited when all of these hold:
///   * the executable does not already list it in `DT_NEEDED`,
///   * it is not itself being merged away, and
///   * it exports at least one of the symbols being injected — a dependency
///     nothing in the extracted code refers to stays dropped.
///
/// `exports` maps a soname to the symbols it defines, or `None` when the
/// library cannot be found. An unresolvable dependency is inherited anyway:
/// guessing that it was unnecessary risks an executable that will not start,
/// while an extra `DT_NEEDED` entry at worst reintroduces a dependency the
/// original binary already had through the merged library.
pub fn inherited_needed(
    merged_lib_deps: &[Vec<String>],
    exe_needed: &[String],
    remove_needed: &[String],
    injected: &HashSet<String>,
    exports: &mut dyn FnMut(&str) -> Option<HashSet<String>>,
) -> Vec<String> {
    if injected.is_empty() {
        // Nothing was referenced beyond what the executable already imports,
        // so every dependency of the merged libraries goes away with them.
        return Vec::new();
    }

    let already_linked: HashSet<&str> = exe_needed
        .iter()
        .chain(remove_needed)
        .map(String::as_str)
        .collect();

    let mut inherited: Vec<String> = Vec::new();
    for soname in merged_lib_deps.iter().flatten() {
        if already_linked.contains(soname.as_str()) || inherited.contains(soname) {
            continue;
        }
        match exports(soname) {
            Some(defined) => {
                let used: Vec<&str> = injected
                    .iter()
                    .filter(|name| defined.contains(*name))
                    .map(String::as_str)
                    .collect();
                if used.is_empty() {
                    debug!(
                        soname,
                        "Merged library's dependency provides nothing the extracted code \
                         references; leaving it out of DT_NEEDED"
                    );
                } else {
                    debug!(
                        soname,
                        symbols = ?used,
                        "Inheriting DT_NEEDED from merged library"
                    );
                    inherited.push(soname.clone());
                }
            }
            None => {
                warn!(
                    soname,
                    "Dependency of a merged library could not be found; adding it to DT_NEEDED \
                     without checking whether the extracted code needs it"
                );
                inherited.push(soname.clone());
            }
        }
    }

    inherited
}

/// For a given set of imported symbols, find the file offsets of their JUMP_SLOT
/// and GLOB_DAT relocation entries (so we can zero them out later to prevent ld.so
/// from overwriting our pre-patched GOT entries).
///
/// JUMP_SLOT relocations are in .rela.plt, GLOB_DAT relocations are in .rela.dyn.
pub fn find_jump_slot_reloc_offsets(
    elf: &ElfFile64<'_>,
    imported_names: &std::collections::HashSet<String>,
) -> Result<Vec<u64>> {
    use goblin::elf64::reloc::R_X86_64_GLOB_DAT;

    let bytes = elf.data();
    let goblin_exe = goblin::elf::Elf::parse(bytes).context("goblin parse")?;

    let mut offsets = Vec::new();

    // Build dynsym index → name map once for both sections
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

    // Each Rela64 entry is 24 bytes: r_offset(8) + r_info(8) + r_addend(8)
    // We need the file offset of the r_info field (offset +8) and r_addend (offset+16)
    // to zero them out.

    // Process .rela.plt for JUMP_SLOT relocations
    for section in elf.sections() {
        if section.name() != Ok(".rela.plt") {
            continue;
        }
        let sh_offset = section.file_range().map(|(off, _)| off).unwrap_or(0);
        let data = section.data().context(".rela.plt data")?;
        let n = data.len() / 24;

        for i in 0..n {
            let entry = &data[i * 24..(i + 1) * 24];
            let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            let sym_idx = (r_info >> 32) as usize;
            let name = match dynidx_to_name.get(&sym_idx) {
                Some(n) => n,
                None => continue,
            };
            if imported_names.contains(name) {
                offsets.push(sh_offset + (i as u64) * 24 + 8);
            }
        }
        break;
    }

    // Process .rela.dyn for GLOB_DAT relocations
    for section in elf.sections() {
        if section.name() != Ok(".rela.dyn") {
            continue;
        }
        let sh_offset = section.file_range().map(|(off, _)| off).unwrap_or(0);
        let data = section.data().context(".rela.dyn data")?;
        let n = data.len() / 24;

        for i in 0..n {
            let entry = &data[i * 24..(i + 1) * 24];
            let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            let r_type = (r_info & 0xffffffff) as u32;

            // Only zero out GLOB_DAT relocations for merged symbols
            if r_type != R_X86_64_GLOB_DAT {
                continue;
            }

            let sym_idx = (r_info >> 32) as usize;
            let name = match dynidx_to_name.get(&sym_idx) {
                Some(n) => n,
                None => continue,
            };
            if imported_names.contains(name) {
                offsets.push(sh_offset + (i as u64) * 24 + 8);
            }
        }
        break;
    }

    Ok(offsets)
}

/// Find the file offsets of R_X86_64_COPY relocations in `.rela.dyn` whose symbol
/// is provided by a fully-merged library. Returns the offset of each entry's
/// `r_info` field so the patcher can zero the entry (turning it into
/// R_X86_64_NONE). Copy relocations import an initial data value from a shared
/// object at load time; once that object is merged away, ld.so can no longer
/// find the symbol and aborts with "undefined symbol". The executable already
/// reserves the storage in its own `.bss`, so neutralizing the relocation is
/// sufficient for the common case where the source value is zero-initialized.
pub fn find_copy_reloc_offsets(
    elf: &ElfFile64<'_>,
    removed_provided_syms: &std::collections::HashSet<String>,
) -> Result<Vec<(u64, String)>> {
    use goblin::elf64::reloc::R_X86_64_COPY;

    let bytes = elf.data();
    let goblin_exe = goblin::elf::Elf::parse(bytes).context("goblin parse")?;

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

    let mut found = Vec::new();

    for section in elf.sections() {
        if section.name() != Ok(".rela.dyn") {
            continue;
        }
        let sh_offset = section.file_range().map(|(off, _)| off).unwrap_or(0);
        let data = section.data().context(".rela.dyn data")?;
        let n = data.len() / 24;

        for i in 0..n {
            let entry = &data[i * 24..(i + 1) * 24];
            let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            let r_type = (r_info & 0xffffffff) as u32;

            if r_type != R_X86_64_COPY {
                continue;
            }

            let sym_idx = (r_info >> 32) as usize;
            let name = match dynidx_to_name.get(&sym_idx) {
                Some(n) => n,
                None => continue,
            };
            if removed_provided_syms.contains(name) {
                found.push((sh_offset + (i as u64) * 24 + 8, name.clone()));
            }
        }
        break;
    }

    Ok(found)
}

/// Whether the named defined symbol in `lib_path` is zero-initialized — either
/// it lives in a NOBITS section (.bss) or its backing bytes are all zero. Used
/// to confirm a copy relocation can be safely neutralized without preserving an
/// initial value (the executable's own .bss copy is already zero).
pub fn symbol_is_zero_initialized(lib_path: &std::path::Path, name: &str) -> Result<bool> {
    use object::{Object, ObjectSection, ObjectSymbol};

    let bytes =
        std::fs::read(lib_path).with_context(|| format!("reading {}", lib_path.display()))?;
    let file = object::File::parse(bytes.as_slice())
        .with_context(|| format!("parsing {}", lib_path.display()))?;

    for sym in file.dynamic_symbols() {
        if sym.name().ok() != Some(name) || sym.is_undefined() {
            continue;
        }
        let object::SymbolSection::Section(idx) = sym.section() else {
            // Absolute/other: no backing data to preserve.
            return Ok(true);
        };
        let section = file.section_by_index(idx)?;
        if section.kind() == object::SectionKind::UninitializedData {
            return Ok(true); // .bss — implicitly zero
        }
        let data = section.data().unwrap_or(&[]);
        let start = (sym.address() - section.address()) as usize;
        let end = start + sym.size() as usize;
        return Ok(data
            .get(start..end)
            .is_none_or(|b| b.iter().all(|&x| x == 0)));
    }

    // Symbol not found as a definition — nothing to preserve.
    Ok(true)
}

#[cfg(test)]
mod inherited_needed_tests {
    use super::{HashSet, inherited_needed};

    fn names(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    fn set(entries: &[&str]) -> HashSet<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    /// Resolver over a fixed soname → exports table; anything not listed is
    /// treated as a library that could not be found.
    fn resolver<'t>(
        table: &'t [(&'t str, &'t [&'t str])],
    ) -> impl FnMut(&str) -> Option<HashSet<String>> + 't {
        move |soname: &str| {
            table
                .iter()
                .find(|(name, _)| *name == soname)
                .map(|(_, syms)| set(syms))
        }
    }

    #[test]
    fn a_dependency_providing_an_injected_symbol_is_inherited() {
        // libcrypto is merged away; the extracted code still calls into
        // libzstd, which was reachable only through libcrypto's DT_NEEDED.
        let mut exports = resolver(&[
            ("libzstd.so.1", &["ZSTD_compress", "ZSTD_decompress"]),
            ("libc.so.6", &["memcpy"]),
        ]);
        let inherited = inherited_needed(
            &[names(&["libzstd.so.1", "libc.so.6"])],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &set(&["ZSTD_compress", "memcpy"]),
            &mut exports,
        );
        assert_eq!(inherited, names(&["libzstd.so.1"]));
    }

    #[test]
    fn a_dependency_nothing_references_is_left_out() {
        let mut exports = resolver(&[("libzstd.so.1", &["ZSTD_compress"])]);
        let inherited = inherited_needed(
            &[names(&["libzstd.so.1"])],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &set(&["memcpy", "strlen"]),
            &mut exports,
        );
        assert!(
            inherited.is_empty(),
            "a dependency the extracted code never calls must stay dropped, got {inherited:?}"
        );
    }

    #[test]
    fn a_dependency_that_is_itself_merged_away_is_not_re_added() {
        // Both libcrypto and libz are merged, and libcrypto depends on libz.
        // libz's symbols come from the merged units, not from a DT_NEEDED.
        let mut exports = resolver(&[("libz.so.1", &["compress"])]);
        let inherited = inherited_needed(
            &[names(&["libz.so.1"]), Vec::new()],
            &names(&["libcrypto.so.3", "libz.so.1", "libc.so.6"]),
            &names(&["libcrypto.so.3", "libz.so.1"]),
            &set(&["compress"]),
            &mut exports,
        );
        assert!(
            inherited.is_empty(),
            "a merged-away library must not be put back in DT_NEEDED, got {inherited:?}"
        );
    }

    #[test]
    fn a_dependency_the_executable_already_links_is_not_duplicated() {
        let mut exports = resolver(&[("libc.so.6", &["memcpy"])]);
        let inherited = inherited_needed(
            &[names(&["libc.so.6"])],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &set(&["memcpy"]),
            &mut exports,
        );
        assert!(inherited.is_empty(), "{inherited:?}");
    }

    #[test]
    fn an_unresolvable_dependency_is_inherited_rather_than_guessed_away() {
        let mut exports = resolver(&[]);
        let inherited = inherited_needed(
            &[names(&["libzstd.so.1"])],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &set(&["ZSTD_compress"]),
            &mut exports,
        );
        assert_eq!(inherited, names(&["libzstd.so.1"]));
    }

    #[test]
    fn nothing_is_inherited_when_no_symbols_are_injected() {
        // No injected symbols means the extracted code refers to nothing the
        // executable did not already import, so even a dependency that cannot
        // be resolved is not worth keeping.
        let mut exports = resolver(&[]);
        let inherited = inherited_needed(
            &[names(&["libzstd.so.1"])],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &HashSet::new(),
            &mut exports,
        );
        assert!(inherited.is_empty(), "{inherited:?}");
    }

    #[test]
    fn a_dependency_shared_by_two_merged_libraries_is_added_once() {
        let mut exports = resolver(&[("libz.so.1", &["compress"])]);
        let inherited = inherited_needed(
            &[names(&["libz.so.1"]), names(&["libz.so.1"])],
            &names(&["libcrypto.so.3", "libssl.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3", "libssl.so.3"]),
            &set(&["compress"]),
            &mut exports,
        );
        assert_eq!(inherited, names(&["libz.so.1"]));
    }
}

#[cfg(test)]
mod merge_filter_tests {
    use super::validate_merge_filter;

    fn needed() -> Vec<String> {
        ["libpcre2-8.so.0", "libc.so.6"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn filter(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn an_exact_soname_is_accepted() {
        validate_merge_filter(&needed(), &filter(&["libpcre2-8.so.0"])).expect("exact soname");
    }

    #[test]
    fn a_soname_prefix_is_accepted() {
        validate_merge_filter(&needed(), &filter(&["libpcre2-8"])).expect("soname prefix");
    }

    #[test]
    fn a_mistyped_soname_is_rejected_and_lists_the_real_ones() {
        let err = validate_merge_filter(&needed(), &filter(&["libpcre2.so.0"]))
            .expect_err("mistyped soname must not be silently ignored");
        let msg = format!("{err:#}");
        assert!(msg.contains("libpcre2.so.0"), "{msg}");
        assert!(msg.contains("libpcre2-8.so.0"), "{msg}");
    }

    #[test]
    fn one_bad_entry_rejects_the_whole_invocation() {
        validate_merge_filter(&needed(), &filter(&["libpcre2-8.so.0", "libz.so.1"]))
            .expect_err("a partially matching filter must not merge only the matching subset");
    }

    #[test]
    fn a_never_mergeable_soname_is_rejected() {
        let err = validate_merge_filter(&needed(), &filter(&["libc.so.6"]))
            .expect_err("libc is on the never-merge list");
        assert!(format!("{err:#}").contains("never-mergeable"), "{err:#}");
    }

    #[test]
    fn a_prefix_covering_both_excluded_and_mergeable_libraries_is_accepted() {
        // "lib" matches libc (excluded) *and* libpcre2 (mergeable), so the
        // invocation still has something to do.
        validate_merge_filter(&needed(), &filter(&["lib"])).expect("mixed prefix");
    }
}
