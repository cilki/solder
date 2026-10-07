use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use object::read::elf::ElfFile64;
use object::{Object, ObjectSection};
use tracing::{debug, warn};

use crate::elf_reader::{DynamicTable, va_to_file_offset};
use crate::lib_discovery::{LdsoCache, expand_dynamic_tokens, is_excluded, resolve_library};
use crate::types::{ImportKind, ImportedSymbol};

/// Parse the dynamic section of an ELF to extract DT_NEEDED, DT_RPATH, and DT_RUNPATH.
pub struct DynamicInfo {
    pub needed: Vec<String>,
    /// `DT_RPATH`, with dynamic string tokens expanded. Read it through
    /// [`DynamicInfo::search_rpath`] rather than directly.
    pub rpath: Vec<PathBuf>,
    /// `DT_RUNPATH`, with dynamic string tokens expanded.
    pub runpath: Vec<PathBuf>,
}

impl DynamicInfo {
    /// The `DT_RPATH` directories the loader would actually search.
    ///
    /// `DT_RUNPATH` supersedes `DT_RPATH` outright: ld.so ignores an object's
    /// `DT_RPATH` whenever that object also carries a `DT_RUNPATH`. Searching
    /// both would let solder pick a library out of a directory the loader
    /// never reads, and merge code the executable does not actually run.
    pub fn search_rpath(&self) -> &[PathBuf] {
        if self.runpath.is_empty() {
            &self.rpath
        } else {
            &[]
        }
    }
}

pub fn parse_dynamic(elf: &ElfFile64<'_>, exe_path: &Path) -> Result<DynamicInfo> {
    use goblin::elf::dynamic::{DT_NEEDED, DT_RPATH, DT_RUNPATH};

    let bytes = elf.data();
    let dynamic = DynamicTable::parse(bytes).context("reading .dynamic of the executable")?;

    // `$ORIGIN` is the directory holding the object with symlinks resolved,
    // which is how ld.so computes it. Canonicalizing also turns the usual
    // `solder ./myapp` invocation into an absolute directory, so the resulting
    // search path does not depend on the working directory.
    let exe_real = exe_path
        .canonicalize()
        .unwrap_or_else(|_| exe_path.to_path_buf());
    let origin = exe_real.parent().unwrap_or(Path::new("."));

    // DT_RPATH and DT_RUNPATH each name a colon-separated list of directories,
    // each of which may contain dynamic string tokens.
    let search_list = |tag: u64| -> Vec<PathBuf> {
        dynamic
            .values_of(tag)
            .filter_map(|val| dynamic.string_at(bytes, val))
            .flat_map(|s| s.split(':'))
            .filter(|p| !p.is_empty())
            .filter_map(|p| {
                let dir = expand_dynamic_tokens(p, origin);
                if dir.is_none() {
                    warn!(
                        entry = p,
                        "ignoring library search path with a token that cannot be expanded"
                    );
                }
                dir
            })
            .collect()
    };

    let info = DynamicInfo {
        needed: dynamic
            .values_of(DT_NEEDED)
            .filter_map(|val| dynamic.string_at(bytes, val))
            .map(str::to_owned)
            .collect(),
        rpath: search_list(DT_RPATH),
        runpath: search_list(DT_RUNPATH),
    };

    if !info.runpath.is_empty() && !info.rpath.is_empty() {
        debug!(
            ignored=?info.rpath,
            "DT_RUNPATH is present, so DT_RPATH is ignored as ld.so ignores it"
        );
    }

    Ok(info)
}

/// A `DT_NEEDED` entry solder considered merging, and the file it resolved to.
pub struct MergedLibrary {
    /// The soname exactly as the executable's `.dynstr` spells it, which is
    /// what `remove_dt_needed` and `remove_verneed_entries` match against.
    pub soname: String,
    /// The library `resolve_library` found for that soname — the same path the
    /// imports taken from it carry in `ImportedSymbol::source_library`.
    pub path: PathBuf,
}

/// Collect all symbols the executable imports from shared libraries, resolving
/// each to an absolute library path and a GOT file offset.
/// Result of `collect_imports`: the symbols the executable imports, plus a
/// map of every symbol exported by any mergeable library (used by the
/// extractor to resolve cross-library PLT calls).
pub struct ImportInfo {
    pub imports: Vec<ImportedSymbol>,
    pub merged_lib_syms: std::collections::HashMap<String, PathBuf>,
    /// Every `DT_NEEDED` entry that survived the exclusion list and the `-m`
    /// filter, in the order the executable lists them.
    pub merged_libs: Vec<MergedLibrary>,
}

impl ImportInfo {
    /// The libraries that actually gave up at least one symbol, paired with
    /// the soname that named them.
    ///
    /// Every reference the executable made into such a library is satisfied by
    /// merged code once the merge lands, so its `DT_NEEDED` entry — and the
    /// copy relocations against the data it exported — can go. A candidate
    /// library the executable turned out not to import anything from keeps
    /// both.
    ///
    /// This is the one place the soname ↔ path correspondence is decided.
    /// Recovering it downstream by comparing a resolved library's file name
    /// against a soname (which is what the callers used to do) guesses at
    /// something already known here, and guesses wrong whenever one soname is
    /// a prefix of another: merging `libfoo.so.1` dropped a sibling
    /// `DT_NEEDED` on `libfoo.so` that nothing had been merged out of.
    pub fn absorbed_libraries(&self) -> impl Iterator<Item = &MergedLibrary> {
        self.merged_libs.iter().filter(|lib| {
            self.imports
                .iter()
                .any(|imp| imp.source_library == lib.path)
        })
    }
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

    // Build a map from symbol name → source library path.
    // For each DT_NEEDED entry (in order), find the library, parse its .dynsym,
    // and record which symbols it exports.  The first library providing a symbol wins.
    let mut sym_to_lib: std::collections::HashMap<String, PathBuf> =
        std::collections::HashMap::new();
    let mut merged_libs: Vec<MergedLibrary> = Vec::new();

    let mut search_rpath = dyn_info.search_rpath().to_vec();
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
        merged_libs.push(MergedLibrary {
            soname: needed.clone(),
            path: lib_path,
        });
    }

    // Now walk .rela.plt (all JUMP_SLOT) and the GLOB_DATs of .rela.dyn,
    // recording the GOT slot of every symbol a mergeable library provides. The
    // first relocation naming a symbol wins; later ones point at the same slot.
    let mut imports: Vec<ImportedSymbol> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (entry, kind) in RelaTables::read(elf)?.imports() {
        // A symbol no mergeable library provides is external (glibc etc.).
        let Some(source_library) = sym_to_lib.get(&entry.symbol) else {
            continue;
        };
        if !seen.insert(entry.symbol.clone()) {
            continue;
        }
        imports.push(ImportedSymbol {
            name: entry.symbol.clone(),
            source_library: source_library.clone(),
            got_file_offset: va_to_file_offset(elf, entry.target_vaddr).with_context(|| {
                format!(
                    "GOT VA 0x{:x} not in any PT_LOAD segment",
                    entry.target_vaddr
                )
            })?,
            kind,
        });
    }

    Ok(ImportInfo {
        imports,
        merged_lib_syms: sym_to_lib,
        merged_libs,
    })
}

/// Size of an `Elf64_Rela` entry and the offset of its `r_info` field within
/// one. A relocation is neutralized by zeroing `r_info` and the `r_addend`
/// that follows it, so `RelaEntry::r_info_offset` points at `r_info`.
const RELA_ENTRY_SIZE: u64 = 24;
const RELA_R_INFO_OFFSET: u64 = 8;

/// One entry of a `.rela.*` table, reduced to what anything here wants from it.
struct RelaEntry {
    /// File offset of the entry's `r_info` field.
    r_info_offset: u64,
    /// `r_offset` — the virtual address the relocation applies to, i.e. the
    /// GOT slot or data word being filled in.
    target_vaddr: u64,
    /// Low half of `r_info`: the `R_X86_64_*` relocation type.
    r_type: u32,
    /// Name of the `.dynsym` symbol the entry refers to, empty if it has none.
    symbol: String,
}

/// The executable's two dynamic relocation tables, decoded.
///
/// Entries are read out of the `.rela.*` section bytes rather than taken from a
/// parsed relocation list because every caller needs an entry's *file offset*,
/// which a parsed relocation does not carry. A missing section is an empty
/// table.
struct RelaTables {
    /// `.rela.plt`, which holds nothing but JUMP_SLOTs.
    jump_slot: Vec<RelaEntry>,
    /// `.rela.dyn`, which mixes GLOB_DAT with RELATIVE, COPY and TLS entries.
    dynamic: Vec<RelaEntry>,
}

impl RelaTables {
    fn read(elf: &ElfFile64<'_>) -> Result<Self> {
        // Relocation symbol indices address .dynsym, so resolve them there.
        let goblin_elf =
            goblin::elf::Elf::parse(elf.data()).context("goblin parse of executable")?;
        let names: Vec<&str> = goblin_elf
            .dynsyms
            .iter()
            .map(|sym| goblin_elf.dynstrtab.get_at(sym.st_name).unwrap_or(""))
            .collect();

        Ok(Self {
            jump_slot: read_rela_section(elf, ".rela.plt", &names)?,
            dynamic: read_rela_section(elf, ".rela.dyn", &names)?,
        })
    }

    /// The `.rela.dyn` entries of one relocation type.
    fn dynamic_of_type(&self, r_type: u32) -> impl Iterator<Item = &RelaEntry> {
        self.dynamic.iter().filter(move |e| e.r_type == r_type)
    }

    /// Every entry that can name a symbol imported from a shared library: all
    /// of `.rela.plt` plus the GLOB_DATs of `.rela.dyn`, each paired with the
    /// kind of import it represents.
    fn imports(&self) -> impl Iterator<Item = (&RelaEntry, ImportKind)> {
        use goblin::elf64::reloc::R_X86_64_GLOB_DAT;

        self.jump_slot
            .iter()
            .map(|e| (e, ImportKind::JumpSlot))
            .chain(
                self.dynamic_of_type(R_X86_64_GLOB_DAT)
                    .map(|e| (e, ImportKind::GlobDat)),
            )
    }
}

/// Decode the named `.rela.*` section, naming each entry's symbol out of
/// `dynsym_names` (indexed by `.dynsym` index).
fn read_rela_section(
    elf: &ElfFile64<'_>,
    section_name: &str,
    dynsym_names: &[&str],
) -> Result<Vec<RelaEntry>> {
    let Some(section) = elf.section_by_name(section_name) else {
        return Ok(Vec::new());
    };
    let sh_offset = section.file_range().map(|(off, _)| off).unwrap_or(0);
    let data = section
        .data()
        .with_context(|| format!("{section_name} data"))?;

    let mut entries = Vec::new();
    for (i, entry) in data.chunks_exact(RELA_ENTRY_SIZE as usize).enumerate() {
        let r_offset = u64::from_le_bytes(entry[..8].try_into().unwrap());
        let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        let Some(symbol) = dynsym_names.get((r_info >> 32) as usize) else {
            continue;
        };
        entries.push(RelaEntry {
            r_info_offset: sh_offset + i as u64 * RELA_ENTRY_SIZE + RELA_R_INFO_OFFSET,
            target_vaddr: r_offset,
            r_type: r_info as u32,
            symbol: (*symbol).to_owned(),
        });
    }
    Ok(entries)
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
    imported_names: &HashSet<String>,
) -> Result<Vec<u64>> {
    Ok(RelaTables::read(elf)?
        .imports()
        .filter(|(entry, _)| imported_names.contains(&entry.symbol))
        .map(|(entry, _)| entry.r_info_offset)
        .collect())
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
    removed_provided_syms: &HashSet<String>,
) -> Result<Vec<(u64, String)>> {
    use goblin::elf64::reloc::R_X86_64_COPY;

    Ok(RelaTables::read(elf)?
        .dynamic_of_type(R_X86_64_COPY)
        .filter(|e| removed_provided_syms.contains(&e.symbol))
        .map(|e| (e.r_info_offset, e.symbol.clone()))
        .collect())
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
mod absorbed_library_tests {
    use super::{ImportInfo, MergedLibrary};
    use crate::types::{ImportKind, ImportedSymbol};
    use std::path::PathBuf;

    fn lib(soname: &str) -> MergedLibrary {
        MergedLibrary {
            soname: soname.to_owned(),
            path: PathBuf::from("/usr/lib").join(soname),
        }
    }

    fn import(name: &str, soname: &str) -> ImportedSymbol {
        ImportedSymbol {
            name: name.to_owned(),
            source_library: PathBuf::from("/usr/lib").join(soname),
            got_file_offset: 0,
            kind: ImportKind::JumpSlot,
        }
    }

    fn collected(libs: &[&str], imports: Vec<ImportedSymbol>) -> ImportInfo {
        ImportInfo {
            imports,
            merged_lib_syms: Default::default(),
            merged_libs: libs.iter().copied().map(lib).collect(),
        }
    }

    fn absorbed(info: &ImportInfo) -> Vec<&str> {
        info.absorbed_libraries()
            .map(|l| l.soname.as_str())
            .collect()
    }

    /// A candidate library the executable imports nothing from was never
    /// merged, so its `DT_NEEDED` entry has to stay: dropping it would take
    /// away a dependency whose code is still only in the library.
    #[test]
    fn a_library_nothing_was_taken_from_keeps_its_dt_needed_entry() {
        let info = collected(
            &["libpcre2-8.so.0", "libtinfo.so.6"],
            vec![import("pcre2_compile_8", "libpcre2-8.so.0")],
        );
        assert_eq!(absorbed(&info), ["libpcre2-8.so.0"]);
    }

    /// The case that made the old basename heuristic
    /// (`base.starts_with(soname) || soname.starts_with(base)`) wrong: a
    /// library whose `DT_SONAME` carries no version suffix sits in `DT_NEEDED`
    /// next to a versioned sibling, and each soname is a prefix of the other's
    /// file name. Merging either one used to mark *both* removable, so the
    /// patcher dropped the `DT_NEEDED` entry and unlinked the `Verneed` entry
    /// of a library nothing had been merged out of — leaving the executable's
    /// own references to it unresolvable, which under the `DF_BIND_NOW` solder
    /// forces means the merged binary does not start at all.
    #[test]
    fn merging_a_library_does_not_drop_a_sibling_whose_soname_is_a_prefix() {
        let info = collected(
            &["libfoo.so.1", "libfoo.so"],
            vec![import("foo_one", "libfoo.so.1")],
        );
        assert_eq!(absorbed(&info), ["libfoo.so.1"]);

        // ...and the same the other way round, where the soname that was
        // merged is the shorter of the two.
        let info = collected(
            &["libfoo.so.1", "libfoo.so"],
            vec![import("foo_zero", "libfoo.so")],
        );
        assert_eq!(absorbed(&info), ["libfoo.so"]);
    }

    /// Sonames come back in `DT_NEEDED` order whatever order the imports were
    /// found in: `remove_needed` and the merged-library dependency order are
    /// both built from this, and neither should shift between runs.
    #[test]
    fn sonames_come_back_in_dt_needed_order() {
        let info = collected(
            &["liba.so.1", "libb.so.1", "libc_x.so.1"],
            vec![
                import("c_sym", "libc_x.so.1"),
                import("a_sym", "liba.so.1"),
                import("b_sym", "libb.so.1"),
            ],
        );
        assert_eq!(absorbed(&info), ["liba.so.1", "libb.so.1", "libc_x.so.1"]);
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
