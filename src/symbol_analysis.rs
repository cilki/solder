use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use object::read::elf::ElfFile64;
use object::{Object, ObjectSection};
use tracing::{debug, warn};

use crate::elf_reader::{DynamicTable, va_to_file_offset};
use crate::lib_discovery::{
    LdsoCache, expand_dynamic_tokens, is_excluded, resolve_library, soname_base,
};
use crate::types::{ImportKind, ImportedSymbol};

/// Parse the dynamic section of an ELF to extract DT_NEEDED, DT_RPATH, and DT_RUNPATH.
pub struct DynamicInfo {
    pub needed: Vec<String>,
    /// `DT_RPATH`, with dynamic string tokens expanded. Read it through
    /// [`DynamicInfo::search_rpath`] rather than directly.
    pub rpath: Vec<PathBuf>,
    /// `DT_RUNPATH`, with dynamic string tokens expanded.
    pub runpath: Vec<PathBuf>,
    /// The directory holding the executable, with symlinks resolved — what
    /// `$ORIGIN` means to the loader, and the base a path-valued `DT_NEEDED`
    /// entry of the executable is resolved against.
    pub origin: PathBuf,
}

impl DynamicInfo {
    /// The `DT_RPATH` directories the loader would actually search.
    pub fn search_rpath(&self) -> &[PathBuf] {
        effective_rpath(&self.rpath, &self.runpath)
    }
}

/// One object's `DT_RPATH` as ld.so searches it.
///
/// `DT_RUNPATH` supersedes `DT_RPATH` outright: ld.so ignores an object's
/// `DT_RPATH` whenever that same object also carries a `DT_RUNPATH`. Searching
/// both would let solder pick a library out of a directory the loader never
/// reads, and merge code the executable does not actually run.
fn effective_rpath<'a>(rpath: &'a [PathBuf], runpath: &[PathBuf]) -> &'a [PathBuf] {
    if runpath.is_empty() { rpath } else { &[] }
}

/// The search directories ld.so reads out of one object's `DT_RPATH` or
/// `DT_RUNPATH` values: each value is a colon-separated list of directories,
/// each of which may carry dynamic string tokens. The tokens are expanded
/// against `origin`, the directory of the object that recorded the entry — so
/// these have to be read from the object they belong to, not from another one
/// that happens to be in the same link.
fn search_dirs<'a>(values: impl Iterator<Item = &'a str>, origin: &Path) -> Vec<PathBuf> {
    values
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

    let search_list = |tag: u64| -> Vec<PathBuf> {
        search_dirs(
            dynamic
                .values_of(tag)
                .filter_map(|val| dynamic.string_at(bytes, val)),
            origin,
        )
    };

    let info = DynamicInfo {
        needed: dynamic
            .values_of(DT_NEEDED)
            .filter_map(|val| dynamic.string_at(bytes, val))
            .map(str::to_owned)
            .collect(),
        rpath: search_list(DT_RPATH),
        runpath: search_list(DT_RUNPATH),
        origin: origin.to_path_buf(),
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
    /// The library's own `DT_NEEDED` entries, taken from the same parse its
    /// exports were. Constructor ordering ([`crate::dep_graph`]) and the
    /// inherited-dependency pass ([`inherited_needed`]) both want these, and
    /// each used to read and parse the whole library again to get them.
    pub needed: Vec<String>,
    /// Its own `DT_RPATH` and `DT_RUNPATH`, with dynamic string tokens
    /// expanded against *its* `$ORIGIN`. These are the directories ld.so
    /// searches for the entries in `needed`; read them through
    /// [`dependency_search_path`] rather than directly.
    pub rpath: Vec<PathBuf>,
    pub runpath: Vec<PathBuf>,
}

/// Where ld.so looks for a dependency that `lib` declares, in the two groups
/// [`resolve_library`] takes them in: the directories searched ahead of
/// `LD_LIBRARY_PATH`, and the ones searched behind it.
///
/// glibc's `_dl_map_object` resolves a soname against the `DT_RPATH` of the
/// object that asked for it, then of each object up the chain that loaded it
/// (the executable last), then `LD_LIBRARY_PATH`, then the `DT_RUNPATH` of
/// *that same object*, then the cache and the default directories. So the
/// merged library's own entries lead, and `exe_rpath` — the executable's
/// `DT_RPATH` plus solder's own `$SYSROOT/lib` and `-L` directories — follows
/// them.
///
/// The executable's `DT_RUNPATH` is deliberately absent: a `DT_RUNPATH`
/// governs only the lookups of the object that records it, never those of its
/// dependencies. Resolving a merged library's dependency through the
/// executable's `DT_RUNPATH` — and without the library's own entries — looked
/// up a soname in directories the loader never reads for it, so solder could
/// read the exports of a different file from the one the library was linked
/// against. That file's export list is what decides whether the executable has
/// to inherit the dependency at all ([`inherited_needed`]): a copy that
/// happens not to export the symbol gets the entry dropped, and the merged
/// binary then dies at startup under the `DF_BIND_NOW` solder forces
/// ("symbol lookup error: undefined symbol").
pub fn dependency_search_path<'a>(
    lib: &'a MergedLibrary,
    exe_rpath: &[PathBuf],
) -> (Vec<PathBuf>, &'a [PathBuf]) {
    let mut rpath = effective_rpath(&lib.rpath, &lib.runpath).to_vec();
    rpath.extend_from_slice(exe_rpath);
    (rpath, &lib.runpath)
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

/// Whether a `-m` filter entry selects the given DT_NEEDED entry. A filter
/// entry may be the full soname (`libz.so.1`) or a prefix of it (`libz.so`,
/// `libz`), so that callers don't have to know the exact version suffix.
///
/// A path-valued DT_NEEDED entry is matched on its last component too, so
/// `-m libfoo.so` selects `$ORIGIN/../lib/libfoo.so` without the user having
/// to spell out the path the linker happened to record.
fn filter_selects(filter_entry: &str, needed: &str) -> bool {
    needed.starts_with(filter_entry) || soname_base(needed).starts_with(filter_entry)
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
    rela: &RelaTables,
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

        let lib_path = resolve_library(
            needed,
            &search_rpath,
            search_runpath,
            ldso_cache,
            &dyn_info.origin,
        )
        .with_context(|| format!("resolving DT_NEEDED '{needed}'"))?;

        let lib = read_library_dynamic(&lib_path)?;
        for name in lib.defined {
            sym_to_lib.entry(name).or_insert_with(|| lib_path.clone());
        }
        merged_libs.push(MergedLibrary {
            soname: needed.clone(),
            path: lib_path,
            needed: lib.needed,
            rpath: lib.rpath,
            runpath: lib.runpath,
        });
    }

    // Now walk .rela.plt (all JUMP_SLOT) and the GLOB_DATs of .rela.dyn,
    // recording the GOT slot of every symbol a mergeable library provides. The
    // first relocation naming a symbol wins; later ones point at the same slot.
    let mut imports: Vec<ImportedSymbol> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (entry, kind) in rela.imports() {
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
///
/// Read once, by the caller that drives the merge, and shared: four stages want
/// something out of these two tables, and each one used to decode them again
/// from scratch — three through this type and a fourth (the trampoline GOT map,
/// now [`RelaTables::got_slot_vas`]) through its own copy of the walk.
pub struct RelaTables {
    /// `.rela.plt`, which holds nothing but JUMP_SLOTs.
    jump_slot: Vec<RelaEntry>,
    /// `.rela.dyn`, which mixes GLOB_DAT with RELATIVE, COPY and TLS entries.
    dynamic: Vec<RelaEntry>,
}

impl RelaTables {
    pub fn read(elf: &ElfFile64<'_>) -> Result<Self> {
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

    /// Symbol name → the virtual address of the GOT slot ld.so resolves it
    /// into, for every symbol the executable already imports.
    ///
    /// This is how `layout` finds a slot for a trampoline to `jmp` through: the
    /// merged code calls an external symbol by jumping to a stub that reads the
    /// function pointer out of such a slot, so an external the executable
    /// already imports needs no new slot of its own.
    ///
    /// Only the import entries qualify. A `.rela.dyn` entry of any other type
    /// also names a symbol, but its `r_offset` is not a slot holding that
    /// symbol's address — a `COPY` points at the executable's own `.bss` copy
    /// of the data, a TLS entry at a module/offset pair — so a trampoline
    /// jumping through one would land wherever those bytes happen to lead.
    pub fn got_slot_vas(&self) -> HashMap<String, u64> {
        let mut map: HashMap<String, u64> = HashMap::new();
        for (entry, _) in self.imports() {
            map.entry(entry.symbol.clone())
                .or_insert(entry.target_vaddr);
        }
        map
    }

    /// The names of the symbols the executable copy-relocates
    /// (`R_X86_64_COPY`).
    ///
    /// Such a symbol's storage belongs to the executable: the linker gave the
    /// executable a definition of its own in `.bss` and had ld.so copy the
    /// library's initial value into it. The consequence that matters to the
    /// merge is on the other side of the lookup — the executable is first in
    /// the global scope, so *every* object's reference to that name resolved to
    /// the executable's copy, the defining library's own references included.
    /// Extracted code has to keep reaching that copy or the variable becomes
    /// two unrelated objects (see `collect_dynamic_range_relocs`).
    pub fn copy_reloc_symbols(&self) -> HashSet<String> {
        use goblin::elf64::reloc::R_X86_64_COPY;

        self.dynamic_of_type(R_X86_64_COPY)
            .map(|e| e.symbol.clone())
            .collect()
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

/// What the merge wants to know about a shared library, from one parse of it.
pub struct LibraryDynamic {
    /// Names of every symbol the library defines in its `.dynsym` — i.e.
    /// everything it can satisfy an undefined reference with.
    pub defined: HashSet<String>,
    /// Its own `DT_NEEDED` entries, in the order it lists them.
    pub needed: Vec<String>,
    /// Its own `DT_RPATH` and `DT_RUNPATH`, with dynamic string tokens
    /// expanded against the library's own directory: the search path ld.so
    /// uses for the entries in `needed`.
    pub rpath: Vec<PathBuf>,
    pub runpath: Vec<PathBuf>,
}

/// Read `lib_path`'s exports and dependencies.
///
/// A file that is not an x86-64 shared object is an error rather than a
/// library with no exports: everything this feeds — the symbol-to-library map
/// the merge extracts code through, and the inherited-`DT_NEEDED` decision —
/// assumes the file's code can run in the executable. See
/// [`validate_merge_library`](crate::elf_reader::validate_merge_library).
pub fn read_library_dynamic(lib_path: &Path) -> Result<LibraryDynamic> {
    let bytes =
        std::fs::read(lib_path).with_context(|| format!("reading {}", lib_path.display()))?;
    crate::elf_reader::validate_merge_library(&bytes, lib_path)?;
    let elf = goblin::elf::Elf::parse(&bytes)
        .with_context(|| format!("parsing {}", lib_path.display()))?;

    // `$ORIGIN` in this library's search path is this library's own directory,
    // symlinks resolved — the same rule `parse_dynamic` applies to the
    // executable, applied to the object that recorded these entries.
    let real = lib_path
        .canonicalize()
        .unwrap_or_else(|_| lib_path.to_path_buf());
    let origin = real.parent().unwrap_or(Path::new("."));

    Ok(LibraryDynamic {
        defined: elf
            .dynsyms
            .iter()
            .filter(|sym| sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize)
            .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name).map(str::to_owned))
            .collect(),
        needed: elf.libraries.iter().map(|s| (*s).to_owned()).collect(),
        rpath: search_dirs(elf.rpaths.iter().copied(), origin),
        runpath: search_dirs(elf.runpaths.iter().copied(), origin),
    })
}

/// A `DT_NEEDED` entry of a merged library, looked up: the file the entry names
/// and the symbols that file defines.
pub type ResolvedDependency = (PathBuf, HashSet<String>);

/// `DT_NEEDED` entries the executable has to inherit from the libraries being
/// merged away.
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
/// `merged_lib_deps` is the `DT_NEEDED` entries of every library being merged
/// away, run together; `resolve` maps one of those entries to the file it names
/// and the symbols that file defines, or `None` when the library cannot be
/// found. An unresolvable dependency is inherited anyway: guessing that it was
/// unnecessary risks an executable that will not start, while an extra
/// `DT_NEEDED` entry at worst reintroduces a dependency the original binary
/// already had through the merged library.
///
/// A dependency recorded as a *path* rather than a soname cannot be inherited
/// verbatim, because the path is read relative to whichever object declared it:
/// `$ORIGIN` is the declaring object's own directory and a relative path is the
/// running process's working directory. Copying `$ORIGIN/libbaz.so` off
/// `/usr/lib/libbar.so` and onto `/home/me/app/bin/app` therefore stops naming
/// `/usr/lib/libbaz.so` and starts naming `/home/me/app/bin/libbaz.so` — a file
/// that need not exist, and that anyone who can write next to the executable
/// gets to supply. Such an entry is inherited as the absolute path solder
/// resolved it to, which is the file the merged library was loading, and the
/// merge fails outright when solder cannot work out which file that is.
pub fn inherited_needed<'a>(
    merged_lib_deps: impl IntoIterator<Item = &'a str>,
    exe_needed: &[String],
    remove_needed: &[String],
    injected: &HashSet<String>,
    resolve: &mut dyn FnMut(&str) -> Option<ResolvedDependency>,
) -> Result<Vec<String>> {
    if injected.is_empty() {
        // Nothing was referenced beyond what the executable already imports,
        // so every dependency of the merged libraries goes away with them.
        return Ok(Vec::new());
    }

    let already_linked: HashSet<&str> = exe_needed
        .iter()
        .chain(remove_needed)
        .map(String::as_str)
        .collect();

    let mut seen: HashSet<&str> = HashSet::new();
    let mut inherited: Vec<String> = Vec::new();
    for dep in merged_lib_deps {
        if already_linked.contains(dep) || !seen.insert(dep) {
            continue;
        }
        // glibc's `_dl_map_object` branches on `strchr (name, '/')`: an entry
        // with a slash in it is a filename opened directly, everything else a
        // soname looked up on the search path. Only the former is tied to the
        // object that declared it.
        let names_a_path = dep.contains('/');
        match resolve(dep) {
            Some((path, defined)) => {
                let used: Vec<&str> = injected
                    .iter()
                    .filter(|name| defined.contains(*name))
                    .map(String::as_str)
                    .collect();
                if used.is_empty() {
                    debug!(
                        soname = dep,
                        "Merged library's dependency provides nothing the extracted code \
                         references; leaving it out of DT_NEEDED"
                    );
                    continue;
                }
                let entry = if names_a_path {
                    let resolved = path
                        .to_str()
                        .with_context(|| {
                            format!(
                                "a merged library depends on '{dep}', which resolves to {}; \
                                 that path is not valid UTF-8 and cannot be written into \
                                 .dynstr",
                                path.display()
                            )
                        })?
                        .to_owned();
                    if resolved != dep {
                        debug!(
                            dependency = dep,
                            resolved, "Inheriting a path-valued dependency as the file it names"
                        );
                    }
                    resolved
                } else {
                    dep.to_owned()
                };
                debug!(
                    soname = entry,
                    symbols = ?used,
                    "Inheriting DT_NEEDED from merged library"
                );
                if !already_linked.contains(entry.as_str()) && !inherited.contains(&entry) {
                    inherited.push(entry);
                }
            }
            // Inheriting the entry as it stands would point the executable at
            // a file next to itself (or next to whatever directory it is run
            // from), so there is nothing safe to write here.
            None if names_a_path => anyhow::bail!(
                "a merged library depends on '{dep}', which solder cannot resolve to a file. \
                 The executable cannot inherit that entry as it stands: a path in DT_NEEDED \
                 is read relative to the object that declared it, so on the executable it \
                 names a different file — for a relative path, one in the working directory \
                 of whoever runs it. Leave that library out of the merge, or relink it \
                 against a soname or an absolute path."
            ),
            None => {
                warn!(
                    soname = dep,
                    "Dependency of a merged library could not be found; adding it to DT_NEEDED \
                     without checking whether the extracted code needs it"
                );
                inherited.push(dep.to_owned());
            }
        }
    }

    Ok(inherited)
}

/// For a given set of imported symbols, find the file offsets of their JUMP_SLOT
/// and GLOB_DAT relocation entries (so we can zero them out later to prevent ld.so
/// from overwriting our pre-patched GOT entries).
///
/// JUMP_SLOT relocations are in .rela.plt, GLOB_DAT relocations are in .rela.dyn.
pub fn find_jump_slot_reloc_offsets(
    rela: &RelaTables,
    imported_names: &HashSet<String>,
) -> Vec<u64> {
    rela.imports()
        .filter(|(entry, _)| imported_names.contains(&entry.symbol))
        .map(|(entry, _)| entry.r_info_offset)
        .collect()
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
    rela: &RelaTables,
    removed_provided_syms: &HashSet<String>,
) -> Vec<(u64, String)> {
    use goblin::elf64::reloc::R_X86_64_COPY;

    rela.dynamic_of_type(R_X86_64_COPY)
        .filter(|e| removed_provided_syms.contains(&e.symbol))
        .map(|e| (e.r_info_offset, e.symbol.clone()))
        .collect()
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
mod library_dynamic_tests {
    use super::*;

    const PCRE2: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs/libpcre2-8.so.0");

    #[test]
    fn a_real_library_yields_its_exports_and_dependencies() {
        let lib = read_library_dynamic(Path::new(PCRE2)).expect("read libpcre2-8.so.0");
        assert!(lib.defined.contains("pcre2_compile_8"), "exports");
        assert!(
            lib.needed.iter().any(|n| n.starts_with("libc.so")),
            "{:?}",
            lib.needed
        );
    }

    /// A library solder cannot take code from has to stop the merge here, where
    /// the soname is being resolved to a file, rather than contribute an export
    /// map the extractor then copies instructions through. A 32-bit build of the
    /// right soname is the quiet case: goblin reads it happily, its `.dynsym`
    /// matches none of the executable's imports, and the merge used to report
    /// success having done nothing at all.
    #[test]
    fn a_library_of_the_wrong_architecture_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (at, value, what) in [(4usize, 1u8, "32-bit"), (0x12, 183, "aarch64")] {
            let mut bytes = std::fs::read(PCRE2).expect("read libpcre2-8.so.0");
            bytes[at] = value;
            let path = dir.path().join("libpcre2-8.so.0");
            std::fs::write(&path, &bytes).expect("write the doctored library");

            let Err(e) = read_library_dynamic(&path) else {
                panic!("{what}: a foreign library must be refused");
            };
            let err = format!("{e:#}");
            assert!(
                err.contains(&path.display().to_string()),
                "{what}: {err} should name the file"
            );
        }
    }
}

#[cfg(test)]
mod inherited_needed_tests {
    use super::{HashSet, PathBuf, ResolvedDependency, inherited_needed};

    fn names(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    fn set(entries: &[&str]) -> HashSet<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    /// Resolver over a fixed table of `DT_NEEDED` entry → (the file it names,
    /// the symbols that file exports); anything not listed is treated as a
    /// library that could not be found.
    fn resolver<'t>(
        table: &'t [(&'t str, &'t str, &'t [&'t str])],
    ) -> impl FnMut(&str) -> Option<ResolvedDependency> + 't {
        move |entry: &str| {
            table
                .iter()
                .find(|(needed, _, _)| *needed == entry)
                .map(|(_, path, syms)| (PathBuf::from(path), set(syms)))
        }
    }

    #[test]
    fn a_dependency_providing_an_injected_symbol_is_inherited() {
        // libcrypto is merged away; the extracted code still calls into
        // libzstd, which was reachable only through libcrypto's DT_NEEDED.
        let mut exports = resolver(&[
            (
                "libzstd.so.1",
                "/usr/lib64/libzstd.so.1",
                &["ZSTD_compress", "ZSTD_decompress"],
            ),
            ("libc.so.6", "/usr/lib64/libc.so.6", &["memcpy"]),
        ]);
        let inherited = inherited_needed(
            ["libzstd.so.1", "libc.so.6"],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &set(&["ZSTD_compress", "memcpy"]),
            &mut exports,
        )
        .expect("resolvable dependencies");
        assert_eq!(inherited, names(&["libzstd.so.1"]));
    }

    #[test]
    fn a_dependency_nothing_references_is_left_out() {
        let mut exports = resolver(&[(
            "libzstd.so.1",
            "/usr/lib64/libzstd.so.1",
            &["ZSTD_compress"],
        )]);
        let inherited = inherited_needed(
            ["libzstd.so.1"],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &set(&["memcpy", "strlen"]),
            &mut exports,
        )
        .expect("resolvable dependencies");
        assert!(
            inherited.is_empty(),
            "a dependency the extracted code never calls must stay dropped, got {inherited:?}"
        );
    }

    #[test]
    fn a_dependency_that_is_itself_merged_away_is_not_re_added() {
        // Both libcrypto and libz are merged, and libcrypto depends on libz.
        // libz's symbols come from the merged units, not from a DT_NEEDED.
        let mut exports = resolver(&[("libz.so.1", "/usr/lib64/libz.so.1", &["compress"])]);
        let inherited = inherited_needed(
            ["libz.so.1"],
            &names(&["libcrypto.so.3", "libz.so.1", "libc.so.6"]),
            &names(&["libcrypto.so.3", "libz.so.1"]),
            &set(&["compress"]),
            &mut exports,
        )
        .expect("resolvable dependencies");
        assert!(
            inherited.is_empty(),
            "a merged-away library must not be put back in DT_NEEDED, got {inherited:?}"
        );
    }

    #[test]
    fn a_dependency_the_executable_already_links_is_not_duplicated() {
        let mut exports = resolver(&[("libc.so.6", "/usr/lib64/libc.so.6", &["memcpy"])]);
        let inherited = inherited_needed(
            ["libc.so.6"],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &set(&["memcpy"]),
            &mut exports,
        )
        .expect("resolvable dependencies");
        assert!(inherited.is_empty(), "{inherited:?}");
    }

    #[test]
    fn an_unresolvable_dependency_is_inherited_rather_than_guessed_away() {
        let mut exports = resolver(&[]);
        let inherited = inherited_needed(
            ["libzstd.so.1"],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &set(&["ZSTD_compress"]),
            &mut exports,
        )
        .expect("an unresolvable soname is not fatal");
        assert_eq!(inherited, names(&["libzstd.so.1"]));
    }

    #[test]
    fn nothing_is_inherited_when_no_symbols_are_injected() {
        // No injected symbols means the extracted code refers to nothing the
        // executable did not already import, so even a dependency that cannot
        // be resolved is not worth keeping.
        let mut exports = resolver(&[]);
        let inherited = inherited_needed(
            ["libzstd.so.1"],
            &names(&["libcrypto.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3"]),
            &HashSet::new(),
            &mut exports,
        )
        .expect("nothing to inherit");
        assert!(inherited.is_empty(), "{inherited:?}");
    }

    #[test]
    fn a_dependency_shared_by_two_merged_libraries_is_added_once() {
        let mut exports = resolver(&[("libz.so.1", "/usr/lib64/libz.so.1", &["compress"])]);
        let inherited = inherited_needed(
            // The same soname twice over, as two merged libraries sharing a
            // dependency hands it in.
            ["libz.so.1", "libz.so.1"],
            &names(&["libcrypto.so.3", "libssl.so.3", "libc.so.6"]),
            &names(&["libcrypto.so.3", "libssl.so.3"]),
            &set(&["compress"]),
            &mut exports,
        )
        .expect("resolvable dependencies");
        assert_eq!(inherited, names(&["libz.so.1"]));
    }

    /// `$ORIGIN` in the dependency of a merged library is that *library's*
    /// directory. Copied onto the executable's `DT_NEEDED` unchanged it becomes
    /// the executable's directory, so the merged code would call into whatever
    /// file happens to sit beside the binary instead of the one it was linked
    /// against.
    #[test]
    fn an_origin_relative_dependency_is_inherited_as_the_file_it_named() {
        let mut exports = resolver(&[(
            "$ORIGIN/libbaz.so",
            "/opt/vendor/lib/libbaz.so",
            &["baz_init"],
        )]);
        let inherited = inherited_needed(
            ["$ORIGIN/libbaz.so"],
            &names(&["libbar.so", "libc.so.6"]),
            &names(&["libbar.so"]),
            &set(&["baz_init"]),
            &mut exports,
        )
        .expect("a resolvable path-valued dependency");
        assert_eq!(inherited, names(&["/opt/vendor/lib/libbaz.so"]));
    }

    /// An absolute path names the same file whoever reads it, so it is
    /// inherited as it stands.
    #[test]
    fn an_absolute_path_dependency_is_inherited_unchanged() {
        let mut exports = resolver(&[(
            "/opt/vendor/lib/libbaz.so",
            "/opt/vendor/lib/libbaz.so",
            &["baz_init"],
        )]);
        let inherited = inherited_needed(
            ["/opt/vendor/lib/libbaz.so"],
            &names(&["libbar.so", "libc.so.6"]),
            &names(&["libbar.so"]),
            &set(&["baz_init"]),
            &mut exports,
        )
        .expect("a resolvable path-valued dependency");
        assert_eq!(inherited, names(&["/opt/vendor/lib/libbaz.so"]));
    }

    /// A path solder cannot resolve is the one case where there is nothing
    /// right to write: `../lib/libbaz.so` on the executable's `DT_NEEDED` is
    /// read against the working directory of whoever runs it, which is as good
    /// as letting the caller choose the library. Inheriting it verbatim — what
    /// a bare soname gets — has to be a merge failure instead.
    #[test]
    fn an_unresolvable_path_dependency_fails_the_merge() {
        let mut exports = resolver(&[]);
        let err = inherited_needed(
            ["../lib/libbaz.so"],
            &names(&["libbar.so", "libc.so.6"]),
            &names(&["libbar.so"]),
            &set(&["baz_init"]),
            &mut exports,
        )
        .expect_err("an unresolvable path-valued dependency is fatal");
        assert!(
            err.to_string().contains("../lib/libbaz.so"),
            "the error has to name the entry: {err}"
        );
    }

    /// The check is on the dependency, not on the merge as a whole: a
    /// path-valued entry nothing in the extracted code needs is dropped like
    /// any other unused dependency, so it never reaches the point of having to
    /// be rewritten.
    #[test]
    fn an_unused_path_dependency_is_dropped_rather_than_failing() {
        let mut exports = resolver(&[(
            "$ORIGIN/libbaz.so",
            "/opt/vendor/lib/libbaz.so",
            &["baz_init"],
        )]);
        let inherited = inherited_needed(
            ["$ORIGIN/libbaz.so"],
            &names(&["libbar.so", "libc.so.6"]),
            &names(&["libbar.so"]),
            &set(&["memcpy"]),
            &mut exports,
        )
        .expect("an unused dependency is not fatal");
        assert!(inherited.is_empty(), "{inherited:?}");
    }
}

#[cfg(test)]
mod dependency_search_tests {
    use super::{MergedLibrary, dependency_search_path};
    use std::path::PathBuf;

    fn dirs(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    /// A bundled library, with whichever search path entries the case wants.
    fn lib(rpath: &[&str], runpath: &[&str]) -> MergedLibrary {
        MergedLibrary {
            soname: "libfoo.so.1".to_owned(),
            path: PathBuf::from("/opt/app/lib/libfoo.so.1"),
            needed: vec!["libbar.so.1".to_owned()],
            rpath: dirs(rpath),
            runpath: dirs(runpath),
        }
    }

    /// ld.so searches the `DT_RPATH` of the object that asked for a soname
    /// before it works its way up to the executable's, so a bundled library
    /// that carries its dependencies next to itself resolves them from there
    /// even when the executable's own `DT_RPATH` holds another copy.
    #[test]
    fn the_declaring_librarys_rpath_leads_the_search() {
        let lib = lib(&["/opt/app/lib"], &[]);
        let (rpath, runpath) = dependency_search_path(&lib, &dirs(&["/usr/lib/exe-rpath"]));
        assert_eq!(rpath, dirs(&["/opt/app/lib", "/usr/lib/exe-rpath"]));
        assert!(runpath.is_empty(), "{runpath:?}");
    }

    /// `DT_RUNPATH` is searched after `LD_LIBRARY_PATH` rather than before it,
    /// and it supersedes the `DT_RPATH` of the same object — the library's own
    /// `DT_RPATH` here, not the executable's, which ld.so still reads.
    #[test]
    fn a_runpath_of_its_own_supersedes_only_its_own_rpath() {
        let lib = lib(&["/opt/app/ignored"], &["/opt/app/lib"]);
        let (rpath, runpath) = dependency_search_path(&lib, &dirs(&["/usr/lib/exe-rpath"]));
        assert_eq!(
            rpath,
            dirs(&["/usr/lib/exe-rpath"]),
            "the library's DT_RPATH is dead once it has a DT_RUNPATH"
        );
        assert_eq!(runpath, dirs(&["/opt/app/lib"]).as_slice());
    }

    /// A library with no search path of its own leaves the executable's, which
    /// is where solder's `$SYSROOT/lib` and `-L` directories ride along.
    #[test]
    fn a_library_without_a_search_path_leaves_the_executables() {
        let lib = lib(&[], &[]);
        let (rpath, runpath) =
            dependency_search_path(&lib, &dirs(&["/sysroot/lib", "/opt/mylibs"]));
        assert_eq!(rpath, dirs(&["/sysroot/lib", "/opt/mylibs"]));
        assert!(runpath.is_empty(), "{runpath:?}");
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
            needed: Vec::new(),
            rpath: Vec::new(),
            runpath: Vec::new(),
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
