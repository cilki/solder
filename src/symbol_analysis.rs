use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use object::read::elf::ElfFile64;
use tracing::{debug, warn};

use crate::arch::Arch;
use crate::elf_reader::{DynamicTable, MappedElf, dynamic_table_bytes};
use crate::lib_discovery::{
    LdsoCache, NotFound, expand_dynamic_tokens, is_excluded, resolve_library, soname_base,
};
use crate::types::ImportedSymbol;

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
/// that happens to be in the same link — and `$LIB` against `arch`.
fn search_dirs<'a>(
    values: impl Iterator<Item = &'a str>,
    origin: &Path,
    arch: &Arch,
) -> Vec<PathBuf> {
    values
        .flat_map(|s| s.split(':'))
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let dir = expand_dynamic_tokens(p, origin, arch);
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

/// Read `DT_NEEDED`, `DT_RPATH` and `DT_RUNPATH` out of the object at `path`,
/// the executable or one of its libraries, all of which are built for `arch`.
pub fn parse_dynamic(elf: &ElfFile64<'_>, path: &Path, arch: &Arch) -> Result<DynamicInfo> {
    use goblin::elf::dynamic::{DT_NEEDED, DT_RPATH, DT_RUNPATH};

    let bytes = elf.data();
    let dynamic = DynamicTable::parse(bytes)
        .with_context(|| format!("reading .dynamic of {}", path.display()))?;

    // `$ORIGIN` is the directory holding the object with symlinks resolved,
    // which is how ld.so computes it. Canonicalizing also turns the usual
    // `solder ./myapp` invocation into an absolute directory, so the resulting
    // search path does not depend on the working directory.
    let real = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let origin = real.parent().unwrap_or(Path::new("."));

    let search_list = |tag: u64| -> Vec<PathBuf> {
        search_dirs(
            dynamic
                .values_of(tag)
                .filter_map(|val| dynamic.string_at(bytes, val)),
            origin,
            arch,
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

/// Every `DT_NEEDED` lookup the merge makes, through the one search path the
/// loader would use for it.
///
/// Three stages resolve an entry and read the file it names: `collect_imports`
/// to decide what can be merged, [`inherited_needed`] to decide which of the
/// merged libraries' own dependencies the executable has to take over, and
/// [`unprovided_imports`] to check that the symbols left dynamic still have a
/// provider. Each had its own copy of the rule — the executable's effective
/// `DT_RPATH`, then solder's `$SYSROOT/lib` and `-L` directories, then
/// `LD_LIBRARY_PATH`, then the executable's `DT_RUNPATH`, with `$ORIGIN`
/// meaning the executable's own directory — assembled from `DynamicInfo` and a
/// path list at each call site. Three copies of one search path are three
/// chances to look a soname up somewhere ld.so does not, and a lookup that
/// finds a different file from the one the executable will load merges code the
/// executable never runs.
pub struct LibrarySearch<'a> {
    exe: &'a DynamicInfo,
    cache: &'a LdsoCache,
    /// The executable's architecture: what every library found has to be
    /// built for, and what decides the default directories and `$LIB`.
    arch: &'static Arch,
    /// The executable's effective `DT_RPATH` followed by solder's own search
    /// directories: the group [`resolve_library`] searches ahead of
    /// `LD_LIBRARY_PATH`.
    rpath: Vec<PathBuf>,
}

impl<'a> LibrarySearch<'a> {
    /// `extra` is where solder's own `$SYSROOT/lib` and `-L` directories go —
    /// behind the executable's `DT_RPATH`, ahead of `LD_LIBRARY_PATH`.
    pub fn new(
        exe: &'a DynamicInfo,
        extra: &[PathBuf],
        cache: &'a LdsoCache,
        arch: &'static Arch,
    ) -> Self {
        let mut rpath = exe.search_rpath().to_vec();
        rpath.extend_from_slice(extra);
        Self {
            exe,
            cache,
            arch,
            rpath,
        }
    }

    /// The executable's `DT_NEEDED` entries, in the order it lists them.
    pub fn exe_needed(&self) -> &'a [String] {
        &self.exe.needed
    }

    /// The file an entry the *executable* declares names — which is what every
    /// `DT_NEEDED` entry of the merged binary is, the inherited ones included.
    fn find(&self, entry: &str) -> Result<PathBuf> {
        resolve_library(
            entry,
            &self.rpath,
            &self.exe.runpath,
            self.cache,
            &self.exe.origin,
            self.arch,
        )
    }

    /// Resolve an entry the executable declares and read the exports and
    /// dependencies of the file it names.
    pub fn read(&self, entry: &str) -> Result<(PathBuf, LibraryDynamic)> {
        self.read_declared_by(None, entry)
    }

    /// The same for an entry `declarer` — a library being merged away — is the
    /// one that declares: ld.so resolves it through that library's own search
    /// path ahead of the executable's, and `$ORIGIN` in it means that library's
    /// directory (see [`dependency_search_path`]). `None` for an entry no
    /// merged library declares, which leaves nothing but the executable's own
    /// search path to apply to it.
    pub fn read_declared_by(
        &self,
        declarer: Option<&MergedLibrary>,
        entry: &str,
    ) -> Result<(PathBuf, LibraryDynamic)> {
        let path = match declarer {
            Some(lib) => {
                let (rpath, runpath) = dependency_search_path(lib, &self.rpath);
                let origin = lib.path.parent().unwrap_or(&self.exe.origin);
                resolve_library(entry, &rpath, runpath, self.cache, origin, self.arch)
            }
            None => self.find(entry),
        }?;
        let lib = read_library_dynamic(&path, self.arch)?;
        Ok((path, lib))
    }
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
    rela: &RelaTables,
    search: &LibrarySearch<'_>,
    merge_filter: Option<&[String]>,
) -> Result<ImportInfo> {
    let exe_needed = search.exe_needed();
    if let Some(filter) = merge_filter {
        validate_merge_filter(exe_needed, filter)?;
    }

    // Build a map from symbol name → source library path.
    // For each DT_NEEDED entry (in order), find the library, parse its .dynsym,
    // and record which symbols it exports.  The first library providing a symbol wins.
    let mut sym_to_lib: std::collections::HashMap<String, PathBuf> =
        std::collections::HashMap::new();
    let mut merged_libs: Vec<MergedLibrary> = Vec::new();

    for needed in exe_needed {
        if is_excluded(needed) {
            continue;
        }
        if let Some(filter) = merge_filter
            && !filter.iter().any(|f| filter_selects(f, needed))
        {
            continue;
        }

        let lib_path = match search.find(needed) {
            Ok(path) => path,
            // Nothing here provides the entry, and the user did not ask for
            // this library by name: leave it dynamic and merge the rest.
            //
            // Without the merge, the executable's references into that library
            // are resolved by whatever provides it where the binary runs, and
            // skipping it keeps exactly that — the soname stays in
            // `DT_NEEDED`, no symbol is taken out of it, and nothing about the
            // merged output depends on a file solder never read. Failing the
            // whole run instead meant one dependency that is not installed
            // here (a plugin library, a sysroot that doesn't carry all of
            // them) merged *none* of the ones that were sitting right there.
            Err(e) if merge_filter.is_none() && e.is::<NotFound>() => {
                warn!("{e}; the entry stays in DT_NEEDED and nothing is merged out of it");
                continue;
            }
            // A library named with `-m` has to be merged or the invocation is
            // not the one the user asked for, and an entry solder cannot act
            // on at all (a relative path, an unexpandable token) is never
            // skippable: see `resolve_path_entry`.
            Err(e) => return Err(e).with_context(|| format!("resolving DT_NEEDED '{needed}'")),
        };

        let lib = read_library_dynamic(&lib_path, search.arch)?;
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

    for entry in rela.imports() {
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
            got_vaddr: entry.target_vaddr,
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
    /// Low half of `r_info`: the relocation type, numbered as the executable's
    /// architecture numbers them.
    r_type: u32,
    /// Name of the `.dynsym` symbol the entry refers to, empty if it has none.
    symbol: String,
}

/// The executable's two dynamic relocation tables, decoded.
///
/// Entries are read out of the raw table bytes rather than taken from a parsed
/// relocation list because every caller needs an entry's *file offset*, which a
/// parsed relocation does not carry. A table the image does not declare is an
/// empty one.
///
/// The tables are located through `PT_DYNAMIC` — `DT_JMPREL`/`DT_PLTRELSZ` and
/// `DT_RELA`/`DT_RELASZ` — and not through the `.rela.plt`/`.rela.dyn` section
/// headers that normally also describe them. Those tags are what the loader
/// reads, so they are the authority on which bytes are a relocation table, and
/// they are already what the writer's `read_existing_rela_dyn` rebuilds
/// `.rela.dyn` from: a disagreement between the two views is the patcher
/// neutralizing entries in a table the writer never reads.
///
/// Looking them up by section name also made a section-header-less executable
/// look like one that imports nothing at all — two empty tables, no symbol to
/// merge out of any library, "No mergeable imported symbols found" and status 0
/// with the binary untouched, even when `-m` named a library that had to be
/// merged. Such an executable is now refused by `validate_executable`, for the
/// reasons it is actually unmergeable, before any of this runs.
///
/// Read once, by the caller that drives the merge, and shared: four stages want
/// something out of these two tables, and each one used to decode them again
/// from scratch — three through this type and a fourth (the trampoline GOT map,
/// now [`RelaTables::got_slot_vas`]) through its own copy of the walk.
pub struct RelaTables {
    /// `DT_JMPREL`, normally `.rela.plt`, which holds nothing but JUMP_SLOTs.
    jump_slot: Vec<RelaEntry>,
    /// `DT_RELA`, normally `.rela.dyn`, which mixes GLOB_DAT with RELATIVE,
    /// COPY and TLS entries.
    dynamic: Vec<RelaEntry>,
    /// Names of the `.dynsym` symbols some other object has to define: the
    /// undefined ones that are not weak, so the loader fails the executable
    /// outright rather than resolving them to zero.
    strong_undefined: HashSet<String>,
    /// The executable's architecture, which decides what each `r_type` is.
    arch: &'static Arch,
}

impl RelaTables {
    pub fn read(elf: &ElfFile64<'_>, arch: &'static Arch) -> Result<Self> {
        use goblin::elf::dynamic::{DT_JMPREL, DT_PLTREL, DT_PLTRELSZ, DT_RELA, DT_RELASZ};
        use goblin::elf::section_header::SHN_UNDEF;
        use goblin::elf::sym::STB_WEAK;

        // Relocation symbol indices address .dynsym, so resolve them there.
        let goblin_elf =
            goblin::elf::Elf::parse(elf.data()).context("goblin parse of executable")?;
        let names: Vec<&str> = goblin_elf
            .dynsyms
            .iter()
            .map(|sym| goblin_elf.dynstrtab.get_at(sym.st_name).unwrap_or(""))
            .collect();

        // A name the executable defines itself is one the loader resolves
        // without leaving the executable, however many undefined entries also
        // carry it — two versions of the same name, say.
        let defined_here: HashSet<&str> = goblin_elf
            .dynsyms
            .iter()
            .enumerate()
            .filter(|(_, sym)| sym.st_shndx != SHN_UNDEF as usize)
            .filter_map(|(i, _)| names.get(i).copied())
            .collect();
        let strong_undefined = goblin_elf
            .dynsyms
            .iter()
            .enumerate()
            .filter(|(_, sym)| sym.st_shndx == SHN_UNDEF as usize && sym.st_bind() != STB_WEAK)
            .filter_map(|(i, _)| names.get(i).copied())
            .filter(|name| !name.is_empty() && !defined_here.contains(name))
            .map(str::to_owned)
            .collect();

        let dynamic =
            DynamicTable::parse(elf.data()).context("reading the executable's .dynamic")?;

        // `DT_JMPREL`'s entries are `Elf64_Rela`s only if `DT_PLTREL` says so.
        // The x86-64 ABI mandates `DT_RELA`, and everything below reads the
        // table as 24-byte entries, so a `DT_REL` table is a file this cannot
        // decode rather than one to decode as if the tag had agreed.
        if let Some(pltrel) = dynamic.value_of(DT_PLTREL)
            && pltrel != DT_RELA
        {
            bail!(
                "DT_PLTREL is {pltrel}, but x86-64 relocation tables are DT_RELA ({DT_RELA}); \
                 refusing to read DT_JMPREL as one"
            );
        }

        Ok(Self {
            jump_slot: read_rela_table(elf, &dynamic, "DT_JMPREL", DT_JMPREL, DT_PLTRELSZ, &names)?,
            dynamic: read_rela_table(elf, &dynamic, "DT_RELA", DT_RELA, DT_RELASZ, &names)?,
            strong_undefined,
            arch,
        })
    }

    /// The symbols the loader still has to find for this executable once the
    /// merge has taken `merged` out of it.
    ///
    /// Every JUMP_SLOT and GLOB_DAT naming a merged symbol is neutralized by
    /// the patcher, because the merge fills that GOT slot itself. What is left
    /// is what the loader is still asked to look up: undefined, not weak — a
    /// weak one resolves to zero instead of failing the load — and not merged.
    pub fn loader_resolved_imports(&self, merged: &HashSet<String>) -> BTreeSet<String> {
        self.imports()
            .map(|entry| entry.symbol.as_str())
            .filter(|name| self.strong_undefined.contains(*name) && !merged.contains(*name))
            .map(str::to_owned)
            .collect()
    }

    /// The `.rela.dyn` entries of one relocation type.
    fn dynamic_of_type(&self, r_type: u32) -> impl Iterator<Item = &RelaEntry> {
        self.dynamic.iter().filter(move |e| e.r_type == r_type)
    }

    /// Every entry that can name a symbol imported from a shared library: all
    /// of `.rela.plt` plus the GLOB_DATs of `.rela.dyn`.
    fn imports(&self) -> impl Iterator<Item = &RelaEntry> {
        self.jump_slot
            .iter()
            .chain(self.dynamic_of_type(self.arch.reloc.glob_dat))
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
        for entry in self.imports() {
            map.entry(entry.symbol.clone())
                .or_insert(entry.target_vaddr);
        }
        map
    }

    /// The names of the symbols the executable copy-relocates (`R_*_COPY`).
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
        self.dynamic_of_type(self.arch.reloc.copy)
            .map(|e| e.symbol.clone())
            .collect()
    }
}

/// Decode the `Elf64_Rela` table `addr_tag` points at, sized by `size_tag`,
/// naming each entry's symbol out of `dynsym_names` (indexed by `.dynsym`
/// index). `what` names the tag pair in any error.
///
/// A table the image declares neither tag for is an empty one: the loader
/// processes no relocations it was not pointed at either.
fn read_rela_table(
    elf: &ElfFile64<'_>,
    dynamic: &DynamicTable,
    what: &str,
    addr_tag: u64,
    size_tag: u64,
    dynsym_names: &[&str],
) -> Result<Vec<RelaEntry>> {
    let (Some(vaddr), Some(size)) = (dynamic.value_of(addr_tag), dynamic.value_of(size_tag)) else {
        return Ok(Vec::new());
    };
    let (sh_offset, data) = dynamic_table_bytes(elf, elf.data(), what, vaddr, size)?;
    let sh_offset = sh_offset as u64;

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
/// A file that is not a shared object built for `arch` is an error rather than a
/// library with no exports: everything this feeds — the symbol-to-library map
/// the merge extracts code through, and the inherited-`DT_NEEDED` decision —
/// assumes the file's code can run in the executable. See
/// [`validate_merge_library`](crate::elf_reader::validate_merge_library).
///
/// Only `.dynsym` and `.dynamic` are read, both straight out of the mapping.
/// This used to be a full `goblin::elf::Elf::parse`, which pre-splits the whole
/// of `.dynstr` into a table of strings and walks every dynamic relocation to
/// size `.dynsym` — for `libcrypto.so.3`, 6k strings and 28k relocations, none
/// of which this needs, on every library the merge reads.
pub fn read_library_dynamic(lib_path: &Path, arch: &Arch) -> Result<LibraryDynamic> {
    use object::read::elf::Sym;

    let mapped =
        MappedElf::open(lib_path).with_context(|| format!("reading {}", lib_path.display()))?;
    let bytes = mapped.bytes();
    crate::elf_reader::validate_merge_library(bytes, lib_path, arch)?;
    let elf = mapped.parse()?;
    let endian = elf.endian();

    // `object` finds `.dynsym` through the section headers. A library without
    // them is still loadable — ld.so never reads them — so for that one the
    // table has to be sized from the hash tables, which is how goblin does it.
    let symbols = elf.elf_dynamic_symbol_table();
    let defined: HashSet<String> = if symbols.is_empty() {
        let elf = goblin::elf::Elf::parse(bytes)
            .with_context(|| format!("parsing {}", lib_path.display()))?;
        elf.dynsyms
            .iter()
            .filter(|sym| sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize)
            .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name).map(str::to_owned))
            .collect()
    } else {
        let strings = symbols.strings();
        symbols
            .symbols()
            .iter()
            .filter(|sym| !sym.is_undefined(endian))
            .filter_map(|sym| sym.name(endian, strings).ok())
            .filter_map(|name| std::str::from_utf8(name).ok())
            .map(str::to_owned)
            .collect()
    };

    // `$ORIGIN` in this library's search path is this library's own
    // directory, symlinks resolved — the same rule applied to the executable,
    // so the same reader serves both.
    let DynamicInfo {
        needed,
        rpath,
        runpath,
        ..
    } = parse_dynamic(&elf, lib_path, arch)?;

    Ok(LibraryDynamic {
        defined,
        needed,
        rpath,
        runpath,
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

/// The symbols the merged executable would still ask the loader for that no
/// library it is left linked against defines.
///
/// Solder picks the code it merges out of whichever copy of a soname its search
/// path turns up, but the executable was linked against the copy that was on
/// the machine that built it. When those are not the same file, the copy here
/// can be missing a symbol the executable imports: nothing defines it, so no
/// GOT slot is pre-filled for it and its relocation stays live — against a
/// soname the merge has just taken out of `DT_NEEDED`. The merge reports
/// success and the binary it wrote dies before `main` with "symbol lookup
/// error: undefined symbol", since solder also forces `DF_BIND_NOW` and the
/// loader resolves every such relocation up front.
///
/// So each symbol the loader is still asked for has to be defined by one of the
/// objects the executable is left linked against: every `DT_NEEDED` entry that
/// survives the merge, the ones inherited from the merged libraries included,
/// plus the interpreter, which is loaded without ever appearing in `DT_NEEDED`
/// and is where glibc keeps `__tls_get_addr` and friends.
///
/// `resolve` maps one of those entries to the symbols that file defines, or
/// `None` when solder cannot read it. A single `None` makes the whole answer
/// `None`: a library solder could not look at may define anything, and
/// refusing a merge over a symbol that an unread file defines after all would
/// be worse than letting it through.
pub fn unprovided_imports<'a>(
    loader_resolved: &BTreeSet<String>,
    remaining: impl IntoIterator<Item = &'a str>,
    resolve: &mut dyn FnMut(&str) -> Option<HashSet<String>>,
) -> Option<Vec<String>> {
    let mut unprovided: BTreeSet<&str> = loader_resolved.iter().map(String::as_str).collect();
    for entry in remaining {
        // Everything left is accounted for; whether the rest of the link can be
        // read no longer changes the answer.
        if unprovided.is_empty() {
            break;
        }
        let defined = resolve(entry)?;
        unprovided.retain(|name| !defined.contains(*name));
    }
    Some(unprovided.into_iter().map(str::to_owned).collect())
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
        .filter(|entry| imported_names.contains(&entry.symbol))
        .map(|entry| entry.r_info_offset)
        .collect()
}

/// Find the file offsets of copy relocations in `.rela.dyn` whose symbol
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
    rela.dynamic_of_type(rela.arch.reloc.copy)
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

    let mapped =
        MappedElf::open(lib_path).with_context(|| format!("reading {}", lib_path.display()))?;
    let file = object::File::parse(mapped.bytes())
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
        let lib = read_library_dynamic(Path::new(PCRE2), &crate::arch::X86_64)
            .expect("read libpcre2-8.so.0");
        assert!(lib.defined.contains("pcre2_compile_8"), "exports");
        assert!(
            lib.needed.iter().any(|n| n.starts_with("libc.so")),
            "{:?}",
            lib.needed
        );
    }

    /// ld.so never reads section headers, so a library stripped of them still
    /// loads and still exports everything its `.dynsym` holds. `object` only
    /// finds that table through the headers; the hash tables are what size it
    /// without them, and the exports read either way have to be the same.
    #[test]
    fn a_library_without_section_headers_yields_the_same_exports() {
        let with_headers = read_library_dynamic(Path::new(PCRE2), &crate::arch::X86_64)
            .expect("read libpcre2-8.so.0");

        let mut bytes = std::fs::read(PCRE2).expect("read libpcre2-8.so.0");
        bytes[0x28..0x30].fill(0); // e_shoff
        bytes[0x3c..0x40].fill(0); // e_shnum, e_shstrndx
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("libpcre2-8.so.0");
        std::fs::write(&path, &bytes).expect("write the stripped library");

        let without =
            read_library_dynamic(&path, &crate::arch::X86_64).expect("read the stripped library");
        assert!(without.defined.contains("pcre2_compile_8"), "exports");
        assert_eq!(without.defined, with_headers.defined);
        assert_eq!(without.needed, with_headers.needed);
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

            let Err(e) = read_library_dynamic(&path, &crate::arch::X86_64) else {
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
mod rela_table_tests {
    use super::*;
    use crate::elf_reader::{SectionTable, va_to_file_offset};

    /// The committed `test/` executables are the ones solder actually patches.
    const TEST_BINARIES: [&str; 3] = ["grep", "bash", "md5sum"];

    fn read_test_binary(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test/").to_string() + name;
        std::fs::read(&path).expect("test binary")
    }

    fn tables(bytes: &[u8]) -> RelaTables {
        let elf = ElfFile64::<object::Endianness>::parse(bytes).expect("parse the test binary");
        RelaTables::read(&elf, &crate::arch::X86_64).expect("read the .rela tables")
    }

    /// An entry reduced to everything anything downstream reads off it.
    fn entries(table: &[RelaEntry]) -> Vec<(u64, u64, u32, &str)> {
        table
            .iter()
            .map(|e| (e.r_info_offset, e.target_vaddr, e.r_type, e.symbol.as_str()))
            .collect()
    }

    /// `DT_JMPREL`/`DT_PLTRELSZ` and `DT_RELA`/`DT_RELASZ` have to name exactly
    /// the bytes `.rela.plt` and `.rela.dyn` do. The patcher neutralizes an
    /// entry by writing at the `r_info_offset` that comes out of these tables,
    /// and the writer rebuilds `.rela.dyn` from the region `DT_RELA` names, so
    /// the two views disagreeing means one stage editing a table the next one
    /// never read.
    #[test]
    fn pt_dynamic_and_the_section_headers_name_the_same_tables() {
        use goblin::elf::dynamic::{DT_JMPREL, DT_PLTRELSZ, DT_RELA, DT_RELASZ};

        for name in TEST_BINARIES {
            let bytes = read_test_binary(name);
            let elf = ElfFile64::<object::Endianness>::parse(&*bytes).expect("parse");
            let dynamic = DynamicTable::parse(&bytes).expect("parse .dynamic");
            let sections = SectionTable::parse(&bytes)
                .expect("read the section headers")
                .expect("the fixture has section headers");

            for (section, addr_tag, size_tag) in [
                (".rela.plt", DT_JMPREL, DT_PLTRELSZ),
                (".rela.dyn", DT_RELA, DT_RELASZ),
            ] {
                let header = sections
                    .by_name(section)
                    .unwrap_or_else(|| panic!("{name} has no {section}"));
                let va = dynamic
                    .value_of(addr_tag)
                    .unwrap_or_else(|| panic!("{name} has no dynamic tag for {section}"));
                let offset = va_to_file_offset(&elf, va)
                    .unwrap_or_else(|| panic!("{name}: {section} is in no PT_LOAD"));
                let size = dynamic
                    .value_of(size_tag)
                    .expect("a size beside the address");
                assert_eq!(
                    (offset, size),
                    (header.offset, header.size),
                    "{name}: {section}"
                );
            }
        }
    }

    /// The regression this read exists to rule out: the tables used to be found
    /// with `section_by_name`, so an executable whose section header table had
    /// been stripped yielded two *empty* ones. Every import then looked like it
    /// was not there — the merge found no symbol to take out of any library and
    /// finished with "No mergeable imported symbols found" and status 0, having
    /// changed nothing, even when `-m` named a library it had to merge.
    ///
    /// These are the loader's tables, and the loader has never read a section
    /// header.
    #[test]
    fn the_tables_survive_a_stripped_section_header_table() {
        for name in TEST_BINARIES {
            let whole = read_test_binary(name);
            let mut stripped = whole.clone();
            stripped[0x28..0x30].fill(0); // e_shoff
            stripped[0x3c..0x40].fill(0); // e_shnum, e_shstrndx
            assert!(
                SectionTable::parse(&stripped)
                    .expect("read the stripped section headers")
                    .is_none(),
                "{name}: the copy should have no usable section header table"
            );

            let before = tables(&whole);
            let after = tables(&stripped);

            assert!(
                !before.jump_slot.is_empty() && !before.dynamic.is_empty(),
                "{name}: the fixture should carry both relocation tables"
            );
            assert_eq!(
                entries(&before.jump_slot),
                entries(&after.jump_slot),
                "{name}: .rela.plt"
            );
            assert_eq!(
                entries(&before.dynamic),
                entries(&after.dynamic),
                "{name}: .rela.dyn"
            );
            assert_eq!(
                before.strong_undefined, after.strong_undefined,
                "{name}: the symbols the loader has to find"
            );
        }
    }

    /// Only `DT_RELA` tables are 24 bytes an entry. Reading a `DT_REL` one as
    /// if it were would walk off the stride and hand the patcher offsets into
    /// the middle of entries, so the tag is checked rather than assumed.
    #[test]
    fn a_rel_rather_than_rela_plt_table_is_refused() {
        use goblin::elf::dynamic::{DT_PLTREL, DT_REL};

        let mut bytes = read_test_binary("grep");
        let at = {
            let dynamic = DynamicTable::parse(&bytes).expect("parse .dynamic");
            dynamic.value_offset(
                dynamic
                    .index_of(DT_PLTREL)
                    .expect("test/grep has DT_PLTREL"),
            )
        };
        bytes[at..at + 8].copy_from_slice(&DT_REL.to_le_bytes());

        let elf = ElfFile64::<object::Endianness>::parse(&*bytes).expect("parse");
        let Err(e) = RelaTables::read(&elf, &crate::arch::X86_64) else {
            panic!("a DT_REL jump-slot table must be refused");
        };
        let err = format!("{e:#}");
        assert!(err.contains("DT_PLTREL"), "{err}");
    }
}

#[cfg(test)]
mod unresolvable_dependency_tests {
    use super::*;
    use crate::elf_reader::MappedElf;

    const GREP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/grep");
    const LIBS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs");

    /// The soname the fixture's second dependency is renamed to. No search
    /// directory, cache or default path can hold it, whatever machine the test
    /// runs on — which is the point: `test/grep`'s real dependencies are
    /// `libpcre2-8.so.0` (shipped in `test/libs`) and `libc.so.6` (never
    /// merged), so neither exercises a candidate library that cannot be found.
    ///
    /// It has to be no longer than the string it replaces: `.dynstr` is
    /// rewritten in place, so growing it would shift every string behind it.
    const ABSENT: &str = "libx.so.9";

    /// A copy of `test/grep` whose `libc.so.6` dependency is renamed to
    /// [`ABSENT`], leaving an executable with one dependency that resolves and
    /// one that cannot.
    fn grep_needing_an_absent_library() -> tempfile::NamedTempFile {
        let mut bytes = std::fs::read(GREP).expect("read test/grep");

        let from = b"libc.so.6\0";
        let mut to = ABSENT.as_bytes().to_vec();
        to.resize(from.len(), 0);

        // Every spelling of the soname in the file, which is both the
        // `DT_NEEDED` string and the `.gnu.version_r` file name beside it.
        let mut renamed = 0;
        let mut at = 0;
        while let Some(found) = bytes[at..].windows(from.len()).position(|w| w == from) {
            let start = at + found;
            bytes[start..start + to.len()].copy_from_slice(&to);
            at = start + to.len();
            renamed += 1;
        }
        assert!(renamed > 0, "test/grep should name libc.so.6 somewhere");

        let file = tempfile::NamedTempFile::new().expect("temp executable");
        std::fs::write(file.path(), &bytes).expect("write the renamed fixture");
        file
    }

    /// A dependency that is not installed where the merge runs is not a reason
    /// to merge nothing: the executable keeps naming it in `DT_NEEDED` and
    /// resolves it wherever it ends up running, exactly as it did before, while
    /// the libraries that *are* here still get merged.
    #[test]
    fn a_dependency_that_cannot_be_found_is_skipped_rather_than_failing_the_merge() {
        let fixture = grep_needing_an_absent_library();
        let mapped = MappedElf::open(fixture.path()).expect("open the fixture");
        let exe = mapped.parse().expect("parse the fixture");
        let dyn_info =
            parse_dynamic(&exe, fixture.path(), &crate::arch::X86_64).expect("parse .dynamic");
        assert_eq!(
            dyn_info.needed,
            vec!["libpcre2-8.so.0".to_string(), ABSENT.to_string()],
            "the fixture should need one library that resolves and one that cannot"
        );

        let rela =
            RelaTables::read(&exe, &crate::arch::X86_64).expect("read the fixture's .rela tables");
        let libs = [PathBuf::from(LIBS)];
        let cache = LdsoCache::load(&crate::arch::X86_64);

        let search = LibrarySearch::new(&dyn_info, &libs, &cache, &crate::arch::X86_64);
        let info = collect_imports(&rela, &search, None)
            .expect("an unresolvable dependency must not fail a merge nobody asked for");
        assert_eq!(
            info.merged_libs
                .iter()
                .map(|lib| lib.soname.as_str())
                .collect::<Vec<_>>(),
            ["libpcre2-8.so.0"],
            "the library that is here should still be a merge candidate"
        );
        assert!(
            info.imports.iter().any(|i| i.name.starts_with("pcre2_")),
            "symbols should still be taken out of it"
        );
    }

    /// Named with `-m`, the same library is an error: merging a subset of what
    /// the user asked for is what `validate_merge_filter` exists to prevent,
    /// and a soname that cannot be resolved is no more mergeable than one the
    /// executable never linked against.
    #[test]
    fn the_same_dependency_is_an_error_when_the_user_asked_for_it() {
        let fixture = grep_needing_an_absent_library();
        let mapped = MappedElf::open(fixture.path()).expect("open the fixture");
        let exe = mapped.parse().expect("parse the fixture");
        let dyn_info =
            parse_dynamic(&exe, fixture.path(), &crate::arch::X86_64).expect("parse .dynamic");
        let rela =
            RelaTables::read(&exe, &crate::arch::X86_64).expect("read the fixture's .rela tables");
        let libs = [PathBuf::from(LIBS)];
        let cache = LdsoCache::load(&crate::arch::X86_64);

        let filter = [ABSENT.to_string()];
        let search = LibrarySearch::new(&dyn_info, &libs, &cache, &crate::arch::X86_64);
        let Err(err) = collect_imports(&rela, &search, Some(&filter)) else {
            panic!("a library named with -m has to be merged or refused");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains(ABSENT), "{msg}");
        assert!(msg.contains("-L"), "{msg}");
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

/// The lookups [`super::LibrarySearch`] performs, end to end against the
/// fixtures: the rules above decide which directories apply, and these pin
/// that an entry is actually resolved and read through them.
#[cfg(test)]
mod library_search_tests {
    use super::{DynamicInfo, LibrarySearch, MergedLibrary};
    use crate::lib_discovery::LdsoCache;
    use std::path::{Path, PathBuf};

    const LIBS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs");
    const TINFO: &str = "libtinfo.so.6";

    /// An executable with no search path of its own, so only the directories
    /// solder was given can resolve anything.
    fn exe_without_a_search_path() -> DynamicInfo {
        DynamicInfo {
            needed: vec![TINFO.to_owned()],
            rpath: Vec::new(),
            runpath: Vec::new(),
            origin: PathBuf::from("/nonexistent"),
        }
    }

    /// A merged library whose own `DT_RPATH` is `dir`.
    fn lib_with_rpath(dir: &Path) -> MergedLibrary {
        MergedLibrary {
            soname: "libfoo.so.1".to_owned(),
            path: PathBuf::from(LIBS).join("libfoo.so.1"),
            needed: vec![TINFO.to_owned()],
            rpath: vec![dir.to_path_buf()],
            runpath: Vec::new(),
        }
    }

    /// The directories `-L` and `$SYSROOT/lib` contribute are searched for an
    /// entry the executable declares, and the file found there is the one whose
    /// exports the merge reads. This is how every fixture merge resolves its
    /// libraries: `test/libs` holds sonames that are not the host's.
    #[test]
    fn an_executables_entry_resolves_through_solders_own_directories() {
        let exe = exe_without_a_search_path();
        let cache = LdsoCache::load(&crate::arch::X86_64);
        let search = LibrarySearch::new(&exe, &[PathBuf::from(LIBS)], &cache, &crate::arch::X86_64);

        assert_eq!(search.exe_needed(), [TINFO.to_owned()]);
        let (path, lib) = search.read(TINFO).expect("-L should resolve the fixture");
        assert_eq!(path, Path::new(LIBS).join(TINFO));
        assert!(lib.defined.contains("baudrate"), "no exports were read");
        assert_eq!(lib.needed, ["libc.so.6"]);
    }

    /// A dependency of a library being merged away is looked up through *that*
    /// library's `DT_RPATH` first, so a copy sitting there wins over the one
    /// solder's own directories hold. Getting this wrong reads the exports of a
    /// file the merged library never loaded, and those exports are what decide
    /// whether its `DT_NEEDED` entry is inherited at all.
    #[test]
    fn a_declarers_own_rpath_wins_over_solders_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundled = dir.path().join(TINFO);
        std::fs::copy(Path::new(LIBS).join(TINFO), &bundled).expect("bundle a copy");

        let exe = exe_without_a_search_path();
        let cache = LdsoCache::load(&crate::arch::X86_64);
        let search = LibrarySearch::new(&exe, &[PathBuf::from(LIBS)], &cache, &crate::arch::X86_64);
        let declarer = lib_with_rpath(dir.path());

        let (path, _) = search
            .read_declared_by(Some(&declarer), TINFO)
            .expect("the declarer's own DT_RPATH holds a copy");
        assert_eq!(path, bundled);

        // With no declarer there is no other object's search path to apply, so
        // the same entry falls back to the executable's.
        let (path, _) = search
            .read_declared_by(None, TINFO)
            .expect("the executable's search path holds a copy too");
        assert_eq!(path, Path::new(LIBS).join(TINFO));
    }
}

#[cfg(test)]
mod absorbed_library_tests {
    use super::{ImportInfo, MergedLibrary};
    use crate::types::ImportedSymbol;
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
            got_vaddr: 0,
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

#[cfg(test)]
mod unprovided_import_tests {
    use super::*;
    use crate::elf_reader::MappedElf;

    const GREP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/grep");
    const PCRE2: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs/libpcre2-8.so.0");

    fn names(symbols: &[&str]) -> BTreeSet<String> {
        symbols.iter().map(|s| (*s).to_owned()).collect()
    }

    fn defines(symbols: &[&str]) -> HashSet<String> {
        symbols.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A copy of `test/libs/libpcre2-8.so.0` that no longer exports
    /// `pcre2_match_8`: the symbol is renamed in `.dynstr`, which is what an
    /// executable meets when the copy of a soname on the search path is not the
    /// build it was linked against.
    ///
    /// The replacement is the same length, since `.dynstr` is a run of
    /// NUL-terminated strings indexed by offset and a shorter one would move
    /// every string behind it.
    fn libpcre2_without_match(dir: &Path) {
        let mut bytes = std::fs::read(PCRE2).expect("read libpcre2-8.so.0");
        let from = b"pcre2_match_8\0";
        let at = bytes
            .windows(from.len())
            .position(|w| w == from)
            .expect("libpcre2-8.so.0 exports pcre2_match_8");
        bytes[at + from.len() - 2] = b'9';

        std::fs::write(dir.join("libpcre2-8.so.0"), &bytes).expect("write the doctored library");
    }

    /// The symbols `test/grep` still leaves to the loader after merging
    /// whatever the library in `lib_dir` could provide.
    fn still_imported(lib_dir: &Path) -> BTreeSet<String> {
        let mapped = MappedElf::open(Path::new(GREP)).expect("open test/grep");
        let exe = mapped.parse().expect("parse test/grep");
        let dyn_info =
            parse_dynamic(&exe, Path::new(GREP), &crate::arch::X86_64).expect("parse .dynamic");
        let rela = RelaTables::read(&exe, &crate::arch::X86_64).expect("read .rela tables");

        let cache = LdsoCache::load(&crate::arch::X86_64);
        let search = LibrarySearch::new(
            &dyn_info,
            &[lib_dir.to_path_buf()],
            &cache,
            &crate::arch::X86_64,
        );
        let info = collect_imports(&rela, &search, None).expect("collect imports");

        let merged: HashSet<String> = info.imports.iter().map(|i| i.name.clone()).collect();
        rela.loader_resolved_imports(&merged)
    }

    /// The case the whole check exists for: the library on the search path is
    /// missing a symbol the executable imports from it, so the merge takes the
    /// rest of its code — dropping its `DT_NEEDED` entry — and leaves that one
    /// symbol for a loader that now has nowhere to look it up.
    #[test]
    fn a_symbol_the_merged_library_never_defined_is_left_unprovided() {
        let dir = tempfile::tempdir().expect("tempdir");
        libpcre2_without_match(dir.path());
        let left = still_imported(dir.path());
        assert!(
            left.contains("pcre2_match_8"),
            "the symbol the library no longer defines is still imported: {left:?}"
        );
        assert!(
            !left.contains("pcre2_compile_8"),
            "a symbol the merge did take must not be counted: {left:?}"
        );

        // Everything else grep imports comes from libc, which is what stays.
        let libc = defines(
            &left
                .iter()
                .filter(|n| !n.starts_with("pcre2_"))
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let unprovided = unprovided_imports(&left, ["libc.so.6"], &mut |_| Some(libc.clone()))
            .expect("every remaining library was readable");
        assert_eq!(unprovided, ["pcre2_match_8"]);
    }

    /// The same executable merged against the real library leaves nothing
    /// behind: every pcre2 symbol it imports is merged, and libc keeps the
    /// rest.
    #[test]
    fn the_matching_library_leaves_nothing_unprovided() {
        let left = still_imported(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs")));
        assert!(
            !left.iter().any(|n| n.starts_with("pcre2_")),
            "the matching library provides every pcre2 symbol grep imports: {left:?}"
        );

        let libc = defines(&left.iter().map(String::as_str).collect::<Vec<_>>());
        let unprovided = unprovided_imports(&left, ["libc.so.6"], &mut |_| Some(libc.clone()))
            .expect("every remaining library was readable");
        assert!(unprovided.is_empty(), "{unprovided:?}");
    }

    /// `__gmon_start__` and the `_ITM_*` pair are undefined in nearly every
    /// glibc binary and defined by nothing unless a profiler or a transactional
    /// memory runtime is loaded. They are weak, so the loader resolves them to
    /// zero instead of failing — counting them would refuse every merge there
    /// is.
    #[test]
    fn a_weak_undefined_symbol_is_not_something_the_loader_has_to_find() {
        let left = still_imported(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs")));
        for weak in ["__gmon_start__", "_ITM_registerTMCloneTable"] {
            assert!(
                !left.contains(weak),
                "{weak} is weak and undefined in test/grep, with a relocation of its own"
            );
        }
    }

    /// The interpreter is never named in `DT_NEEDED` and still defines symbols
    /// executables import, so it counts as one of the objects the merged
    /// binary is linked against.
    #[test]
    fn the_interpreter_provides_symbols_no_dt_needed_entry_does() {
        let left = names(&["__tls_get_addr"]);
        let unprovided = unprovided_imports(
            &left,
            ["libc.so.6", "/lib64/ld-linux-x86-64.so.2"],
            &mut |entry| {
                Some(match entry {
                    "/lib64/ld-linux-x86-64.so.2" => defines(&["__tls_get_addr"]),
                    _ => defines(&["malloc"]),
                })
            },
        )
        .expect("both were readable");
        assert!(unprovided.is_empty(), "{unprovided:?}");
    }

    /// A library solder cannot read may define anything, so the answer is "no
    /// idea" rather than "nothing defines it" — refusing a merge over a symbol
    /// that an unread file turns out to define would block work that is fine.
    #[test]
    fn a_library_that_cannot_be_read_makes_the_answer_inconclusive() {
        let left = names(&["pcre2_match_8"]);
        assert!(
            unprovided_imports(&left, ["libwhoknows.so.1"], &mut |_| None).is_none(),
            "an unreadable library leaves the question open"
        );
    }

    /// Once every symbol has a provider the rest of the link does not matter,
    /// including the part of it solder cannot read.
    #[test]
    fn an_unreadable_library_behind_a_complete_answer_does_not_matter() {
        let left = names(&["getenv"]);
        let unprovided = unprovided_imports(
            &left,
            ["libc.so.6", "libwhoknows.so.1"],
            &mut |entry| match entry {
                "libc.so.6" => Some(defines(&["getenv"])),
                _ => None,
            },
        )
        .expect("libc already accounted for everything");
        assert!(unprovided.is_empty(), "{unprovided:?}");
    }
}
