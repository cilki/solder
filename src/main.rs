mod dep_graph;
mod eh_frame;
mod elf_reader;
mod extractor;
mod jump_table;
mod layout;
mod lib_discovery;
mod patcher;
mod relocator;
mod symbol_analysis;
mod types;
mod writer;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

use elf_reader::MappedElf;
use lib_discovery::{LdsoCache, resolve_library};
use symbol_analysis::{RelaTables, collect_imports, parse_dynamic};

#[derive(Parser)]
#[command(
    version,
    name = "solder",
    about = "Post-link static merger for ELF shared libraries\n\n\
             Extracts the symbols actually used from shared libraries and merges\n\
             them directly into the executable, pre-filling GOT entries so the\n\
             merged libraries no longer need to be present at runtime."
)]
struct Cli {
    /// ELF executable to merge libraries into (modified in-place)
    input: PathBuf,

    /// Merge only specific libraries (by soname, e.g. libz.so.1).
    /// If omitted, all non-excluded DT_NEEDED libraries are merged.
    #[arg(short = 'm', long = "merge", value_name = "SONAME")]
    merge_libs: Vec<String>,

    /// Additional library search directories (searched after the executable's
    /// DT_RPATH and $SYSROOT/lib, ahead of LD_LIBRARY_PATH)
    #[arg(short = 'L', long = "library-path", value_name = "PATH")]
    library_path: Vec<PathBuf>,

    /// Analyse and print the merge plan without writing any output
    #[arg(long)]
    dry_run: bool,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let merge_filter: Option<&[String]> = if cli.merge_libs.is_empty() {
        None
    } else {
        Some(&cli.merge_libs)
    };

    // Build library search path, prepending $SYSROOT/lib if SYSROOT is set
    let mut library_path = cli.library_path.clone();
    if let Ok(sysroot) = std::env::var("SYSROOT") {
        library_path.insert(0, PathBuf::from(sysroot).join("lib"));
    }

    // ── Step 0: load and validate the input executable ───────────────────────
    let exe_mapped =
        MappedElf::open(&cli.input).with_context(|| format!("opening {}", cli.input.display()))?;
    let exe_elf = exe_mapped.parse()?;

    let is_pie = elf_reader::validate_executable(&exe_elf, &cli.input)?;

    if is_pie {
        info!("Input is a PIE executable (ET_DYN)");
    }

    // ── Step 1: parse dynamic section + collect imports ──────────────────────
    let dyn_info = parse_dynamic(&exe_elf, &cli.input)?;

    if dyn_info.needed.is_empty() {
        anyhow::bail!("executable has no DT_NEEDED entries — nothing to merge");
    }

    let ldso_cache = LdsoCache::load();

    // The executable's `.rela.plt` and `.rela.dyn`, decoded once: which symbols
    // it imports and through which GOT slot, which JUMP_SLOT and COPY entries
    // the patcher has to neutralize, and which slots a trampoline can reuse all
    // come out of these two tables.
    let rela = RelaTables::read(&exe_elf).context("reading the executable's .rela tables")?;

    let import_info = collect_imports(
        &exe_elf,
        &rela,
        &dyn_info,
        &ldso_cache,
        &library_path,
        merge_filter,
    )?;
    let imports = &import_info.imports;
    let merged_lib_syms = &import_info.merged_lib_syms;

    if imports.is_empty() {
        warn!("No mergeable imported symbols found");
        return Ok(());
    }

    for imp in imports {
        info!(
            kind=?imp.kind,
            name=imp.name,
            source=%imp.source_library.display(),
            "Imported symbol to merge"
        );
    }

    // ── Step 2: transitive closure extraction ────────────────────────────────
    // A variable the executable copy-relocates stays the executable's: the
    // extracted code has to reach that copy rather than the definition in the
    // library it is being lifted out of.
    let copy_relocated = rela.copy_reloc_symbols();

    let extractor::Extraction {
        units,
        init_fini,
        got_slot_fixups,
        data_section_copies,
    } = extractor::extract_units(imports, &exe_elf, merged_lib_syms, &copy_relocated)?;

    for u in &units {
        info!(
            section_kind=?u.section_kind,
            name=u.name,
            size=u.bytes.len(),
            relocations=u.relocations.len(),
            source=%u.source_lib.display(),
            "Extracted unit"
        );
    }
    let total: usize = units.iter().map(|u| u.bytes.len()).sum();
    info!(
        total_bytes = total,
        units = units.len(),
        "Extraction complete"
    );

    // Warned rather than logged at `info!`, which the default filter drops:
    // a data section copied past what the merged code reads is the step of the
    // merge with the least bound on it, and the pointers it roots are what turn
    // a handful of imported symbols into most of a library. Nothing else in a
    // successful run says so — the output is correct, just larger than the
    // symbols asked for. A copy that is exactly the bytes referenced is not
    // worth a line; the two that are each explain themselves differently.
    for copy in data_section_copies.iter().filter(|c| c.is_oversized()) {
        if copy.runs_to_section_end() {
            // The copy's end is where the section's is, so what it took is
            // either all of the section or everything from its first reference
            // on.
            let extent = if copy.start_offset == 0 {
                format!("merged whole — {} bytes", copy.bytes)
            } else {
                format!(
                    "merged {} of {} bytes, everything from offset {} on",
                    copy.bytes, copy.section_bytes, copy.start_offset
                )
            };
            warn!(
                "{} {}: {extent} and {} pointers that root further extraction — \
                 because no symbol and no unwind record bounds the object at \
                 {:#x} that '{}' references, and the reference says nothing \
                 about its size either",
                copy.library.display(),
                copy.section,
                copy.pointers,
                copy.address,
                copy.reached_from
            );
        } else {
            warn!(
                "{} {}: merged {} of {} bytes from offset {} — of which the first \
                 {} precede everything the merge references, kept because they \
                 hold pointers the extraction already rests on — and {} pointers \
                 that root further extraction, because no symbol and no unwind \
                 record bounds the object at {:#x} that '{}' references",
                copy.library.display(),
                copy.section,
                copy.bytes,
                copy.section_bytes,
                copy.start_offset,
                copy.unreferenced_prefix,
                copy.pointers,
                copy.address,
                copy.reached_from
            );
        }
    }

    if !init_fini.init_entries.is_empty() || !init_fini.fini_entries.is_empty() {
        info!(
            init_entries = init_fini.init_entries.len(),
            fini_entries = init_fini.fini_entries.len(),
            "Init/fini arrays"
        );
    }

    // ── Step 2.5: topological ordering of merged libraries ────────────────────
    // The libraries that actually gave up a symbol, in DT_NEEDED order, which
    // is also exactly the set whose sonames the merge removes.
    let absorbed: Vec<&symbol_analysis::MergedLibrary> = import_info.absorbed_libraries().collect();
    let lib_order = dep_graph::topological_order(&absorbed)?;

    // ── Step 3: layout planning ───────────────────────────────────────────────
    let mut plan = layout::plan_layout(
        units,
        &exe_elf,
        imports,
        &rela.got_slot_vas(),
        is_pie,
        init_fini,
        &lib_order,
        got_slot_fixups,
    )?;

    // Nothing in the executable reaches these libraries any more, so their
    // DT_NEEDED entries (and the version requirements against them) go.
    plan.remove_needed = absorbed.iter().map(|lib| lib.soname.clone()).collect();

    info!(
        load_address = format_args!("0x{:016x}", plan.load_address),
        got_patches = plan.got_patches.len(),
        trampolines = plan.trampoline_stubs.len(),
        new_externals = plan.new_externals.len(),
        "Merge plan"
    );
    for ext in &plan.new_externals {
        info!(
            symbol = ext.name,
            got_vaddr = format_args!("0x{:x}", ext.got_vaddr),
            "New external symbol (injected into .dynsym)"
        );
    }
    for t in &plan.trampoline_stubs {
        info!(
            symbol = t.symbol_name,
            vaddr = format_args!("0x{:x}", t.vaddr),
            got_vaddr = format_args!("0x{:x}", t.target_got_vaddr),
            "Trampoline"
        );
    }
    info!(remove_needed=?plan.remove_needed, "DT_NEEDED entries to remove");

    // ── Step 3.5: inherit the merged libraries' own dependencies ─────────────
    // The merged code keeps calling into whatever its library linked against,
    // so any dependency that still provides one of those symbols has to move
    // onto the executable's DT_NEEDED as the merged library leaves it.
    plan.add_needed = {
        let injected: HashSet<String> = plan
            .new_externals
            .iter()
            .map(|e| e.name.clone())
            .chain(plan.got_imports.iter().map(|g| g.name.clone()))
            .collect();

        // A dependency is looked up the way ld.so looks it up for the library
        // that declared it: through that library's own DT_RPATH/DT_RUNPATH
        // ahead of the executable's, and with `$ORIGIN` — in a search-path
        // entry as in a path-valued DT_NEEDED one — meaning the declaring
        // library's directory rather than the executable's. The first library
        // to name a dependency decides, as it did when each entry carried its
        // own origin.
        let mut declarer: HashMap<&str, &symbol_analysis::MergedLibrary> = HashMap::new();
        for &lib in &absorbed {
            for dep in &lib.needed {
                declarer.entry(dep.as_str()).or_insert(lib);
            }
        }

        let mut exe_rpath = dyn_info.search_rpath().to_vec();
        exe_rpath.extend_from_slice(&library_path);
        let mut resolve_exports = |soname: &str| {
            let (rpath, runpath, origin) = match declarer.get(soname) {
                Some(lib) => {
                    let (rpath, runpath) = symbol_analysis::dependency_search_path(lib, &exe_rpath);
                    (
                        rpath,
                        runpath,
                        lib.path.parent().unwrap_or(dyn_info.origin.as_path()),
                    )
                }
                // Nothing being merged away declares this entry, so there is no
                // other object whose search path could apply to it.
                None => (
                    exe_rpath.clone(),
                    dyn_info.runpath.as_slice(),
                    dyn_info.origin.as_path(),
                ),
            };
            resolve_library(soname, &rpath, runpath, &ldso_cache, origin)
                .and_then(|path| {
                    symbol_analysis::read_library_dynamic(&path).map(|lib| (path, lib.defined))
                })
                .ok()
        };

        symbol_analysis::inherited_needed(
            absorbed
                .iter()
                .flat_map(|lib| lib.needed.iter().map(String::as_str)),
            &dyn_info.needed,
            &plan.remove_needed,
            &injected,
            &mut resolve_exports,
        )?
    };
    info!(add_needed=?plan.add_needed, "DT_NEEDED entries to add");

    // ── Step 3.6: every symbol the loader is left looking for has a home ─────
    // A symbol the library solder read does not define is left dynamic, while
    // that library's soname goes out of DT_NEEDED with the code that was
    // merged. If the copy solder found is not the one the executable was
    // linked against, that pairing leaves a live relocation against a symbol
    // nothing in the link defines any more.
    let merged_names: HashSet<String> = imports.iter().map(|i| i.name.clone()).collect();
    refuse_unresolvable_imports(
        &exe_elf,
        &rela,
        &dyn_info,
        &plan,
        &merged_names,
        &ldso_cache,
        &library_path,
    )?;

    // The loader protects the range `PT_GNU_RELRO` names and nothing else, and
    // the merged region is necessarily outside it. Say so before writing
    // anything, since the result is a binary whose function-pointer tables are
    // writable where they were read-only before.
    if let Some(downgrade) = layout::relro_downgrade(&exe_elf, &plan) {
        warn!("{downgrade}");
    }

    if cli.dry_run {
        print_merge_plan(
            &cli.input,
            &plan,
            imports,
            &dyn_info.needed,
            &data_section_copies,
        );
        return Ok(());
    }

    // ── Step 4: apply relocations ─────────────────────────────────────────────
    relocator::apply_all_relocations(&mut plan)?;

    // ── Step 5: patch executable in-place (GOT, JUMP_SLOTs, DT_NEEDED) ───────
    // Find JUMP_SLOT reloc file offsets for the merged symbols.
    plan.jump_slot_reloc_offsets =
        symbol_analysis::find_jump_slot_reloc_offsets(&rela, &merged_names);

    // Neutralize copy relocations for data symbols exported by a library we are
    // removing (e.g. ncurses' UP/PC/BC). Only symbols a library we are dropping
    // provides are eligible, so a candidate library that stays in DT_NEEDED
    // keeps its copy relocations.
    let removed_libs: HashSet<&std::path::Path> =
        absorbed.iter().map(|lib| lib.path.as_path()).collect();
    let removed_provided_syms: HashSet<String> = merged_lib_syms
        .iter()
        .filter(|(_, lib)| removed_libs.contains(lib.as_path()))
        .map(|(name, _)| name.clone())
        .collect();
    let copy_relocs = symbol_analysis::find_copy_reloc_offsets(&rela, &removed_provided_syms);
    for (off, name) in copy_relocs {
        if let Some(lib) = merged_lib_syms.get(&name)
            && !symbol_analysis::symbol_is_zero_initialized(lib, &name)?
        {
            anyhow::bail!(
                "copy-relocated symbol '{name}' from {} has a non-zero initializer; \
                 preserving copy-relocation initial values is not yet supported",
                lib.display()
            );
        }
        plan.copy_reloc_offsets.push(off);
    }

    let mut patched_exe = exe_mapped.bytes().to_vec();
    patcher::apply_patches(&mut patched_exe, &mut plan)?;

    // ── Step 6: build merged segment + write output ────────────────────────────
    let merged_seg = writer::build_merged_segment(&mut plan)?;
    writer::write_output(&patched_exe, &plan, &merged_seg, &cli.input)?;

    if plan.is_pie {
        info!(
            count = plan.relative_relocs.len(),
            "Added R_X86_64_RELATIVE relocations for PIE"
        );
    }

    info!(
        symbols=imports.len(),
        bytes=merged_seg.len(),
        output=%cli.input.display(),
        "Merge complete"
    );

    Ok(())
}

/// Stop a merge that would leave the executable importing a symbol none of the
/// libraries it is still linked against defines.
///
/// Such a binary does not run: solder forces `DF_BIND_NOW`, so the loader
/// resolves every remaining JUMP_SLOT and GLOB_DAT before `main` and fails the
/// whole process when one of them has no definition. It is worth a refusal
/// rather than a warning because there is no half of it worth keeping — the
/// executable that was there before the merge still runs, and the one solder
/// would write in its place does not.
///
/// The check needs to read every object the merged executable would be linked
/// against, so anything solder cannot find makes it inconclusive and the merge
/// goes ahead unjudged: that is the same file set the loader will search, and
/// the entry solder cannot open may well be the one defining the symbol.
fn refuse_unresolvable_imports(
    exe_elf: &object::read::elf::ElfFile64<'_>,
    rela: &RelaTables,
    dyn_info: &symbol_analysis::DynamicInfo,
    plan: &types::MergePlan,
    merged: &HashSet<String>,
    ldso_cache: &LdsoCache,
    library_path: &[PathBuf],
) -> Result<()> {
    let loader_resolved = rela.loader_resolved_imports(merged);
    if loader_resolved.is_empty() {
        return Ok(());
    }

    // What the executable's DT_NEEDED says after the merge: the entries no
    // merged library took with it, plus the ones inherited from the libraries
    // that did go. The interpreter rides along, defining symbols of its own
    // without ever being listed.
    let remaining: Vec<&str> = dyn_info
        .needed
        .iter()
        .map(String::as_str)
        .filter(|needed| !plan.remove_needed.iter().any(|gone| gone == needed))
        .chain(plan.add_needed.iter().map(String::as_str))
        .chain(elf_reader::interpreter(exe_elf))
        .collect();

    let mut exe_rpath = dyn_info.search_rpath().to_vec();
    exe_rpath.extend_from_slice(library_path);
    let mut unreadable = None;
    let mut consulted: Vec<String> = Vec::new();
    let mut resolve = |entry: &str| -> Option<HashSet<String>> {
        // Every one of these is looked up the way the loader looks it up for
        // the *executable*, which is what each one of them is a dependency of
        // once the merge is done.
        let found = resolve_library(
            entry,
            &exe_rpath,
            &dyn_info.runpath,
            ldso_cache,
            &dyn_info.origin,
        )
        .and_then(|path| {
            symbol_analysis::read_library_dynamic(&path).map(|lib| (path, lib.defined))
        });
        match found {
            Ok((path, defined)) => {
                consulted.push(format!("{} ({entry})", path.display()));
                Some(defined)
            }
            Err(e) => {
                unreadable = Some(format!("{entry}: {e:#}"));
                None
            }
        }
    };

    let Some(unprovided) = symbol_analysis::unprovided_imports(
        &loader_resolved,
        remaining.iter().copied(),
        &mut resolve,
    ) else {
        warn!(
            reason = unreadable,
            "Cannot check that the symbols the merged binary still imports will resolve: \
             one of the libraries it stays linked against could not be read. Point -L or \
             $SYSROOT at it to have the merge verify that"
        );
        return Ok(());
    };
    if unprovided.is_empty() {
        return Ok(());
    }

    // Listing every missing symbol helps nobody once there are dozens of them;
    // the first few are enough to recognize which library is the wrong one.
    const SHOWN: usize = 8;
    let shown = unprovided
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "the merged executable would import {} that nothing it is still linked against \
         defines: {shown}{}. A library that does not define everything the executable \
         imports from it is not the copy the executable was linked against, so the merge \
         would take its code and leave those symbols for a loader with nowhere to find \
         them — the binary would fail to start. Libraries consulted: {}. Point -L or \
         $SYSROOT at the matching copy, or leave that library out of the merge with -m.",
        if unprovided.len() == 1 {
            "a symbol".to_owned()
        } else {
            format!("{} symbols", unprovided.len())
        },
        if unprovided.len() > SHOWN {
            format!(", and {} more", unprovided.len() - SHOWN)
        } else {
            String::new()
        },
        consulted.join(", "),
    )
}

/// Print the merge plan for `--dry-run`.
///
/// This goes to stdout directly rather than through `tracing`: previewing the
/// plan is the whole point of the flag, and the default log filter is `warn`,
/// so routing it through `info!` meant `solder --dry-run` printed nothing at
/// all unless the user happened to set `RUST_LOG`.
fn print_merge_plan(
    input: &std::path::Path,
    plan: &types::MergePlan,
    imports: &[types::ImportedSymbol],
    needed: &[String],
    data_section_copies: &[types::DataSectionCopy],
) {
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct LibStats {
        symbols: usize,
        units: usize,
        bytes: usize,
    }

    let mut per_lib: BTreeMap<&std::path::Path, LibStats> = BTreeMap::new();
    for imp in imports {
        per_lib
            .entry(imp.source_library.as_path())
            .or_default()
            .symbols += 1;
    }
    for au in &plan.units {
        let stats = per_lib.entry(au.unit.source_lib.as_path()).or_default();
        stats.units += 1;
        stats.bytes += au.unit.bytes.len();
    }

    println!("Merge plan for {}", input.display());
    println!("  libraries to merge:");
    for (lib, stats) in &per_lib {
        println!(
            "    {} ({} imported symbols, {} units, {} bytes)",
            lib.display(),
            stats.symbols,
            stats.units,
            stats.bytes
        );
    }

    // The totals behind the per-copy warnings printed above: how much of what
    // is about to be merged is there because a data object could not be
    // bounded, rather than because a symbol the executable imports needs it.
    if !data_section_copies.is_empty() {
        let bytes: usize = data_section_copies.iter().map(|c| c.bytes).sum();
        let pointers: usize = data_section_copies.iter().map(|c| c.pointers).sum();
        let whole = data_section_copies
            .iter()
            .filter(|c| c.runs_to_section_end())
            .count();
        println!(
            "  data sections copied for want of a symbol: {} ({} of them whole \
             for want of a bound, {} bytes, {} pointers rooting further \
             extraction)",
            data_section_copies.len(),
            whole,
            bytes,
            pointers
        );
    }

    if plan.remove_needed.is_empty() {
        println!("  no DT_NEEDED entries become removable");
    } else {
        println!(
            "  DT_NEEDED entries removed: {}",
            plan.remove_needed.join(", ")
        );
    }
    let kept: Vec<&str> = needed
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !plan.remove_needed.iter().any(|r| r == s))
        .collect();
    if !kept.is_empty() {
        println!("  DT_NEEDED entries kept: {}", kept.join(", "));
    }
    if !plan.add_needed.is_empty() {
        println!(
            "  DT_NEEDED entries inherited from the merged libraries: {}",
            plan.add_needed.join(", ")
        );
    }

    println!(
        "  new mapping at 0x{:016x}, {} bytes: {} read-execute (code, trampolines), \
         {} read-only (constants), {} read-write (data, loader-written slots)",
        plan.load_address,
        plan.segment_size(),
        plan.exec_size,
        plan.rodata_end - plan.exec_size,
        plan.writable_end - plan.rodata_end
    );
    println!("  GOT entries patched: {}", plan.got_patches.len());
    println!(
        "  trampolines for symbols still resolved at runtime: {}",
        plan.trampoline_stubs.len()
    );
    println!(
        "  symbols injected into .dynsym: {}",
        plan.new_externals.len()
    );
    if let Some(init_fini) = &plan.init_fini {
        // Both arrays are rebuilt whole: the merged libraries' entries *and*
        // whatever the executable already had in the corresponding array, which
        // has to keep running. Calling the totals "merged" overstated how many
        // constructors the merge is adding.
        println!(
            "  rebuilt preinit array entries: {}, fini array entries: {} \
             (merged constructors and destructors, plus the executable's own)",
            init_fini.preinit.entries.len(),
            init_fini.fini.entries.len()
        );
    }
    println!("Dry run: {} left unchanged", input.display());
}
