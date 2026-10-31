// Only the tests reach it until the extractor decodes aarch64 code; see the
// module's own comment.
#[cfg_attr(not(test), allow(dead_code))]
mod aarch64;
mod arch;
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
use lib_discovery::LdsoCache;
use symbol_analysis::{LibrarySearch, RelaTables, collect_imports, parse_dynamic};

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

    let (arch, is_pie) = elf_reader::validate_executable(&exe_elf, &cli.input)?;

    if is_pie {
        info!("Input is a PIE executable (ET_DYN)");
    }

    // ── Step 1: parse dynamic section + collect imports ──────────────────────
    let dyn_info = parse_dynamic(&exe_elf, &cli.input, arch)?;

    if dyn_info.needed.is_empty() {
        anyhow::bail!("executable has no DT_NEEDED entries — nothing to merge");
    }

    let ldso_cache = LdsoCache::load(arch);

    // Every `DT_NEEDED` lookup the merge makes goes through this: the search
    // path ld.so uses for the executable, with solder's own `-L` and
    // `$SYSROOT/lib` directories folded in.
    let search = LibrarySearch::new(&dyn_info, &library_path, &ldso_cache, arch);

    // The executable's `.rela.plt` and `.rela.dyn`, decoded once: which symbols
    // it imports and through which GOT slot, which JUMP_SLOT and COPY entries
    // the patcher has to neutralize, and which slots a trampoline can reuse all
    // come out of these two tables.
    let rela = RelaTables::read(&exe_elf, arch).context("reading the executable's .rela tables")?;

    let import_info = collect_imports(&exe_elf, &rela, &search, merge_filter)?;
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
    } = extractor::extract_units(imports, &exe_elf, merged_lib_syms, &copy_relocated, arch)?;

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
        if let Some(unbounded) = &copy.unbounded_end {
            // Nothing says where the referenced object ends, so the copy runs
            // to the next thing the library does name — and in a library that
            // names nothing in its data sections, that is the section's end.
            let extent = if copy.is_whole_section() {
                format!("merged whole — {} bytes", copy.bytes)
            } else {
                format!(
                    "merged {} of {} bytes from offset {}, up to the next symbol \
                     the library defines in it,",
                    copy.bytes, copy.section_bytes, copy.start_offset
                )
            };
            warn!(
                "{} {}: {extent} and {} pointers that root further extraction \
                 — because no symbol and no unwind record bounds the object at \
                 {:#x} that '{}' references, and the reference says nothing \
                 about its size either",
                copy.library.display(),
                copy.section,
                copy.pointers,
                unbounded.address,
                unbounded.reached_from
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
        arch,
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

        let mut resolve_exports = |soname: &str| {
            search
                .read_declared_by(declarer.get(soname).copied(), soname)
                .map(|(path, lib)| (path, lib.defined))
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
    refuse_unresolvable_imports(&exe_elf, &rela, &search, &plan, &merged_names)?;

    // The loader protects the range `PT_GNU_RELRO` names and nothing else, and
    // the merged region is necessarily outside it. Say so before writing
    // anything, since the result is a binary whose function-pointer tables are
    // writable where they were read-only before.
    if let Some(downgrade) = layout::relro_downgrade(&exe_elf, &plan) {
        warn!("{downgrade}");
    }

    if cli.dry_run {
        let report = render_merge_plan(
            &cli.input,
            &plan,
            imports,
            &dyn_info.needed,
            &data_section_copies,
        );
        return write_report(std::io::stdout().lock(), &report);
    }

    // ── Step 4: apply relocations ─────────────────────────────────────────────
    relocator::apply_all_relocations(&mut plan)?;

    // ── Step 5: patch executable in-place (GOT, JUMP_SLOTs, DT_NEEDED) ───────
    // Find JUMP_SLOT reloc file offsets for the merged symbols.
    plan.neutralized_relocs = symbol_analysis::find_jump_slot_reloc_offsets(&rela, &merged_names);

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
        plan.neutralized_relocs.push(off);
    }

    let mut patched_exe = exe_mapped.bytes().to_vec();
    patcher::apply_patches(&mut patched_exe, &mut plan)?;

    // ── Step 6: build merged segment + write output ────────────────────────────
    let merged_seg = writer::build_merged_segment(&mut plan)?;
    writer::write_output(&patched_exe, &plan, &merged_seg, &cli.input)?;

    if plan.is_pie {
        info!(
            count = plan.relative_relocs.len(),
            "Added RELATIVE relocations for PIE"
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
    search: &LibrarySearch<'_>,
    plan: &types::MergePlan,
    merged: &HashSet<String>,
) -> Result<()> {
    let loader_resolved = rela.loader_resolved_imports(merged);
    if loader_resolved.is_empty() {
        return Ok(());
    }

    // What the executable's DT_NEEDED says after the merge: the entries no
    // merged library took with it, plus the ones inherited from the libraries
    // that did go. The interpreter rides along, defining symbols of its own
    // without ever being listed.
    let remaining: Vec<&str> = search
        .exe_needed()
        .iter()
        .map(String::as_str)
        .filter(|needed| !plan.remove_needed.iter().any(|gone| gone == needed))
        .chain(plan.add_needed.iter().map(String::as_str))
        .chain(elf_reader::interpreter(exe_elf))
        .collect();

    let mut unreadable = None;
    let mut consulted: Vec<String> = Vec::new();
    // Every one of these is looked up the way the loader looks it up for the
    // *executable*, which is what each one of them is a dependency of once the
    // merge is done.
    let mut resolve = |entry: &str| -> Option<HashSet<String>> {
        match search.read(entry) {
            Ok((path, lib)) => {
                consulted.push(format!("{} ({entry})", path.display()));
                Some(lib.defined)
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

/// Hand the rendered `--dry-run` report to stdout.
///
/// `println!` panics when stdout will not take the write, so printing the plan
/// a line at a time turned `solder --dry-run | head` — or `| grep -q`, or
/// quitting `less` — into `failed printing to stdout: Broken pipe` and exit
/// 101. A reader that stopped reading is not a failure of the run: the report
/// is rendered whole and written once, and an `EPIPE` ends the run quietly and
/// successfully, which is what clap already does for `--help` into a closed
/// pipe. Any other write error (a full disk under `> file`) is still reported
/// like every other error, rather than as a panic.
fn write_report<W: std::io::Write>(mut out: W, report: &str) -> Result<()> {
    match out.write_all(report.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other.context("writing the merge plan to stdout"),
    }
}

/// Render the merge plan for `--dry-run`.
///
/// This goes to stdout directly rather than through `tracing`: previewing the
/// plan is the whole point of the flag, and the default log filter is `warn`,
/// so routing it through `info!` meant `solder --dry-run` printed nothing at
/// all unless the user happened to set `RUST_LOG`.
fn render_merge_plan(
    input: &std::path::Path,
    plan: &types::MergePlan,
    imports: &[types::ImportedSymbol],
    needed: &[String],
    data_section_copies: &[types::DataSectionCopy],
) -> String {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    #[derive(Default)]
    struct LibStats {
        symbols: usize,
        units: usize,
        bytes: usize,
    }

    let mut report = String::new();
    // One report line. Formatting into a `String` cannot fail, so the
    // `fmt::Result` each `writeln!` hands back carries no information.
    macro_rules! say {
        ($($arg:tt)*) => {
            writeln!(report, $($arg)*).expect("formatting into a String cannot fail")
        };
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

    say!("Merge plan for {}", input.display());
    say!("  libraries to merge:");
    for (lib, stats) in &per_lib {
        say!(
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
        let unbounded = data_section_copies
            .iter()
            .filter(|c| c.unbounded_end.is_some())
            .count();
        say!(
            "  data sections copied for want of a symbol: {} ({} of them with no \
             bound but the next symbol or the section's end, {} bytes, {} \
             pointers rooting further extraction)",
            data_section_copies.len(),
            unbounded,
            bytes,
            pointers
        );
    }

    if plan.remove_needed.is_empty() {
        say!("  no DT_NEEDED entries become removable");
    } else {
        say!(
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
        say!("  DT_NEEDED entries kept: {}", kept.join(", "));
    }
    if !plan.add_needed.is_empty() {
        say!(
            "  DT_NEEDED entries inherited from the merged libraries: {}",
            plan.add_needed.join(", ")
        );
    }

    say!(
        "  new mapping at 0x{:016x}, {} bytes: {} read-execute (code, trampolines), \
         {} read-only (constants), {} read-write (data, loader-written slots)",
        plan.load_address,
        plan.segment_size(),
        plan.exec_size,
        plan.rodata_end - plan.exec_size,
        plan.writable_end - plan.rodata_end
    );
    say!("  GOT entries patched: {}", plan.got_patches.len());
    say!(
        "  trampolines for symbols still resolved at runtime: {}",
        plan.trampoline_stubs.len()
    );
    say!(
        "  symbols injected into .dynsym: {}",
        plan.new_externals.len()
    );
    if let Some(init_fini) = &plan.init_fini {
        // Both arrays are rebuilt whole: the merged libraries' entries *and*
        // whatever the executable already had in the corresponding array, which
        // has to keep running. Calling the totals "merged" overstated how many
        // constructors the merge is adding.
        say!(
            "  rebuilt preinit array entries: {}, fini array entries: {} \
             (merged constructors and destructors, plus the executable's own)",
            init_fini.preinit.entries.len(),
            init_fini.fini.entries.len()
        );
    }
    say!("Dry run: {} left unchanged", input.display());

    report
}

/// What `solder --dry-run` prints, and what happens to it when stdout will not
/// take it.
#[cfg(test)]
mod dry_run_report_tests {
    use super::{render_merge_plan, write_report};
    use crate::types::{
        AssignedUnit, DataSectionCopy, ExtractedUnit, ImportKind, ImportedSymbol, InitFiniPlan,
        MergePlan, MergedArray, SectionKind, UnboundedEnd, UnitId,
    };
    use std::io::{self, ErrorKind, Write};
    use std::path::{Path, PathBuf};

    /// A writer whose every write fails with `kind`, standing in for the stdout
    /// of a `solder --dry-run | head` whose `head` has already exited.
    struct FailingWriter(ErrorKind);

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(self.0, "writer under test"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(self.0, "writer under test"))
        }
    }

    /// An empty plan with a merged region laid out as one page of each run, so
    /// the three sizes the report derives from it are all distinguishable.
    fn plan() -> MergePlan {
        MergePlan {
            arch: &crate::arch::X86_64,
            is_pie: true,
            page_size: crate::elf_reader::MIN_PAGE_SIZE,
            load_address: 0x4_3000,
            exec_size: 0x1000,
            rodata_end: 0x3000,
            writable_end: 0x4000,
            units: Vec::new(),
            trampoline_stubs: Vec::new(),
            got_patches: Vec::new(),
            neutralized_relocs: Vec::new(),
            remove_needed: Vec::new(),
            add_needed: Vec::new(),
            relative_relocs: Vec::new(),
            new_externals: Vec::new(),
            got_imports: Vec::new(),
            init_fini: None,
        }
    }

    fn import(name: &str, lib: &str) -> ImportedSymbol {
        ImportedSymbol {
            name: name.to_owned(),
            source_library: PathBuf::from(lib),
            got_file_offset: 0,
            kind: ImportKind::JumpSlot,
        }
    }

    /// A unit of `bytes` bytes extracted from `lib`.
    fn unit(lib: &str, bytes: usize) -> AssignedUnit {
        AssignedUnit {
            unit: ExtractedUnit {
                id: UnitId(0),
                name: "unit".to_owned(),
                source_lib: PathBuf::from(lib),
                bytes: vec![0x90; bytes],
                section_kind: SectionKind::Text,
                alignment: 16,
                relocations: Vec::new(),
            },
            assigned_vaddr: 0x4_3000,
        }
    }

    /// A copy of `bytes` bytes out of a `section_bytes`-byte section, starting
    /// at `start_offset`. `end_unbounded` is what the totals line counts
    /// apart: the furthest reference into the section said nothing about the
    /// size of what it points at, so the copy ends where the next symbol or
    /// the section does rather than where the merged code stops reading.
    fn copy(
        bytes: usize,
        section_bytes: usize,
        start_offset: usize,
        pointers: usize,
        end_unbounded: bool,
    ) -> DataSectionCopy {
        DataSectionCopy {
            library: PathBuf::from("/opt/lib/libfoo.so.1"),
            section: ".data.rel.ro".to_owned(),
            bytes,
            section_bytes,
            start_offset,
            unreferenced_prefix: 0,
            pointers,
            unbounded_end: end_unbounded.then(|| UnboundedEnd {
                address: 0x1040,
                reached_from: "bar".to_owned(),
            }),
            address: 0x1000,
            reached_from: "foo".to_owned(),
        }
    }

    fn render(plan: &MergePlan, imports: &[ImportedSymbol], needed: &[&str]) -> String {
        let needed: Vec<String> = needed.iter().map(|s| (*s).to_owned()).collect();
        render_merge_plan(Path::new("/tmp/app"), plan, imports, &needed, &[])
    }

    /// The line for one library pairs the symbols the *executable* imports out
    /// of it with the units and bytes the *extraction* pulled from it — two
    /// different inputs, grouped by the library's path.
    #[test]
    fn each_library_is_reported_with_its_own_symbols_units_and_bytes() {
        let mut plan = plan();
        plan.units = vec![
            unit("/opt/lib/libfoo.so.1", 100),
            unit("/opt/lib/libfoo.so.1", 20),
            unit("/opt/lib/libbar.so.2", 7),
        ];
        let imports = [
            import("foo_one", "/opt/lib/libfoo.so.1"),
            import("foo_two", "/opt/lib/libfoo.so.1"),
            import("bar_one", "/opt/lib/libbar.so.2"),
        ];

        let report = render(&plan, &imports, &["libfoo.so.1", "libbar.so.2"]);

        assert!(
            report.contains("/opt/lib/libfoo.so.1 (2 imported symbols, 2 units, 120 bytes)"),
            "{report}"
        );
        assert!(
            report.contains("/opt/lib/libbar.so.2 (1 imported symbols, 1 units, 7 bytes)"),
            "{report}"
        );
    }

    /// The three runs of the merged region are reported as sizes, which the
    /// plan holds as offsets of each run's end: getting the subtraction wrong
    /// would misreport how much of the region is executable.
    #[test]
    fn the_merged_regions_runs_are_reported_as_sizes() {
        let report = render(&plan(), &[], &[]);
        assert!(
            report.contains(
                "new mapping at 0x0000000000043000, 16384 bytes: 4096 read-execute \
                 (code, trampolines), 8192 read-only (constants), 4096 read-write \
                 (data, loader-written slots)"
            ),
            "{report}"
        );
    }

    /// Only the entries that survive the merge are "kept": a soname the plan
    /// removes has to come off the list the executable declared, and an
    /// inherited one is neither removed nor kept but reported on its own.
    #[test]
    fn removed_kept_and_inherited_sonames_are_reported_separately() {
        let mut plan = plan();
        plan.remove_needed = vec!["libfoo.so.1".to_owned()];
        plan.add_needed = vec!["libz.so.1".to_owned()];

        let report = render(&plan, &[], &["libfoo.so.1", "libc.so.6"]);

        assert!(
            report.contains("DT_NEEDED entries removed: libfoo.so.1"),
            "{report}"
        );
        assert!(
            report.contains("DT_NEEDED entries kept: libc.so.6"),
            "{report}"
        );
        assert!(
            report.contains("DT_NEEDED entries inherited from the merged libraries: libz.so.1"),
            "{report}"
        );
        assert!(
            !report.contains("no DT_NEEDED entries become removable"),
            "{report}"
        );
    }

    /// A merge that removes nothing says so, rather than leaving the reader to
    /// notice the line is missing.
    #[test]
    fn a_merge_that_removes_no_soname_says_so() {
        let report = render(&plan(), &[], &["libfoo.so.1"]);
        assert!(
            report.contains("no DT_NEEDED entries become removable"),
            "{report}"
        );
        assert!(
            report.contains("DT_NEEDED entries kept: libfoo.so.1"),
            "{report}"
        );
    }

    /// The data-copy totals sum the bytes and pointers of every copy, and
    /// count separately the ones whose end nothing bounded — the copies worth
    /// acting on. A copy cut at the next symbol the library names is one of
    /// them while taking a sliver of its section, so counting the copies that
    /// run to their section's end instead would miss it.
    #[test]
    fn data_copy_totals_count_the_unbounded_copies_apart() {
        let copies = [
            copy(96, 12168, 4032, 9, true),
            copy(64, 4096, 128, 2, false),
        ];
        let needed = ["libfoo.so.1".to_owned()];

        let report = render_merge_plan(Path::new("/tmp/app"), &plan(), &[], &needed, &copies);

        assert!(
            report.contains(
                "data sections copied for want of a symbol: 2 (1 of them with no bound \
                 but the next symbol or the section's end, 160 bytes, 11 pointers \
                 rooting further extraction)"
            ),
            "{report}"
        );
    }

    /// A merge with nothing to copy for want of a symbol — every fixture merge
    /// of `test/md5sum` — leaves the totals line out altogether.
    #[test]
    fn a_merge_with_no_unbounded_copy_omits_the_totals() {
        let report = render(&plan(), &[], &["libfoo.so.1"]);
        assert!(
            !report.contains("data sections copied"),
            "nothing was copied for want of a symbol: {report}"
        );
    }

    /// Both arrays are rebuilt whole, so the counts include the executable's
    /// own entries and not just the merged libraries'.
    #[test]
    fn the_rebuilt_arrays_are_reported_when_the_merge_rebuilds_them() {
        let mut plan = plan();
        plan.init_fini = Some(InitFiniPlan {
            preinit: MergedArray {
                vaddr: 0x4_3000,
                exe_vaddr: None,
                entries: vec![0x1000],
            },
            fini: MergedArray {
                vaddr: 0x4_3008,
                exe_vaddr: Some(0x2000),
                entries: vec![0x2000, 0x3000],
            },
        });

        let report = render(&plan, &[], &[]);
        assert!(
            report.contains("rebuilt preinit array entries: 1, fini array entries: 2"),
            "{report}"
        );
    }

    /// The report is one write, and it is the whole report.
    #[test]
    fn the_whole_report_reaches_the_writer() {
        let report = render(&plan(), &[], &["libfoo.so.1"]);
        let mut sink = Vec::new();
        write_report(&mut sink, &report).expect("a Vec takes every write");
        assert_eq!(String::from_utf8(sink).expect("utf-8"), report);
        assert!(
            report.ends_with("Dry run: /tmp/app left unchanged\n"),
            "{report}"
        );
    }

    /// `solder --dry-run | head` is an ordinary thing to type, and `head`
    /// closing the pipe is not a failure of the merge analysis: the run ends
    /// successfully and silently instead of panicking out of `println!`.
    #[test]
    fn a_reader_that_hung_up_ends_the_run_successfully() {
        write_report(
            FailingWriter(ErrorKind::BrokenPipe),
            "Merge plan for /tmp/app\n",
        )
        .expect("a closed pipe is not an error");
    }

    /// Every other write failure — `> file` on a full disk — is still an
    /// error, and still reported rather than panicked out of.
    #[test]
    fn any_other_write_failure_is_reported() {
        let err = write_report(FailingWriter(ErrorKind::StorageFull), "Merge plan\n")
            .expect_err("a report that could not be written is a failed run");
        let msg = format!("{err:#}");
        assert!(msg.contains("writing the merge plan to stdout"), "{msg}");
    }
}
