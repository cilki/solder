mod dep_graph;
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

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

use elf_reader::MappedElf;
use lib_discovery::LdsoCache;
use symbol_analysis::{collect_imports, parse_dynamic};

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

    /// Additional library search directories (prepended to default search order)
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
    let dyn_info = parse_dynamic(&exe_elf)?;

    if dyn_info.needed.is_empty() {
        anyhow::bail!("executable has no DT_NEEDED entries — nothing to merge");
    }

    let ldso_cache = LdsoCache::load();

    let import_info = collect_imports(
        &exe_elf,
        &dyn_info,
        &ldso_cache,
        &library_path,
        merge_filter,
    )?;
    let imports = import_info.imports;
    let merged_lib_syms = import_info.merged_lib_syms;

    if imports.is_empty() {
        warn!("No mergeable imported symbols found");
        return Ok(());
    }

    for imp in &imports {
        info!(
            kind=?imp.kind,
            name=imp.name,
            source=%imp.source_library.display(),
            "Imported symbol to merge"
        );
    }

    // ── Step 2: transitive closure extraction ────────────────────────────────
    let (units, init_fini) = extractor::extract_units(&imports, &exe_elf, &merged_lib_syms)?;

    for u in &units {
        info!(
            section_kind=?u.section_kind,
            name=u.name,
            size=u.size,
            relocations=u.relocations.len(),
            source=%u.source_lib.display(),
            "Extracted unit"
        );
    }
    let total: usize = units.iter().map(|u| u.size).sum();
    info!(
        total_bytes = total,
        units = units.len(),
        "Extraction complete"
    );

    if !init_fini.init_entries.is_empty() || !init_fini.fini_entries.is_empty() {
        info!(
            init_entries = init_fini.init_entries.len(),
            fini_entries = init_fini.fini_entries.len(),
            "Init/fini arrays"
        );
    }

    // ── Step 2.5: topological ordering of merged libraries ────────────────────
    let merged_libs: Vec<PathBuf> = imports
        .iter()
        .map(|i| i.source_library.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let lib_order = dep_graph::topological_order(&merged_libs)?;

    // ── Step 2.6: parse executable's existing init/fini info ──────────────────
    let exe_init_fini = parse_exe_init_fini(&exe_elf)?;

    // ── Step 3: layout planning ───────────────────────────────────────────────
    let mut plan = layout::plan_layout(
        units,
        &exe_elf,
        &imports,
        is_pie,
        init_fini,
        exe_init_fini,
        &lib_order,
    )?;

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

    if cli.dry_run {
        info!("Dry-run: no output written");
        return Ok(());
    }

    // ── Step 4: apply relocations ─────────────────────────────────────────────
    relocator::apply_all_relocations(&mut plan)?;

    // ── Step 5: patch executable in-place (GOT, JUMP_SLOTs, DT_NEEDED) ───────
    // Find JUMP_SLOT reloc file offsets for the merged symbols.
    let merged_names: HashSet<String> = imports.iter().map(|i| i.name.clone()).collect();
    plan.jump_slot_reloc_offsets =
        symbol_analysis::find_jump_slot_reloc_offsets(&exe_elf, &merged_names)
            .context("finding JUMP_SLOT reloc offsets")?;

    // Neutralize copy relocations for data symbols exported by a library we are
    // removing (e.g. ncurses' UP/PC/BC). Only symbols whose providing library's
    // soname is in remove_needed are eligible, so a partially-merged library's
    // copy relocations are left untouched.
    let removed_provided_syms: HashSet<String> = merged_lib_syms
        .iter()
        .filter(|(_, lib)| {
            lib.file_name()
                .and_then(|n| n.to_str())
                .map(|base| {
                    plan.remove_needed
                        .iter()
                        .any(|soname| base.starts_with(soname.as_str()) || soname.starts_with(base))
                })
                .unwrap_or(false)
        })
        .map(|(name, _)| name.clone())
        .collect();
    let copy_relocs = symbol_analysis::find_copy_reloc_offsets(&exe_elf, &removed_provided_syms)
        .context("finding COPY reloc offsets")?;
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

/// Parse the executable's existing init/fini array info from .dynamic.
fn parse_exe_init_fini(
    exe_elf: &object::read::elf::ElfFile64<'_>,
) -> Result<types::ExeInitFiniInfo> {
    let exe_bytes = exe_elf.data();
    let goblin = goblin::elf::Elf::parse(exe_bytes).context("goblin for init/fini parsing")?;

    let mut info = types::ExeInitFiniInfo::default();

    if let Some(dynamic) = &goblin.dynamic {
        for entry in &dynamic.dyns {
            match entry.d_tag {
                goblin::elf::dynamic::DT_INIT_ARRAY => {
                    info.init_array_vaddr = Some(entry.d_val);
                }
                goblin::elf::dynamic::DT_INIT_ARRAYSZ => {
                    info.init_array_size = entry.d_val;
                }
                goblin::elf::dynamic::DT_FINI_ARRAY => {
                    info.fini_array_vaddr = Some(entry.d_val);
                }
                goblin::elf::dynamic::DT_FINI_ARRAYSZ => {
                    info.fini_array_size = entry.d_val;
                }
                _ => {}
            }
        }
    }

    Ok(info)
}
