mod elf_reader;
mod extractor;
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

use elf_reader::MappedElf;
use lib_discovery::LdsoCache;
use symbol_analysis::{collect_imports, parse_dynamic};

#[derive(Parser)]
#[command(
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

    /// Override the base virtual address for the merged segment (hex, e.g. 0x800000)
    #[arg(long, value_name = "HEX")]
    merge_base: Option<String>,

    /// Show verbose relocation details
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let merge_base: Option<u64> = cli
        .merge_base
        .as_deref()
        .map(|s| {
            let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
            u64::from_str_radix(s, 16).context("--merge-base must be a hex address")
        })
        .transpose()?;

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
    let exe_mapped = MappedElf::open(&cli.input)
        .with_context(|| format!("opening {}", cli.input.display()))?;
    let exe_elf = exe_mapped.parse()?;

    elf_reader::validate_executable(&exe_elf, &cli.input)?;

    // ── Step 1: parse dynamic section + collect imports ──────────────────────
    let dyn_info = parse_dynamic(&exe_elf)?;

    if dyn_info.needed.is_empty() {
        anyhow::bail!("executable has no DT_NEEDED entries — nothing to merge");
    }

    let ldso_cache = LdsoCache::load();

    let imports = collect_imports(
        &exe_elf,
        &dyn_info,
        &ldso_cache,
        &library_path,
        merge_filter,
    )?;

    if imports.is_empty() {
        eprintln!("warning: no mergeable imported symbols found");
        return Ok(());
    }

    if cli.verbose || cli.dry_run {
        println!("Discovered {} directly imported symbol(s) to merge:", imports.len());
        for imp in &imports {
            println!(
                "  {:?}  {}  (from {})",
                imp.kind,
                imp.name,
                imp.source_library.display()
            );
        }
    }

    // ── Step 2: transitive closure extraction ────────────────────────────────
    let units = extractor::extract_units(&imports, &exe_elf)?;

    if cli.verbose || cli.dry_run {
        println!(
            "\nExtracted {} unit(s) (including transitive dependencies):",
            units.len()
        );
        for u in &units {
            println!(
                "  [{:?}] {} ({} bytes, {} relocs)  from {}",
                u.section_kind,
                u.name,
                u.size,
                u.relocations.len(),
                u.source_lib.display()
            );
        }
        let total: usize = units.iter().map(|u| u.size).sum();
        println!("  Total: {total} bytes");
    }

    // ── Step 3: layout planning ───────────────────────────────────────────────
    let mut plan = layout::plan_layout(units, &exe_elf, &imports, merge_base)?;

    if cli.verbose || cli.dry_run {
        println!(
            "\nMerged segment base VA: 0x{:016x}",
            plan.load_address
        );
        println!("GOT patches: {}", plan.got_patches.len());
        println!("Trampolines: {}", plan.trampoline_stubs.len());
        for t in &plan.trampoline_stubs {
            println!(
                "  trampoline '{}' at 0x{:x} → GOT[0x{:x}]",
                t.symbol_name, t.vaddr, t.target_got_vaddr
            );
        }
        println!("DT_NEEDED entries to remove: {:?}", plan.remove_needed);

        if cli.dry_run {
            println!("\n(dry-run: no output written)");
            return Ok(());
        }
    }

    // ── Step 4: apply relocations ─────────────────────────────────────────────
    relocator::apply_all_relocations(&mut plan)?;

    // ── Step 5: patch executable in-place (GOT, JUMP_SLOTs, DT_NEEDED) ───────
    // Find JUMP_SLOT reloc file offsets for the merged symbols.
    let merged_names: HashSet<String> = imports.iter().map(|i| i.name.clone()).collect();
    plan.jump_slot_reloc_offsets =
        symbol_analysis::find_jump_slot_reloc_offsets(&exe_elf, &merged_names)
            .context("finding JUMP_SLOT reloc offsets")?;

    let mut patched_exe = exe_mapped.bytes().to_vec();
    patcher::apply_patches(&mut patched_exe, &plan)?;

    // ── Step 6: build merged segment + write output ────────────────────────────
    let merged_seg = writer::build_merged_segment(&plan)?;
    writer::write_output(&patched_exe, &plan, &merged_seg, &cli.input)?;

    println!(
        "Merged {} symbol(s) ({} bytes) into {}",
        imports.len(),
        merged_seg.len(),
        cli.input.display()
    );

    Ok(())
}
