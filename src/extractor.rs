use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind as ObjSectionKind};
use tracing::{debug, warn};

use crate::types::{
    ExtractedReloc, ExtractedUnit, GotSlotFixup, InitFiniArrays, InitFiniEntry, RelocTarget,
    SectionKind, UnitId,
};

/// Relocation type names we explicitly reject with a helpful error.
fn describe_reloc(
    kind: object::RelocationKind,
    encoding: object::RelocationEncoding,
) -> &'static str {
    match (kind, encoding) {
        (object::RelocationKind::Got, _) => "GOT-relative (GOTPCREL/GOTPCRELX)",
        (object::RelocationKind::GotRelative, _) => "GOT-relative",
        (object::RelocationKind::GotBaseRelative, _) => "GOT-base-relative",
        _ => "unsupported",
    }
}

/// Key used to deduplicate units during BFS.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UnitKey {
    lib: PathBuf,
    sym: String,
}

/// Key for data blob deduplication: (library_path, section_name)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DataBlobKey {
    lib: PathBuf,
    section: String,
}

/// Info about an extracted data section blob.
struct DataBlobInfo {
    id: UnitId,
    base_vaddr: u64,
    size: usize,
}

/// State threaded through the BFS.
struct ExtractionState {
    extracted: HashMap<UnitKey, UnitId>,
    units: Vec<ExtractedUnit>,
    // Pending placeholder mappings: (UnitId, reloc_index) → target UnitKey
    pending: Vec<(UnitId, usize, UnitKey)>,
    next_id: u32,
    /// Symbols that stay external (glibc etc.). Maps name → known.
    external_syms: HashSet<String>,
    /// Symbols exported by any merged library, mapped to the library that
    /// defines them. Used to redirect cross-library PLT calls (e.g. libssl
    /// calling into libcore) to direct merged-unit references instead of
    /// leaving the original library-relative PLT offset in place.
    cross_lib_syms: HashMap<String, PathBuf>,
    /// Symbols the executable actually DEFINES (subset of `external_syms`,
    /// which also contains the executable's undefined imports).
    exe_defined_syms: HashSet<String>,
    /// Libraries we've already extracted init/fini arrays from.
    processed_libs: HashSet<PathBuf>,
    /// Accumulated init/fini entries from all processed libraries.
    init_fini: InitFiniArrays,
    /// Extracted data section blobs: maps (lib, section_name) → blob info
    data_blobs: HashMap<DataBlobKey, DataBlobInfo>,
    /// Copied GOT slots that need a GLOB_DAT in the output (see GotSlotFixup).
    got_slot_fixups: Vec<GotSlotFixup>,
}

impl ExtractionState {
    fn alloc_id(&mut self) -> UnitId {
        let id = UnitId(self.next_id);
        self.next_id += 1;
        id
    }
}

/// Extract all symbols transitively reachable from `seeds` (direct imports).
/// Returns the list of extracted units with placeholder RelocTargets resolved,
/// along with init/fini array entries from all processed libraries and GOT
/// slots that need re-resolution by ld.so.
pub fn extract_units(
    seeds: &[crate::types::ImportedSymbol],
    exe_elf: &object::read::elf::ElfFile64<'_>,
    merged_lib_syms: &HashMap<String, PathBuf>,
) -> Result<(Vec<ExtractedUnit>, InitFiniArrays, Vec<GotSlotFixup>)> {
    // Collect symbol names from the executable's .dynsym that merged library code
    // can reference. This includes both defined symbols (callable directly) and
    // undefined/imported symbols (callable through the executable's PLT).
    let exe_dynsym_names: HashSet<String> = exe_elf
        .dynamic_symbols()
        .filter_map(|s| s.name().ok().map(String::from))
        .filter(|name| !name.is_empty())
        .collect();
    let exe_defined_syms: HashSet<String> = exe_elf
        .dynamic_symbols()
        .filter(|s| !s.is_undefined())
        .filter_map(|s| s.name().ok().map(String::from))
        .filter(|name| !name.is_empty())
        .collect();

    let mut state = ExtractionState {
        extracted: HashMap::new(),
        units: Vec::new(),
        pending: Vec::new(),
        next_id: 0,
        external_syms: exe_dynsym_names,
        cross_lib_syms: merged_lib_syms.clone(),
        exe_defined_syms,
        processed_libs: HashSet::new(),
        init_fini: InitFiniArrays::default(),
        data_blobs: HashMap::new(),
        got_slot_fixups: Vec::new(),
    };

    let mut worklist: VecDeque<UnitKey> = VecDeque::new();
    for imp in seeds {
        worklist.push_back(UnitKey {
            lib: imp.source_library.clone(),
            sym: imp.name.clone(),
        });
    }

    while let Some(key) = worklist.pop_front() {
        if state.extracted.contains_key(&key) {
            continue;
        }

        let new_deps = process_symbol(&key, &mut state)
            .with_context(|| format!("extracting '{}' from {}", key.sym, key.lib.display()))?;

        for dep in new_deps {
            if !state.extracted.contains_key(&dep) {
                worklist.push_back(dep);
            }
        }
    }

    // Second pass: resolve placeholder UnitIds in RelocTarget::MergedUnit
    let pending = std::mem::take(&mut state.pending);
    let mut unresolved_relocs: Vec<(UnitId, usize)> = Vec::new();

    for (unit_id, reloc_idx, target_key) in pending {
        let target_unit_id = match state.extracted.get(&target_key) {
            Some(id) => *id,
            None => {
                warn!(
                    target=target_key.sym,
                    lib=%target_key.lib.display(),
                    "Unresolved relocation, skipping"
                );
                unresolved_relocs.push((unit_id, reloc_idx));
                continue;
            }
        };
        let unit = state
            .units
            .iter_mut()
            .find(|u| u.id == unit_id)
            .expect("unit must exist");
        unit.relocations[reloc_idx].target = RelocTarget::MergedUnit(target_unit_id);
    }

    // Remove unresolved relocations (in reverse order to preserve indices)
    for (unit_id, reloc_idx) in unresolved_relocs.iter().rev() {
        let unit = state
            .units
            .iter_mut()
            .find(|u| u.id == *unit_id)
            .expect("unit must exist");
        unit.relocations.remove(*reloc_idx);
    }

    Ok((state.units, state.init_fini, state.got_slot_fixups))
}

/// Process a single symbol: extract its bytes, parse its relocations, and
/// return new symbols to enqueue.
fn process_symbol(key: &UnitKey, state: &mut ExtractionState) -> Result<Vec<UnitKey>> {
    let lib_bytes =
        std::fs::read(&key.lib).with_context(|| format!("reading {}", key.lib.display()))?;

    let object_file = object::File::parse(lib_bytes.as_slice())
        .with_context(|| format!("object parse {}", key.lib.display()))?;

    let object::File::Elf64(elf64) = &object_file else {
        bail!("{}: not a 64-bit ELF shared library", key.lib.display());
    };

    let mut new_deps: Vec<UnitKey> = Vec::new();

    // Extract init/fini arrays from this library if we haven't already. Each
    // constructor/destructor becomes an extraction root of its own: when the
    // library is dynamically linked, ld.so runs every one of these at load/exit,
    // so a merged binary must include them (and their closure) to behave
    // identically. Provably no-op CRT glue is skipped inside
    // extract_init_fini_arrays.
    if !state.processed_libs.contains(&key.lib) {
        state.processed_libs.insert(key.lib.clone());
        let lib_init_fini = extract_init_fini_arrays(elf64, &key.lib)?;
        for entry in lib_init_fini
            .init_entries
            .iter()
            .chain(&lib_init_fini.fini_entries)
        {
            let dep_key = UnitKey {
                lib: entry.source_lib.clone(),
                sym: entry.unit_name.clone(),
            };
            if !new_deps.contains(&dep_key) {
                new_deps.push(dep_key);
            }
        }
        state
            .init_fini
            .init_entries
            .extend(lib_init_fini.init_entries);
        state
            .init_fini
            .fini_entries
            .extend(lib_init_fini.fini_entries);
    }

    // Find the symbol in .symtab first, fall back to .dynsym.
    let sym = find_symbol(elf64, &key.sym)
        .with_context(|| format!("symbol '{}' in {}", key.sym, key.lib.display()))?;

    // Determine symbol size.
    let sym_size = if sym.size > 0 {
        sym.size as usize
    } else {
        // Infer from the next symbol in the same section by address.
        infer_symbol_size(elf64, &sym)?
    };

    if sym_size == 0 {
        bail!(
            "cannot determine size of symbol '{}' in {} (st_size=0 and no adjacent symbol)",
            key.sym,
            key.lib.display()
        );
    }

    let section = elf64
        .section_by_index(sym.section)
        .with_context(|| format!("symbol '{}' has no section", key.sym))?;

    let section_kind = match section.kind() {
        ObjSectionKind::Text | ObjSectionKind::Common => SectionKind::Text,
        ObjSectionKind::ReadOnlyData | ObjSectionKind::ReadOnlyString => SectionKind::ReadOnlyData,
        ObjSectionKind::Data | ObjSectionKind::UninitializedData => SectionKind::Data,
        other => bail!("symbol '{}': unsupported section kind {:?}", key.sym, other),
    };

    let section_data = section.data().context("section data")?;
    let sym_vaddr = sym.vaddr;
    let section_vaddr = section.address();
    let offset_in_section = (sym_vaddr - section_vaddr) as usize;

    let bytes = if section.kind() == ObjSectionKind::UninitializedData {
        // .bss has no file-backed data — emit zero-filled bytes
        vec![0u8; sym_size]
    } else {
        if offset_in_section + sym_size > section_data.len() {
            bail!(
                "symbol '{}' byte range [{}, {}) overflows section of size {}",
                key.sym,
                offset_in_section,
                offset_in_section + sym_size,
                section_data.len()
            );
        }
        section_data[offset_in_section..offset_in_section + sym_size].to_vec()
    };
    let alignment = section.align().max(1);

    // Collect relocations that fall within this symbol's byte range.
    let mut relocations: Vec<ExtractedReloc> = Vec::new();
    // Track which relocations need resolution: (reloc_index, dep_key)
    let mut pending_relocs: Vec<(usize, UnitKey)> = Vec::new();

    for (roff, reloc) in section.relocations() {
        // Only care about relocations within our symbol's byte range.
        if roff < sym_vaddr || roff >= sym_vaddr + sym_size as u64 {
            continue;
        }
        let offset_within_unit = roff - sym_vaddr;

        // Validate relocation kind.
        let kind = reloc.kind();
        let encoding = reloc.encoding();
        if kind == object::RelocationKind::Got
            || kind == object::RelocationKind::GotRelative
            || kind == object::RelocationKind::GotBaseRelative
            || kind == object::RelocationKind::GotBaseOffset
        {
            bail!(
                "symbol '{}' in {}: {} relocation is not supported in Tier 1; \
                 recompile the library with an older toolchain or wait for Tier 2 support",
                key.sym,
                key.lib.display(),
                describe_reloc(kind, encoding)
            );
        }

        // Resolve the relocation target symbol.
        let target_sym = match reloc.target() {
            object::RelocationTarget::Symbol(si) => elf64.symbol_by_index(si).ok(),
            _ => None,
        };

        let target = if let Some(ts) = target_sym {
            let ts_name = ts.name().unwrap_or("").to_owned();
            let ts_in_section = matches!(ts.section(), object::SymbolSection::Section(_));
            if ts.is_undefined() || ts_name.is_empty() || !ts_in_section {
                // Undefined, unnamed, or absolute (e.g. a GNU version-node
                // pseudo-symbol like NCURSESW6_*, which is SHN_ABS with value 0).
                // None of these are extractable units, so route them through the
                // same resolution as externals: (1) executable's exports, then
                // (2) other merged libraries; anything else is fatal.
                if state.external_syms.contains(&ts_name) || ts_name.is_empty() {
                    RelocTarget::External(ts_name)
                } else if let Some(other_lib) = state.cross_lib_syms.get(&ts_name).cloned() {
                    let dep_key = UnitKey {
                        lib: other_lib,
                        sym: ts_name,
                    };
                    if !new_deps
                        .iter()
                        .any(|k| k.sym == dep_key.sym && k.lib == dep_key.lib)
                    {
                        new_deps.push(dep_key.clone());
                    }
                    pending_relocs.push((relocations.len(), dep_key));
                    RelocTarget::MergedUnit(UnitId(u32::MAX))
                } else {
                    bail!(
                        "symbol '{}' in {}: references external symbol '{}' which is not \
                         exported by the executable — cannot merge this library",
                        key.sym,
                        key.lib.display(),
                        ts_name
                    );
                }
            } else {
                // Internal to the library (or another merged lib).
                // Check if this is a data symbol - if so, try to use data blob offset
                let ts_vaddr = ts.address();
                if let Some((blob_id, blob_base)) = find_existing_data_blob(ts_vaddr, state) {
                    // Target is in an already-extracted data blob
                    let offset_in_blob = ts_vaddr - blob_base;
                    RelocTarget::DataBlobOffset(blob_id, offset_in_blob)
                } else {
                    // Try to extract this data section containing the symbol
                    // This will populate state.data_blobs if it's a data section
                    let extract_result =
                        ensure_data_blob_extracted(elf64, ts_vaddr, &key.lib, state);
                    if let Ok(Some((blob_id, blob_base, blob_deps))) = extract_result {
                        let offset_in_blob = ts_vaddr - blob_base;
                        for dep in blob_deps {
                            if !new_deps.iter().any(|k| k.sym == dep.sym) {
                                new_deps.push(dep);
                            }
                        }
                        RelocTarget::DataBlobOffset(blob_id, offset_in_blob)
                    } else {
                        // It's a code symbol or unknown - extract as a unit
                        let dep_key = UnitKey {
                            lib: key.lib.clone(),
                            sym: ts_name,
                        };
                        if !new_deps.iter().any(|k| k.sym == dep_key.sym) {
                            new_deps.push(dep_key.clone());
                        }
                        // Track for later resolution
                        pending_relocs.push((relocations.len(), dep_key));
                        // Placeholder — resolved in second pass.
                        RelocTarget::MergedUnit(UnitId(u32::MAX))
                    }
                }
            }
        } else {
            // Section-relative or absolute with no symbol — treat as fixed.
            RelocTarget::MergedUnit(UnitId(u32::MAX))
        };

        relocations.push(ExtractedReloc {
            offset_within_unit,
            kind,
            encoding,
            size: reloc.size(),
            addend: reloc.addend(),
            target,
        });
    }

    // Data symbol units: pick up .rela.dyn entries within the symbol's range
    // (e.g. __dso_handle's self-pointing RELATIVE, function pointers in .data).
    // Section-attached relocation tables don't exist in linked shared objects.
    let mut got_fixup_offsets: Vec<(u64, String, bool)> = Vec::new();
    if section_kind != SectionKind::Text {
        collect_dynamic_range_relocs(
            elf64,
            &key.lib,
            &key.sym,
            sym_vaddr,
            sym_size as u64,
            state,
            &mut relocations,
            &mut new_deps,
            &mut pending_relocs,
            &mut got_fixup_offsets,
        )?;
    }

    // Scan for RIP-relative references (calls, jumps, and data accesses).
    // Create synthetic relocations for each reference so they get patched correctly.
    if section_kind == SectionKind::Text {
        let rip_refs = scan_rip_relative_refs(&bytes, sym_vaddr);
        for rip_ref in rip_refs {
            let target_addr = rip_ref.target_vaddr;

            // Skip references within our own function
            if target_addr >= sym_vaddr && target_addr < sym_vaddr + sym_size as u64 {
                continue;
            }

            // Check if there's already a relocation at this offset (from .rela.text)
            if relocations
                .iter()
                .any(|r| r.offset_within_unit == rip_ref.offset as u64)
            {
                continue;
            }

            if rip_ref.is_code_ref {
                // rel8 (short jump) displacements get an 8-bit relocation; the
                // relocator verifies the final offset still fits.
                let reloc_size: u8 = if rip_ref.disp_size == 1 { 8 } else { 32 };
                let reloc_addend = rip_ref.addend;
                // First check if this is a PLT call (call to external symbol)
                if let Some(ext_name) = find_plt_target(elf64, target_addr, &lib_bytes) {
                    // PLT call resolution order:
                    //   1. Executable exports the symbol → trampoline through exe's GOT.
                    //   2. Another merged library defines the symbol → extract from
                    //      that library and create a direct merged-unit reference.
                    //   3. Otherwise unresolvable; leaving the original library
                    //      offset in place will crash if this path runs. Warn so
                    //      it's at least visible.
                    if state.external_syms.contains(&ext_name) {
                        relocations.push(ExtractedReloc {
                            offset_within_unit: rip_ref.offset as u64,
                            kind: object::RelocationKind::Relative,
                            encoding: object::RelocationEncoding::Generic,
                            size: reloc_size,
                            addend: reloc_addend,
                            target: RelocTarget::External(ext_name),
                        });
                    } else if let Some(other_lib) = state.cross_lib_syms.get(&ext_name).cloned() {
                        let dep_key = UnitKey {
                            lib: other_lib,
                            sym: ext_name,
                        };
                        if !new_deps
                            .iter()
                            .any(|k| k.sym == dep_key.sym && k.lib == dep_key.lib)
                        {
                            new_deps.push(dep_key.clone());
                        }
                        pending_relocs.push((relocations.len(), dep_key));
                        relocations.push(ExtractedReloc {
                            offset_within_unit: rip_ref.offset as u64,
                            kind: object::RelocationKind::Relative,
                            encoding: object::RelocationEncoding::Generic,
                            size: reloc_size,
                            addend: reloc_addend,
                            target: RelocTarget::MergedUnit(UnitId(u32::MAX)),
                        });
                    } else {
                        // Not in exe and not in merged libs: a libc/runtime
                        // symbol the executable doesn't already import. Emit
                        // an External reloc; the writer will inject a new
                        // .dynsym entry and a GLOB_DAT relocation so ld.so
                        // resolves it at load time.
                        relocations.push(ExtractedReloc {
                            offset_within_unit: rip_ref.offset as u64,
                            kind: object::RelocationKind::Relative,
                            encoding: object::RelocationEncoding::Generic,
                            size: reloc_size,
                            addend: reloc_addend,
                            target: RelocTarget::External(ext_name),
                        });
                    }
                } else {
                    // Direct call/jmp to an internal address. Prefer a named
                    // symbol; otherwise synthesize an anonymous unit for a
                    // symbol-less local helper. Stripped libraries routinely
                    // reach such helpers via a plain `call` with no symbol of
                    // their own — e.g. OpenSSL's md5_block_asm_data_order, which
                    // MD5_Update/MD5_Final call directly. Without this, the call
                    // bytes were copied verbatim and the stale displacement
                    // pointed into unmapped memory, crashing at runtime.
                    let dep_name = find_symbol_at_address(elf64, target_addr)
                        .filter(|n| find_symbol(elf64, n).is_ok())
                        .or_else(|| {
                            anon_target_is_extractable(elf64, target_addr)
                                .then(|| anon_unit_name(target_addr))
                        });
                    if let Some(target_name) = dep_name {
                        let dep_key = UnitKey {
                            lib: key.lib.clone(),
                            sym: target_name,
                        };
                        if !new_deps.iter().any(|k| k.sym == dep_key.sym) {
                            new_deps.push(dep_key.clone());
                        }
                        // Track for later resolution
                        pending_relocs.push((relocations.len(), dep_key));
                        // Add synthetic PC-relative relocation
                        relocations.push(ExtractedReloc {
                            offset_within_unit: rip_ref.offset as u64,
                            kind: object::RelocationKind::Relative,
                            encoding: object::RelocationEncoding::Generic,
                            size: reloc_size,
                            addend: reloc_addend,
                            target: RelocTarget::MergedUnit(UnitId(u32::MAX)),
                        });
                    } else {
                        warn!(
                            symbol = key.sym,
                            offset = format_args!("{:#x}", rip_ref.offset),
                            target = format_args!("{:#x}", target_addr),
                            "direct code ref to an unresolved internal target; \
                             merged binary may crash if this path executes"
                        );
                    }
                }
            } else {
                // Data reference (LEA/MOV) — could be loading address of data or code
                // First try as a code symbol (e.g. LEA loading a function pointer).
                // Zero-size boundary markers (e.g. __TMC_END__, which sits at the
                // exact end of .data with nothing after it) are not extractable
                // units — let those fall through to the blob path.
                let named_unit = find_symbol_at_address(elf64, target_addr).filter(|n| {
                    find_symbol(elf64, n)
                        .and_then(|s| {
                            if s.size > 0 {
                                Ok(s.size as usize)
                            } else {
                                infer_symbol_size(elf64, &s)
                            }
                        })
                        .map(|sz| sz > 0)
                        .unwrap_or(false)
                });
                if let Some(target_name) = named_unit {
                    let dep_key = UnitKey {
                        lib: key.lib.clone(),
                        sym: target_name,
                    };
                    if !new_deps.iter().any(|k| k.sym == dep_key.sym) {
                        new_deps.push(dep_key.clone());
                    }
                    pending_relocs.push((relocations.len(), dep_key));
                    relocations.push(ExtractedReloc {
                        offset_within_unit: rip_ref.offset as u64,
                        kind: object::RelocationKind::Relative,
                        encoding: object::RelocationEncoding::Generic,
                        size: 32,
                        addend: rip_ref.addend,
                        target: RelocTarget::MergedUnit(UnitId(u32::MAX)),
                    });
                    continue;
                }
                // Otherwise try to extract the data section
                if let Some((blob_id, blob_base, blob_deps)) =
                    ensure_data_blob_extracted(elf64, target_addr, &key.lib, state)?
                {
                    let offset_in_blob = target_addr - blob_base;
                    for dep in blob_deps {
                        if !new_deps.iter().any(|k| k.sym == dep.sym) {
                            new_deps.push(dep);
                        }
                    }
                    // Add synthetic PC-relative relocation pointing to data blob
                    relocations.push(ExtractedReloc {
                        offset_within_unit: rip_ref.offset as u64,
                        kind: object::RelocationKind::Relative,
                        encoding: object::RelocationEncoding::Generic,
                        size: 32,
                        addend: rip_ref.addend,
                        target: RelocTarget::DataBlobOffset(blob_id, offset_in_blob),
                    });
                } else {
                    warn!(
                        symbol = key.sym,
                        offset = format_args!("{:#x}", rip_ref.offset),
                        target = format_args!("{:#x}", target_addr),
                        "RIP-relative data ref target not found"
                    );
                }
            }
        }
    }

    // Jump table detection via symbolic execution
    if section_kind == SectionKind::Text
        && let Ok(jump_tables) =
            crate::jump_table::detect_jump_tables(&bytes, sym_vaddr, &key.sym, elf64, &lib_bytes)
    {
        if !jump_tables.is_empty() {
            debug!(
                count = jump_tables.len(),
                symbol = key.sym,
                "Found jump tables"
            );
        }

        for table in jump_tables {
            // 1. Ensure .rodata blob containing table is extracted
            if let Some((blob_id, blob_base, blob_deps)) =
                ensure_data_blob_extracted(elf64, table.table_vaddr, &key.lib, state)?
            {
                for dep in blob_deps {
                    if !new_deps.iter().any(|k| k.sym == dep.sym) {
                        new_deps.push(dep);
                    }
                }
                // 2. Create relocations for each table entry
                for (idx, target_addr) in table.targets.iter().enumerate() {
                    let entry_offset_in_blob = (table.table_vaddr - blob_base) + (idx * 4) as u64;

                    // Skip if a relocation already exists at this offset (from another
                    // function detecting an overlapping table at the same .rodata address)
                    if let Some(blob_unit) = state.units.iter().find(|u| u.id == blob_id)
                        && blob_unit
                            .relocations
                            .iter()
                            .any(|r| r.offset_within_unit == entry_offset_in_blob)
                    {
                        continue;
                    }

                    // 3. Find or extract target function
                    let target_name =
                        crate::jump_table::find_symbol_at_address(elf64, *target_addr)
                            .unwrap_or_else(|| format!("jumptarget_{:x}", target_addr));

                    // 4. Check if target is within our own function (intra-function jump)
                    let is_internal =
                        *target_addr >= sym_vaddr && *target_addr < sym_vaddr + bytes.len() as u64;

                    // 5. Compute the target symbol's base address to calculate offset
                    let target_sym_vaddr = if is_internal {
                        sym_vaddr
                    } else {
                        // Find the symbol that contains this address
                        find_symbol(elf64, &target_name)
                            .map(|s| s.vaddr)
                            .unwrap_or(*target_addr)
                    };

                    // Calculate offset within the target function
                    let offset_in_target = (*target_addr - target_sym_vaddr) as i64;

                    // Jump table entry format: target = table_base + *(i32*)entry
                    // Therefore: *(i32*)entry = target - table_base
                    //
                    // After relocation:
                    // - entry is at address P (= table_base_va + idx*4)
                    // - target is at address S + offset_in_target
                    // - We need: *(i32*)P = (S + offset_in_target) - table_base_va
                    //
                    // Relocation formula writes: *(i32*)P = S + A - P
                    // Since P = table_base_va + idx*4:
                    //   S + A - P = S + A - table_base_va - idx*4
                    // We need this to equal S + offset_in_target - table_base_va
                    // Therefore: A = offset_in_target + idx*4
                    let addend = offset_in_target + (idx * 4) as i64;

                    // 6. Add jump table entry relocation to the data blob
                    // Find the blob unit and add the relocation
                    if let Some(blob_unit) = state.units.iter_mut().find(|u| u.id == blob_id) {
                        let reloc_idx = blob_unit.relocations.len();

                        blob_unit.relocations.push(ExtractedReloc {
                            offset_within_unit: entry_offset_in_blob,
                            kind: object::RelocationKind::Relative,
                            encoding: object::RelocationEncoding::Generic,
                            size: 32,
                            addend, // Offset within target function, adjusted for PC-relative
                            target: RelocTarget::MergedUnit(UnitId(u32::MAX)), // Placeholder
                        });

                        // Track for resolution
                        let dep_key = UnitKey {
                            lib: key.lib.clone(),
                            sym: if is_internal {
                                // Internal jump - target is the current function itself
                                key.sym.clone()
                            } else {
                                target_name.clone()
                            },
                        };

                        // Only add as dependency if it's a real symbol we can extract
                        // For internal jumps, we don't need to add as a new dependency
                        // since we're already extracting it
                        if !is_internal
                            && find_symbol(elf64, &target_name).is_ok()
                            && !new_deps.iter().any(|k| k.sym == dep_key.sym)
                        {
                            new_deps.push(dep_key.clone());
                        }

                        // Add to pending resolutions for this blob
                        // (don't use pending_relocs which is for the current unit's relocations)
                        state.pending.push((blob_id, reloc_idx, dep_key));
                    }
                }
            }
        }
    }

    // Rewrite short (rel8) branch relocations through 5-byte `jmp rel32`
    // veneers. A 1-byte displacement can rarely reach its real target once
    // units are repacked. The veneer goes at the end of the unit when the
    // short jump can reach it; for larger units (over-extended anonymous units
    // in stripped libraries), it overwrites the never-executed inter-function
    // alignment padding that follows the branch instead.
    // (Reloc indices are preserved, so pending resolutions stay valid.)
    let mut bytes = bytes;
    let mut sym_size = sym_size;
    for reloc in relocations.iter_mut() {
        if reloc.size != 8 {
            continue;
        }
        let disp_off = reloc.offset_within_unit as usize;
        let end_off = bytes.len();
        let veneer_off = if end_off as i64 - (disp_off as i64 + 1) <= i8::MAX as i64 {
            bytes.extend_from_slice(&[0xe9, 0, 0, 0, 0]);
            sym_size = bytes.len();
            end_off
        } else if let Some(slot) = find_padding_slot(&bytes, disp_off + 1, 5) {
            bytes[slot..slot + 5].copy_from_slice(&[0xe9, 0, 0, 0, 0]);
            slot
        } else {
            bail!(
                "short jump at offset {:#x} in '{}' has no reachable spot for a \
                 rel32 veneer (unit end {} bytes away, no padding after the jump)",
                disp_off,
                key.sym,
                end_off - disp_off
            );
        };
        bytes[disp_off] = (veneer_off as i64 - (disp_off as i64 + 1)) as i8 as u8;
        reloc.offset_within_unit = veneer_off as u64 + 1;
        reloc.size = 32;
        reloc.addend = -4;
    }

    // Register this unit.
    let id = state.alloc_id();
    state.extracted.insert(key.clone(), id);

    // Record pending resolutions using our explicit tracking.
    for (reloc_idx, dep_key) in pending_relocs {
        state.pending.push((id, reloc_idx, dep_key));
    }

    // Zero re-resolved GOT slots and register their fixups (see GotSlotFixup).
    for (offset, name, weak) in got_fixup_offsets {
        let off = offset as usize;
        if off + 8 <= bytes.len() {
            bytes[off..off + 8].fill(0);
        }
        state.got_slot_fixups.push(GotSlotFixup {
            unit: id,
            offset,
            name,
            weak,
        });
    }

    state.units.push(ExtractedUnit {
        id,
        name: key.sym.clone(),
        source_lib: key.lib.clone(),
        size: sym_size,
        bytes,
        section_kind,
        alignment,
        relocations,
    });

    Ok(new_deps)
}

/// Lightweight snapshot of a symbol we care about.
struct SymInfo {
    vaddr: u64,
    size: u64,
    section: object::SectionIndex,
}

/// Find a symbol by name in an ELF's .symtab, falling back to .dynsym.
fn find_symbol(elf: &object::read::elf::ElfFile64<'_>, name: &str) -> Result<SymInfo> {
    // Synthetic anonymous unit: resolve the address encoded in the name to the
    // executable section that contains it. Size is left at 0 so the caller
    // infers it from the next symbol boundary.
    if let Some(hex) = name.strip_prefix(ANON_UNIT_PREFIX) {
        let addr = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .with_context(|| format!("malformed anonymous unit name '{name}'"))?;
        for section in elf.sections() {
            let sec_addr = section.address();
            if addr >= sec_addr
                && addr < sec_addr + section.size()
                && section.kind() == ObjSectionKind::Text
            {
                return Ok(SymInfo {
                    vaddr: addr,
                    size: 0,
                    section: section.index(),
                });
            }
        }
        bail!("anonymous unit address {addr:#x} not in any executable section");
    }

    // Prefer .symtab (has sizes + section indices).
    for sym in elf.symbols() {
        if sym.name().ok() == Some(name) && !sym.is_undefined() {
            let section = match sym.section() {
                object::SymbolSection::Section(si) => si,
                _ => bail!("symbol '{name}' is not in a regular section"),
            };
            return Ok(SymInfo {
                vaddr: sym.address(),
                size: sym.size(),
                section,
            });
        }
    }
    // Fall back to .dynsym.
    for sym in elf.dynamic_symbols() {
        if sym.name().ok() == Some(name) && !sym.is_undefined() {
            let section = match sym.section() {
                object::SymbolSection::Section(si) => si,
                _ => bail!("symbol '{name}' is not in a regular section"),
            };
            return Ok(SymInfo {
                vaddr: sym.address(),
                size: sym.size(),
                section,
            });
        }
    }
    bail!("symbol '{name}' not found in .symtab or .dynsym")
}

/// Look up a symbol by index in the dynamic symbol table. Symbol indices in
/// dynamic relocations (.rela.dyn) refer to .dynsym; resolving them with
/// `elf.symbol_by_index` would index .symtab and return an unrelated symbol.
fn dynamic_symbol_by_index<'data, 'file>(
    elf: &'file object::read::elf::ElfFile64<'data>,
    si: object::SymbolIndex,
) -> Option<object::read::elf::ElfSymbol64<'data, 'file>> {
    use object::ObjectSymbolTable;
    elf.dynamic_symbol_table()?.symbol_by_index(si).ok()
}

/// Find a symbol by virtual address in an ELF's .symtab (including local symbols).
/// Returns the symbol name if found, or None if no symbol starts at that address.
///
/// Only symbols that live in a real section are eligible: GNU version-node
/// pseudo-symbols (e.g. `NCURSESW6_5.8.20110226`) are `SHN_ABS` with value 0, so
/// a scanned reference that resolves to address 0 would otherwise match one of
/// them and then fail extraction with "not in a regular section".
fn find_symbol_at_address(elf: &object::read::elf::ElfFile64<'_>, addr: u64) -> Option<String> {
    // First check .symtab (has local symbols like .cold functions)
    for sym in elf.symbols() {
        if sym.address() == addr
            && matches!(sym.section(), object::SymbolSection::Section(_))
            && let Ok(name) = sym.name()
            && !name.is_empty()
        {
            return Some(name.to_string());
        }
    }
    // Fall back to .dynsym
    for sym in elf.dynamic_symbols() {
        if sym.address() == addr
            && matches!(sym.section(), object::SymbolSection::Section(_))
            && let Ok(name) = sym.name()
            && !name.is_empty()
        {
            return Some(name.to_string());
        }
    }
    None
}

/// Reserved synthetic-name prefix for anonymous (symbol-less) code units. A
/// stripped library may reach a local helper function through a direct `call`
/// while exporting no symbol for it. We give that helper a synthetic name with
/// its address encoded so `find_symbol` can resolve it back to a location and
/// `infer_symbol_size` can bound it by the next symbol.
const ANON_UNIT_PREFIX: &str = ".solder.anon.";

fn anon_unit_name(addr: u64) -> String {
    format!("{ANON_UNIT_PREFIX}{addr:#x}")
}

/// Whether `addr` points into executable code we can extract as an anonymous
/// unit. Excludes PLT sections (those are resolved via `find_plt_target`) so we
/// never mistake a PLT stub for a mergeable function.
fn anon_target_is_extractable(elf: &object::read::elf::ElfFile64<'_>, addr: u64) -> bool {
    for section in elf.sections() {
        let sec_addr = section.address();
        if addr >= sec_addr && addr < sec_addr + section.size() {
            let name = section.name().unwrap_or("");
            let is_plt = matches!(name, ".plt" | ".plt.got" | ".plt.sec");
            return section.kind() == ObjSectionKind::Text && !is_plt;
        }
    }
    false
}

/// Find a run of at least `need` bytes of alignment padding starting at
/// `start`: nop-family instructions or int3 fill emitted between functions,
/// which is never executed and can be overwritten by a branch veneer.
fn find_padding_slot(bytes: &[u8], start: usize, need: usize) -> Option<usize> {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

    if start >= bytes.len() {
        return None;
    }
    let mut decoder = Decoder::with_ip(64, &bytes[start..], 0, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut run = 0usize;
    while decoder.can_decode() && run < need {
        decoder.decode_out(&mut instr);
        match instr.mnemonic() {
            Mnemonic::Nop | Mnemonic::Int3 => run += instr.len(),
            _ => break,
        }
    }
    (run >= need).then_some(start)
}

/// A RIP-relative reference found in machine code.
#[derive(Debug, Clone)]
struct RipRelativeRef {
    /// Byte offset within the code where the displacement starts.
    offset: usize,
    /// Target virtual address this reference points to.
    target_vaddr: u64,
    /// Whether this is a code reference (call/jmp) vs data reference (lea/mov).
    is_code_ref: bool,
    /// Size of the encoded displacement in bytes: 4 (rel32) or 1 (rel8, short
    /// jumps only).
    disp_size: u8,
    /// Relocation addend: -(bytes from displacement start to instruction end).
    /// This is -4 when the displacement is the final field, but instructions
    /// like `cmpb $imm, [rip+d]` carry an immediate after the displacement,
    /// which shifts next_ip further and makes the addend more negative.
    addend: i64,
}

/// Scan machine code for all RIP-relative references (calls, jumps, and data accesses).
/// Returns a list of references with their offsets and target addresses.
fn scan_rip_relative_refs(bytes: &[u8], base_vaddr: u64) -> Vec<RipRelativeRef> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

    let mut refs = Vec::new();
    let mut decoder = Decoder::with_ip(64, bytes, base_vaddr, DecoderOptions::NONE);
    let mut instr = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        let instr_offset = (instr.ip() - base_vaddr) as usize;

        match instr.flow_control() {
            FlowControl::Call
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch => {
                // Near call/jmp/jcc. rel32 forms carry the displacement in the
                // last 4 bytes; short (rel8) jmp/jcc forms in the last byte.
                // Verify the encoded bytes actually match before recording, so
                // an unexpected encoding is skipped instead of corrupted.
                if instr.op_count() >= 1 && instr.op_kind(0) == OpKind::NearBranch64 {
                    let target = instr.near_branch_target();
                    let rel = target.wrapping_sub(instr.next_ip()) as i64;
                    let instr_bytes = &bytes[instr_offset..instr_offset + instr.len()];
                    let is_rel32 = instr.len() >= 5
                        && i32::try_from(rel)
                            .is_ok_and(|r| instr_bytes[instr.len() - 4..] == r.to_le_bytes());
                    let is_rel8 = !is_rel32
                        && i8::try_from(rel)
                            .is_ok_and(|r| instr_bytes[instr.len() - 1] == r as u8);
                    if is_rel32 || is_rel8 {
                        let disp_size: u8 = if is_rel32 { 4 } else { 1 };
                        refs.push(RipRelativeRef {
                            offset: instr_offset + instr.len() - disp_size as usize,
                            target_vaddr: target,
                            is_code_ref: true,
                            disp_size,
                            addend: -(disp_size as i64),
                        });
                    }
                }
            }
            _ => {
                // Check all operands for RIP-relative memory references
                for op_idx in 0..instr.op_count() {
                    if instr.op_kind(op_idx) == OpKind::Memory && instr.is_ip_rel_memory_operand() {
                        let target = instr.ip_rel_memory_address();
                        // Find the displacement bytes within the instruction.
                        // The disp32 encodes (target - next_ip) as a signed 32-bit value.
                        let disp32 = (target as i64 - instr.next_ip() as i64) as i32;
                        let disp_bytes = disp32.to_le_bytes();
                        let instr_bytes = &bytes[instr_offset..instr_offset + instr.len()];
                        // Search backwards — the displacement is near the end
                        let disp_pos = instr_bytes.windows(4).rposition(|w| w == disp_bytes);
                        if let Some(pos) = disp_pos {
                            refs.push(RipRelativeRef {
                                offset: instr_offset + pos,
                                target_vaddr: target,
                                is_code_ref: false,
                                disp_size: 4,
                                addend: -((instr.len() - pos) as i64),
                            });
                        }
                        break; // Only one memory operand per instruction
                    }
                }
            }
        }
    }

    refs
}

/// Check if an address is in the PLT section and return the external symbol name if so.
/// PLT entries follow a pattern: jmp *GOT_OFFSET(%rip) or push index; jmp resolver
fn find_plt_target(
    elf: &object::read::elf::ElfFile64<'_>,
    addr: u64,
    lib_bytes: &[u8],
) -> Option<String> {
    // Find the .plt section
    for section in elf.sections() {
        let name = match section.name() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if name != ".plt" && name != ".plt.got" && name != ".plt.sec" {
            continue;
        }
        let sec_addr = section.address();
        let sec_size = section.size();
        if addr < sec_addr || addr >= sec_addr + sec_size {
            continue;
        }

        // This address is in a PLT section. Decode the stub itself instead of
        // guessing by entry index: every flavor (.plt, .plt.got, .plt.sec)
        // starts with an optional endbr64 and/or bnd prefix followed by
        // `ff 25 <disp32>` (jmp [rip+disp32]) through its GOT slot. The slot's
        // dynamic relocation — JUMP_SLOT for classic PLT entries, GLOB_DAT for
        // .plt.got-style stubs like __cxa_finalize@plt — names the symbol.
        let goblin_lib = match goblin::elf::Elf::parse(lib_bytes) {
            Ok(g) => g,
            Err(_) => return None,
        };

        let sec_data = section.data().ok()?;
        let mut off = (addr - sec_addr) as usize;
        if sec_data.len() >= off + 4 && sec_data[off..off + 4] == [0xf3, 0x0f, 0x1e, 0xfa] {
            off += 4; // endbr64
        }
        if sec_data.get(off) == Some(&0xf2) {
            off += 1; // bnd prefix
        }
        if sec_data.len() < off + 6 || sec_data[off] != 0xff || sec_data[off + 1] != 0x25 {
            return None; // not an indirect-jump stub (e.g. the PLT0 resolver)
        }
        let disp = i32::from_le_bytes(sec_data[off + 2..off + 6].try_into().expect("4 bytes"));
        let got_va = (sec_addr + off as u64 + 6).wrapping_add(disp as i64 as u64);

        for rela in goblin_lib.pltrelocs.iter().chain(goblin_lib.dynrelas.iter()) {
            if rela.r_offset == got_va
                && let Some(sym) = goblin_lib.dynsyms.get(rela.r_sym)
                && let Some(name) = goblin_lib.dynstrtab.get_at(sym.st_name)
                && !name.is_empty()
            {
                return Some(name.to_string());
            }
        }

        // Fallback: try to find symbol at this exact address
        for sym in goblin_lib.dynsyms.iter() {
            if sym.st_value == addr
                && let Some(name) = goblin_lib.dynstrtab.get_at(sym.st_name)
            {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Check if a virtual address falls within an already-extracted data blob.
/// Returns (blob_id, blob_base_vaddr) if found.
fn find_existing_data_blob(addr: u64, state: &ExtractionState) -> Option<(UnitId, u64)> {
    for info in state.data_blobs.values() {
        if addr >= info.base_vaddr && addr < info.base_vaddr + info.size as u64 {
            return Some((info.id, info.base_vaddr));
        }
    }
    None
}

/// Find the section containing a given virtual address and return section info.
fn find_section_for_address(
    elf: &object::read::elf::ElfFile64<'_>,
    addr: u64,
) -> Option<(String, u64, usize, Vec<u8>, SectionKind)> {
    for section in elf.sections() {
        let sec_addr = section.address();
        let sec_size = section.size();
        if addr >= sec_addr && addr < sec_addr + sec_size {
            let name = section.name().ok()?.to_string();
            let kind = match section.kind() {
                ObjSectionKind::Text => SectionKind::Text,
                ObjSectionKind::ReadOnlyData | ObjSectionKind::ReadOnlyString => {
                    SectionKind::ReadOnlyData
                }
                ObjSectionKind::Data | ObjSectionKind::UninitializedData => SectionKind::Data,
                _ => return None, // Skip unsupported section types
            };
            // Handle NOBITS sections (.bss) which have no data in the file
            let data =
                if kind == SectionKind::Data && section.data().ok().is_none_or(|d| d.is_empty()) {
                    // NOBITS section - create zero-filled data
                    vec![0u8; sec_size as usize]
                } else {
                    section.data().ok()?.to_vec()
                };
            return Some((name, sec_addr, data.len(), data, kind));
        }
    }
    None
}

/// Collect dynamic relocations (.rela.dyn) that fall within
/// [range_start, range_start + range_size) into `relocations`, resolving their
/// targets. Linked shared objects carry data relocations only in .rela.dyn —
/// there are no section-attached relocation tables — so every extracted data
/// range (whole-section blob or single-symbol unit) must consult this table or
/// its copied bytes hold stale library VAs.
///
/// Offsets pushed into `relocations`/`got_fixups` are relative to `range_start`.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::ptr_arg)]
fn collect_dynamic_range_relocs(
    elf64: &object::read::elf::ElfFile64<'_>,
    lib: &PathBuf,
    ctx: &str,
    range_start: u64,
    range_size: u64,
    state: &mut ExtractionState,
    relocations: &mut Vec<ExtractedReloc>,
    new_deps: &mut Vec<UnitKey>,
    pending_relocs: &mut Vec<(usize, UnitKey)>,
    got_fixups: &mut Vec<(u64, String, bool)>,
) -> Result<()> {
    let Some(dyn_relocs) = elf64.dynamic_relocations() else {
        return Ok(());
    };
    for (roff, reloc) in dyn_relocs {
        if roff < range_start || roff >= range_start + range_size {
            continue;
        }
        let offset_within_unit = roff - range_start;
        if relocations
            .iter()
            .any(|r| r.offset_within_unit == offset_within_unit)
        {
            continue;
        }

        // Validate relocation kind (same as code extraction)
        let kind = reloc.kind();
        let encoding = reloc.encoding();
        if kind == object::RelocationKind::Got
            || kind == object::RelocationKind::GotRelative
            || kind == object::RelocationKind::GotBaseRelative
            || kind == object::RelocationKind::GotBaseOffset
        {
            bail!(
                "'{}' in {}: {} relocation is not supported in Tier 1",
                ctx,
                lib.display(),
                describe_reloc(kind, encoding)
            );
        }

        // Resolve the relocation target symbol. Dynamic relocation symbol
        // indices refer to .dynsym, not .symtab.
        let target_sym = match reloc.target() {
            object::RelocationTarget::Symbol(si) => dynamic_symbol_by_index(elf64, si),
            _ => None,
        };

        let mut relative_addend_consumed = false;
        let target = if let Some(ts) = target_sym {
            let ts_name = ts.name().unwrap_or("").to_owned();
            if ts.is_undefined() || ts_name.is_empty() {
                if ts_name.is_empty() {
                    RelocTarget::External(ts_name)
                } else if !state.exe_defined_syms.contains(&ts_name)
                    && let Some(other_lib) = state.cross_lib_syms.get(&ts_name).cloned()
                {
                    // Sole provider is another merged (removed) library —
                    // resolve directly to the merged copy, as ld.so would
                    // have resolved to that library.
                    let dep_key = UnitKey {
                        lib: other_lib,
                        sym: ts_name,
                    };
                    if !new_deps
                        .iter()
                        .any(|k| k.sym == dep_key.sym && k.lib == dep_key.lib)
                    {
                        new_deps.push(dep_key.clone());
                    }
                    pending_relocs.push((relocations.len(), dep_key));
                    RelocTarget::MergedUnit(UnitId(u32::MAX))
                } else {
                    // A slot holding an external symbol's address (a copied
                    // GOT slot, or a data pointer to an external). Defer to
                    // ld.so with a GLOB_DAT in the output so the runtime value
                    // matches dynamic linking exactly — including 0 for
                    // unresolved weak symbols, which CRT code null-checks. A
                    // trampoline address here would break those checks.
                    got_fixups.push((offset_within_unit, ts_name, ts.is_weak()));
                    continue;
                }
            } else {
                // Internal to the library
                let dep_key = UnitKey {
                    lib: lib.clone(),
                    sym: ts_name,
                };
                if !new_deps.iter().any(|k| k.sym == dep_key.sym) {
                    new_deps.push(dep_key.clone());
                }
                // Track for later resolution
                pending_relocs.push((relocations.len(), dep_key));
                // Placeholder — resolved in second pass
                RelocTarget::MergedUnit(UnitId(u32::MAX))
            }
        } else {
            // RELATIVE relocation (no symbol, addend is the target)
            // For R_X86_64_RELATIVE: *(reloc_offset) = load_base + addend
            // The addend contains the original VA of the code/data being
            // pointed to. That VA is translated to a RelocTarget below, so
            // the extracted relocation's addend must drop to 0 or the old
            // VA would be added on top of the resolved new address.
            relative_addend_consumed = true;
            let addend_va = reloc.addend() as u64;

            // Check if the target is within an already-extracted data blob
            if let Some((blob_id, blob_base)) = find_existing_data_blob(addend_va, state) {
                let offset_in_blob = addend_va - blob_base;
                RelocTarget::DataBlobOffset(blob_id, offset_in_blob)
            } else if let Some(target_name) =
                find_symbol_at_address(elf64, addend_va).filter(|n| {
                    // Only symbols with a determinable non-zero size can become
                    // units; boundary markers like __TMC_END__ cannot.
                    find_symbol(elf64, n)
                        .and_then(|s| {
                            if s.size > 0 {
                                Ok(s.size as usize)
                            } else {
                                infer_symbol_size(elf64, &s)
                            }
                        })
                        .map(|sz| sz > 0)
                        .unwrap_or(false)
                })
            {
                let dep_key = UnitKey {
                    lib: lib.clone(),
                    sym: target_name,
                };
                if !new_deps.iter().any(|k| k.sym == dep_key.sym) {
                    new_deps.push(dep_key.clone());
                }
                pending_relocs.push((relocations.len(), dep_key));
                RelocTarget::MergedUnit(UnitId(u32::MAX))
            } else {
                warn!(
                    ctx,
                    lib = %lib.display(),
                    target = format_args!("{:#x}", addend_va),
                    "RELATIVE relocation target not resolvable; leaving stale"
                );
                continue;
            }
        };

        // For RELATIVE relocations, the size might be reported as 0 by the object crate
        // but we know it's always 64 bits (8 bytes) for R_X86_64_RELATIVE
        let reloc_size = if reloc.size() == 0 { 64 } else { reloc.size() };

        relocations.push(ExtractedReloc {
            offset_within_unit,
            kind,
            encoding,
            size: reloc_size,
            addend: if relative_addend_consumed {
                0
            } else {
                reloc.addend()
            },
            target,
        });
    }
    Ok(())
}

/// Extract a data section blob if not already extracted.
/// Returns the blob's UnitId and base vaddr.
#[allow(clippy::ptr_arg)]
fn ensure_data_blob_extracted(
    elf64: &object::read::elf::ElfFile64<'_>,
    target_addr: u64,
    lib: &PathBuf,
    state: &mut ExtractionState,
) -> Result<Option<(UnitId, u64, Vec<UnitKey>)>> {
    // Find the section containing this address
    let (sec_name, sec_addr, sec_size, sec_data, sec_kind) =
        match find_section_for_address(elf64, target_addr) {
            Some(info) => info,
            None => return Ok(None), // Address not in any extractable section
        };

    // Skip .text section - code references are handled separately
    if sec_kind == SectionKind::Text {
        return Ok(None);
    }

    let blob_key = DataBlobKey {
        lib: lib.clone(),
        section: sec_name.clone(),
    };

    // Check if already extracted
    if let Some(info) = state.data_blobs.get(&blob_key) {
        return Ok(Some((info.id, info.base_vaddr, Vec::new())));
    }

    // Collect relocations that fall within this data section's byte range.
    let mut relocations: Vec<ExtractedReloc> = Vec::new();
    let mut new_deps: Vec<UnitKey> = Vec::new();
    let mut pending_relocs: Vec<(usize, UnitKey)> = Vec::new();
    // (offset within blob, symbol name, weak) — becomes GotSlotFixup entries.
    let mut got_fixup_offsets: Vec<(u64, String, bool)> = Vec::new();

    collect_dynamic_range_relocs(
        elf64,
        lib,
        &sec_name,
        sec_addr,
        sec_size as u64,
        state,
        &mut relocations,
        &mut new_deps,
        &mut pending_relocs,
        &mut got_fixup_offsets,
    )?;

    // Extract the entire section as a blob
    let id = state.alloc_id();

    // Register pending relocations for this data blob
    for (reloc_idx, dep_key) in pending_relocs {
        state.pending.push((id, reloc_idx, dep_key));
    }

    if !relocations.is_empty() {
        debug!(
            section = sec_name,
            relocations = relocations.len(),
            "Extracted data blob"
        );
    }

    // Zero re-resolved GOT slots and register their fixups: the copied bytes
    // hold stale library VAs and ld.so's GLOB_DAT will overwrite them anyway.
    let mut sec_data = sec_data;
    for (offset, name, weak) in got_fixup_offsets {
        let off = offset as usize;
        if off + 8 <= sec_data.len() {
            sec_data[off..off + 8].fill(0);
        }
        state.got_slot_fixups.push(GotSlotFixup {
            unit: id,
            offset,
            name,
            weak,
        });
    }

    let unit = ExtractedUnit {
        id,
        name: format!(
            "{}:{}",
            lib.file_name().unwrap_or_default().to_string_lossy(),
            sec_name
        ),
        source_lib: lib.clone(),
        size: sec_size,
        bytes: sec_data,
        section_kind: sec_kind,
        alignment: 32, // Conservative alignment for data sections
        relocations,
    };

    state.units.push(unit);
    state.data_blobs.insert(
        blob_key,
        DataBlobInfo {
            id,
            base_vaddr: sec_addr,
            size: sec_size,
        },
    );

    Ok(Some((id, sec_addr, new_deps)))
}

/// Infer symbol size from the next symbol in the same section by address.
fn infer_symbol_size(elf: &object::read::elf::ElfFile64<'_>, sym: &SymInfo) -> Result<usize> {
    let sym_vaddr = sym.vaddr;
    let sym_section = sym.section;

    let mut next_addr: Option<u64> = None;
    for other in elf.symbols().chain(elf.dynamic_symbols()) {
        if other.address() > sym_vaddr
            && let object::SymbolSection::Section(si) = other.section()
            && si == sym_section
        {
            let candidate = other.address();
            next_addr = Some(match next_addr {
                Some(cur) if cur < candidate => cur,
                _ => candidate,
            });
        }
    }

    let section = elf
        .section_by_index(sym_section)
        .context("section lookup")?;
    let section_end = section.address() + section.size();
    let limit = next_addr.unwrap_or(section_end);

    if limit <= sym_vaddr {
        return Ok(0);
    }
    Ok((limit - sym_vaddr) as usize)
}

/// Init-side CRT glue that crtbeginS.o places in every shared library's
/// .init_array. In a normally linked process these only touch weak symbols
/// that resolve to null (`_ITM_registerTMCloneTable`, `__register_frame_info`),
/// so they are no-ops for the merged binary and are skipped instead of dragged
/// in with their closure. In stripped libraries these have no symbol names and
/// are conservatively extracted as anonymous units, which is still
/// behaviorally correct.
///
/// `__do_global_dtors_aux` (fini side) is deliberately NOT in this list: it
/// calls `__cxa_finalize(&__dso_handle)`, which is what runs the library's
/// C++ static destructors at the correct point in the shutdown sequence.
fn is_crt_glue(name: &str) -> bool {
    matches!(name, "frame_dummy" | "register_tm_clones")
}

/// Extract init/fini array entries from a library, resolving each function
/// pointer to an extractable unit name.
///
/// The raw section bytes normally hold each function's link-time address, but
/// some linkers zero the slots and rely on the R_X86_64_RELATIVE addend
/// instead, so relocation addends take precedence over raw content.
/// Sentinel values (0 or -1) are skipped.
fn extract_init_fini_arrays(
    elf64: &object::read::elf::ElfFile64<'_>,
    lib_path: &std::path::Path,
) -> Result<InitFiniArrays> {
    let mut result = InitFiniArrays::default();

    // Function addresses for init/fini slots, recovered from .rela.dyn:
    // R_X86_64_RELATIVE carries the address in its addend; a symbol-based
    // relocation (e.g. R_X86_64_64) resolves to symbol address + addend.
    let mut reloc_targets: HashMap<u64, u64> = HashMap::new();
    if let Some(dyn_relocs) = elf64.dynamic_relocations() {
        for (roff, reloc) in dyn_relocs {
            let func_vaddr = match reloc.target() {
                object::RelocationTarget::Symbol(si) => match dynamic_symbol_by_index(elf64, si) {
                    Some(sym) if !sym.is_undefined() => {
                        sym.address().wrapping_add(reloc.addend() as u64)
                    }
                    _ => continue,
                },
                _ => reloc.addend() as u64,
            };
            reloc_targets.insert(roff, func_vaddr);
        }
    }

    for section in elf64.sections() {
        let sname = section.name().unwrap_or("");
        let is_init = sname == ".init_array";
        let is_fini = sname == ".fini_array";
        if !is_init && !is_fini {
            continue;
        }

        let sec_addr = section.address();
        let section_data = section
            .data()
            .with_context(|| format!("{}: {} section data", lib_path.display(), sname))?;

        for (i, chunk) in section_data.as_chunks::<8>().0.iter().enumerate() {
            let slot_vaddr = sec_addr + (i * 8) as u64;
            let func_vaddr = match reloc_targets.get(&slot_vaddr) {
                Some(&target) => target,
                None => u64::from_le_bytes(*chunk),
            };

            // Skip sentinel values (0 or -1)
            if func_vaddr == 0 || func_vaddr == u64::MAX {
                continue;
            }

            let sym_name = find_symbol_at_address(elf64, func_vaddr);
            if let Some(ref name) = sym_name
                && is_crt_glue(name)
            {
                debug!(
                    lib = %lib_path.display(),
                    name,
                    "Skipping no-op CRT glue in {}", sname
                );
                continue;
            }

            let unit_name = sym_name
                .filter(|n| find_symbol(elf64, n).is_ok())
                .or_else(|| {
                    anon_target_is_extractable(elf64, func_vaddr)
                        .then(|| anon_unit_name(func_vaddr))
                })
                .with_context(|| {
                    format!(
                        "{}: {} entry {:#x} is not extractable — the merged binary \
                         would skip a constructor/destructor and behave differently",
                        lib_path.display(),
                        sname,
                        func_vaddr
                    )
                })?;

            let entry = InitFiniEntry {
                source_lib: lib_path.to_path_buf(),
                unit_name,
            };

            if is_init {
                result.init_entries.push(entry);
            } else {
                result.fini_entries.push(entry);
            }
        }
    }

    Ok(result)
}
