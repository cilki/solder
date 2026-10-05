use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, bail};
use indexmap::IndexSet;
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
    /// Cache of raw library bytes keyed by path. `process_symbol` runs once per
    /// extracted symbol, and a large library (e.g. libcrypto.so.3 at ~6MB) can
    /// yield thousands of symbols; re-reading the whole file from disk each time
    /// dominated the runtime. The parse itself is lazy and cheap, so only the
    /// bytes need caching.
    lib_bytes_cache: HashMap<PathBuf, Rc<Vec<u8>>>,
    /// Precomputed symbol lookups per library (see `LibIndex`).
    lib_index_cache: HashMap<PathBuf, Rc<LibIndex>>,
    /// Precomputed PLT stub → external symbol maps per library (see `PltMap`).
    plt_map_cache: HashMap<PathBuf, Rc<PltMap>>,
}

impl ExtractionState {
    fn alloc_id(&mut self) -> UnitId {
        let id = UnitId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Return the raw bytes of `lib`, reading and caching them on first use.
    fn lib_bytes(&mut self, lib: &Path) -> Result<Rc<Vec<u8>>> {
        if let Some(bytes) = self.lib_bytes_cache.get(lib) {
            return Ok(Rc::clone(bytes));
        }
        let bytes =
            Rc::new(std::fs::read(lib).with_context(|| format!("reading {}", lib.display()))?);
        self.lib_bytes_cache
            .insert(lib.to_path_buf(), Rc::clone(&bytes));
        Ok(bytes)
    }

    /// Return the symbol index for `lib`, building and caching it on first use.
    fn lib_index(&mut self, lib: &Path, elf: &object::read::elf::ElfFile64<'_>) -> Rc<LibIndex> {
        if let Some(idx) = self.lib_index_cache.get(lib) {
            return Rc::clone(idx);
        }
        let idx = Rc::new(LibIndex::build(elf));
        debug!(
            lib = %lib.display(),
            symbols = idx.by_name.len(),
            fdes = idx.fdes.fde_count(),
            "Indexed library"
        );
        self.lib_index_cache
            .insert(lib.to_path_buf(), Rc::clone(&idx));
        idx
    }

    /// Return the PLT map for `lib`, building and caching it on first use.
    fn plt_map(&mut self, lib: &Path, lib_bytes: Rc<Vec<u8>>) -> Rc<PltMap> {
        if let Some(m) = self.plt_map_cache.get(lib) {
            return Rc::clone(m);
        }
        let m = Rc::new(PltMap::build(lib_bytes));
        self.plt_map_cache.insert(lib.to_path_buf(), Rc::clone(&m));
        m
    }

    /// Zero the copied GOT slots at `slots` within `bytes` and register a fixup
    /// for each: the copied bytes hold stale library VAs, and ld.so's GLOB_DAT
    /// overwrites them at startup anyway (see `GotSlotFixup`).
    fn register_got_slot_fixups(
        &mut self,
        unit: UnitId,
        bytes: &mut [u8],
        slots: Vec<(u64, String, bool)>,
    ) {
        for (offset, name, weak) in slots {
            let off = offset as usize;
            if off + 8 <= bytes.len() {
                bytes[off..off + 8].fill(0);
            }
            self.got_slot_fixups.push(GotSlotFixup {
                unit,
                offset,
                name,
                weak,
            });
        }
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
        lib_bytes_cache: HashMap::new(),
        lib_index_cache: HashMap::new(),
        plt_map_cache: HashMap::new(),
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

/// Record a dependency on `dep_key`, queue the relocation that will be pushed
/// at index `reloc_idx` for second-pass resolution, and hand back the
/// placeholder target to store in it until then. The three steps have to stay
/// in lockstep — the pending entry is keyed by the relocation's index — so they
/// live in one place.
fn depend_on(
    dep_key: UnitKey,
    reloc_idx: usize,
    new_deps: &mut IndexSet<UnitKey>,
    pending_relocs: &mut Vec<(usize, UnitKey)>,
) -> RelocTarget {
    new_deps.insert(dep_key.clone());
    pending_relocs.push((reloc_idx, dep_key));
    RelocTarget::MergedUnit(UnitId(u32::MAX))
}

/// A synthetic PC-relative relocation over a displacement the instruction
/// scanner found, at `offset` bytes into the unit being extracted. Every
/// scanned reference is patched the same way — only the displacement width,
/// the addend and the target differ.
fn pcrel_reloc(offset: u64, size: u8, addend: i64, target: RelocTarget) -> ExtractedReloc {
    ExtractedReloc {
        offset_within_unit: offset,
        kind: object::RelocationKind::Relative,
        encoding: object::RelocationEncoding::Generic,
        size,
        addend,
        target,
    }
}

/// Reject relocation kinds that need a GOT we cannot reproduce. `ctx` names the
/// symbol or section being extracted.
fn reject_got_reloc(
    kind: object::RelocationKind,
    encoding: object::RelocationEncoding,
    ctx: &str,
    lib: &Path,
) -> Result<()> {
    if matches!(
        kind,
        object::RelocationKind::Got
            | object::RelocationKind::GotRelative
            | object::RelocationKind::GotBaseRelative
            | object::RelocationKind::GotBaseOffset
    ) {
        bail!(
            "'{}' in {}: {} relocation is not supported in Tier 1; \
             recompile the library with an older toolchain or wait for Tier 2 support",
            ctx,
            lib.display(),
            describe_reloc(kind, encoding)
        );
    }
    Ok(())
}

/// Process a single symbol: extract its bytes, parse its relocations, and
/// return new symbols to enqueue.
fn process_symbol(key: &UnitKey, state: &mut ExtractionState) -> Result<IndexSet<UnitKey>> {
    let lib_bytes = state.lib_bytes(&key.lib)?;

    let object_file = object::File::parse(lib_bytes.as_slice())
        .with_context(|| format!("object parse {}", key.lib.display()))?;

    let object::File::Elf64(elf64) = &object_file else {
        bail!("{}: not a 64-bit ELF shared library", key.lib.display());
    };

    let lib_index = state.lib_index(&key.lib, elf64);

    let mut new_deps: IndexSet<UnitKey> = IndexSet::new();

    // Extract init/fini arrays from this library if we haven't already. Each
    // constructor/destructor becomes an extraction root of its own: when the
    // library is dynamically linked, ld.so runs every one of these at load/exit,
    // so a merged binary must include them (and their closure) to behave
    // identically. Provably no-op CRT glue is skipped inside
    // extract_init_fini_arrays.
    if !state.processed_libs.contains(&key.lib) {
        state.processed_libs.insert(key.lib.clone());
        let lib_init_fini = extract_init_fini_arrays(elf64, &lib_index, &key.lib)?;
        for entry in lib_init_fini
            .init_entries
            .iter()
            .chain(&lib_init_fini.fini_entries)
        {
            new_deps.insert(UnitKey {
                lib: entry.source_lib.clone(),
                sym: entry.unit_name.clone(),
            });
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
    let sym = find_symbol(elf64, &lib_index, &key.sym)
        .with_context(|| format!("symbol '{}' in {}", key.sym, key.lib.display()))?;

    // Determine symbol size.
    let sym_size = if sym.size > 0 {
        sym.size as usize
    } else {
        // Infer from the next symbol in the same section by address.
        infer_symbol_size(elf64, &lib_index, &sym)?
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
        ObjSectionKind::Text => SectionKind::Text,
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
        reject_got_reloc(kind, encoding, &key.sym, &key.lib)?;

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
                    depend_on(
                        dep_key,
                        relocations.len(),
                        &mut new_deps,
                        &mut pending_relocs,
                    )
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
                        ensure_data_blob_extracted(elf64, &lib_index, ts_vaddr, &key.lib, state);
                    if let Ok(Some((blob_id, blob_base, blob_deps))) = extract_result {
                        let offset_in_blob = ts_vaddr - blob_base;
                        new_deps.extend(blob_deps);
                        RelocTarget::DataBlobOffset(blob_id, offset_in_blob)
                    } else {
                        // It's a code symbol or unknown - extract as a unit
                        let dep_key = UnitKey {
                            lib: key.lib.clone(),
                            sym: ts_name,
                        };
                        depend_on(
                            dep_key,
                            relocations.len(),
                            &mut new_deps,
                            &mut pending_relocs,
                        )
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
            &lib_index,
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
        let plt_map = state.plt_map(&key.lib, Rc::clone(&lib_bytes));
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
                // First check if this is a PLT call (call to external symbol)
                if let Some(ext_name) = plt_map.target(target_addr) {
                    // PLT call resolution order:
                    //   1. Another merged library defines the symbol, and the
                    //      executable's own .dynsym does not mention it →
                    //      extract from that library and create a direct
                    //      merged-unit reference.
                    //   2. Otherwise the symbol stays external. Either the
                    //      executable already exports or imports it, in which
                    //      case the reference trampolines through the exe's
                    //      GOT, or it is a libc/runtime symbol the executable
                    //      does not import yet, in which case the writer
                    //      injects a .dynsym entry and a GLOB_DAT relocation
                    //      so ld.so resolves it at load time.
                    let target = if !state.external_syms.contains(&ext_name)
                        && let Some(other_lib) = state.cross_lib_syms.get(&ext_name).cloned()
                    {
                        depend_on(
                            UnitKey {
                                lib: other_lib,
                                sym: ext_name,
                            },
                            relocations.len(),
                            &mut new_deps,
                            &mut pending_relocs,
                        )
                    } else {
                        RelocTarget::External(ext_name)
                    };
                    relocations.push(pcrel_reloc(
                        rip_ref.offset as u64,
                        reloc_size,
                        rip_ref.addend,
                        target,
                    ));
                } else {
                    // Direct call/jmp to an internal address. Prefer a named
                    // symbol; otherwise synthesize an anonymous unit for a
                    // symbol-less local helper. Stripped libraries routinely
                    // reach such helpers via a plain `call` with no symbol of
                    // their own — e.g. OpenSSL's md5_block_asm_data_order, which
                    // MD5_Update/MD5_Final call directly. Without this, the call
                    // bytes were copied verbatim and the stale displacement
                    // pointed into unmapped memory, crashing at runtime.
                    let dep = resolve_owning_unit(elf64, &lib_index, target_addr).or_else(|| {
                        anon_target_is_extractable(elf64, target_addr)
                            .then(|| (anon_unit_name(target_addr), 0))
                    });
                    if let Some((target_name, offset_in_target)) = dep {
                        let target = depend_on(
                            UnitKey {
                                lib: key.lib.clone(),
                                sym: target_name,
                            },
                            relocations.len(),
                            &mut new_deps,
                            &mut pending_relocs,
                        );
                        // The relocator computes S + A - P against the unit's
                        // base, so an interior target is reached through the
                        // addend.
                        relocations.push(pcrel_reloc(
                            rip_ref.offset as u64,
                            reloc_size,
                            rip_ref.addend + offset_in_target as i64,
                            target,
                        ));
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
                // Data reference (LEA/MOV) — could be loading the address of
                // data or of code (e.g. LEA of a function pointer, or of a
                // label inside the function doing the load). Resolve it to an
                // owning unit first; anything else falls through to the blob
                // path below.
                if let Some((target_name, offset_in_target)) =
                    resolve_owning_unit(elf64, &lib_index, target_addr)
                {
                    let target = depend_on(
                        UnitKey {
                            lib: key.lib.clone(),
                            sym: target_name,
                        },
                        relocations.len(),
                        &mut new_deps,
                        &mut pending_relocs,
                    );
                    relocations.push(pcrel_reloc(
                        rip_ref.offset as u64,
                        32,
                        rip_ref.addend + offset_in_target as i64,
                        target,
                    ));
                    continue;
                }
                // Otherwise try to extract the data section
                if let Some((blob_id, blob_base, blob_deps)) =
                    ensure_data_blob_extracted(elf64, &lib_index, target_addr, &key.lib, state)?
                {
                    let offset_in_blob = target_addr - blob_base;
                    new_deps.extend(blob_deps);
                    relocations.push(pcrel_reloc(
                        rip_ref.offset as u64,
                        32,
                        rip_ref.addend,
                        RelocTarget::DataBlobOffset(blob_id, offset_in_blob),
                    ));
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
            crate::jump_table::detect_jump_tables(&bytes, sym_vaddr, &key.sym, elf64)
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
                ensure_data_blob_extracted(elf64, &lib_index, table.table_vaddr, &key.lib, state)?
            {
                new_deps.extend(blob_deps);
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

                    // 3. `detect_jump_tables` only keeps entries that branch into
                    // this unit, so the target is always an offset into it.
                    let offset_in_target = (*target_addr - sym_vaddr) as i64;

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

                    // 4. Add jump table entry relocation to the data blob
                    // Find the blob unit and add the relocation
                    if let Some(blob_unit) = state.units.iter_mut().find(|u| u.id == blob_id) {
                        let reloc_idx = blob_unit.relocations.len();

                        blob_unit.relocations.push(pcrel_reloc(
                            entry_offset_in_blob,
                            32,
                            addend, // offset within target function, PC-relative
                            RelocTarget::MergedUnit(UnitId(u32::MAX)), // placeholder
                        ));

                        // The target is this very unit, which is already being
                        // extracted, so there is no new dependency to enqueue —
                        // only a pending resolution of the placeholder UnitId.
                        // (Not `pending_relocs`: that one is for relocations of
                        // the current unit, these belong to the blob.)
                        state.pending.push((
                            blob_id,
                            reloc_idx,
                            UnitKey {
                                lib: key.lib.clone(),
                                sym: key.sym.clone(),
                            },
                        ));
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
    for reloc in relocations.iter_mut() {
        if reloc.size != 8 {
            continue;
        }
        let disp_off = reloc.offset_within_unit as usize;
        let end_off = bytes.len();
        let veneer_off = if end_off as i64 - (disp_off as i64 + 1) <= i8::MAX as i64 {
            bytes.extend_from_slice(&[0xe9, 0, 0, 0, 0]);
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
        // The addend of a scanned branch is -(displacement width) plus the
        // target's offset into its unit. Only the width changes here, from the
        // rel8 field to the veneer's rel32 one; the target offset must survive.
        reloc.addend -= 3;
    }

    // Register this unit.
    let id = state.alloc_id();
    state.extracted.insert(key.clone(), id);

    // Record pending resolutions using our explicit tracking.
    for (reloc_idx, dep_key) in pending_relocs {
        state.pending.push((id, reloc_idx, dep_key));
    }

    state.register_got_slot_fixups(id, &mut bytes, got_fixup_offsets);

    state.units.push(ExtractedUnit {
        id,
        name: key.sym.clone(),
        source_lib: key.lib.clone(),
        bytes,
        section_kind,
        alignment,
        relocations,
    });

    Ok(new_deps)
}

/// Lightweight snapshot of a symbol we care about.
#[derive(Clone)]
struct SymInfo {
    vaddr: u64,
    size: u64,
    section: object::SectionIndex,
}

/// Precomputed per-library symbol lookups.
///
/// `process_symbol` runs once per extracted symbol, and each run performs many
/// name/address lookups (`find_symbol`, `find_symbol_at_address`,
/// `infer_symbol_size`). Done naively each of those linearly scans both the
/// full `.symtab` and `.dynsym` — an O(symbols) cost paid per lookup, which for
/// a large library like libcrypto.so.3 (tens of thousands of symbols, an
/// enormous extraction closure) turns the whole run quadratic. Building these
/// maps once per library collapses each lookup to O(1)/O(log n).
struct LibIndex {
    /// Defined symbols by name, preferring `.symtab` over `.dynsym` (the order
    /// the linear `find_symbol` used). Only symbols in a real section.
    by_name: HashMap<String, SymInfo>,
    /// First defined symbol name at a given address, `.symtab` before `.dynsym`.
    addr_to_name: HashMap<u64, String>,
    /// Every defined symbol address paired with its section index (as a plain
    /// `usize`, since `SectionIndex` isn't `Ord`), sorted by address, for
    /// `infer_symbol_size`'s "next symbol boundary" search.
    addrs_by_section: Vec<(u64, usize)>,
    /// Exact function bounds from `.eh_frame`, which cover code the symbol
    /// tables say nothing about (see `resolve_owning_unit`).
    fdes: crate::eh_frame::FdeTable,
}

impl LibIndex {
    fn build(elf: &object::read::elf::ElfFile64<'_>) -> Self {
        let mut by_name: HashMap<String, SymInfo> = HashMap::new();
        let mut addr_to_name: HashMap<u64, String> = HashMap::new();
        let mut addrs_by_section: Vec<(u64, usize)> = Vec::new();

        // Iterate .symtab first, then .dynsym, so first-writer-wins matches the
        // ".symtab preferred" order of the original linear scans.
        for sym in elf.symbols().chain(elf.dynamic_symbols()) {
            let object::SymbolSection::Section(si) = sym.section() else {
                continue;
            };
            let addr = sym.address();
            addrs_by_section.push((addr, si.0));

            let Ok(name) = sym.name() else { continue };
            if name.is_empty() {
                continue;
            }

            if !sym.is_undefined() {
                by_name.entry(name.to_string()).or_insert(SymInfo {
                    vaddr: addr,
                    size: sym.size(),
                    section: si,
                });
            }
            addr_to_name.entry(addr).or_insert_with(|| name.to_string());
        }

        addrs_by_section.sort_unstable();
        addrs_by_section.dedup();

        let fdes = elf
            .section_by_name(".eh_frame")
            .and_then(|s| s.data().ok().map(|d| (d, s.address())))
            .map(|(data, vaddr)| crate::eh_frame::FdeTable::parse(data, vaddr))
            .unwrap_or_default();

        LibIndex {
            by_name,
            addr_to_name,
            addrs_by_section,
            fdes,
        }
    }

    /// Smallest defined-symbol address greater than `addr` within `section`.
    fn next_addr_in_section(&self, addr: u64, section: object::SectionIndex) -> Option<u64> {
        let start = self.addrs_by_section.partition_point(|&(a, _)| a <= addr);
        self.addrs_by_section[start..]
            .iter()
            .find(|&&(_, s)| s == section.0)
            .map(|&(a, _)| a)
    }
}

/// Find a symbol by name using the precomputed library index, falling back to
/// the ELF only for synthetic anonymous-unit names.
fn find_symbol(
    elf: &object::read::elf::ElfFile64<'_>,
    index: &LibIndex,
    name: &str,
) -> Result<SymInfo> {
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

    index
        .by_name
        .get(name)
        .cloned()
        .with_context(|| format!("symbol '{name}' not found in .symtab or .dynsym"))
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
fn find_symbol_at_address(index: &LibIndex, addr: u64) -> Option<String> {
    index.addr_to_name.get(&addr).cloned()
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

/// Resolve `addr` to the unit that owns it: the name to extract that unit
/// under, and the offset of `addr` within it.
///
/// A reference does not have to land on a function entry: compilers branch to
/// and take the address of interior labels all the time, and in a stripped
/// library most branch targets have no symbol of their own. Resolving such an
/// address to the function that contains it — plus an offset — keeps one unit
/// per function instead of starting a fresh, over-extended unit at every
/// address that happens to be referenced.
///
/// Returns `None` when nothing is known to own `addr`; the caller decides
/// whether to fall back to an anonymous unit starting there.
fn resolve_owning_unit(
    elf: &object::read::elf::ElfFile64<'_>,
    index: &LibIndex,
    addr: u64,
) -> Option<(String, u64)> {
    // A symbol defined at exactly this address, as long as it has a usable
    // size: zero-size boundary markers (e.g. `__TMC_END__`, which sits at the
    // exact end of .data with nothing after it) own nothing.
    if let Some(name) = find_symbol_at_address(index, addr)
        && symbol_unit_size(elf, index, &name).is_some_and(|size| size > 0)
    {
        return Some((name, 0));
    }

    // Otherwise the function whose `.eh_frame` range covers the address. Prefer
    // a named symbol at that function's entry so the interior reference shares
    // the unit the function is already extracted as, instead of duplicating its
    // tail under an anonymous name.
    let (fde_start, _) = index.fdes.containing(addr)?;
    let offset = addr - fde_start;
    if let Some(name) = find_symbol_at_address(index, fde_start)
        && symbol_unit_size(elf, index, &name).is_some_and(|size| size as u64 > offset)
    {
        return Some((name, offset));
    }
    anon_target_is_extractable(elf, fde_start).then(|| (anon_unit_name(fde_start), offset))
}

/// The size `process_symbol` would extract for `name`, or `None` if the symbol
/// cannot be resolved at all.
fn symbol_unit_size(
    elf: &object::read::elf::ElfFile64<'_>,
    index: &LibIndex,
    name: &str,
) -> Option<usize> {
    let sym = find_symbol(elf, index, name).ok()?;
    if sym.size > 0 {
        Some(sym.size as usize)
    } else {
        infer_symbol_size(elf, index, &sym).ok()
    }
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
                        && i8::try_from(rel).is_ok_and(|r| instr_bytes[instr.len() - 1] == r as u8);
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

/// Precomputed PLT-resolution data for a library. `find_plt_target` is called
/// for every code reference into a PLT stub during extraction; parsing the whole
/// library with goblin each time (as the original did) was a major quadratic
/// cost. This captures the small amount that lookup actually needs so it can be
/// built once per library.
struct PltMap {
    /// Each PLT section's (start_va, file_offset, size), so a stub's address can
    /// be recognised and its bytes located without reparsing.
    plt_spans: Vec<(u64, u64, u64)>,
    /// GOT slot VA → external symbol name, from JUMP_SLOT/GLOB_DAT relocations.
    got_to_name: HashMap<u64, String>,
    /// Symbol address → name (dynsym), for the fallback path.
    addr_to_name: HashMap<u64, String>,
    /// Raw library bytes (needed to read a stub's disp32 at lookup time), shared
    /// with `ExtractionState::lib_bytes_cache`.
    bytes: Rc<Vec<u8>>,
}

impl PltMap {
    fn build(lib_bytes: Rc<Vec<u8>>) -> Self {
        let mut plt_spans = Vec::new();
        let mut got_to_name = HashMap::new();
        let mut addr_to_name = HashMap::new();

        if let Ok(g) = goblin::elf::Elf::parse(&lib_bytes) {
            for sh in &g.section_headers {
                let Some(name) = g.shdr_strtab.get_at(sh.sh_name) else {
                    continue;
                };
                if name == ".plt" || name == ".plt.got" || name == ".plt.sec" {
                    plt_spans.push((sh.sh_addr, sh.sh_offset, sh.sh_size));
                }
            }

            for rela in g.pltrelocs.iter().chain(g.dynrelas.iter()) {
                if let Some(sym) = g.dynsyms.get(rela.r_sym)
                    && let Some(name) = g.dynstrtab.get_at(sym.st_name)
                    && !name.is_empty()
                {
                    got_to_name
                        .entry(rela.r_offset)
                        .or_insert_with(|| name.to_string());
                }
            }

            for sym in g.dynsyms.iter() {
                if let Some(name) = g.dynstrtab.get_at(sym.st_name)
                    && !name.is_empty()
                {
                    addr_to_name
                        .entry(sym.st_value)
                        .or_insert_with(|| name.to_string());
                }
            }
        }

        PltMap {
            plt_spans,
            got_to_name,
            addr_to_name,
            bytes: lib_bytes,
        }
    }

    /// If `addr` lands in a PLT stub, return the external symbol it resolves to.
    fn target(&self, addr: u64) -> Option<String> {
        // Locate the stub's bytes via the containing PLT section's file span.
        let (sec_addr, sec_off, sec_size) = self
            .plt_spans
            .iter()
            .copied()
            .find(|&(start, _, size)| addr >= start && addr < start + size)?;
        let sec_data = self
            .bytes
            .get(sec_off as usize..(sec_off + sec_size) as usize)?;

        // Decode the stub itself instead of guessing by entry index: every
        // flavor (.plt, .plt.got, .plt.sec) starts with an optional endbr64
        // and/or bnd prefix followed by `ff 25 <disp32>` (jmp [rip+disp32])
        // through its GOT slot. The slot's dynamic relocation — JUMP_SLOT for
        // classic PLT entries, GLOB_DAT for .plt.got-style stubs like
        // __cxa_finalize@plt — names the symbol.
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

        if let Some(name) = self.got_to_name.get(&got_va) {
            return Some(name.clone());
        }
        // Fallback: a symbol defined at this exact address.
        self.addr_to_name.get(&addr).cloned()
    }
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

/// Find the section containing a given virtual address and return its name,
/// base vaddr, contents and kind.
fn find_section_for_address(
    elf: &object::read::elf::ElfFile64<'_>,
    addr: u64,
) -> Option<(String, u64, Vec<u8>, SectionKind)> {
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
            return Some((name, sec_addr, data, kind));
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
fn collect_dynamic_range_relocs(
    elf64: &object::read::elf::ElfFile64<'_>,
    index: &LibIndex,
    lib: &Path,
    ctx: &str,
    range_start: u64,
    range_size: u64,
    state: &mut ExtractionState,
    relocations: &mut Vec<ExtractedReloc>,
    new_deps: &mut IndexSet<UnitKey>,
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
        reject_got_reloc(kind, encoding, ctx, lib)?;

        // Resolve the relocation target symbol. Dynamic relocation symbol
        // indices refer to .dynsym, not .symtab.
        let target_sym = match reloc.target() {
            object::RelocationTarget::Symbol(si) => dynamic_symbol_by_index(elf64, si),
            _ => None,
        };

        // Set for relocations whose own addend was consumed while resolving the
        // target (see the RELATIVE case below); holds the offset into the
        // resolved unit, which is 0 unless the target is a unit interior.
        let mut resolved_addend: Option<i64> = None;
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
                    depend_on(dep_key, relocations.len(), new_deps, pending_relocs)
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
                    lib: lib.to_path_buf(),
                    sym: ts_name,
                };
                depend_on(dep_key, relocations.len(), new_deps, pending_relocs)
            }
        } else {
            // RELATIVE relocation (no symbol, addend is the target)
            // For R_X86_64_RELATIVE: *(reloc_offset) = load_base + addend
            // The addend contains the original VA of the code/data being
            // pointed to. That VA is translated to a RelocTarget below, so
            // the extracted relocation's addend must drop to the offset of the
            // target within whatever unit ends up holding it — 0 unless the
            // target is a unit interior — or the old VA would be added on top
            // of the resolved new address.
            resolved_addend = Some(0);
            let addend_va = reloc.addend() as u64;

            // Check if the target is within an already-extracted data blob
            if let Some((blob_id, blob_base)) = find_existing_data_blob(addend_va, state) {
                let offset_in_blob = addend_va - blob_base;
                RelocTarget::DataBlobOffset(blob_id, offset_in_blob)
            } else if let Some((target_name, offset_in_target)) =
                resolve_owning_unit(elf64, index, addend_va)
            {
                resolved_addend = Some(offset_in_target as i64);
                let dep_key = UnitKey {
                    lib: lib.to_path_buf(),
                    sym: target_name,
                };
                depend_on(dep_key, relocations.len(), new_deps, pending_relocs)
            } else if let Some((blob_id, blob_base, blob_deps)) =
                ensure_data_blob_extracted(elf64, index, addend_va, lib, state)?
            {
                // No symbol and no unwind info describe the target, but it does
                // live in a data section we can copy wholesale — most often a
                // string or a struct in .rodata that a pointer table in
                // .data.rel.ro points at (ncurses' `strnames` is a table of
                // several hundred of these). Pulling that section in and
                // retargeting the pointer at it is the only way the copied
                // table keeps working once the library is gone.
                new_deps.extend(blob_deps);
                RelocTarget::DataBlobOffset(blob_id, addend_va - blob_base)
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
            addend: resolved_addend.unwrap_or_else(|| reloc.addend()),
            target,
        });
    }
    Ok(())
}

/// Extract a data section blob if not already extracted.
/// Returns the blob's UnitId and base vaddr.
fn ensure_data_blob_extracted(
    elf64: &object::read::elf::ElfFile64<'_>,
    index: &LibIndex,
    target_addr: u64,
    lib: &Path,
    state: &mut ExtractionState,
) -> Result<Option<(UnitId, u64, IndexSet<UnitKey>)>> {
    // Find the section containing this address
    let (sec_name, sec_addr, sec_data, sec_kind) =
        match find_section_for_address(elf64, target_addr) {
            Some(info) => info,
            None => return Ok(None), // Address not in any extractable section
        };

    // Skip .text section - code references are handled separately
    if sec_kind == SectionKind::Text {
        return Ok(None);
    }

    let blob_key = DataBlobKey {
        lib: lib.to_path_buf(),
        section: sec_name.clone(),
    };

    // Check if already extracted
    if let Some(info) = state.data_blobs.get(&blob_key) {
        return Ok(Some((info.id, info.base_vaddr, IndexSet::new())));
    }

    // Claim the blob's id and register it *before* collecting its relocations.
    // Resolving those relocations can lead back to this same section — directly
    // (a pointer in .data to the start of .data) or through another section
    // whose own pointers come back here — and `find_existing_data_blob` has to
    // be able to see the blob while that happens. Registering afterwards made
    // such a target look unresolvable, and the copied bytes kept the library's
    // own load-time VA, which points into unmapped memory once the library is
    // dropped from DT_NEEDED. It also bounds the mutual recursion with
    // `collect_dynamic_range_relocs` at one visit per section.
    let id = state.alloc_id();
    state.data_blobs.insert(
        blob_key,
        DataBlobInfo {
            id,
            base_vaddr: sec_addr,
            size: sec_data.len(),
        },
    );

    // Collect relocations that fall within this data section's byte range.
    let mut relocations: Vec<ExtractedReloc> = Vec::new();
    let mut new_deps: IndexSet<UnitKey> = IndexSet::new();
    let mut pending_relocs: Vec<(usize, UnitKey)> = Vec::new();
    // (offset within blob, symbol name, weak) — becomes GotSlotFixup entries.
    let mut got_fixup_offsets: Vec<(u64, String, bool)> = Vec::new();

    collect_dynamic_range_relocs(
        elf64,
        index,
        lib,
        &sec_name,
        sec_addr,
        sec_data.len() as u64,
        state,
        &mut relocations,
        &mut new_deps,
        &mut pending_relocs,
        &mut got_fixup_offsets,
    )?;

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

    let mut sec_data = sec_data;
    state.register_got_slot_fixups(id, &mut sec_data, got_fixup_offsets);

    let unit = ExtractedUnit {
        id,
        name: format!(
            "{}:{}",
            lib.file_name().unwrap_or_default().to_string_lossy(),
            sec_name
        ),
        source_lib: lib.to_path_buf(),
        bytes: sec_data,
        section_kind: sec_kind,
        alignment: 32, // Conservative alignment for data sections
        relocations,
    };

    state.units.push(unit);

    Ok(Some((id, sec_addr, new_deps)))
}

/// Infer the size of a symbol whose `st_size` is 0, by bounding it with the
/// tightest safe end marker: the start of the next function with unwind info,
/// the next symbol in the same section, or the end of the section.
///
/// The next symbol alone is a poor bound in a stripped library, where the run
/// between two exported symbols can hold dozens of local functions: the whole
/// run would be copied once for every one of them that gets referenced, and a
/// unit that long also breaks short-branch veneering.
fn infer_symbol_size(
    elf: &object::read::elf::ElfFile64<'_>,
    index: &LibIndex,
    sym: &SymInfo,
) -> Result<usize> {
    let sym_vaddr = sym.vaddr;
    let sym_section = sym.section;

    let next_addr = index.next_addr_in_section(sym_vaddr, sym_section);

    let section = elf
        .section_by_index(sym_section)
        .context("section lookup")?;
    let section_end = section.address() + section.size();
    let mut limit = next_addr.unwrap_or(section_end);

    // The start of the next function with unwind info is a far tighter bound
    // than the next symbol in a stripped library, where one run between two
    // exported symbols can hold dozens of local functions.
    //
    // It is the *next* FDE's start rather than the containing FDE's end
    // because the two are not always the same: hand-written assembly
    // (OpenSSL's RC4_options, for one) carries unwind info for only part of
    // the function, and cutting the unit at that FDE's end would drop real
    // code. Padding between functions can be copied; missing instructions
    // cannot. Unwind ranges only describe code, so this is consulted only for
    // symbols in an executable section.
    if section.kind() == ObjSectionKind::Text
        && let Some(next_fde) = index.fdes.next_start_after(sym_vaddr)
    {
        limit = limit.min(next_fde);
    }

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
    index: &LibIndex,
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

            let sym_name = find_symbol_at_address(index, func_vaddr);
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
                .filter(|n| find_symbol(elf64, index, n).is_ok())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> ExtractionState {
        ExtractionState {
            extracted: HashMap::new(),
            units: Vec::new(),
            pending: Vec::new(),
            next_id: 0,
            external_syms: HashSet::new(),
            cross_lib_syms: HashMap::new(),
            exe_defined_syms: HashSet::new(),
            processed_libs: HashSet::new(),
            init_fini: InitFiniArrays::default(),
            data_blobs: HashMap::new(),
            got_slot_fixups: Vec::new(),
            lib_bytes_cache: HashMap::new(),
            lib_index_cache: HashMap::new(),
            plt_map_cache: HashMap::new(),
        }
    }

    fn test_lib(name: &str) -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs")).join(name)
    }

    /// Every R_X86_64_RELATIVE slot inside an extracted unit has to come out
    /// with a relocation of its own. The copied bytes still hold the library's
    /// link-time address, so a slot that keeps its original value points into
    /// memory that is no longer mapped once the library leaves DT_NEEDED.
    ///
    /// `strnames` is ncurses' table of 414 pointers into `.rodata`, none of
    /// which has a symbol or unwind info of its own — exactly the shape that
    /// used to resolve to nothing and get left stale.
    #[test]
    fn every_relative_slot_in_a_pointer_table_is_retargeted() {
        let lib = test_lib("libtinfo.so.6");
        let key = UnitKey {
            lib: lib.clone(),
            sym: "strnames".to_string(),
        };
        let mut state = test_state();
        process_symbol(&key, &mut state).expect("extract strnames");

        let unit = state
            .units
            .iter()
            .find(|u| u.name == "strnames")
            .expect("strnames unit")
            .clone();
        assert_eq!(unit.bytes.len() % 8, 0);
        let slots = unit.bytes.len() / 8;
        assert!(slots > 400, "expected a large table, got {slots} slots");

        let bytes = std::fs::read(&lib).expect("read library");
        let elf = object::File::parse(&*bytes).expect("parse library");
        let object::File::Elf64(elf64) = &elf else {
            panic!("not ELF64")
        };
        let sym_vaddr = state.lib_index(&lib, elf64).by_name["strnames"].vaddr;

        let relative_slots: Vec<u64> = elf64
            .dynamic_relocations()
            .expect("dynamic relocations")
            .filter(|(roff, reloc)| {
                *roff >= sym_vaddr
                    && *roff < sym_vaddr + unit.bytes.len() as u64
                    && matches!(reloc.target(), object::RelocationTarget::Absolute)
            })
            .map(|(roff, _)| roff - sym_vaddr)
            .collect();
        assert!(
            relative_slots.len() > 400,
            "expected the table to be relocated, got {} entries",
            relative_slots.len()
        );

        for offset in relative_slots {
            let reloc = unit
                .relocations
                .iter()
                .find(|r| r.offset_within_unit == offset)
                .unwrap_or_else(|| {
                    panic!("slot {offset:#x} of strnames kept its stale library address")
                });
            // The target is a `.rodata` string, so it must land in the copied
            // blob rather than being deferred to ld.so as an external.
            assert!(
                matches!(reloc.target, RelocTarget::DataBlobOffset(..)),
                "slot {offset:#x} resolved to {:?}",
                reloc.target
            );
        }
    }

    /// A pointer in `.data` that points back into `.data` has to resolve to the
    /// blob being built, not fall through as unresolvable because the blob is
    /// not registered yet.
    #[test]
    fn a_data_section_pointing_into_itself_resolves_to_its_own_blob() {
        let lib = test_lib("libpcre2-8.so.0");
        let mut state = test_state();
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = object::File::parse(&*bytes).expect("parse library");
        let object::File::Elf64(elf64) = &elf else {
            panic!("not ELF64")
        };
        let index = state.lib_index(&lib, elf64);
        let data = elf64.section_by_name(".data").expect(".data").address();

        let (blob_id, base, _) = ensure_data_blob_extracted(elf64, &index, data, &lib, &mut state)
            .expect("extract .data")
            .expect(".data is extractable");
        assert_eq!(base, data);

        let unit = state
            .units
            .iter()
            .find(|u| u.id == blob_id)
            .expect("blob unit");
        assert!(
            unit.relocations.iter().any(|r| matches!(
                r.target,
                RelocTarget::DataBlobOffset(id, _) if id == blob_id
            )),
            "no self-referential pointer resolved to the blob itself"
        );
    }
}
