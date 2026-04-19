use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind as ObjSectionKind};
use tracing::{debug, warn};

use crate::types::{
    ExtractedReloc, ExtractedUnit, InitFiniArrays, InitFiniEntry, RelocTarget, SectionKind, UnitId,
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
    /// Libraries we've already extracted init/fini arrays from.
    processed_libs: HashSet<PathBuf>,
    /// Accumulated init/fini entries from all processed libraries.
    init_fini: InitFiniArrays,
    /// Extracted data section blobs: maps (lib, section_name) → blob info
    data_blobs: HashMap<DataBlobKey, DataBlobInfo>,
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
/// along with init/fini array entries from all processed libraries.
pub fn extract_units(
    seeds: &[crate::types::ImportedSymbol],
    exe_elf: &object::read::elf::ElfFile64<'_>,
) -> Result<(Vec<ExtractedUnit>, InitFiniArrays)> {
    // Collect symbol names from the executable's .dynsym that merged library code
    // can reference. This includes both defined symbols (callable directly) and
    // undefined/imported symbols (callable through the executable's PLT).
    let exe_defined_syms: HashSet<String> = exe_elf
        .dynamic_symbols()
        .filter_map(|s| s.name().ok().map(String::from))
        .filter(|name| !name.is_empty())
        .collect();

    let mut state = ExtractionState {
        extracted: HashMap::new(),
        units: Vec::new(),
        pending: Vec::new(),
        next_id: 0,
        external_syms: exe_defined_syms,
        processed_libs: HashSet::new(),
        init_fini: InitFiniArrays::default(),
        data_blobs: HashMap::new(),
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
            },
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

    Ok((state.units, state.init_fini))
}

/// Process a single symbol: extract its bytes, parse its relocations, and
/// return new symbols to enqueue.
fn process_symbol(key: &UnitKey, state: &mut ExtractionState) -> Result<Vec<UnitKey>> {
    let lib_bytes =
        std::fs::read(&key.lib).with_context(|| format!("reading {}", key.lib.display()))?;

    // Extract init/fini arrays from this library if we haven't already
    if !state.processed_libs.contains(&key.lib) {
        state.processed_libs.insert(key.lib.clone());
        let lib_init_fini = extract_init_fini_arrays(&lib_bytes, &key.lib)?;
        state.init_fini.init_entries.extend(lib_init_fini.init_entries);
        state.init_fini.fini_entries.extend(lib_init_fini.fini_entries);
    }

    let object_file = object::File::parse(lib_bytes.as_slice())
        .with_context(|| format!("object parse {}", key.lib.display()))?;

    let object::File::Elf64(elf64) = &object_file else {
        bail!("{}: not a 64-bit ELF shared library", key.lib.display());
    };

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
    let mut new_deps: Vec<UnitKey> = Vec::new();
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
            if ts.is_undefined() || ts_name.is_empty() {
                // External symbol.
                if !state.external_syms.contains(&ts_name) && !ts_name.is_empty() {
                    bail!(
                        "symbol '{}' in {}: references external symbol '{}' which is not \
                         exported by the executable — cannot merge this library",
                        key.sym,
                        key.lib.display(),
                        ts_name
                    );
                }
                RelocTarget::External(ts_name)
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
                    let extract_result = ensure_data_blob_extracted(elf64, ts_vaddr, &key.lib, state);
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
                // First check if this is a PLT call (call to external symbol)
                if let Some(ext_name) = find_plt_target(elf64, target_addr, &lib_bytes) {
                    // This is a call to an external symbol via PLT
                    // Check if the executable exports this symbol
                    if state.external_syms.contains(&ext_name) {
                        relocations.push(ExtractedReloc {
                            offset_within_unit: rip_ref.offset as u64,
                            kind: object::RelocationKind::Relative,
                            encoding: object::RelocationEncoding::Generic,
                            size: 32,
                            addend: -4,
                            target: RelocTarget::External(ext_name),
                        });
                    }
                    // If not in external_syms, the call will be left as-is
                    // (will likely crash, but that's the expected behavior for unsupported externals)
                } else if let Some(target_name) = find_symbol_at_address(elf64, target_addr) {
                    // Code reference (call/jmp) to internal symbol
                    if find_symbol(elf64, &target_name).is_ok() {
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
                            size: 32,
                            addend: -4, // Standard PC-relative addend
                            target: RelocTarget::MergedUnit(UnitId(u32::MAX)),
                        });
                    }
                }
            } else {
                // Data reference (LEA/MOV) — could be loading address of data or code
                // First try as a code symbol (e.g. LEA loading a function pointer)
                if let Some(target_name) = find_symbol_at_address(elf64, target_addr) {
                    if find_symbol(elf64, &target_name).is_ok() {
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
                            addend: -4,
                            target: RelocTarget::MergedUnit(UnitId(u32::MAX)),
                        });
                        continue;
                    }
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
                        addend: -4,
                        target: RelocTarget::DataBlobOffset(blob_id, offset_in_blob),
                    });
                } else {
                    warn!(
                        symbol=key.sym,
                        offset=format_args!("{:#x}", rip_ref.offset),
                        target=format_args!("{:#x}", target_addr),
                        "RIP-relative data ref target not found"
                    );
                }
            }
        }
    }

    // Jump table detection via symbolic execution
    if section_kind == SectionKind::Text {
        if let Ok(jump_tables) = crate::jump_table::detect_jump_tables(
            &bytes,
            sym_vaddr,
            &key.sym,
            elf64,
            &lib_bytes,
        ) {
            if !jump_tables.is_empty() {
                debug!(count=jump_tables.len(), symbol=key.sym, "Found jump tables");
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
                        if let Some(blob_unit) = state.units.iter().find(|u| u.id == blob_id) {
                            if blob_unit.relocations.iter().any(|r| r.offset_within_unit == entry_offset_in_blob) {
                                continue;
                            }
                        }

                        // 3. Find or extract target function
                        let target_name = crate::jump_table::find_symbol_at_address(elf64, *target_addr)
                            .unwrap_or_else(|| format!("jumptarget_{:x}", target_addr));

                        // 4. Check if target is within our own function (intra-function jump)
                        let is_internal = *target_addr >= sym_vaddr
                            && *target_addr < sym_vaddr + bytes.len() as u64;

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
                                addend,  // Offset within target function, adjusted for PC-relative
                                target: RelocTarget::MergedUnit(UnitId(u32::MAX)),  // Placeholder
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
                            if !is_internal && find_symbol(elf64, &target_name).is_ok()
                                && !new_deps.iter().any(|k| k.sym == dep_key.sym) {
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
    }

    // Register this unit.
    let id = state.alloc_id();
    state.extracted.insert(key.clone(), id);

    // Record pending resolutions using our explicit tracking.
    for (reloc_idx, dep_key) in pending_relocs {
        state.pending.push((id, reloc_idx, dep_key));
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

/// Find a symbol by virtual address in an ELF's .symtab (including local symbols).
/// Returns the symbol name if found, or None if no symbol starts at that address.
fn find_symbol_at_address(elf: &object::read::elf::ElfFile64<'_>, addr: u64) -> Option<String> {
    // First check .symtab (has local symbols like .cold functions)
    for sym in elf.symbols() {
        if sym.address() == addr && !sym.is_undefined() {
            if let Ok(name) = sym.name() {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    // Fall back to .dynsym
    for sym in elf.dynamic_symbols() {
        if sym.address() == addr && !sym.is_undefined() {
            if let Ok(name) = sym.name() {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// A RIP-relative reference found in machine code.
#[derive(Debug, Clone)]
struct RipRelativeRef {
    /// Byte offset within the code where the 32-bit displacement starts.
    offset: usize,
    /// Target virtual address this reference points to.
    target_vaddr: u64,
    /// Whether this is a code reference (call/jmp) vs data reference (lea/mov).
    is_code_ref: bool,
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
            FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                // Near call/jmp/jcc with rel32 — the displacement starts after the opcode bytes
                if instr.op_count() >= 1 && instr.op_kind(0) == OpKind::NearBranch64 {
                    let target = instr.near_branch_target();
                    // The displacement occupies the last 4 bytes of the instruction
                    let disp_offset = instr_offset + instr.len() - 4;
                    refs.push(RipRelativeRef {
                        offset: disp_offset,
                        target_vaddr: target,
                        is_code_ref: true,
                    });
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

        // This address is in the PLT. We need to find which symbol it corresponds to.
        // Parse the .rela.plt section to find JUMP_SLOT relocations.
        let goblin_lib = match goblin::elf::Elf::parse(lib_bytes) {
            Ok(g) => g,
            Err(_) => return None,
        };

        // Each PLT entry is typically 16 bytes (after the first stub)
        // Find the PLT entry index based on offset from section start
        let plt_offset = addr - sec_addr;

        // Look through pltrelocs to find the matching entry
        for (i, rela) in goblin_lib.pltrelocs.iter().enumerate() {
            // PLT entries are typically at plt_base + 16 + i*16 (first 16 bytes are resolver stub)
            let entry_offset = 16 + (i as u64) * 16;
            if plt_offset >= entry_offset && plt_offset < entry_offset + 16 {
                // Found the PLT entry - get the symbol name
                let sym_idx = rela.r_sym;
                if let Some(sym) = goblin_lib.dynsyms.get(sym_idx) {
                    if let Some(name) = goblin_lib.dynstrtab.get_at(sym.st_name) {
                        return Some(name.to_string());
                    }
                }
            }
        }

        // Fallback: try to find symbol at this exact address
        for sym in goblin_lib.dynsyms.iter() {
            if sym.st_value == addr {
                if let Some(name) = goblin_lib.dynstrtab.get_at(sym.st_name) {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Check if a virtual address falls within an already-extracted data blob.
/// Returns (blob_id, blob_base_vaddr) if found.
fn find_existing_data_blob(
    addr: u64,
    state: &ExtractionState,
) -> Option<(UnitId, u64)> {
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
            let data = if kind == SectionKind::Data && section.data().ok().is_none_or(|d| d.is_empty()) {
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

    // Find the corresponding section object to extract relocations
    let section = elf64
        .sections()
        .find(|s| {
            s.name().ok() == Some(sec_name.as_str())
                && s.address() == sec_addr
        })
        .context("section not found for data blob extraction")?;

    // Collect relocations that fall within this data section's byte range.
    // For shared libraries, we need to check dynamic relocations (.rela.dyn)
    // not just section relocations, since RELATIVE relocations are stored there.
    let mut relocations: Vec<ExtractedReloc> = Vec::new();
    let mut new_deps: Vec<UnitKey> = Vec::new();
    let mut pending_relocs: Vec<(usize, UnitKey)> = Vec::new();

    // Iterate through dynamic relocations and collect those within this section's range
    if let Some(dyn_relocs) = elf64.dynamic_relocations() {
        for (roff, reloc) in dyn_relocs {
        // Only care about relocations within this section's range
        if roff < sec_addr || roff >= sec_addr + sec_size as u64 {
            continue;
        }
        let offset_within_unit = roff - sec_addr;

        // Validate relocation kind (same as code extraction)
        let kind = reloc.kind();
        let encoding = reloc.encoding();
        if kind == object::RelocationKind::Got
            || kind == object::RelocationKind::GotRelative
            || kind == object::RelocationKind::GotBaseRelative
            || kind == object::RelocationKind::GotBaseOffset
        {
            bail!(
                "data section '{}' in {}: {} relocation is not supported in Tier 1",
                sec_name,
                lib.display(),
                describe_reloc(kind, encoding)
            );
        }

        // Resolve the relocation target symbol
        let target_sym = match reloc.target() {
            object::RelocationTarget::Symbol(si) => elf64.symbol_by_index(si).ok(),
            _ => None,
        };

        let target = if let Some(ts) = target_sym {
            let ts_name = ts.name().unwrap_or("").to_owned();
            if ts.is_undefined() || ts_name.is_empty() {
                // External symbol
                if !state.external_syms.contains(&ts_name) && !ts_name.is_empty() {
                    bail!(
                        "data section '{}' in {}: references external symbol '{}' which is not \
                         exported by the executable — cannot merge this library",
                        sec_name,
                        lib.display(),
                        ts_name
                    );
                }
                RelocTarget::External(ts_name)
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
            // The addend contains the original VA of the code/data being pointed to
            let addend_va = reloc.addend() as u64;

            // Check if the target is within an already-extracted data blob
            if let Some((blob_id, blob_base)) = find_existing_data_blob(addend_va, state) {
                let offset_in_blob = addend_va - blob_base;
                RelocTarget::DataBlobOffset(blob_id, offset_in_blob)
            } else if let Some(target_name) = find_symbol_at_address(elf64, addend_va) {
                // Try to find what symbol this points to
                // Special case: __dso_handle and other marker symbols should be data offsets
                if target_name == "__dso_handle" || target_name.starts_with("_") && target_name.contains("handle") {
                    // Skip these marker symbols - they're not real code/data to extract
                    continue;
                }

                // This could be a pointer to code - we'll try to resolve it
                // Note: we don't add these as new_deps because they might be local symbols
                // that we don't want to extract as separate units
                // Instead, we'll just create a pending relocation and let the second pass resolve it

                // Only create a relocation if this symbol is already being extracted
                // (i.e., it's in the extracted map or will be extracted)
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
                // Unknown target address, skip this relocation
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
            addend: reloc.addend(),
            target,
        });
        }
    }

    // Extract the entire section as a blob
    let id = state.alloc_id();

    // Register pending relocations for this data blob
    for (reloc_idx, dep_key) in pending_relocs {
        state.pending.push((id, reloc_idx, dep_key));
    }

    if !relocations.is_empty() {
        debug!(section=sec_name, relocations=relocations.len(), "Extracted data blob");
    }

    let unit = ExtractedUnit {
        id,
        name: format!("{}:{}", lib.file_name().unwrap_or_default().to_string_lossy(), sec_name),
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
        if other.address() > sym_vaddr {
            if let object::SymbolSection::Section(si) = other.section() {
                if si == sym_section {
                    let candidate = other.address();
                    next_addr = Some(match next_addr {
                        Some(cur) if cur < candidate => cur,
                        _ => candidate,
                    });
                }
            }
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

/// Extract init/fini array entries from a library.
///
/// Reads .init_array and .fini_array sections, extracting 8-byte function pointers.
/// Sentinel values (0 or -1) are skipped.
fn extract_init_fini_arrays(
    lib_bytes: &[u8],
    lib_path: &std::path::Path,
) -> Result<InitFiniArrays> {
    let goblin_lib = goblin::elf::Elf::parse(lib_bytes)
        .with_context(|| format!("goblin parse {}", lib_path.display()))?;

    let mut result = InitFiniArrays::default();

    for sh in &goblin_lib.section_headers {
        let sname = goblin_lib.shdr_strtab.get_at(sh.sh_name).unwrap_or("");

        let is_init = sname == ".init_array";
        let is_fini = sname == ".fini_array";

        if !is_init && !is_fini {
            continue;
        }

        if sh.sh_size == 0 {
            continue;
        }

        // Read function pointers from the section
        let start = sh.sh_offset as usize;
        let end = start + sh.sh_size as usize;

        if end > lib_bytes.len() {
            bail!(
                "{}: {} section extends past end of file",
                lib_path.display(),
                sname
            );
        }

        let section_data = &lib_bytes[start..end];
        let num_entries = sh.sh_size as usize / 8;

        for i in 0..num_entries {
            let offset = i * 8;
            if offset + 8 > section_data.len() {
                break;
            }

            let func_vaddr = u64::from_le_bytes(
                section_data[offset..offset + 8]
                    .try_into()
                    .expect("8 bytes"),
            );

            // Skip sentinel values (0 or -1)
            if func_vaddr == 0 || func_vaddr == u64::MAX {
                continue;
            }

            let entry = InitFiniEntry {
                source_lib: lib_path.to_path_buf(),
                func_vaddr,
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
