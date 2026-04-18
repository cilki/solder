use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind as ObjSectionKind};

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
    // Collect external symbol names defined in the executable's .dynsym (not SHN_UNDEF).
    // These are callable from merged library code through trampolines.
    let exe_defined_syms: HashSet<String> = exe_elf
        .dynamic_symbols()
        .filter(|s| !s.is_undefined())
        .filter_map(|s| s.name().ok().map(String::from))
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
    for (unit_id, reloc_idx, target_key) in pending {
        let target_unit_id = match state.extracted.get(&target_key) {
            Some(id) => *id,
            None => bail!(
                "internal: unresolved pending reloc target '{}' in '{}'",
                target_key.sym,
                target_key.lib.display()
            ),
        };
        let unit = state
            .units
            .iter_mut()
            .find(|u| u.id == unit_id)
            .expect("unit must exist");
        unit.relocations[reloc_idx].target = RelocTarget::MergedUnit(target_unit_id);
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

    if offset_in_section + sym_size > section_data.len() {
        bail!(
            "symbol '{}' byte range [{}, {}) overflows section of size {}",
            key.sym,
            offset_in_section,
            offset_in_section + sym_size,
            section_data.len()
        );
    }

    let bytes = section_data[offset_in_section..offset_in_section + sym_size].to_vec();
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
                // Data reference (LEA/MOV) - extract the data section if needed
                if let Some((blob_id, blob_base)) =
                    ensure_data_blob_extracted(elf64, target_addr, &key.lib, state)?
                {
                    let offset_in_blob = target_addr - blob_base;
                    // Add synthetic PC-relative relocation pointing to data blob
                    relocations.push(ExtractedReloc {
                        offset_within_unit: rip_ref.offset as u64,
                        kind: object::RelocationKind::Relative,
                        encoding: object::RelocationEncoding::Generic,
                        size: 32,
                        addend: -4,
                        target: RelocTarget::DataBlobOffset(blob_id, offset_in_blob),
                    });
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
    let mut refs = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        // E8 xx xx xx xx = CALL rel32 (5 bytes)
        if bytes[i] == 0xE8 && i + 5 <= bytes.len() {
            let rel32 = i32::from_le_bytes([bytes[i+1], bytes[i+2], bytes[i+3], bytes[i+4]]);
            let target = (base_vaddr as i64 + i as i64 + 5 + rel32 as i64) as u64;
            refs.push(RipRelativeRef {
                offset: i + 1,
                target_vaddr: target,
                is_code_ref: true,
            });
            i += 5;
            continue;
        }

        // E9 xx xx xx xx = JMP rel32 (5 bytes)
        if bytes[i] == 0xE9 && i + 5 <= bytes.len() {
            let rel32 = i32::from_le_bytes([bytes[i+1], bytes[i+2], bytes[i+3], bytes[i+4]]);
            let target = (base_vaddr as i64 + i as i64 + 5 + rel32 as i64) as u64;
            refs.push(RipRelativeRef {
                offset: i + 1,
                target_vaddr: target,
                is_code_ref: true,
            });
            i += 5;
            continue;
        }

        // 0F 8x xx xx xx xx = Jcc rel32 (6 bytes) - conditional jumps
        if bytes[i] == 0x0F && i + 6 <= bytes.len() && (bytes[i+1] & 0xF0) == 0x80 {
            let rel32 = i32::from_le_bytes([bytes[i+2], bytes[i+3], bytes[i+4], bytes[i+5]]);
            let target = (base_vaddr as i64 + i as i64 + 6 + rel32 as i64) as u64;
            refs.push(RipRelativeRef {
                offset: i + 2,
                target_vaddr: target,
                is_code_ref: true,
            });
            i += 6;
            continue;
        }

        // Check for RIP-relative addressing in ModR/M byte (mod=00, r/m=101)
        // This appears in LEA, MOV, and other instructions.
        // We need to handle REX prefixes (0x40-0x4F) and optional prefixes.

        let mut pos = i;

        // Skip legacy prefixes (66, 67, F2, F3, 2E, 3E, 26, 64, 65, 36)
        while pos < bytes.len() && matches!(bytes[pos], 0x66 | 0x67 | 0xF2 | 0xF3 | 0x2E | 0x3E | 0x26 | 0x64 | 0x65 | 0x36) {
            pos += 1;
        }

        // Check for REX prefix (0x40-0x4F)
        let has_rex = pos < bytes.len() && (bytes[pos] & 0xF0) == 0x40;
        if has_rex {
            pos += 1;
        }

        if pos >= bytes.len() {
            i += 1;
            continue;
        }

        let opcode = bytes[pos];
        pos += 1;

        // Check for two-byte opcode (0F xx)
        let is_two_byte = opcode == 0x0F;
        if is_two_byte {
            if pos >= bytes.len() {
                i += 1;
                continue;
            }
            pos += 1; // Skip second opcode byte
        }

        // Now check if there's a ModR/M byte with RIP-relative addressing
        // ModR/M with mod=00, r/m=101 indicates RIP-relative
        if pos < bytes.len() {
            let modrm = bytes[pos];
            let mod_bits = (modrm >> 6) & 0x3;
            let rm_bits = modrm & 0x7;

            // mod=00 and r/m=101 = RIP-relative addressing (32-bit displacement follows)
            if mod_bits == 0 && rm_bits == 5 {
                let disp_offset = pos + 1;
                if disp_offset + 4 <= bytes.len() {
                    let rel32 = i32::from_le_bytes([
                        bytes[disp_offset],
                        bytes[disp_offset + 1],
                        bytes[disp_offset + 2],
                        bytes[disp_offset + 3],
                    ]);
                    // RIP points to after the instruction. The instruction length is:
                    // disp_offset + 4 - i (from start to end of displacement)
                    let instr_end = disp_offset + 4;
                    let rip = base_vaddr + instr_end as u64;
                    let target = (rip as i64 + rel32 as i64) as u64;

                    // Only add if this looks like a valid instruction with RIP-relative addressing
                    // Common opcodes that use RIP-relative: 8B (MOV), 8D (LEA), 89 (MOV), etc.
                    let valid_opcode = if is_two_byte {
                        true // Two-byte opcodes are complex, assume valid
                    } else {
                        matches!(opcode,
                            0x8B | 0x8D | 0x89 | 0x8A | 0x88 | // MOV, LEA
                            0x03 | 0x0B | 0x13 | 0x1B | 0x23 | 0x2B | 0x33 | 0x3B | // arithmetic
                            0x39 | 0x3D | 0x85 | 0x84 | // CMP, TEST
                            0xC7 | 0xC6 | // MOV immediate
                            0xFF | 0xFE | // INC/DEC, CALL/JMP indirect
                            0x63 // MOVSXD
                        )
                    };

                    if valid_opcode {
                        refs.push(RipRelativeRef {
                            offset: disp_offset,
                            target_vaddr: target,
                            is_code_ref: false,
                        });
                        i = instr_end;
                        continue;
                    }
                }
            }
        }

        i += 1;
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
            let data = section.data().ok()?;
            let kind = match section.kind() {
                ObjSectionKind::Text => SectionKind::Text,
                ObjSectionKind::ReadOnlyData | ObjSectionKind::ReadOnlyString => {
                    SectionKind::ReadOnlyData
                }
                ObjSectionKind::Data | ObjSectionKind::UninitializedData => SectionKind::Data,
                _ => return None, // Skip unsupported section types
            };
            return Some((name, sec_addr, data.len(), data.to_vec(), kind));
        }
    }
    None
}

/// Extract a data section blob if not already extracted.
/// Returns the blob's UnitId and base vaddr.
fn ensure_data_blob_extracted(
    elf: &object::read::elf::ElfFile64<'_>,
    target_addr: u64,
    lib_path: &std::path::Path,
    state: &mut ExtractionState,
) -> Result<Option<(UnitId, u64)>> {
    // Find the section containing this address
    let (sec_name, sec_addr, sec_size, sec_data, sec_kind) =
        match find_section_for_address(elf, target_addr) {
            Some(info) => info,
            None => return Ok(None), // Address not in any extractable section
        };

    // Skip .text section - code references are handled separately
    if sec_kind == SectionKind::Text {
        return Ok(None);
    }

    let blob_key = DataBlobKey {
        lib: lib_path.to_path_buf(),
        section: sec_name.clone(),
    };

    // Check if already extracted
    if let Some(info) = state.data_blobs.get(&blob_key) {
        return Ok(Some((info.id, info.base_vaddr)));
    }

    // Extract the entire section as a blob
    let id = state.alloc_id();
    let unit = ExtractedUnit {
        id,
        name: format!("{}:{}", lib_path.file_name().unwrap_or_default().to_string_lossy(), sec_name),
        source_lib: lib_path.to_path_buf(),
        size: sec_size,
        bytes: sec_data,
        section_kind: sec_kind,
        alignment: 32, // Conservative alignment for data sections
        relocations: Vec::new(),
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

    Ok(Some((id, sec_addr)))
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
