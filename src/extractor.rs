use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind as ObjSectionKind};

use crate::types::{ExtractedReloc, ExtractedUnit, RelocTarget, SectionKind, UnitId};

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

/// State threaded through the BFS.
struct ExtractionState {
    extracted: HashMap<UnitKey, UnitId>,
    units: Vec<ExtractedUnit>,
    // Pending placeholder mappings: (UnitId, reloc_index) → target UnitKey
    pending: Vec<(UnitId, usize, UnitKey)>,
    next_id: u32,
    /// Symbols that stay external (glibc etc.). Maps name → known.
    external_syms: HashSet<String>,
}

impl ExtractionState {
    fn alloc_id(&mut self) -> UnitId {
        let id = UnitId(self.next_id);
        self.next_id += 1;
        id
    }
}

/// Extract all symbols transitively reachable from `seeds` (direct imports).
/// Returns the list of extracted units with placeholder RelocTargets resolved.
pub fn extract_units(
    seeds: &[crate::types::ImportedSymbol],
    exe_elf: &object::read::elf::ElfFile64<'_>,
) -> Result<Vec<ExtractedUnit>> {
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

    Ok(state.units)
}

/// Process a single symbol: extract its bytes, parse its relocations, and
/// return new symbols to enqueue.
fn process_symbol(key: &UnitKey, state: &mut ExtractionState) -> Result<Vec<UnitKey>> {
    let lib_bytes =
        std::fs::read(&key.lib).with_context(|| format!("reading {}", key.lib.display()))?;

    // Check for unsupported features before extraction.
    {
        let goblin_lib = goblin::elf::Elf::parse(&lib_bytes)
            .with_context(|| format!("goblin parse {}", key.lib.display()))?;

        // Reject libraries with .init_array / .fini_array (constructor ordering issue).
        for sh in &goblin_lib.section_headers {
            let sname = goblin_lib.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if sname == ".init_array" || sname == ".fini_array" {
                if sh.sh_size > 0 {
                    bail!(
                        "{}: library has non-empty {} — merging libraries with constructors \
                         is not yet supported",
                        key.lib.display(),
                        sname
                    );
                }
            }
        }
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
                new_deps.push(dep_key.clone());
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

    // Register this unit.
    let id = state.alloc_id();
    state.extracted.insert(key.clone(), id);

    // Record pending resolutions: for each relocation with a MergedUnit placeholder,
    // associate it with the corresponding dep_key (built in the same order).
    {
        let mut dep_iter = new_deps.iter();
        for (reloc_idx, reloc) in relocations.iter().enumerate() {
            if matches!(reloc.target, RelocTarget::MergedUnit(UnitId(u32::MAX))) {
                if let Some(dep_key) = dep_iter.next() {
                    state.pending.push((id, reloc_idx, dep_key.clone()));
                }
            }
        }
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
