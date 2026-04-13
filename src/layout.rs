use std::collections::HashMap;

use anyhow::{Context, Result};

use crate::elf_reader::next_free_va;
use crate::types::{
    AssignedUnit, ExtractedUnit, GotPatch, MergePlan, RelocTarget, SectionKind,
    TrampolineStub,
};

/// Plan the virtual address layout of all extracted units and trampolines,
/// producing a `MergePlan` ready for relocation application.
pub fn plan_layout(
    mut units: Vec<ExtractedUnit>,
    exe_elf: &object::read::elf::ElfFile64<'_>,
    imports: &[crate::types::ImportedSymbol],
    base_override: Option<u64>,
) -> Result<MergePlan> {
    let load_address = base_override.unwrap_or_else(|| next_free_va(exe_elf));

    // Separate units by section kind.
    let mut text: Vec<ExtractedUnit> = Vec::new();
    let mut rodata: Vec<ExtractedUnit> = Vec::new();
    let mut data: Vec<ExtractedUnit> = Vec::new();

    for unit in units.drain(..) {
        match unit.section_kind {
            SectionKind::Text => text.push(unit),
            SectionKind::ReadOnlyData => rodata.push(unit),
            SectionKind::Data => data.push(unit),
        }
    }

    // Assign virtual addresses, packing units together with alignment.
    let mut offset: u64 = 0;

    let text_units = assign_addresses(load_address, &mut offset, text);
    let rodata_units = assign_addresses(load_address, &mut offset, rodata);
    let data_units = assign_addresses(load_address, &mut offset, data);

    // Collect unique External symbol names referenced by any relocation.
    let mut external_names: indexmap::IndexSet<String> = indexmap::IndexSet::new();
    for au in text_units.iter().chain(&rodata_units).chain(&data_units) {
        for reloc in &au.unit.relocations {
            if let RelocTarget::External(name) = &reloc.target {
                external_names.insert(name.clone());
            }
        }
    }

    // Build a map: external symbol name → GOT VA in the executable.
    // We need these to populate the trampoline stubs.
    let exe_got_vas = build_exe_got_map(exe_elf)?;

    // Assign VA to each trampoline stub (14 bytes: FF 25 00 00 00 00 + 8 byte addr).
    // Trampolines are placed after all data units.
    let mut trampoline_stubs: Vec<TrampolineStub> = Vec::new();
    for name in &external_names {
        let target_got_vaddr = *exe_got_vas.get(name).with_context(|| {
            format!(
                "external symbol '{name}' referenced in merged library code is not \
                 in the executable's GOT — cannot create trampoline"
            )
        })?;
        // Align each trampoline to 16 bytes for neatness.
        offset = align_up(offset, 16);
        let vaddr = load_address + offset;
        offset += 14;
        trampoline_stubs.push(TrampolineStub {
            symbol_name: name.clone(),
            vaddr,
            target_got_vaddr,
        });
    }

    // Build GOT patches: one per imported symbol.
    // The patch value is the assigned_vaddr of the corresponding extracted unit.
    let unit_vaddr_by_name: HashMap<String, u64> = text_units
        .iter()
        .chain(&rodata_units)
        .chain(&data_units)
        .map(|au| (au.unit.name.clone(), au.assigned_vaddr))
        .collect();

    let mut got_patches: Vec<GotPatch> = Vec::new();
    for imp in imports {
        let vaddr = unit_vaddr_by_name.get(&imp.name).with_context(|| {
            format!("imported symbol '{}' was not extracted — internal error", imp.name)
        })?;
        got_patches.push(GotPatch {
            got_file_offset: imp.got_file_offset,
            value: *vaddr,
        });
    }

    // List of DT_NEEDED sonames to remove: those whose libraries were fully merged.
    let remove_needed: Vec<String> = {
        // We need the sonames, not paths. Re-derive from imports by finding what
        // soname maps to each library. Use the DT_NEEDED list from the executable.
        let exe_bytes = exe_elf.data();
        let goblin = goblin::elf::Elf::parse(exe_bytes).context("goblin for needed list")?;
        goblin
            .libraries
            .iter()
            .filter(|soname| {
                // If all imports from this soname's library are covered, remove it.
                // Check: is there any import whose library path corresponds to this soname?
                // We do a best-effort match by basename.
                imports.iter().any(|imp| {
                    imp.source_library
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with(*soname) || soname.starts_with(n))
                        .unwrap_or(false)
                })
            })
            .map(|s| s.to_string())
            .collect()
    };

    // Jump-slot reloc offsets are populated by the caller (patcher.rs), so leave empty here.
    Ok(MergePlan {
        load_address,
        text_units,
        rodata_units,
        data_units,
        trampoline_stubs,
        got_patches,
        jump_slot_reloc_offsets: Vec::new(),
        remove_needed,
    })
}

fn assign_addresses(
    load_address: u64,
    offset: &mut u64,
    units: Vec<ExtractedUnit>,
) -> Vec<AssignedUnit> {
    units
        .into_iter()
        .map(|unit| {
            let align = unit.alignment.max(1);
            *offset = align_up(*offset, align);
            let assigned_vaddr = load_address + *offset;
            *offset += unit.size as u64;
            AssignedUnit { unit, assigned_vaddr }
        })
        .collect()
}

pub fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

/// Build a map from symbol name → GOT virtual address for all JUMP_SLOT and GLOB_DAT
/// relocations in the executable.  This is how we find the GOT slot VA for external
/// symbols that merged library code calls through (we'll create trampolines that
/// jump to these GOT slots at load time after ld.so fills them).
fn build_exe_got_map(
    elf: &object::read::elf::ElfFile64<'_>,
) -> Result<HashMap<String, u64>> {
    let bytes = elf.data();
    let goblin_exe = goblin::elf::Elf::parse(bytes).context("goblin for GOT map")?;

    let dynidx_to_name: HashMap<usize, String> = goblin_exe
        .dynsyms
        .iter()
        .enumerate()
        .filter_map(|(i, sym)| {
            goblin_exe.dynstrtab.get_at(sym.st_name).map(|n| (i, n.to_owned()))
        })
        .collect();

    let mut map: HashMap<String, u64> = HashMap::new();

    for rela in goblin_exe.pltrelocs.iter().chain(goblin_exe.dynrelas.iter()) {
        let sym_idx = rela.r_sym;
        if let Some(name) = dynidx_to_name.get(&sym_idx) {
            map.entry(name.clone()).or_insert(rela.r_offset);
        }
    }

    Ok(map)
}
