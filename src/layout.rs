use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::{debug, trace};

use crate::elf_reader::file_offset_to_va;
use crate::elf_reader::next_free_va;
use crate::types::{
    AssignedUnit, ExeInitFiniInfo, ExtractedUnit, GotPatch, InitFiniArrays, InitFiniPlan,
    MergePlan, NewExternalSym, RelocTarget, SectionKind, TrampolineStub,
};

/// Plan the virtual address layout of all extracted units and trampolines,
/// producing a `MergePlan` ready for relocation application.
pub fn plan_layout(
    mut units: Vec<ExtractedUnit>,
    exe_elf: &object::read::elf::ElfFile64<'_>,
    imports: &[crate::types::ImportedSymbol],
    is_pie: bool,
    init_fini: InitFiniArrays,
    exe_init_fini: ExeInitFiniInfo,
    lib_order: &[PathBuf],
    got_slot_fixups: Vec<crate::types::GotSlotFixup>,
) -> Result<MergePlan> {
    let load_address = next_free_va(exe_elf);

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

    debug!(
        text = text.len(),
        rodata = rodata.len(),
        data = data.len(),
        "Layout unit counts"
    );

    // Collect unique External symbol names referenced by any relocation. This
    // happens before any address is handed out because the trampoline stubs
    // are code: they share the executable run of the segment with the text
    // units, so they have to be placed before the non-executable units.
    let mut external_names: indexmap::IndexSet<String> = indexmap::IndexSet::new();
    for unit in text.iter().chain(&rodata).chain(&data) {
        for reloc in &unit.relocations {
            if let RelocTarget::External(name) = &reloc.target {
                external_names.insert(name.clone());
            }
        }
    }

    // Build a map: external symbol name → GOT VA in the executable.
    // We need these to populate the trampoline stubs.
    let exe_got_vas = build_exe_got_map(exe_elf)?;

    let text_units = assign_addresses(load_address, &mut offset, text);

    // Assign VA to each trampoline stub (14 bytes: FF 25 00 00 00 00 + 8 byte addr).
    //
    // For each external name we need a GOT slot the loader will fill with the
    // resolved function address; the trampoline does `jmp [got_slot]`. If the
    // executable already imports the symbol, we reuse its existing GOT slot.
    // Otherwise a fresh 8-byte slot is allocated further down, in the writable
    // run — ld.so writes the resolved address into it, so it cannot sit next
    // to the code.
    let mut trampoline_stubs: Vec<TrampolineStub> = Vec::new();
    let mut pending_got_slots: Vec<(usize, String)> = Vec::new();
    for name in &external_names {
        // Align each trampoline to 16 bytes for neatness.
        offset = align_up(offset, 16);
        let vaddr = load_address + offset;
        offset += 14;
        let target_got_vaddr = match exe_got_vas.get(name) {
            Some(va) => *va,
            None => {
                pending_got_slots.push((trampoline_stubs.len(), name.clone()));
                0 // patched below, once the slot has an address
            }
        };
        trampoline_stubs.push(TrampolineStub {
            symbol_name: name.clone(),
            vaddr,
            target_got_vaddr,
        });
    }

    // End of the executable run. Padding to a page boundary is what lets the
    // writer map the code read-execute and everything after it read-write,
    // instead of one read-write-execute mapping covering the lot.
    offset = align_up(offset, PAGE_SIZE);
    let exec_size = offset;

    let rodata_units = assign_addresses(load_address, &mut offset, rodata);
    let data_units = assign_addresses(load_address, &mut offset, data);

    // Fresh GOT slots for the externals the executable does not already
    // import, plus the NewExternalSym records the writer turns into .dynsym
    // entries and GLOB_DAT relocations.
    let mut new_externals: Vec<NewExternalSym> = Vec::with_capacity(pending_got_slots.len());
    for (stub_idx, name) in pending_got_slots {
        offset = align_up(offset, 8);
        let got_vaddr = load_address + offset;
        offset += 8;
        trampoline_stubs[stub_idx].target_got_vaddr = got_vaddr;
        new_externals.push(NewExternalSym { name, got_vaddr });
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
            format!(
                "imported symbol '{}' was not extracted — internal error",
                imp.name
            )
        })?;
        let got_vaddr = file_offset_to_va(exe_elf, imp.got_file_offset).with_context(|| {
            format!(
                "GOT file offset 0x{:x} for '{}' is not in any PT_LOAD segment",
                imp.got_file_offset, imp.name
            )
        })?;
        got_patches.push(GotPatch {
            got_file_offset: imp.got_file_offset,
            got_vaddr,
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

    // Map (library, unit name) → assigned VA so init/fini entries can be
    // resolved unambiguously even if two libraries define same-named locals.
    let unit_vaddr_by_lib_name: HashMap<(&PathBuf, &str), u64> = text_units
        .iter()
        .chain(&rodata_units)
        .chain(&data_units)
        .map(|au| ((&au.unit.source_lib, au.unit.name.as_str()), au.assigned_vaddr))
        .collect();

    // Plan init/fini arrays if there are any entries to merge
    let init_fini_plan = plan_init_fini_arrays(
        exe_elf,
        &init_fini,
        &exe_init_fini,
        lib_order,
        &unit_vaddr_by_lib_name,
        load_address,
        &mut offset,
    )?;

    // End of the writable run; the writer appends the rebuilt read-only
    // tables and the new program header table after this point.
    offset = align_up(offset, PAGE_SIZE);
    let writable_end = offset;

    // Resolve copied-GOT-slot fixups now that every unit has an assigned VA.
    let unit_vaddr_by_id: HashMap<crate::types::UnitId, u64> = text_units
        .iter()
        .chain(&rodata_units)
        .chain(&data_units)
        .map(|au| (au.unit.id, au.assigned_vaddr))
        .collect();
    let mut got_imports = Vec::with_capacity(got_slot_fixups.len());
    for fixup in got_slot_fixups {
        let base = unit_vaddr_by_id.get(&fixup.unit).with_context(|| {
            format!(
                "GOT slot fixup for '{}' references UnitId({}) not in plan",
                fixup.name, fixup.unit.0
            )
        })?;
        got_imports.push(crate::types::GotSlotImport {
            got_vaddr: base + fixup.offset,
            name: fixup.name,
            weak: fixup.weak,
        });
    }

    // Jump-slot reloc offsets are populated by the caller (patcher.rs), so leave empty here.
    // Relative relocs are populated during segment building (trampolines) and patching (GOT).
    Ok(MergePlan {
        is_pie,
        load_address,
        exec_size,
        writable_end,
        text_units,
        rodata_units,
        data_units,
        trampoline_stubs,
        got_patches,
        jump_slot_reloc_offsets: Vec::new(),
        copy_reloc_offsets: Vec::new(),
        remove_needed,
        // Filled in by the caller, once the injected symbol set is known.
        add_needed: Vec::new(),
        relative_relocs: Vec::new(),
        new_externals,
        got_imports,
        init_fini: init_fini_plan,
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
            trace!(
                name = unit.name,
                unit_id = unit.id.0,
                size = format_args!("{:#x}", unit.bytes.len()),
                vaddr = format_args!("{:#x}", assigned_vaddr),
                "Assigned unit VA"
            );
            *offset += unit.bytes.len() as u64;
            AssignedUnit {
                unit,
                assigned_vaddr,
            }
        })
        .collect()
}

/// Page size the merged segment's mappings are aligned to.
pub const PAGE_SIZE: u64 = 0x1000;

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
fn build_exe_got_map(elf: &object::read::elf::ElfFile64<'_>) -> Result<HashMap<String, u64>> {
    let bytes = elf.data();
    let goblin_exe = goblin::elf::Elf::parse(bytes).context("goblin for GOT map")?;

    let dynidx_to_name: HashMap<usize, String> = goblin_exe
        .dynsyms
        .iter()
        .enumerate()
        .filter_map(|(i, sym)| {
            goblin_exe
                .dynstrtab
                .get_at(sym.st_name)
                .map(|n| (i, n.to_owned()))
        })
        .collect();

    let mut map: HashMap<String, u64> = HashMap::new();

    for rela in goblin_exe
        .pltrelocs
        .iter()
        .chain(goblin_exe.dynrelas.iter())
    {
        let sym_idx = rela.r_sym;
        if let Some(name) = dynidx_to_name.get(&sym_idx) {
            map.entry(name.clone()).or_insert(rela.r_offset);
        }
    }

    Ok(map)
}

/// Plan the preinit array (merged constructors) and combined fini array for
/// the merged segment. See `InitFiniPlan` for why constructors go into
/// DT_PREINIT_ARRAY rather than the executable's init_array: both run library
/// constructors before the executable's own, but only the preinit phase runs
/// before `_dl_fini` is registered with `__cxa_atexit`, which is what keeps
/// `__cxa_atexit`-registered C++ static destructors in the dynamic-linking
/// exit order.
fn plan_init_fini_arrays(
    exe_elf: &object::read::elf::ElfFile64<'_>,
    init_fini: &InitFiniArrays,
    exe_init_fini: &ExeInitFiniInfo,
    lib_order: &[PathBuf],
    unit_vaddrs: &HashMap<(&PathBuf, &str), u64>,
    load_address: u64,
    offset: &mut u64,
) -> Result<Option<InitFiniPlan>> {
    let exe_bytes = exe_elf.data();

    // Copy the executable's existing entries verbatim — their functions stay
    // at their original addresses.
    let read_exe_entries = |array_vaddr: Option<u64>, array_size: u64| -> Result<Vec<u64>> {
        let mut entries = Vec::new();
        let Some(va) = array_vaddr else {
            return Ok(entries);
        };
        if array_size == 0 {
            return Ok(entries);
        }
        let file_offset = crate::elf_reader::va_to_file_offset(exe_elf, va)
            .context("exe init/fini array VA not in any PT_LOAD segment")?;
        for i in 0..(array_size / 8) as usize {
            let entry_offset = file_offset as usize + i * 8;
            if entry_offset + 8 > exe_bytes.len() {
                break;
            }
            let func_va = u64::from_le_bytes(
                exe_bytes[entry_offset..entry_offset + 8]
                    .try_into()
                    .expect("8 bytes"),
            );
            // Skip sentinel values
            if func_va != 0 && func_va != u64::MAX {
                entries.push(func_va);
            }
        }
        Ok(entries)
    };

    // Resolve merged library entries to their assigned VAs, grouped by
    // dependency order. A library that stays in DT_NEEDED (not fully merged,
    // so absent from lib_order) keeps running its constructors dynamically —
    // duplicating them here would run them twice, so those are skipped.
    let collect_lib_entries = |entries: &[crate::types::InitFiniEntry]| -> Result<Vec<u64>> {
        let mut out = Vec::new();
        for lib in lib_order {
            for entry in entries.iter().filter(|e| &e.source_lib == lib) {
                let va = unit_vaddrs
                    .get(&(lib, entry.unit_name.as_str()))
                    .with_context(|| {
                        format!(
                            "init/fini entry '{}' from {} was not extracted — internal error",
                            entry.unit_name,
                            lib.display()
                        )
                    })?;
                out.push(*va);
            }
        }
        for entry in entries {
            if !lib_order.contains(&entry.source_lib) {
                debug!(
                    lib = %entry.source_lib.display(),
                    entry = entry.unit_name,
                    "Library stays in DT_NEEDED; its constructors run dynamically"
                );
            }
        }
        Ok(out)
    };

    let lib_init_entries = collect_lib_entries(&init_fini.init_entries)?;
    let lib_fini_entries = collect_lib_entries(&init_fini.fini_entries)?;

    if lib_init_entries.is_empty() && lib_fini_entries.is_empty() {
        return Ok(None);
    }

    // Preinit: the exe's existing preinit entries keep running first (matching
    // _dl_init's order: exe preinit, then library constructors).
    let mut preinit_entries = Vec::new();
    if !lib_init_entries.is_empty() {
        preinit_entries = read_exe_entries(
            exe_init_fini.preinit_array_vaddr,
            exe_init_fini.preinit_array_size,
        )?;
        preinit_entries.extend(lib_init_entries);
    }

    // Fini: merged entries first, exe entries last; ld.so runs the array
    // backward, so the exe's destructors still run first at exit.
    let mut combined_fini_entries = lib_fini_entries;
    if !combined_fini_entries.is_empty() {
        combined_fini_entries.extend(read_exe_entries(
            exe_init_fini.fini_array_vaddr,
            exe_init_fini.fini_array_size,
        )?);
    }

    // Allocate space for the arrays in the merged segment
    // Align to 8 bytes (pointer size)
    *offset = align_up(*offset, 8);
    let preinit_vaddr = load_address + *offset;
    *offset += (preinit_entries.len() * 8) as u64;

    *offset = align_up(*offset, 8);
    let combined_fini_vaddr = load_address + *offset;
    *offset += (combined_fini_entries.len() * 8) as u64;

    Ok(Some(InitFiniPlan {
        preinit_vaddr,
        preinit_entries,
        combined_fini_vaddr,
        combined_fini_entries,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_reader::MappedElf;
    use crate::types::{ExtractedReloc, UnitId};

    fn unit(
        id: u32,
        name: &str,
        kind: SectionKind,
        len: usize,
        externals: &[&str],
    ) -> ExtractedUnit {
        ExtractedUnit {
            id: UnitId(id),
            name: name.to_owned(),
            source_lib: PathBuf::from("/nonexistent/libtest.so.1"),
            bytes: vec![0x90; len],
            section_kind: kind,
            alignment: 16,
            relocations: externals
                .iter()
                .enumerate()
                .map(|(i, sym)| ExtractedReloc {
                    offset_within_unit: (i * 8) as u64,
                    kind: object::RelocationKind::Relative,
                    encoding: object::RelocationEncoding::Generic,
                    size: 32,
                    addend: -4,
                    target: RelocTarget::External((*sym).to_owned()),
                })
                .collect(),
        }
    }

    /// The reason the layout is split in two runs at all: the writer maps the
    /// leading run read-execute and the rest read-write, so a unit or a
    /// loader-written GOT slot on the wrong side of the boundary either loses
    /// write access it needs or gains execute permission it shouldn't have.
    #[test]
    fn code_and_loader_written_slots_never_share_a_page() {
        let path = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/test/grep"));
        let mapped = MappedElf::open(path).expect("open test/grep");
        let exe = mapped.parse().expect("parse test/grep");

        // test/grep imports `memcpy`, so that trampoline reuses an existing GOT
        // slot in the executable; the made-up name has no slot to reuse and so
        // forces a fresh one inside the merged segment.
        let units = vec![
            unit(
                0,
                "fn_a",
                SectionKind::Text,
                64,
                &["memcpy", "solder_absent_symbol"],
            ),
            unit(1, "ro_a", SectionKind::ReadOnlyData, 32, &[]),
            unit(2, "data_a", SectionKind::Data, 48, &[]),
        ];

        let plan = plan_layout(
            units,
            &exe,
            &[],
            true,
            InitFiniArrays::default(),
            ExeInitFiniInfo::default(),
            &[],
            Vec::new(),
        )
        .expect("plan layout");

        assert_eq!(plan.exec_size % PAGE_SIZE, 0, "exec run not page-aligned");
        assert_eq!(
            plan.writable_end % PAGE_SIZE,
            0,
            "writable run not page-aligned"
        );
        assert!(plan.exec_size > 0 && plan.writable_end > plan.exec_size);
        assert_eq!(plan.segment_size(), plan.writable_end as usize);

        let code_end = plan.load_address + plan.exec_size;
        let writable_end = plan.load_address + plan.writable_end;

        for au in &plan.text_units {
            assert!(
                au.assigned_vaddr >= plan.load_address
                    && au.assigned_vaddr + au.unit.bytes.len() as u64 <= code_end,
                "text unit '{}' is not inside the executable run",
                au.unit.name
            );
        }
        assert_eq!(plan.trampoline_stubs.len(), 2);
        for stub in &plan.trampoline_stubs {
            assert!(
                stub.vaddr >= plan.load_address && stub.vaddr + 14 <= code_end,
                "trampoline for '{}' is not inside the executable run",
                stub.symbol_name
            );
        }
        for au in plan.rodata_units.iter().chain(&plan.data_units) {
            assert!(
                au.assigned_vaddr >= code_end
                    && au.assigned_vaddr + au.unit.bytes.len() as u64 <= writable_end,
                "unit '{}' is not inside the writable run",
                au.unit.name
            );
        }

        assert_eq!(plan.new_externals.len(), 1, "{:?}", plan.new_externals);
        let ext = &plan.new_externals[0];
        assert_eq!(ext.name, "solder_absent_symbol");
        assert!(
            ext.got_vaddr >= code_end && ext.got_vaddr + 8 <= writable_end,
            "GOT slot for '{}' is not inside the writable run",
            ext.name
        );
        // The trampoline has to point at the slot that was actually allocated,
        // which now happens in a later pass than the stub placement.
        let stub = plan
            .trampoline_stubs
            .iter()
            .find(|s| s.symbol_name == ext.name)
            .expect("trampoline for the injected external");
        assert_eq!(stub.target_got_vaddr, ext.got_vaddr);
    }
}
