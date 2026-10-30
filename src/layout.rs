use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::{debug, trace};

use crate::elf_reader::file_offset_to_va;
use crate::elf_reader::merged_load_address;
use crate::types::{
    AssignedUnit, ExtractedUnit, GotPatch, InitFiniArrays, InitFiniKind, InitFiniPlan, MergePlan,
    MergedArray, NewExternalSym, RelocTarget, SectionKind, TrampolineStub,
};

/// Plan the virtual address layout of all extracted units and trampolines,
/// producing a `MergePlan` ready for relocation application.
///
/// `exe_got_vas` maps an external symbol the executable already imports to the
/// GOT slot ld.so resolves it into (see `RelaTables::got_slot_vas`); a
/// trampoline for such a symbol reuses that slot instead of allocating one.
#[allow(clippy::too_many_arguments)]
pub fn plan_layout(
    extracted: Vec<ExtractedUnit>,
    exe_elf: &object::read::elf::ElfFile64<'_>,
    imports: &[crate::types::ImportedSymbol],
    exe_got_vas: &HashMap<String, u64>,
    arch: &'static crate::arch::Arch,
    is_pie: bool,
    init_fini: InitFiniArrays,
    lib_order: &[PathBuf],
    got_slot_fixups: Vec<crate::types::GotSlotFixup>,
) -> Result<MergePlan> {
    let load_address = merged_load_address(exe_elf);

    // Separate units by section kind.
    let mut text: Vec<ExtractedUnit> = Vec::new();
    let mut rodata: Vec<ExtractedUnit> = Vec::new();
    let mut data: Vec<ExtractedUnit> = Vec::new();

    for unit in extracted {
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

    let mut units: Vec<AssignedUnit> = assign_addresses(load_address, &mut offset, text);

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

    // Read-only data that nothing writes to at runtime gets a mapping of its
    // own, so the merged constants keep the permissions the library gave them.
    // The rest — anything the dynamic loader rebases or resolves at startup —
    // has to stay in the writable run.
    let got_slot_units: HashSet<crate::types::UnitId> =
        got_slot_fixups.iter().map(|f| f.unit).collect();
    let (rebased_rodata, const_rodata): (Vec<ExtractedUnit>, Vec<ExtractedUnit>) =
        rodata.into_iter().partition(|unit| {
            got_slot_units.contains(&unit.id)
                || (is_pie && unit.relocations.iter().any(|r| r.is_absolute64()))
        });
    debug!(
        read_only = const_rodata.len(),
        loader_written = rebased_rodata.len(),
        "Read-only data units by mapping"
    );

    units.extend(assign_addresses(load_address, &mut offset, const_rodata));

    // End of the read-only run, for the same page-boundary reason.
    offset = align_up(offset, PAGE_SIZE);
    let rodata_end = offset;

    units.extend(assign_addresses(load_address, &mut offset, rebased_rodata));
    units.extend(assign_addresses(load_address, &mut offset, data));

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

    // Map (library, unit name) → assigned VA. The library is part of the key
    // because a unit name on its own does not identify a unit: two merged
    // libraries can each define a symbol of the same name, and so can a
    // library and the anonymous units synthesized for another. Every lookup
    // below knows which library it means — an import carries the library it
    // was resolved from, an init/fini entry the library whose array it came
    // out of — so nothing needs the ambiguous form.
    let unit_vaddrs: HashMap<(&PathBuf, &str), u64> = units
        .iter()
        .map(|au| ((&au.unit.source_lib, au.unit.name.as_str()), au.assigned_vaddr))
        .collect();

    // Build GOT patches: one per imported symbol.
    // The patch value is the assigned_vaddr of the corresponding extracted unit.
    let mut got_patches: Vec<GotPatch> = Vec::new();
    for imp in imports {
        let vaddr = unit_vaddrs
            .get(&(&imp.source_library, imp.name.as_str()))
            .with_context(|| {
                format!(
                    "imported symbol '{}' was not extracted from {} — internal error",
                    imp.name,
                    imp.source_library.display()
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

    // Plan init/fini arrays if there are any entries to merge
    let init_fini_plan = plan_init_fini_arrays(
        exe_elf,
        &init_fini,
        lib_order,
        &unit_vaddrs,
        load_address,
        &mut offset,
    )?;

    // End of the writable run; the writer appends the rebuilt read-only
    // tables and the new program header table after this point.
    offset = align_up(offset, PAGE_SIZE);
    let writable_end = offset;

    // Resolve copied-GOT-slot fixups now that every unit has an assigned VA.
    let unit_vaddr_by_id: HashMap<crate::types::UnitId, u64> = units
        .iter()
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

    // The relocations to neutralize are chosen by the caller, so leave them empty here.
    // Relative relocs are populated during segment building (trampolines) and patching (GOT).
    Ok(MergePlan {
        arch,
        is_pie,
        load_address,
        exec_size,
        rodata_end,
        writable_end,
        units,
        trampoline_stubs,
        got_patches,
        neutralized_relocs: Vec::new(),
        // Which DT_NEEDED entries go and which arrive is decided by the
        // caller: it holds the soname → library mapping `collect_imports`
        // resolved, and the injected symbol set.
        remove_needed: Vec::new(),
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
    lib_order: &[PathBuf],
    unit_vaddrs: &HashMap<(&PathBuf, &str), u64>,
    load_address: u64,
    offset: &mut u64,
) -> Result<Option<InitFiniPlan>> {
    let exe_bytes = exe_elf.data();
    let exe_dynamic = crate::elf_reader::DynamicTable::parse(exe_bytes)
        .context("reading .dynamic for the executable's own init/fini arrays")?;

    // Copy the executable's existing entries verbatim — their functions stay
    // at their original addresses.
    let read_exe_entries = |kind: InitFiniKind| -> Result<Vec<u64>> {
        let (array_tag, size_tag) = kind.dynamic_tags();
        let Some(va) = exe_dynamic.value_of(array_tag) else {
            return Ok(Vec::new());
        };
        let array_size = exe_dynamic.value_of(size_tag).unwrap_or(0);
        if array_size == 0 {
            return Ok(Vec::new());
        }
        let (_, array) = crate::elf_reader::dynamic_table_bytes(
            exe_elf,
            exe_bytes,
            &format!("the executable's {}", kind.section()),
            va,
            array_size,
        )?;
        Ok(array
            .chunks_exact(8)
            .map(|word| u64::from_le_bytes(word.try_into().expect("8 bytes")))
            // Skip sentinel values
            .filter(|&func_va| func_va != 0 && func_va != u64::MAX)
            .collect())
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
        preinit_entries = read_exe_entries(InitFiniKind::Preinit)?;
        preinit_entries.extend(lib_init_entries);
    }

    // Fini: merged entries first, exe entries last; ld.so runs the array
    // backward, so the exe's destructors still run first at exit.
    let mut combined_fini_entries = lib_fini_entries;
    if !combined_fini_entries.is_empty() {
        combined_fini_entries.extend(read_exe_entries(InitFiniKind::Fini)?);
    }

    // Place each array in the merged segment, aligned to the pointer size.
    // Where the executable had its own array of that kind travels with it:
    // the linker may have put it inside `PT_GNU_RELRO`, and the merged segment
    // is past the end of the image, so the move can cost the array that
    // protection (`relro_downgrade`).
    let mut place = |kind: InitFiniKind, entries: Vec<u64>| {
        *offset = align_up(*offset, 8);
        let array = MergedArray {
            vaddr: load_address + *offset,
            exe_vaddr: exe_dynamic.value_of(kind.dynamic_tags().0),
            entries,
        };
        *offset += array.size();
        array
    };

    Ok(Some(InitFiniPlan {
        preinit: place(InitFiniKind::Preinit, preinit_entries),
        fini: place(InitFiniKind::Fini, combined_fini_entries),
    }))
}

/// The RELRO protection a merge does not extend to what it adds — and, where
/// the rebuilt init/fini arrays are concerned, takes away from what was
/// already there.
///
/// `PT_GNU_RELRO` names the bytes `ld.so` makes read-only once it has finished
/// relocating (see [`crate::elf_reader::gnu_relro`]). `solder` forces
/// `DF_BIND_NOW`, so every GOT slot and every array entry in the merged
/// writable run is likewise written once, by the loader, before any code runs:
/// exactly the data that range exists to protect. None of it is covered.
///
/// It cannot be, as the merged segment is laid out past the end of the image
/// and glibc enforces one RELRO range per object, so this is a report rather
/// than a fix: protecting the run needs code in the merged binary itself,
/// calling `mprotect` from a preinit constructor once the loader is done.
/// Until then the loss is at least visible at merge time.
#[derive(Debug)]
pub struct RelroDowngrade {
    /// What `PT_GNU_RELRO` covers in the executable. The merge leaves it as it
    /// is, so this is the protection the output still has.
    pub relro: std::ops::Range<u64>,
    /// The writable run of the merged segment, which nothing protects.
    pub writable: std::ops::Range<u64>,
    /// Words in the writable run that only `ld.so` ever writes: the GOT slots
    /// the merge allocated, the init/fini array entries, and the absolute
    /// pointers in merged data that the loader rebases under PIE.
    pub loader_written: usize,
    /// The init/fini arrays the linker had placed inside `PT_GNU_RELRO` that
    /// the merge rebuilds outside it: which array, where it was, where it is
    /// now. The executable's own destructor pointers are in there.
    pub moved_arrays: Vec<(InitFiniKind, u64, u64)>,
}

/// Work out what `plan` costs the executable's RELRO region, or `None` if
/// there is nothing to report — the executable has no `PT_GNU_RELRO` to begin
/// with, or the merge puts nothing the loader writes past the end of it.
pub fn relro_downgrade(
    exe_elf: &object::read::elf::ElfFile64<'_>,
    plan: &MergePlan,
) -> Option<RelroDowngrade> {
    let relro = crate::elf_reader::gnu_relro(exe_elf)?;
    let writable = plan.load_address + plan.rodata_end..plan.load_address + plan.writable_end;

    let arrays = || plan.init_fini.iter().flat_map(|p| p.arrays());

    let moved_arrays: Vec<(InitFiniKind, u64, u64)> = arrays()
        .filter(|(_, array)| !array.entries.is_empty())
        .filter_map(|(kind, array)| {
            let was = array.exe_vaddr?;
            relro.contains(&was).then_some((kind, was, array.vaddr))
        })
        .collect();

    // The loader resolves a GOT slot whether or not the executable is PIE; the
    // array entries and the pointers inside merged data are link-time
    // addresses, which it only has to rebase when the image moves.
    let mut loader_written = plan.new_externals.len() + plan.got_imports.len();
    if plan.is_pie {
        loader_written += arrays()
            .map(|(_, array)| array.entries.len())
            .sum::<usize>();
        loader_written += plan
            .units
            .iter()
            .filter(|au| writable.contains(&au.assigned_vaddr))
            .map(|au| {
                au.unit
                    .relocations
                    .iter()
                    .filter(|r| r.is_absolute64())
                    .count()
            })
            .sum::<usize>();
    }

    (loader_written > 0 || !moved_arrays.is_empty()).then_some(RelroDowngrade {
        relro,
        writable,
        loader_written,
        moved_arrays,
    })
}

impl std::fmt::Display for RelroDowngrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RELRO is not extended to the merged region: {} word(s) in {:#x}..{:#x} are \
             written by ld.so before main and by nothing afterwards, but PT_GNU_RELRO still \
             covers only {:#x}..{:#x}, so they stay writable for the life of the process",
            self.loader_written,
            self.writable.start,
            self.writable.end,
            self.relro.start,
            self.relro.end,
        )?;
        for (kind, was, now) in &self.moved_arrays {
            write!(
                f,
                ". The executable's {} was inside that range at {was:#x} and the merge rebuilds \
                 it at {now:#x}, so its function pointers lose the protection they had",
                kind.name(),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_reader::MappedElf;
    use crate::types::{ExtractedReloc, InitFiniEntry, UnitId};

    const GREP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/grep");
    const LIB: &str = "/nonexistent/libtest.so.1";

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

    /// A read-only unit holding one 64-bit absolute pointer: under PIE the
    /// loader rebases that pointer at startup, so the unit cannot be mapped
    /// read-only even though the library had it in `.rodata`.
    fn rebased_rodata_unit(id: u32, name: &str) -> ExtractedUnit {
        let mut u = unit(id, name, SectionKind::ReadOnlyData, 16, &[]);
        u.relocations.push(ExtractedReloc {
            offset_within_unit: 0,
            kind: object::RelocationKind::Absolute,
            encoding: object::RelocationEncoding::Generic,
            size: 64,
            addend: 0,
            target: RelocTarget::MergedUnit(UnitId(0)),
        });
        u
    }

    fn plan_for(units: Vec<ExtractedUnit>, is_pie: bool) -> MergePlan {
        plan_for_with(units, is_pie, InitFiniArrays::default(), &[])
    }

    fn plan_for_with(
        units: Vec<ExtractedUnit>,
        is_pie: bool,
        init_fini: InitFiniArrays,
        lib_order: &[PathBuf],
    ) -> MergePlan {
        let mapped = MappedElf::open(std::path::Path::new(GREP)).expect("open test/grep");
        let exe = mapped.parse().expect("parse test/grep");
        let rela = crate::symbol_analysis::RelaTables::read(&exe, &crate::arch::X86_64)
            .expect("test/grep .rela tables");
        plan_layout(
            units,
            &exe,
            &[],
            &rela.got_slot_vas(),
            &crate::arch::X86_64,
            is_pie,
            init_fini,
            lib_order,
            Vec::new(),
        )
        .expect("plan layout")
    }

    /// `relro_downgrade` needs the executable the plan was made against, and a
    /// parsed `ElfFile64` borrows the mapping it came out of, so the caller has
    /// to own both.
    fn with_grep<T>(f: impl FnOnce(&object::read::elf::ElfFile64<'_>) -> T) -> T {
        let mapped = MappedElf::open(std::path::Path::new(GREP)).expect("open test/grep");
        f(&mapped.parse().expect("parse test/grep"))
    }

    /// The reason the layout is split into runs at all: the writer maps the
    /// leading run read-execute, the next read-only and the one after that
    /// read-write, so a unit or a loader-written GOT slot on the wrong side of
    /// a boundary either loses write access it needs, keeps write access it
    /// does not, or gains execute permission it shouldn't have.
    #[test]
    fn each_unit_lands_in_the_run_with_the_permissions_it_needs() {
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
            rebased_rodata_unit(3, "ro_rebased"),
        ];

        let plan = plan_for(units, true);

        assert_eq!(plan.exec_size % PAGE_SIZE, 0, "exec run not page-aligned");
        assert_eq!(
            plan.rodata_end % PAGE_SIZE,
            0,
            "read-only run not page-aligned"
        );
        assert_eq!(
            plan.writable_end % PAGE_SIZE,
            0,
            "writable run not page-aligned"
        );
        assert!(plan.exec_size > 0);
        assert!(plan.rodata_end > plan.exec_size);
        assert!(plan.writable_end > plan.rodata_end);
        assert_eq!(plan.segment_size(), plan.writable_end as usize);

        let code_end = plan.load_address + plan.exec_size;
        let rodata_end = plan.load_address + plan.rodata_end;
        let writable_end = plan.load_address + plan.writable_end;
        let within = |au: &AssignedUnit, start: u64, end: u64| {
            au.assigned_vaddr >= start && au.assigned_vaddr + au.unit.bytes.len() as u64 <= end
        };
        let named = |name: &str| {
            plan.units
                .iter()
                .find(|au| au.unit.name == name)
                .unwrap_or_else(|| panic!("unit '{name}' is missing from the plan"))
        };

        for au in plan
            .units
            .iter()
            .filter(|au| au.unit.section_kind == SectionKind::Text)
        {
            assert!(
                within(au, plan.load_address, code_end),
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
        assert!(
            within(named("ro_a"), code_end, rodata_end),
            "read-only data nothing writes to is not inside the read-only run"
        );
        for name in ["data_a", "ro_rebased"] {
            assert!(
                within(named(name), rodata_end, writable_end),
                "unit '{name}' is not inside the writable run"
            );
        }

        assert_eq!(plan.new_externals.len(), 1, "{:?}", plan.new_externals);
        let ext = &plan.new_externals[0];
        assert_eq!(ext.name, "solder_absent_symbol");
        assert!(
            ext.got_vaddr >= rodata_end && ext.got_vaddr + 8 <= writable_end,
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

    /// Nothing rebases an absolute pointer in a non-PIE executable — the
    /// relocator writes its final value at merge time — so that data can be
    /// mapped read-only, unlike in the PIE case above.
    #[test]
    fn non_pie_keeps_pointer_bearing_rodata_read_only() {
        let units = vec![
            unit(0, "fn_a", SectionKind::Text, 64, &[]),
            rebased_rodata_unit(1, "ro_rebased"),
        ];

        let plan = plan_for(units, false);

        let au = plan
            .units
            .iter()
            .find(|au| au.unit.name == "ro_rebased")
            .expect("the rodata unit");
        assert!(
            au.assigned_vaddr >= plan.load_address + plan.exec_size
                && au.assigned_vaddr + au.unit.bytes.len() as u64
                    <= plan.load_address + plan.rodata_end,
            "non-PIE rodata is not inside the read-only run"
        );
        assert_eq!(
            plan.writable_end, plan.rodata_end,
            "nothing should have been placed in the writable run"
        );
    }

    /// `test/grep`'s `DT_FINI_ARRAY` is at 0x30f58, inside the 0x30f50..0x32000
    /// its `PT_GNU_RELRO` covers: the linker put the executable's destructor
    /// pointer where `ld.so` would make it read-only after startup. The merge
    /// has to rebuild that array to run the merged destructors too, and can
    /// only do so in the merged segment — outside the protected range, which
    /// the merge leaves exactly as it found it. That is a protection the input
    /// had and the output does not, so it has to be reported.
    #[test]
    fn the_rebuilt_fini_array_leaving_relro_is_reported() {
        let plan = plan_for_with(
            vec![unit(0, "dtor", SectionKind::Text, 32, &[])],
            true,
            InitFiniArrays {
                init_entries: Vec::new(),
                fini_entries: vec![InitFiniEntry {
                    source_lib: PathBuf::from(LIB),
                    unit_name: "dtor".to_owned(),
                }],
            },
            &[PathBuf::from(LIB)],
        );

        let fini = &plan.init_fini.as_ref().expect("a rebuilt fini array").fini;
        let downgrade = with_grep(|exe| relro_downgrade(exe, &plan)).expect("a report");

        assert_eq!(
            downgrade.moved_arrays.len(),
            1,
            "{:?}",
            downgrade.moved_arrays
        );
        let (kind, was, now) = downgrade.moved_arrays[0];
        assert_eq!(kind, InitFiniKind::Fini);
        assert_eq!(now, fini.vaddr, "the report names the wrong destination");
        assert!(
            downgrade.relro.contains(&was),
            "{was:#x} was not inside the protected range {:#x}..{:#x}",
            downgrade.relro.start,
            downgrade.relro.end
        );
        assert!(
            downgrade.writable.contains(&now) && !downgrade.relro.contains(&now),
            "the rebuilt array at {now:#x} is not in the unprotected writable run"
        );
        // The executable's own destructor is still in there, behind the merged
        // one — the array the loader walks backwards at exit.
        assert_eq!(
            fini.entries.len(),
            2,
            "the merged and the executable's own destructor"
        );

        // The two array entries are rebased at startup like any other pointer
        // in the writable run, so they count towards what RELRO would cover.
        assert_eq!(downgrade.loader_written, 2, "{downgrade:?}");
    }

    /// What the report counts: every word in the writable run that `ld.so`
    /// writes once and nothing writes again — a GOT slot the merge allocated
    /// for a symbol the executable did not import, and an absolute pointer in
    /// merged read-only data that PIE leaves the loader to rebase. Those are
    /// the words a RELRO region would be covering.
    #[test]
    fn loader_written_words_in_the_writable_run_are_counted() {
        let plan = plan_for(
            vec![
                unit(
                    0,
                    "fn_a",
                    SectionKind::Text,
                    64,
                    &["memcpy", "solder_absent_symbol"],
                ),
                rebased_rodata_unit(1, "ro_rebased"),
            ],
            true,
        );
        // `memcpy` reuses test/grep's own GOT slot, so only the made-up symbol
        // needs a slot of the merge's own.
        assert_eq!(plan.new_externals.len(), 1, "{:?}", plan.new_externals);

        let downgrade = with_grep(|exe| relro_downgrade(exe, &plan)).expect("a report");
        assert_eq!(downgrade.loader_written, 2, "{downgrade:?}");
        assert!(downgrade.moved_arrays.is_empty(), "{downgrade:?}");
    }

    /// Nothing in a non-PIE merge is written at runtime by the loader: the
    /// relocator resolves the pointers at merge time, and with no GOT slots to
    /// allocate the writable run is empty. There is no protection to lose, so
    /// there is nothing to warn about.
    #[test]
    fn a_non_pie_merge_has_nothing_to_report() {
        let plan = plan_for(
            vec![
                unit(0, "fn_a", SectionKind::Text, 64, &[]),
                rebased_rodata_unit(1, "ro_rebased"),
            ],
            false,
        );

        assert!(
            with_grep(|exe| relro_downgrade(exe, &plan)).is_none(),
            "a non-PIE merge reported a RELRO downgrade"
        );
    }
}
