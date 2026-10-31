use anyhow::{Context, Result};

use crate::types::{AssignedUnit, MergePlan, RelativeReloc, RelocTarget};

/// Apply all relocations to all units in the merge plan.
/// This modifies `unit.bytes` in-place.
///
/// Each relocation's [`Site`](crate::arch::Site) writes its own value, so
/// nothing here depends on the architecture.
///
/// For PIE executables, every absolute 64-bit patch site also gets a
/// `RELATIVE` relocation added to the plan: the written value is a
/// link-time VA inside the output image, so ld.so must rebase it at load time
/// (e.g. function pointers in copied GOT/data sections, which constructors
/// pass to __cxa_atexit).
pub fn apply_all_relocations(plan: &mut MergePlan) -> Result<()> {
    // Collect the lookup tables we need before borrowing plan mutably for iteration.
    // (unit_id → vaddr, trampoline_name → vaddr)
    //
    // A `UnitId` is the position at which extraction handed the id out, so the
    // ids in a plan are the dense range `0..next_id` and an array indexes them
    // directly. This table is consulted once per relocation — 110091 times for
    // `test/md5sum` against `libcrypto.so.3` — and that many lookups are worth
    // an index rather than a hash of the id into a 10218-entry map.
    let id_to_vaddr = UnitVaddrs::of(plan);

    let tramp_to_vaddr: std::collections::HashMap<String, u64> = plan
        .trampoline_stubs
        .iter()
        .map(|t| (t.symbol_name.clone(), t.vaddr))
        .collect();

    let is_pie = plan.is_pie;
    let mut new_relative: Vec<RelativeReloc> = Vec::new();
    for au in &mut plan.units {
        apply_unit_relocations(au, &id_to_vaddr, &tramp_to_vaddr, is_pie, &mut new_relative)
            .with_context(|| format!("applying relocations to '{}'", au.unit.name))?;
    }
    plan.relative_relocs.extend(new_relative);
    Ok(())
}

/// The address each unit in the plan was assigned, indexed by its `UnitId`.
struct UnitVaddrs(Vec<Option<u64>>);

impl UnitVaddrs {
    fn of(plan: &MergePlan) -> Self {
        let len = plan
            .units
            .iter()
            .map(|au| au.unit.id.0 as usize + 1)
            .max()
            .unwrap_or(0);
        let mut vaddrs = vec![None; len];
        for au in &plan.units {
            vaddrs[au.unit.id.0 as usize] = Some(au.assigned_vaddr);
        }
        Self(vaddrs)
    }

    /// The address of the unit with `id`, or `None` for an id no unit in the
    /// plan was registered under — a dangling relocation target, which the
    /// caller reports rather than patches.
    fn get(&self, id: crate::types::UnitId) -> Option<u64> {
        *self.0.get(id.0 as usize)?
    }
}

fn apply_unit_relocations(
    au: &mut AssignedUnit,
    id_to_vaddr: &UnitVaddrs,
    tramp_to_vaddr: &std::collections::HashMap<String, u64>,
    is_pie: bool,
    new_relative: &mut Vec<RelativeReloc>,
) -> Result<()> {
    // What each site was written to reach, for the checks that can only run
    // once every site of the unit has been written: nothing orders an aarch64
    // `adrp`'s relocation before those of the `:lo12:` halves completing it.
    let mut written: Vec<(&crate::arch::Site, usize, u64)> =
        Vec::with_capacity(au.unit.relocations.len());
    for reloc in &au.unit.relocations {
        // P = patch site VA
        let p: u64 = au.assigned_vaddr + reloc.offset_within_unit;
        let off = reloc.offset_within_unit as usize;

        // S = target symbol VA
        let s: u64 = match &reloc.target {
            RelocTarget::MergedUnit(id) => id_to_vaddr
                .get(*id)
                .with_context(|| format!("reloc target UnitId({}) not found in plan", id.0))?,
            RelocTarget::External(name) => *tramp_to_vaddr
                .get(name)
                .with_context(|| format!("no trampoline for external symbol '{name}'"))?,
            RelocTarget::DataBlobOffset(blob_id, offset) => {
                let blob_base = id_to_vaddr.get(*blob_id).with_context(|| {
                    format!("data blob UnitId({}) not found in plan", blob_id.0)
                })?;
                blob_base + offset
            }
        };

        let a: i64 = reloc.addend;

        reloc
            .site
            .write(&mut au.unit.bytes, off, s, a, p)
            .with_context(|| format!("reloc at offset 0x{off:x} ({:?})", reloc.site))?;
        written.push((&reloc.site, off, s.wrapping_add(a as u64)));

        // Absolute 64-bit sites hold image VAs and must be rebased under PIE.
        // `layout` reads the same predicate off the unit to decide whether it
        // can go in the merged region's read-only run, so the two must agree.
        if is_pie && reloc.is_absolute64() {
            new_relative.push(RelativeReloc {
                vaddr: p,
                addend: s.wrapping_add(a as u64) as i64,
            });
        }
    }

    for (site, off, target) in written {
        site.check_placed(&au.unit.bytes, au.assigned_vaddr, off, target)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unit at 0x40_0010 holding `adrp x2, 0; ldr w1, [x2]; str w1, [x2]`,
    /// the load reaching 0x10 and the store `store_at` bytes into unit 1 at
    /// 0x50_0f00, both completing the one `adrp`.
    fn shared_adrp_unit(store_at: i64) -> (AssignedUnit, UnitVaddrs) {
        use crate::arch::Site;
        use crate::arch::aarch64::Field::{AdrpPage, Lo12};
        use crate::arch::aarch64::InsnField;
        use crate::types::{ExtractedReloc, ExtractedUnit, SectionKind, UnitId};

        const ADRP_X2: u32 = 0x9000_0002;
        const LDR_W1_X2: u32 = 0xb940_0041;
        const STR_W1_X2: u32 = 0xb900_0041;
        let reloc = |offset: u64, field, adrps: Vec<u64>, addend| ExtractedReloc {
            offset_within_unit: offset,
            site: Site::Aarch64(InsnField { field, adrps }),
            addend,
            target: RelocTarget::MergedUnit(UnitId(1)),
        };
        let unit = ExtractedUnit {
            id: UnitId(0),
            name: "f".into(),
            source_lib: "libf.so".into(),
            bytes: [ADRP_X2, LDR_W1_X2, STR_W1_X2]
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect(),
            section_kind: SectionKind::Text,
            alignment: 4,
            relocations: vec![
                reloc(4, Lo12, vec![0], 0x10),
                reloc(8, Lo12, vec![0], store_at),
                reloc(0, AdrpPage, vec![], 0x10),
            ],
        };
        let au = AssignedUnit {
            unit,
            assigned_vaddr: 0x40_0010,
        };
        (au, UnitVaddrs(vec![Some(0x40_0010), Some(0x50_0f00)]))
    }

    fn apply(au: &mut AssignedUnit, vaddrs: &UnitVaddrs) -> Result<()> {
        apply_unit_relocations(au, vaddrs, &Default::default(), true, &mut Vec::new())
    }

    /// An aarch64 site is a bit-field of an instruction word: the `adrp` gets
    /// the target's page, each `:lo12:` the target's low twelve bits scaled
    /// by its access size, and the opcode and registers around them are kept.
    #[test]
    fn an_adrp_pair_is_rewritten_in_its_instruction_fields() {
        let (mut au, vaddrs) = shared_adrp_unit(0xfc);
        apply(&mut au, &vaddrs).expect("both objects are in page 0x50_0000");

        let words: Vec<u32> = au
            .unit
            .bytes
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
            .collect();
        let adrp = crate::arch::aarch64::pc_relative_ref(words[0], 0x40_0010)
            .unwrap()
            .expect("still an adrp");
        assert_eq!(adrp.target, 0x50_0000);
        // 0x50_0f10 and 0x50_0ffc, in four-byte units.
        assert_eq!(words[1], 0xb940_0041 | (0xf10 / 4) << 10);
        assert_eq!(words[2], 0xb900_0041 | (0xffc / 4) << 10);
    }

    /// One `adrp` serving two objects only works while the two share a
    /// page. The second `:lo12:` is right on its own, so nothing but a check
    /// against the `adrp` notices that the merge put its object on the next.
    #[test]
    fn a_shared_adrp_whose_objects_land_on_different_pages_is_refused() {
        let (mut au, vaddrs) = shared_adrp_unit(0x100);
        let err = apply(&mut au, &vaddrs).expect_err("0x50_1000 is the next page");
        let msg = format!("{err:#}");
        assert!(msg.contains("different pages"), "{msg}");
    }
}
