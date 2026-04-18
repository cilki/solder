use anyhow::{bail, Context, Result};

use crate::types::{AssignedUnit, MergePlan, RelocTarget};

/// Apply all relocations to all units in the merge plan.
/// This modifies `unit.bytes` in-place.
pub fn apply_all_relocations(plan: &mut MergePlan) -> Result<()> {
    // Collect the lookup tables we need before borrowing plan mutably for iteration.
    // (unit_id → vaddr, trampoline_name → vaddr)
    let id_to_vaddr: std::collections::HashMap<crate::types::UnitId, u64> = plan
        .all_units()
        .map(|au| (au.unit.id, au.assigned_vaddr))
        .collect();

    let tramp_to_vaddr: std::collections::HashMap<String, u64> = plan
        .trampoline_stubs
        .iter()
        .map(|t| (t.symbol_name.clone(), t.vaddr))
        .collect();

    for au in plan.all_units_mut() {
        apply_unit_relocations(au, &id_to_vaddr, &tramp_to_vaddr)
            .with_context(|| format!("applying relocations to '{}'", au.unit.name))?;
    }
    Ok(())
}

fn apply_unit_relocations(
    au: &mut AssignedUnit,
    id_to_vaddr: &std::collections::HashMap<crate::types::UnitId, u64>,
    tramp_to_vaddr: &std::collections::HashMap<String, u64>,
) -> Result<()> {
    for reloc in &au.unit.relocations {
        // P = patch site VA
        let p: u64 = au.assigned_vaddr + reloc.offset_within_unit;
        let off = reloc.offset_within_unit as usize;

        // S = target symbol VA
        let s: u64 = match &reloc.target {
            RelocTarget::MergedUnit(id) => *id_to_vaddr
                .get(id)
                .with_context(|| format!("reloc target UnitId({}) not found in plan", id.0))?,
            RelocTarget::External(name) => *tramp_to_vaddr
                .get(name)
                .with_context(|| format!("no trampoline for external symbol '{name}'"))?,
            RelocTarget::DataBlobOffset(blob_id, offset) => {
                let blob_base = *id_to_vaddr
                    .get(blob_id)
                    .with_context(|| format!("data blob UnitId({}) not found in plan", blob_id.0))?;
                blob_base + offset
            }
        };

        let a: i64 = reloc.addend;

        apply_one_reloc(
            &mut au.unit.bytes,
            reloc.kind,
            reloc.encoding,
            reloc.size,
            off,
            s,
            a,
            p,
        )
        .with_context(|| {
            format!(
                "reloc at offset 0x{:x} (kind={:?}, size={}b)",
                off, reloc.kind, reloc.size
            )
        })?;
    }
    Ok(())
}

/// Apply a single relocation formula and write the result into `bytes`.
///
/// Arguments:
///   `bytes`    — mutable byte slice for the unit being patched
///   `kind`     — relocation kind from the `object` crate
///   `encoding` — relocation encoding from the `object` crate
///   `size`     — field width in bits (8, 16, 32, or 64)
///   `offset`   — byte offset within `bytes` to patch
///   `s`        — symbol virtual address
///   `a`        — addend
///   `p`        — patch site virtual address (= unit base VA + offset)
pub fn apply_one_reloc(
    bytes: &mut [u8],
    kind: object::RelocationKind,
    encoding: object::RelocationEncoding,
    size: u8,
    offset: usize,
    s: u64,
    a: i64,
    p: u64,
) -> Result<()> {
    let value: i128 = match kind {
        // R_X86_64_64: S + A, 64-bit absolute
        object::RelocationKind::Absolute if size == 64 => (s as i128) + (a as i128),
        // R_X86_64_32: (S + A), truncate to 32 bits, unsigned — must not overflow
        object::RelocationKind::Absolute
            if size == 32 && encoding == object::RelocationEncoding::Generic =>
        {
            let v = (s as i128) + (a as i128);
            if v < 0 || v > u32::MAX as i128 {
                bail!("R_X86_64_32 overflow: value 0x{:x} does not fit in u32", v);
            }
            v
        }
        // R_X86_64_32S: S + A, sign-extended 32 bits — must fit in i32
        object::RelocationKind::Absolute
            if size == 32 && encoding == object::RelocationEncoding::X86Signed =>
        {
            let v = (s as i128) + (a as i128);
            if v < i32::MIN as i128 || v > i32::MAX as i128 {
                bail!("R_X86_64_32S overflow: value 0x{:x} does not fit in i32", v);
            }
            v
        }
        // R_X86_64_PC32 / R_X86_64_PLT32: S + A - P, 32-bit PC-relative
        object::RelocationKind::Relative if size == 32 => {
            let v = (s as i128) + (a as i128) - (p as i128);
            if v < i32::MIN as i128 || v > i32::MAX as i128 {
                bail!(
                    "R_X86_64_PC32 overflow: PC-relative offset 0x{:x} does not fit in i32 \
                     (S=0x{s:x}, A={a}, P=0x{p:x})",
                    v
                );
            }
            v
        }
        object::RelocationKind::PltRelative if size == 32 => {
            let v = (s as i128) + (a as i128) - (p as i128);
            if v < i32::MIN as i128 || v > i32::MAX as i128 {
                bail!(
                    "R_X86_64_PLT32 overflow: offset 0x{:x} does not fit in i32 \
                     (S=0x{s:x}, A={a}, P=0x{p:x})",
                    v
                );
            }
            v
        }
        // R_X86_64_PC64: S + A - P, 64-bit PC-relative (rare)
        object::RelocationKind::Relative if size == 64 => (s as i128) + (a as i128) - (p as i128),
        other => {
            bail!("unsupported relocation kind {:?} (size={size})", other);
        }
    };

    write_reloc_value(bytes, offset, size, value)
}

fn write_reloc_value(bytes: &mut [u8], offset: usize, size: u8, value: i128) -> Result<()> {
    match size {
        8 => {
            let v = value as u8;
            bytes[offset] = v;
        }
        16 => {
            let v = (value as u16).to_le_bytes();
            bytes[offset..offset + 2].copy_from_slice(&v);
        }
        32 => {
            let v = (value as u32).to_le_bytes();
            if offset + 4 > bytes.len() {
                bail!(
                    "reloc write at offset {offset} + 4 bytes overflows unit of size {}",
                    bytes.len()
                );
            }
            bytes[offset..offset + 4].copy_from_slice(&v);
        }
        64 => {
            let v = (value as u64).to_le_bytes();
            if offset + 8 > bytes.len() {
                bail!(
                    "reloc write at offset {offset} + 8 bytes overflows unit of size {}",
                    bytes.len()
                );
            }
            bytes[offset..offset + 8].copy_from_slice(&v);
        }
        _ => bail!("unsupported relocation field size {size} bits"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abs64() {
        let mut bytes = [0u8; 8];
        apply_one_reloc(
            &mut bytes,
            object::RelocationKind::Absolute,
            object::RelocationEncoding::Generic,
            64,
            0,
            0x0000_0000_0040_1000, // S
            0,                     // A
            0x0000_0000_0040_0100, // P (unused for Absolute)
        )
        .unwrap();
        assert_eq!(u64::from_le_bytes(bytes), 0x0000_0000_0040_1000);
    }

    #[test]
    fn test_pc32_basic() {
        let mut bytes = [0u8; 4];
        // S=0x402000, A=-4, P=0x401000 → offset = 0x402000 - 4 - 0x401000 = 0xFFC
        apply_one_reloc(
            &mut bytes,
            object::RelocationKind::Relative,
            object::RelocationEncoding::Generic,
            32,
            0,
            0x402000, // S
            -4,       // A
            0x401000, // P
        )
        .unwrap();
        let result = i32::from_le_bytes(bytes);
        assert_eq!(result, 0xffc);
    }

    #[test]
    fn test_abs32_overflow() {
        let mut bytes = [0u8; 4];
        let result = apply_one_reloc(
            &mut bytes,
            object::RelocationKind::Absolute,
            object::RelocationEncoding::Generic,
            32,
            0,
            0xffff_ffff_0000_0000, // S — too large for u32
            0,
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_pc32_overflow() {
        let mut bytes = [0u8; 4];
        let result = apply_one_reloc(
            &mut bytes,
            object::RelocationKind::Relative,
            object::RelocationEncoding::Generic,
            32,
            0,
            0x8000_0000_0000_0000, // S — too far
            0,
            0x0000_0000_0040_0000, // P
        );
        assert!(result.is_err());
    }
}
