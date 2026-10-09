use anyhow::{Context, Result, bail};

use crate::types::{AssignedUnit, MergePlan, RelativeReloc, RelocTarget};

/// Apply all relocations to all units in the merge plan.
/// This modifies `unit.bytes` in-place.
///
/// For PIE executables, every absolute 64-bit patch site also gets an
/// R_X86_64_RELATIVE relocation added to the plan: the written value is a
/// link-time VA inside the output image, so ld.so must rebase it at load time
/// (e.g. function pointers in copied GOT/data sections, which constructors
/// pass to __cxa_atexit).
pub fn apply_all_relocations(plan: &mut MergePlan) -> Result<()> {
    // Collect the lookup tables we need before borrowing plan mutably for iteration.
    // (unit_id → vaddr, trampoline_name → vaddr)
    let id_to_vaddr: std::collections::HashMap<crate::types::UnitId, u64> = plan
        .units
        .iter()
        .map(|au| (au.unit.id, au.assigned_vaddr))
        .collect();

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

fn apply_unit_relocations(
    au: &mut AssignedUnit,
    id_to_vaddr: &std::collections::HashMap<crate::types::UnitId, u64>,
    tramp_to_vaddr: &std::collections::HashMap<String, u64>,
    is_pie: bool,
    new_relative: &mut Vec<RelativeReloc>,
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
                let blob_base = *id_to_vaddr.get(blob_id).with_context(|| {
                    format!("data blob UnitId({}) not found in plan", blob_id.0)
                })?;
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
    Ok(())
}

/// Apply a single relocation formula and write the result into `bytes`.
///
/// Every relocation solder applies is `S + A`, optionally minus the patch site
/// address, truncated into a little-endian field. Only two things differ
/// between them — whether `P` is subtracted and which values the field can
/// represent — so each supported relocation is a row of the table below rather
/// than its own copy of the arithmetic, the overflow check and the write.
///
/// Arguments:
///   `bytes`    — mutable byte slice for the unit being patched
///   `kind`     — relocation kind from the `object` crate
///   `encoding` — relocation encoding from the `object` crate
///   `size`     — field width in bits (8, 32, or 64)
///   `offset`   — byte offset within `bytes` to patch
///   `s`        — symbol virtual address
///   `a`        — addend
///   `p`        — patch site virtual address (= unit base VA + offset)
#[allow(clippy::too_many_arguments)]
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
    use object::RelocationKind::{Absolute, PltRelative, Relative, Unknown};

    let i32_field = || Some(i128::from(i32::MIN)..=i128::from(i32::MAX));

    // Per relocation: its x86-64 name and anything worth saying about it when
    // the value does not fit, whether the patch site address is subtracted, and
    // the values its field can hold — `None` for a 64-bit field, which holds
    // anything the formula can produce.
    let (name, note, pc_relative, field_range) = match (kind, size) {
        // R_X86_64_64. `Unknown` covers the RELATIVE/GLOB_DAT/JUMP_SLOT entries
        // lifted out of a library's own .rela.dyn, which the `object` crate
        // does not name but which are absolute 64-bit slots all the same. It is
        // `extractor::reject_unliftable_dynamic_reloc` that keeps the other
        // unnamed types — the TLS family, IRELATIVE, SIZE64 — from arriving
        // here and being patched as if they were addresses.
        (Absolute | Unknown, 64) => ("R_X86_64_64", "", false, None),
        // R_X86_64_32S is sign-extended, R_X86_64_32 unsigned — the one place
        // the encoding rather than the kind and width picks the form.
        (Absolute, 32) if encoding == object::RelocationEncoding::X86Signed => {
            ("R_X86_64_32S", "", false, i32_field())
        }
        (Absolute, 32) => ("R_X86_64_32", "", false, Some(0..=i128::from(u32::MAX))),
        // R_X86_64_PC64, rare.
        (Relative, 64) => ("R_X86_64_PC64", "", true, None),
        (Relative, 32) => ("R_X86_64_PC32", "", true, i32_field()),
        (PltRelative, 32) => ("R_X86_64_PLT32", "", true, i32_field()),
        // A short `jmp`/`jcc` displacement the instruction scanner found. The
        // 1-byte field cannot be widened in place, so a target the layout put
        // out of reach cannot be patched at all.
        (Relative, 8) => (
            "rel8 branch displacement",
            "; the target was laid out too far from a short jump",
            true,
            Some(i128::from(i8::MIN)..=i128::from(i8::MAX)),
        ),
        _ => bail!("unsupported relocation kind {kind:?} (size={size})"),
    };

    let mut value = (s as i128) + (a as i128);
    if pc_relative {
        value -= p as i128;
    }
    if let Some(range) = field_range
        && !range.contains(&value)
    {
        bail!(
            "{name} overflow: 0x{value:x} does not fit in {size} bits \
             (S=0x{s:x}, A={a}, P=0x{p:x}){note}"
        );
    }

    // The low bytes of the little-endian encoding are the field; the range
    // check above is what makes dropping the rest lossless.
    let width = usize::from(size) / 8;
    let unit_len = bytes.len();
    let end = offset
        .checked_add(width)
        .context("relocation offset overflows the address space")?;
    let field = bytes.get_mut(offset..end).with_context(|| {
        format!("reloc write at offset {offset} + {width} bytes overflows unit of size {unit_len}")
    })?;
    field.copy_from_slice(&(value as u64).to_le_bytes()[..width]);

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

    const GENERIC: object::RelocationEncoding = object::RelocationEncoding::Generic;
    const SIGNED: object::RelocationEncoding = object::RelocationEncoding::X86Signed;
    const ABS: object::RelocationKind = object::RelocationKind::Absolute;
    const REL: object::RelocationKind = object::RelocationKind::Relative;
    const PLT: object::RelocationKind = object::RelocationKind::PltRelative;
    const UNKNOWN: object::RelocationKind = object::RelocationKind::Unknown;

    /// R_X86_64_32 and R_X86_64_32S occupy the same four bytes but accept
    /// different values: the unsigned form cannot hold a negative result, and
    /// the signed form cannot hold one above `i32::MAX`. Giving both the same
    /// range would either corrupt a patch site or refuse a legitimate one.
    #[test]
    fn the_two_absolute_32_bit_forms_accept_different_values() {
        let mut bytes = [0u8; 4];

        // -8 is representable as R_X86_64_32S but not as R_X86_64_32.
        apply_one_reloc(&mut bytes, ABS, SIGNED, 32, 0, 0, -8, 0)
            .expect("R_X86_64_32S is sign-extended");
        assert_eq!(i32::from_le_bytes(bytes), -8);
        apply_one_reloc(&mut bytes, ABS, GENERIC, 32, 0, 0, -8, 0)
            .expect_err("R_X86_64_32 is unsigned; a negative value does not fit");

        // 0x8000_0000 is representable as R_X86_64_32 but not as R_X86_64_32S.
        apply_one_reloc(&mut bytes, ABS, GENERIC, 32, 0, 0x8000_0000, 0, 0)
            .expect("R_X86_64_32 spans the whole u32 range");
        assert_eq!(u32::from_le_bytes(bytes), 0x8000_0000);
        apply_one_reloc(&mut bytes, ABS, SIGNED, 32, 0, 0x8000_0000, 0, 0)
            .expect_err("0x80000000 does not fit in an i32");
    }

    /// A short `jmp`/`jcc` displacement is one byte wide and cannot be widened
    /// in place, so a target out of its reach has to be refused rather than
    /// truncated into a branch to the wrong address.
    #[test]
    fn a_short_branch_is_written_in_one_byte_or_refused() {
        let mut bytes = [0u8; 2];
        // S + A - P = 0x1080 - 1 - 0x1000 = 0x7f, the furthest a rel8 reaches.
        apply_one_reloc(&mut bytes, REL, GENERIC, 8, 1, 0x1080, -1, 0x1000).expect("rel8 in reach");
        assert_eq!(bytes, [0, 0x7f]);

        let err = apply_one_reloc(&mut bytes, REL, GENERIC, 8, 1, 0x1081, -1, 0x1000)
            .expect_err("one byte past the reach of a rel8");
        assert!(
            format!("{err}").contains("short jump"),
            "unhelpful error: {err}"
        );
    }

    /// R_X86_64_PLT32 is computed exactly like R_X86_64_PC32 — the merged code
    /// calls the target directly, there being no PLT left to go through.
    #[test]
    fn plt_relative_is_patched_pc_relative() {
        let mut bytes = [0u8; 4];
        apply_one_reloc(&mut bytes, PLT, GENERIC, 32, 0, 0x402000, -4, 0x401000).expect("PLT32");
        assert_eq!(i32::from_le_bytes(bytes), 0xffc);
    }

    /// The RELATIVE and GLOB_DAT entries lifted out of a library's own
    /// `.rela.dyn` reach the relocator as `RelocationKind::Unknown`, and the
    /// value belonging at such a slot is the target address itself. Treating
    /// them as PC-relative would leave every copied pointer off by its own
    /// address.
    #[test]
    fn entries_lifted_from_a_library_are_patched_as_absolute() {
        let mut bytes = [0u8; 8];
        apply_one_reloc(
            &mut bytes,
            UNKNOWN,
            GENERIC,
            64,
            0,
            0x40_1000,
            0x20,
            0xdead_beef, // P must not enter the formula
        )
        .expect("lifted RELATIVE entry");
        assert_eq!(u64::from_le_bytes(bytes), 0x40_1020);
    }

    /// A field that runs off the end of its unit means the extractor mis-sized
    /// the unit; saying so beats panicking partway through a merge, which is
    /// what indexing the slice directly used to do for the 1-byte case.
    #[test]
    fn a_field_running_past_the_end_of_a_unit_is_an_error() {
        for (kind, size, len) in [(REL, 8u8, 0usize), (ABS, 32, 3), (ABS, 64, 7)] {
            let mut bytes = vec![0u8; len];
            let err = apply_one_reloc(&mut bytes, kind, GENERIC, size, 0, 0, 0, 0)
                .expect_err("the field does not fit in the unit");
            assert!(
                format!("{err}").contains("overflows unit"),
                "size {size}: {err}"
            );
        }
    }

    #[test]
    fn an_unsupported_kind_or_width_is_rejected() {
        let mut bytes = [0u8; 8];
        // 16-bit fields (R_X86_64_16) are not among the supported forms.
        assert!(apply_one_reloc(&mut bytes, ABS, GENERIC, 16, 0, 0, 0, 0).is_err());
        // Nor is an 8-bit absolute, or a 64-bit PLT-relative.
        assert!(apply_one_reloc(&mut bytes, ABS, GENERIC, 8, 0, 0, 0, 0).is_err());
        assert!(apply_one_reloc(&mut bytes, PLT, GENERIC, 64, 0, 0, 0, 0).is_err());
    }
}
