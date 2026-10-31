//! Where a relocation writes its value, and which values fit there.
//!
//! Every relocation the merge applies is `S + A`, perhaps minus the patch site
//! `P`, written into the unit's bytes. What differs is the site: a
//! little-endian integer of some width — a pointer slot in data on any
//! architecture, or an x86-64 displacement — or bits scattered through an
//! instruction word, which only the architecture that encodes the
//! instruction knows how to rewrite. A [`Site`] says which, and writes the
//! value itself, so the relocator computes `S`, `A` and `P` and never looks at
//! how they are encoded.

use anyhow::{Context, Result, bail};

use super::aarch64;

/// How one relocation's value is written into its unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Site {
    /// A little-endian integer field.
    Word(Word),
    /// An address kept in an aarch64 instruction word.
    Aarch64(aarch64::InsnField),
}

impl Site {
    /// Write `S + A`, as reached from `P`, into the site at `offset` of
    /// `bytes`; an error where the value does not fit.
    pub fn write(&self, bytes: &mut [u8], offset: usize, s: u64, a: i64, p: u64) -> Result<()> {
        match self {
            Site::Word(word) => word.write(bytes, offset, s, a, p),
            Site::Aarch64(insn) => insn.write(bytes, offset, s, a, p),
        }
    }

    /// Check, once every site of the unit at `base` has been written, that
    /// what this one depends on elsewhere in `bytes` agrees with the `target`
    /// it was written for. Only the `:lo12:` half of an aarch64 `adrp` pair
    /// depends on anything: the `adrp`s that supply its page.
    pub fn check_placed(&self, bytes: &[u8], base: u64, offset: usize, target: u64) -> Result<()> {
        match self {
            Site::Word(_) => Ok(()),
            Site::Aarch64(insn) => insn.check_placed(bytes, base, offset, target),
        }
    }

    /// Whether the site holds a 64-bit absolute address. The value written
    /// there is a VA inside the output image, so under PIE the loader has to
    /// rebase it at startup, which both adds a `RELATIVE` entry and requires
    /// the containing page to be writable while it does so.
    pub fn is_absolute64(&self) -> bool {
        matches!(self, Site::Word(Word::Abs64))
    }
}

/// A little-endian integer field holding `S + A` (absolute) or `S + A - P`
/// (PC-relative), of a width and signedness that bound what it can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Word {
    /// 64-bit absolute: `R_X86_64_64`, `R_AARCH64_ABS64`, and the
    /// `RELATIVE`/`GLOB_DAT`/`JUMP_SLOT` slots lifted out of a library's own
    /// dynamic relocations.
    Abs64,
    /// 32-bit absolute, zero-extended: `R_X86_64_32`.
    Abs32,
    /// 32-bit absolute, sign-extended: `R_X86_64_32S`.
    Abs32Signed,
    /// 64-bit PC-relative: `R_X86_64_PC64`.
    Pc64,
    /// 32-bit PC-relative: `R_X86_64_PC32` and `R_X86_64_PLT32` (the merged
    /// code calls the target directly, there being no PLT left to go
    /// through), a scanned rel32 displacement, and a jump table entry.
    Pc32,
    /// A short `jmp`/`jcc` displacement the instruction scanner found.
    Pc8,
}

impl Word {
    /// The field of a relocation the `object` crate read, or `None` for a
    /// form the merge does not write.
    ///
    /// `Unknown` covers the `RELATIVE`/`GLOB_DAT`/`JUMP_SLOT` entries of a
    /// library's own dynamic relocations, which `object` does not name but
    /// which are absolute 64-bit slots all the same. It is
    /// `extractor::reject_unliftable_dynamic_reloc` that keeps the other
    /// unnamed types — the TLS family, `IRELATIVE`, `SIZE64` — from arriving
    /// here and being taken for addresses.
    pub fn of_object(
        kind: object::RelocationKind,
        encoding: object::RelocationEncoding,
        size: u8,
    ) -> Option<Word> {
        use object::RelocationKind::{Absolute, PltRelative, Relative, Unknown};
        Some(match (kind, size) {
            (Absolute | Unknown, 64) => Word::Abs64,
            // The one place the encoding rather than the kind and width picks
            // the form.
            (Absolute, 32) if encoding == object::RelocationEncoding::X86Signed => {
                Word::Abs32Signed
            }
            (Absolute, 32) => Word::Abs32,
            (Relative, 64) => Word::Pc64,
            (Relative | PltRelative, 32) => Word::Pc32,
            (Relative, 8) => Word::Pc8,
            _ => return None,
        })
    }

    /// The field's width in bytes.
    pub fn width(self) -> usize {
        match self {
            Word::Abs64 | Word::Pc64 => 8,
            Word::Abs32 | Word::Abs32Signed | Word::Pc32 => 4,
            Word::Pc8 => 1,
        }
    }

    /// Write `S + A`, minus `P` for a PC-relative field, at `offset` of
    /// `bytes`; an error where the value does not fit.
    pub fn write(self, bytes: &mut [u8], offset: usize, s: u64, a: i64, p: u64) -> Result<()> {
        let signed = |bits: u32| Some(-(1i128 << (bits - 1))..=(1i128 << (bits - 1)) - 1);

        // Per field: how messages name it, anything worth saying when the value
        // does not fit, whether `P` is subtracted, and the values it can hold —
        // `None` for a 64-bit field, which holds anything the formula can
        // produce.
        let (name, note, pc_relative, range) = match self {
            Word::Abs64 => ("64-bit absolute address", "", false, None),
            Word::Abs32 => (
                "32-bit absolute address",
                "",
                false,
                Some(0..=i128::from(u32::MAX)),
            ),
            Word::Abs32Signed => ("32-bit signed absolute address", "", false, signed(32)),
            Word::Pc64 => ("64-bit PC-relative offset", "", true, None),
            Word::Pc32 => ("32-bit PC-relative offset", "", true, signed(32)),
            // The 1-byte field cannot be widened in place, so a target the
            // layout put out of reach cannot be patched at all.
            Word::Pc8 => (
                "rel8 branch displacement",
                "; the target was laid out too far from a short jump",
                true,
                signed(8),
            ),
        };

        let mut value = (s as i128) + (a as i128);
        if pc_relative {
            value -= p as i128;
        }
        let width = self.width();
        if let Some(range) = range
            && !range.contains(&value)
        {
            bail!(
                "{name} overflow: 0x{value:x} does not fit in {} bits \
                 (S=0x{s:x}, A={a}, P=0x{p:x}){note}",
                width * 8
            );
        }

        // The low bytes of the little-endian encoding are the field; the range
        // check above is what makes dropping the rest lossless.
        let unit_len = bytes.len();
        let end = offset
            .checked_add(width)
            .context("relocation offset overflows the address space")?;
        let field = bytes.get_mut(offset..end).with_context(|| {
            format!(
                "reloc write at offset {offset} + {width} bytes overflows unit of size {unit_len}"
            )
        })?;
        field.copy_from_slice(&(value as u64).to_le_bytes()[..width]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::RelocationEncoding::{Generic, X86Signed};
    use object::RelocationKind::{Absolute, PltRelative, Relative, Unknown};

    #[test]
    fn abs64_is_the_target_itself() {
        let mut bytes = [0u8; 8];
        // P is unused for an absolute field.
        Word::Abs64
            .write(&mut bytes, 0, 0x40_1000, 0, 0x40_0100)
            .unwrap();
        assert_eq!(u64::from_le_bytes(bytes), 0x40_1000);
    }

    #[test]
    fn pc32_is_the_distance_from_the_site() {
        let mut bytes = [0u8; 4];
        // S=0x402000, A=-4, P=0x401000 → 0x402000 - 4 - 0x401000 = 0xffc
        Word::Pc32
            .write(&mut bytes, 0, 0x402000, -4, 0x401000)
            .unwrap();
        assert_eq!(i32::from_le_bytes(bytes), 0xffc);
    }

    #[test]
    fn a_value_out_of_a_32_bit_fields_range_is_refused() {
        let mut bytes = [0u8; 4];
        Word::Abs32
            .write(&mut bytes, 0, 0xffff_ffff_0000_0000, 0, 0)
            .expect_err("too large for a u32");
        Word::Pc32
            .write(&mut bytes, 0, 0x8000_0000_0000_0000, 0, 0x40_0000)
            .expect_err("too far for an i32");
    }

    /// R_X86_64_32 and R_X86_64_32S occupy the same four bytes but accept
    /// different values: the unsigned form cannot hold a negative result, and
    /// the signed form cannot hold one above `i32::MAX`. Giving both the same
    /// range would either corrupt a patch site or refuse a legitimate one.
    #[test]
    fn the_two_absolute_32_bit_forms_accept_different_values() {
        let mut bytes = [0u8; 4];

        // -8 is representable as R_X86_64_32S but not as R_X86_64_32.
        Word::Abs32Signed
            .write(&mut bytes, 0, 0, -8, 0)
            .expect("R_X86_64_32S is sign-extended");
        assert_eq!(i32::from_le_bytes(bytes), -8);
        Word::Abs32
            .write(&mut bytes, 0, 0, -8, 0)
            .expect_err("R_X86_64_32 is unsigned; a negative value does not fit");

        // 0x8000_0000 is representable as R_X86_64_32 but not as R_X86_64_32S.
        Word::Abs32
            .write(&mut bytes, 0, 0x8000_0000, 0, 0)
            .expect("R_X86_64_32 spans the whole u32 range");
        assert_eq!(u32::from_le_bytes(bytes), 0x8000_0000);
        Word::Abs32Signed
            .write(&mut bytes, 0, 0x8000_0000, 0, 0)
            .expect_err("0x80000000 does not fit in an i32");
    }

    /// A short `jmp`/`jcc` displacement is one byte wide and cannot be widened
    /// in place, so a target out of its reach has to be refused rather than
    /// truncated into a branch to the wrong address.
    #[test]
    fn a_short_branch_is_written_in_one_byte_or_refused() {
        let mut bytes = [0u8; 2];
        // S + A - P = 0x1080 - 1 - 0x1000 = 0x7f, the furthest a rel8 reaches.
        Word::Pc8
            .write(&mut bytes, 1, 0x1080, -1, 0x1000)
            .expect("rel8 in reach");
        assert_eq!(bytes, [0, 0x7f]);

        let err = Word::Pc8
            .write(&mut bytes, 1, 0x1081, -1, 0x1000)
            .expect_err("one byte past the reach of a rel8");
        assert!(
            format!("{err}").contains("short jump"),
            "unhelpful error: {err}"
        );
    }

    /// A field that runs off the end of its unit means the extractor mis-sized
    /// the unit; saying so beats panicking partway through a merge.
    #[test]
    fn a_field_running_past_the_end_of_a_unit_is_an_error() {
        for (word, len) in [(Word::Pc8, 0usize), (Word::Abs32, 3), (Word::Abs64, 7)] {
            let mut bytes = vec![0u8; len];
            let err = word
                .write(&mut bytes, 0, 0, 0, 0)
                .expect_err("the field does not fit in the unit");
            assert!(
                format!("{err}").contains("overflows unit"),
                "{word:?}: {err}"
            );
        }
    }

    /// R_X86_64_PLT32 is computed exactly like R_X86_64_PC32, and the RELATIVE
    /// and GLOB_DAT entries lifted out of a library's own `.rela.dyn` — which
    /// `object` reports as `Unknown`, widened to their 64-bit slot — hold the
    /// target address itself. Treating those as PC-relative would leave every
    /// copied pointer off by its own address.
    #[test]
    fn relocations_read_by_object_map_to_their_fields() {
        assert_eq!(Word::of_object(Absolute, Generic, 64), Some(Word::Abs64));
        assert_eq!(Word::of_object(Unknown, Generic, 64), Some(Word::Abs64));
        assert_eq!(Word::of_object(Absolute, Generic, 32), Some(Word::Abs32));
        assert_eq!(
            Word::of_object(Absolute, X86Signed, 32),
            Some(Word::Abs32Signed)
        );
        assert_eq!(Word::of_object(Relative, Generic, 64), Some(Word::Pc64));
        assert_eq!(Word::of_object(Relative, Generic, 32), Some(Word::Pc32));
        assert_eq!(Word::of_object(PltRelative, Generic, 32), Some(Word::Pc32));
        assert_eq!(Word::of_object(Relative, Generic, 8), Some(Word::Pc8));
    }

    #[test]
    fn an_unsupported_kind_or_width_has_no_field() {
        // 16-bit fields (R_X86_64_16) are not among the supported forms.
        assert_eq!(Word::of_object(Absolute, Generic, 16), None);
        // Nor is an 8-bit absolute, a 64-bit PLT-relative, or an unnamed type
        // of any width but a pointer's.
        assert_eq!(Word::of_object(Absolute, Generic, 8), None);
        assert_eq!(Word::of_object(PltRelative, Generic, 64), None);
        assert_eq!(Word::of_object(Unknown, Generic, 32), None);
    }
}
