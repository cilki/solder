//! The aarch64 instruction forms that carry an address, and how to rewrite one
//! when the code or its target moves (#97, stage 3).
//!
//! An x86-64 reference is a little-endian rel8/rel32 displacement at the tail
//! of the instruction, which `relocator::apply_one_reloc` overwrites whole. An
//! aarch64 reference is a bit-field inside a 32-bit instruction word, scaled
//! by the instruction's granule and split in two for `adr`/`adrp`, so moving
//! one means re-encoding just those bits and leaving the opcode and registers
//! around them alone. [`Field`] names each such layout and [`Field::patch`]
//! is its write path; [`pc_relative_ref`] finds them in decoded code.
//!
//! The decoder is `yaxpeax-arm`. It says which instruction a word is and
//! where its PC-relative operand points; this module adds what the decoder
//! does not, which is where in the word that operand is kept.
//!
//! Nothing outside the tests calls this yet: the extractor still decodes with
//! iced-x86 only, and `arch::SUPPORTED` still refuses aarch64 executables.

use anyhow::{Context, Result, bail};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand};

/// Size of every aarch64 instruction.
pub const INSN_LEN: usize = 4;

/// The granule `adrp` addresses: it names a 4 KiB page whatever the page size
/// the kernel runs with, and the `:lo12:` half that pairs with it supplies the
/// low twelve bits.
const ADRP_PAGE: u64 = 0x1000;

/// One layout of an address-carrying immediate in an instruction word.
///
/// The names in the comments are the static relocations a linker resolves
/// into the same bits, which is what the merge is redoing after the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// `adr`: `immhi:immlo`, a byte offset from the instruction, ±1 MiB.
    /// `R_AARCH64_ADR_PREL_LO21`.
    Adr,
    /// `adrp`: `immhi:immlo`, a 4 KiB page offset from the instruction's
    /// page, ±4 GiB. `R_AARCH64_ADR_PREL_PG_HI21`.
    AdrpPage,
    /// `b`/`bl`: `imm26`, a word offset, ±128 MiB.
    /// `R_AARCH64_JUMP26`/`R_AARCH64_CALL26`.
    Imm26,
    /// `b.cond`/`bc.cond`, `cbz`/`cbnz` and the load-literal forms (`ldr`,
    /// `ldrsw`, `prfm`): `imm19`, a word offset, ±1 MiB.
    /// `R_AARCH64_CONDBR19`/`R_AARCH64_LD_PREL_LO19`.
    Imm19,
    /// `tbz`/`tbnz`: `imm14`, a word offset, ±32 KiB.
    /// `R_AARCH64_TSTBR14`.
    Imm14,
    /// The `:lo12:` half of an `adrp` pair: `add xd, xn, #imm12` or an
    /// unsigned-offset load/store `[xn, #imm12]`, the low twelve bits of an
    /// absolute address, scaled by the access size for a load/store.
    /// `R_AARCH64_ADD_ABS_LO12_NC`/`R_AARCH64_LDST{8,16,32,64,128}_ABS_LO12_NC`.
    Lo12,
}

impl Field {
    /// How messages name the field.
    fn name(self) -> &'static str {
        match self {
            Field::Adr => "adr offset",
            Field::AdrpPage => "adrp page offset",
            Field::Imm26 => "imm26 branch offset",
            Field::Imm19 => "imm19 offset",
            Field::Imm14 => "imm14 test-branch offset",
            Field::Lo12 => ":lo12: offset",
        }
    }

    /// Whether `word` is an instruction this field is a part of. Patching a
    /// word of some other class would overwrite its opcode or registers with
    /// address bits, so [`Field::patch`] refuses one.
    pub fn fits(self, word: u32) -> bool {
        match self {
            Field::Adr => word & 0x9f00_0000 == 0x1000_0000,
            Field::AdrpPage => word & 0x9f00_0000 == 0x9000_0000,
            // b (0x14) and bl (0x94).
            Field::Imm26 => word & 0x7c00_0000 == 0x1400_0000,
            Field::Imm19 => {
                // b.cond and bc.cond, which differ only in bit 4.
                word & 0xff00_0000 == 0x5400_0000
                    // cbz/cbnz, 32- or 64-bit.
                    || word & 0x7e00_0000 == 0x3400_0000
                    // Load literal, general-purpose or SIMD&FP.
                    || word & 0x3b00_0000 == 0x1800_0000
            }
            Field::Imm14 => word & 0x7e00_0000 == 0x3600_0000,
            Field::Lo12 => lo12_scale(word).is_some(),
        }
    }

    /// `word` with this field rewritten to reach `S + A` from an instruction
    /// at `P`, every other bit unchanged.
    ///
    /// A target the field cannot reach, or one that is not aligned to the
    /// field's granule, is an error rather than a truncation: the low bits are
    /// simply not encoded, so writing them anyway would silently send the
    /// instruction somewhere else.
    pub fn patch(self, word: u32, s: u64, a: i64, p: u64) -> Result<u32> {
        if !self.fits(word) {
            bail!(
                "0x{word:08x} at 0x{p:x} is not an instruction with an {}",
                self.name()
            );
        }
        let target = (s as i128) + (a as i128);
        let pc = p as i128;

        // Per field: the value to encode, the number of low bits it must have
        // clear (dropped by the encoding), and its width as a signed field
        // once they are dropped.
        let (value, align_bits, bits) = match self {
            Field::Adr => (target - pc, 0, 21),
            Field::AdrpPage => {
                let page = |v: i128| v & !(ADRP_PAGE as i128 - 1);
                ((page(target) - page(pc)) >> 12, 0, 21)
            }
            Field::Imm26 => (target - pc, 2, 26),
            Field::Imm19 => (target - pc, 2, 19),
            Field::Imm14 => (target - pc, 2, 14),
            Field::Lo12 => {
                let scale = lo12_scale(word).expect("checked by fits");
                let lo12 = target & 0xfff;
                if lo12 & ((1 << scale) - 1) != 0 {
                    bail!(
                        "{} 0x{lo12:x} for 0x{target:x} at 0x{p:x} is not a multiple of \
                         the {}-byte access",
                        self.name(),
                        1 << scale
                    );
                }
                let imm12 = (lo12 >> scale) as u32;
                return Ok(word & !(0xfff << 10) | imm12 << 10);
            }
        };

        if value & ((1 << align_bits) - 1) != 0 {
            bail!(
                "{} to 0x{target:x} from 0x{p:x} is not a multiple of {}",
                self.name(),
                1 << align_bits
            );
        }
        let scaled = value >> align_bits;
        let half = 1i128 << (bits - 1);
        if !(-half..half).contains(&scaled) {
            bail!(
                "{} overflow: 0x{target:x} is out of reach of 0x{p:x} \
                 (S=0x{s:x}, A={a}, P=0x{p:x})",
                self.name()
            );
        }
        let imm = (scaled as u32) & ((1u32 << bits) - 1);

        Ok(match self {
            Field::Adr | Field::AdrpPage => {
                let (immlo, immhi) = (imm & 0b11, imm >> 2);
                word & !(0b11 << 29 | 0x7ffff << 5) | immlo << 29 | immhi << 5
            }
            Field::Imm26 => word & !0x03ff_ffff | imm,
            Field::Imm19 => word & !(0x7ffff << 5) | imm << 5,
            Field::Imm14 => word & !(0x3fff << 5) | imm << 5,
            Field::Lo12 => unreachable!("returned above"),
        })
    }
}

/// The power of two a `:lo12:` immediate in `word` is scaled by — 0 for an
/// `add`, the access size for an unsigned-offset load/store — or `None` when
/// `word` is neither.
fn lo12_scale(word: u32) -> Option<u32> {
    // add (immediate), 32- or 64-bit, without `lsl #12`: the shifted form
    // takes bits 12-23 of an address, not the low twelve.
    if word & 0x7fc0_0000 == 0x1100_0000 {
        return Some(0);
    }
    // Load/store register (unsigned immediate).
    if word & 0x3b00_0000 == 0x3900_0000 {
        let size = word >> 30;
        let simd = word & (1 << 26) != 0;
        let opc_hi = word & (1 << 23) != 0;
        // A SIMD&FP access with size 0 and opc<1> set is the 128-bit `q` one.
        return Some(if simd && size == 0 && opc_hi { 4 } else { size });
    }
    None
}

/// A reference an instruction makes relative to its own address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcRelRef {
    /// Where in the word the offset is kept.
    pub field: Field,
    /// The address the instruction reaches. For `adrp` that is the page,
    /// which is all the instruction itself knows; the `:lo12:` half that
    /// completes it is a separate reference.
    pub target: u64,
    /// Whether control transfers there (a branch or call), rather than the
    /// address being taken or loaded from.
    pub is_code_ref: bool,
}

/// Decode the instruction in `word`, or `None` if it is not one.
pub fn decode(word: u32) -> Option<Instruction> {
    let bytes = word.to_le_bytes();
    InstDecoder::default()
        .decode(&mut U8Reader::new(&bytes))
        .ok()
}

/// The PC-relative reference the instruction `word` at `pc` makes, if any.
///
/// An instruction the decoder gives a PC-relative operand but that this
/// module has no [`Field`] for is an error, not `None`: the merge moves every
/// byte of code it copies, so a reference it cannot rewrite is one it would
/// leave pointing at whatever the old offset lands on.
pub fn pc_relative_ref(word: u32, pc: u64) -> Result<Option<PcRelRef>> {
    let Some(insn) = decode(word) else {
        return Ok(None);
    };
    let Some(offset) = insn.operands.iter().find_map(|op| match op {
        Operand::PCOffset(off) => Some(*off),
        _ => None,
    }) else {
        return Ok(None);
    };

    let (field, is_code_ref) = match insn.opcode {
        Opcode::ADR => (Field::Adr, false),
        Opcode::ADRP => (Field::AdrpPage, false),
        Opcode::B | Opcode::BL => (Field::Imm26, true),
        Opcode::Bcc(_) | Opcode::BCcc(_) | Opcode::CBZ | Opcode::CBNZ => (Field::Imm19, true),
        Opcode::TBZ | Opcode::TBNZ => (Field::Imm14, true),
        Opcode::LDR | Opcode::LDRSW | Opcode::PRFM => (Field::Imm19, false),
        other => bail!(
            "0x{word:08x} at 0x{pc:x} ({other:?}) has a PC-relative operand solder \
             cannot relocate"
        ),
    };
    // The decoder chose the opcode and the table above the field; a word the
    // field's own encoding check disagrees with would be patched in the wrong
    // bits.
    debug_assert!(field.fits(word), "{field:?} for 0x{word:08x}");

    // `adrp`'s offset counts from the instruction's page, not the instruction.
    let base = match field {
        Field::AdrpPage => pc & !(ADRP_PAGE - 1),
        _ => pc,
    };
    Ok(Some(PcRelRef {
        field,
        target: base.wrapping_add(offset as u64),
        is_code_ref,
    }))
}

/// Every PC-relative reference in `bytes`, loaded at `vaddr`, with its byte
/// offset into `bytes`.
///
/// A trailing partial word is not code and is skipped; a word that does not
/// decode is skipped too, the way the x86-64 scanner skips an invalid
/// instruction, since literal pools and padding sit between functions.
pub fn scan_pc_relative_refs(bytes: &[u8], vaddr: u64) -> Result<Vec<(usize, PcRelRef)>> {
    let mut refs = Vec::new();
    for (i, chunk) in bytes.chunks_exact(INSN_LEN).enumerate() {
        let offset = i * INSN_LEN;
        let word = u32::from_le_bytes(chunk.try_into().expect("chunks_exact"));
        let pc = vaddr + offset as u64;
        if let Some(r) = pc_relative_ref(word, pc)
            .with_context(|| format!("scanning offset 0x{offset:x} of code at 0x{vaddr:x}"))?
        {
            refs.push((offset, r));
        }
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `_start` of a program GNU as assembled and `ld -Ttext=0x400000`
    /// linked, with `objdump -d`'s view of each word: every form with a
    /// PC-relative field, each aimed at `there` (0x400054), `lit` (0x400058)
    /// or, for `adrp`, page 0x534000.
    const BASE: u64 = 0x40_0000;
    const THERE: u64 = 0x40_0054;
    const LIT: u64 = 0x40_0058;
    const SAMPLES: &[(u32, Field, u64, bool)] = &[
        (0x1000_02a1, Field::Adr, THERE, false), // adr x1, there
        (0x9000_09a2, Field::AdrpPage, 0x53_4000, false), // adrp x2, far
        (0x1400_0013, Field::Imm26, THERE, true), // b there
        (0x9400_0012, Field::Imm26, THERE, true), // bl there
        (0x5400_0221, Field::Imm19, THERE, true), // b.ne there
        (0x3400_0203, Field::Imm19, THERE, true), // cbz w3, there
        (0xb500_01e4, Field::Imm19, THERE, true), // cbnz x4, there
        (0x3618_01c5, Field::Imm14, THERE, true), // tbz w5, #3, there
        (0xb740_01a6, Field::Imm14, THERE, true), // tbnz x6, #40, there
        (0x5800_01a7, Field::Imm19, LIT, false), // ldr x7, lit
        (0x1800_0188, Field::Imm19, LIT, false), // ldr w8, lit
        (0x9800_0169, Field::Imm19, LIT, false), // ldrsw x9, lit
        (0xd800_0140, Field::Imm19, LIT, false), // prfm pldl1keep, lit
        (0x9c00_012a, Field::Imm19, LIT, false), // ldr q10, lit
        (0x5c00_010b, Field::Imm19, LIT, false), // ldr d11, lit
        (0x1c00_00ec, Field::Imm19, LIT, false), // ldr s12, lit
    ];
    /// The rest of `_start`: `add x13, x2, :lo12:far`, `ldr x14, [x2,
    /// :lo12:far]`, `ret`, `nop`, `bti c`.
    const ADD_LO12: u32 = 0x9111_404d;
    const LDR_X_LO12: u32 = 0xf942_284e;
    const NO_REFS: &[u32] = &[ADD_LO12, LDR_X_LO12, 0xd65f_03c0, 0xd503_201f, 0xd503_245f];

    fn start() -> Vec<u8> {
        SAMPLES
            .iter()
            .map(|s| s.0)
            .chain(NO_REFS.iter().copied())
            .flat_map(u32::to_le_bytes)
            .collect()
    }

    #[test]
    fn every_reference_form_is_found_with_the_target_the_assembler_gave_it() {
        let refs = scan_pc_relative_refs(&start(), BASE).unwrap();
        let expected: Vec<_> = SAMPLES
            .iter()
            .enumerate()
            .map(|(i, &(_, field, target, is_code_ref))| {
                (
                    i * INSN_LEN,
                    PcRelRef {
                        field,
                        target,
                        is_code_ref,
                    },
                )
            })
            .collect();
        assert_eq!(refs, expected);
    }

    /// Re-encoding the target an instruction already has is what the merge
    /// does to every reference it leaves where it is, so it has to give back
    /// the word the assembler wrote, bit for bit.
    #[test]
    fn patching_in_the_existing_target_reproduces_the_word() {
        for (i, &(word, field, target, _)) in SAMPLES.iter().enumerate() {
            let pc = BASE + (i * INSN_LEN) as u64;
            assert_eq!(
                field.patch(word, target, 0, pc).unwrap(),
                word,
                "{word:08x}"
            );
        }
        // `far` is 0x534450; its low twelve bits, unscaled for the add and in
        // eight-byte units for the 64-bit load.
        for word in [ADD_LO12, LDR_X_LO12] {
            assert_eq!(Field::Lo12.patch(word, 0x53_4450, 0, 0).unwrap(), word);
        }
    }

    /// A moved instruction aimed at a moved target, forwards and backwards,
    /// as far as each field reaches: the decoder has to read back the target
    /// that was written, and no bit outside the field may change.
    #[test]
    fn a_patched_reference_decodes_to_its_new_target() {
        // High enough that the furthest `adrp` reach below it is not below 0.
        let pc = 0x2_0000_0000u64;
        for &(word, field, _, _) in SAMPLES {
            let reach: i64 = match field {
                Field::Adr | Field::Imm19 => 1 << 20,
                Field::AdrpPage => 1 << 32,
                Field::Imm26 => 1 << 27,
                Field::Imm14 => 1 << 15,
                Field::Lo12 => unreachable!(),
            };
            let granule = match field {
                Field::Adr => 1,
                Field::AdrpPage => ADRP_PAGE as i64,
                _ => 4,
            };
            for delta in [
                0,
                granule,
                -granule,
                0x7f0 * granule,
                reach - granule,
                -reach,
            ] {
                let target = pc.wrapping_add(delta as u64);
                let patched = field.patch(word, target, 0, pc).unwrap();
                let r = pc_relative_ref(patched, pc).unwrap().unwrap();
                assert_eq!(r.target, target, "{word:08x} delta {delta:#x}");
                assert_eq!(r.field, field);
                let mask = match field {
                    Field::Adr | Field::AdrpPage => 0b11 << 29 | 0x7ffff << 5,
                    Field::Imm26 => 0x03ff_ffff,
                    Field::Imm19 => 0x7ffff << 5,
                    Field::Imm14 => 0x3fff << 5,
                    Field::Lo12 => unreachable!(),
                };
                assert_eq!(patched & !mask, word & !mask, "{word:08x} delta {delta:#x}");
            }
        }
    }

    #[test]
    fn a_target_one_granule_past_the_reach_is_refused() {
        let pc = 0x1000_0000u64;
        for (word, field, past) in [
            (0x1000_02a1, Field::Adr, 1i64 << 20),
            (0x1000_02a1, Field::Adr, -(1i64 << 20) - 1),
            (0x9000_09a2, Field::AdrpPage, 1 << 32),
            (0x1400_0013, Field::Imm26, 1 << 27),
            (0x9400_0012, Field::Imm26, -(1 << 27) - 4),
            (0x5400_0221, Field::Imm19, 1 << 20),
            (0x5800_01a7, Field::Imm19, -(1 << 20) - 4),
            (0x3618_01c5, Field::Imm14, 1 << 15),
            (0x3618_01c5, Field::Imm14, -(1 << 15) - 4),
        ] {
            let err = field
                .patch(word, pc.wrapping_add(past as u64), 0, pc)
                .unwrap_err();
            assert!(err.to_string().contains("overflow"), "{word:08x}: {err}");
        }
    }

    /// The addend counts: `S + A` is the target, so the same reach applies to
    /// the sum and not to `S` alone.
    #[test]
    fn the_addend_is_part_of_the_target() {
        let pc = 0x1000_0000u64;
        let b = 0x1400_0013;
        let patched = Field::Imm26.patch(b, pc + 0x100, 0x40, pc).unwrap();
        assert_eq!(
            pc_relative_ref(patched, pc).unwrap().unwrap().target,
            pc + 0x140
        );
    }

    /// The low two bits of a branch or literal offset are not encoded, and
    /// an `ldr x` cannot address a byte that is not eight-aligned; writing
    /// either would quietly point the instruction elsewhere.
    #[test]
    fn a_target_the_encoding_cannot_express_is_refused() {
        let pc = 0x1000_0000u64;
        assert!(Field::Imm26.patch(0x1400_0013, pc + 2, 0, pc).is_err());
        assert!(Field::Imm19.patch(0x5800_01a7, pc + 1, 0, pc).is_err());
        assert!(Field::Imm14.patch(0x3618_01c5, pc + 3, 0, pc).is_err());
        assert!(Field::Lo12.patch(LDR_X_LO12, 0x53_4454, 0, 0).is_err());
        // The add takes any byte, and `adr` any byte offset.
        assert!(Field::Lo12.patch(ADD_LO12, 0x53_4455, 0, 0).is_ok());
        assert!(Field::Adr.patch(0x1000_02a1, pc + 3, 0, pc).is_ok());
    }

    /// `adrp` sees only pages: where in its page the instruction or the target
    /// sits makes no difference to what is encoded.
    #[test]
    fn adrp_encodes_the_distance_between_pages() {
        let adrp = 0x9000_09a2;
        let a = Field::AdrpPage
            .patch(adrp, 0x20_3000, 0, 0x10_0ffc)
            .unwrap();
        let b = Field::AdrpPage
            .patch(adrp, 0x20_3fff, 0, 0x10_0000)
            .unwrap();
        assert_eq!(a, b);
        let r = pc_relative_ref(a, 0x10_0ffc).unwrap().unwrap();
        assert_eq!(r.target, 0x20_3000);
    }

    #[test]
    fn lo12_is_scaled_by_the_access_size() {
        // ldrb w0, [x1, #0]; ldrh w0, [x1, #0]; ldr w0, [x1, #0];
        // ldr x0, [x1, #0]; ldr q0, [x1, #0]; str x0, [x1, #0].
        for (word, scale) in [
            (0x3940_0020u32, 0u32),
            (0x7940_0020, 1),
            (0xb940_0020, 2),
            (0xf940_0020, 3),
            (0x3dc0_0020, 4),
            (0xf900_0020, 3),
        ] {
            let patched = Field::Lo12.patch(word, 0x1230, 0, 0).unwrap();
            assert_eq!((patched >> 10) & 0xfff, 0x230 >> scale, "{word:08x}");
            assert_eq!(patched & !(0xfff << 10), word, "{word:08x}");
        }
    }

    /// A word of the wrong class has its opcode or registers where the field
    /// would go, so patching it is refused instead of corrupting it.
    #[test]
    fn a_field_is_not_written_into_an_instruction_without_one() {
        let nop = 0xd503_201f;
        for field in [
            Field::Adr,
            Field::AdrpPage,
            Field::Imm26,
            Field::Imm19,
            Field::Imm14,
            Field::Lo12,
        ] {
            assert!(field.patch(nop, 0, 0, 0).is_err(), "{field:?}");
        }
        // `add x0, x1, #1, lsl #12` adds bits 12-23, not a `:lo12:` offset.
        assert!(!Field::Lo12.fits(0x9140_0420));
        // An adrp is not an adr, nor the other way round.
        assert!(!Field::Adr.fits(0x9000_09a2));
        assert!(!Field::AdrpPage.fits(0x1000_02a1));
    }

    /// `retaasppc` (FEAT_PAuth_LR) names a PC-relative return address that
    /// no field here can rewrite; silently skipping it would leave it wrong.
    #[test]
    fn a_pc_relative_form_without_a_field_is_an_error() {
        // Miscellaneous branch (immediate), opc 000, op2 0b11111, imm16 0xfffd.
        let word = 0x5500_0000 | (0xfffd << 5) | 0b11111;
        let Some(insn) = decode(word) else {
            panic!("the decoder knows retaasppc");
        };
        assert_eq!(insn.opcode, Opcode::RETAASPPC);
        assert!(pc_relative_ref(word, 0x1000).is_err());
    }

    #[test]
    fn a_trailing_partial_word_is_not_scanned() {
        let mut bytes = start();
        bytes.extend_from_slice(&[0x13, 0x00]);
        assert_eq!(
            scan_pc_relative_refs(&bytes, BASE).unwrap().len(),
            SAMPLES.len()
        );
    }
}
