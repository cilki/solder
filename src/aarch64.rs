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
//! An `adrp` only reaches a 4 KiB page. The `add`, load or store that adds
//! the low twelve bits is an ordinary instruction with an ordinary immediate,
//! so [`pair_lo12_refs`] finds it by following the `adrp`'s register.
//!
//! The decoder is `yaxpeax-arm`. It says which instruction a word is and
//! where its PC-relative operand points; this module adds what the decoder
//! does not, which is where in the word that operand is kept.
//!
//! Nothing outside the tests calls this yet: the extractor still decodes with
//! iced-x86 only, and `arch::SUPPORTED` still refuses aarch64 executables.

use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow, bail};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand, ShiftStyle, SizeCode};

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

/// The `:lo12:` half of an `adrp` pair: an `add`, load or store whose
/// immediate is the low twelve bits of the address an `adrp` took the page of.
///
/// Nothing in the word says so. `add x0, x0, #0xff0` is the same instruction
/// whether `0xff0` is the bottom of a symbol's address or a struct offset, so
/// which ones are addresses comes from following each `adrp`'s register to
/// the instructions that read it; see [`pair_lo12_refs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lo12Ref {
    /// Byte offset of the `add`/load/store.
    pub offset: usize,
    /// Byte offsets of the `adrp`s whose page can reach it, in order. More
    /// than one when paths from different `adrp`s of the same page meet.
    pub adrps: Vec<usize>,
    /// The address the pair forms: the `adrp`s' page plus this instruction's
    /// low twelve bits, scaled by its access size.
    pub target: u64,
}

/// Registers an `adrp`'s page can be followed through: `x0`-`x30`. Register
/// number 31 is `sp` or `xzr` depending on the instruction, and neither is an
/// `adrp` destination.
const GPRS: usize = 31;

/// Where the value in one register may have come from, over every path that
/// reaches an instruction: `Some(i)` is the page the `adrp` at word `i` took,
/// `None` anything else. Empty means no path has reached it yet.
type Origins = BTreeSet<Option<usize>>;
type Regs = Vec<Origins>;

fn holds_page(origins: &Origins) -> bool {
    origins.iter().any(Option::is_some)
}

/// Join `from` into `into`, reporting whether `into` grew.
fn join(into: &mut Regs, from: &Regs) -> bool {
    let mut grew = false;
    for (into, from) in into.iter_mut().zip(from) {
        let before = into.len();
        into.extend(from.iter().copied());
        grew |= into.len() != before;
    }
    grew
}

/// Opcodes whose first operand is a general-purpose register they write
/// without reading. Any register operand after it is read.
fn writes_first_operand(opcode: Opcode) -> bool {
    use Opcode::*;
    matches!(
        opcode,
        MOVN | MOVZ
            | ADC | ADCS | SBC | SBCS | ADD | ADDS | SUB | SUBS
            | AND | ANDS | ORR | ORN | EOR | EON | BIC | BICS
            | UBFM | SBFM | EXTR
            | ADR | ADRP
            | CSEL | CSINC | CSINV | CSNEG
            | RBIT | REV16 | REV | REV32 | CLZ | CLS
            | MADD | MSUB | SMADDL | SMSUBL | SMULH | UMADDL | UMSUBL | UMULH
            | UDIV | SDIV | LSLV | LSRV | ASRV | RORV
            | CRC32B | CRC32H | CRC32W | CRC32X | CRC32CB | CRC32CH | CRC32CW | CRC32CX
            | MRS
            | FMOV | SMOV | UMOV | FJCVTZS
            | FCVTZS | FCVTZU | FCVTNS | FCVTNU | FCVTPS | FCVTPU
            | FCVTMS | FCVTMU | FCVTAS | FCVTAU
            | LDR | LDRB | LDRH | LDRSB | LDRSH | LDRSW
            | LDUR | LDURB | LDURH | LDURSB | LDURSH | LDURSW
            | LDTR | LDTRB | LDTRH | LDTRSB | LDTRSH | LDTRSW
            | LDAR | LDARB | LDARH | LDLAR | LDLARB | LDLARH
            | LDAPR | LDAPRB | LDAPRH
            | LDAPUR | LDAPURB | LDAPURH | LDAPURSB | LDAPURSH | LDAPURSW
            | LDXR | LDXRB | LDXRH | LDAXR | LDAXRB | LDAXRH
            | LDRAA | LDRAB
            | LDP | LDPSW | LDNP | LDXP | LDAXP
            // The exclusive stores' first operand is the status they write.
            | STXR | STXRB | STXRH | STLXR | STLXRB | STLXRH | STXP | STLXP
    )
}

/// Opcodes that also write their second operand: the second destination of
/// a load pair, and the old memory value an atomic returns.
fn writes_second_operand(opcode: Opcode) -> bool {
    use Opcode::*;
    matches!(
        opcode,
        LDP | LDPSW
            | LDNP
            | LDXP
            | LDAXP
            | SWP(_)
            | SWPB(_)
            | SWPH(_)
            | LDADD(_)
            | LDADDB(_)
            | LDADDH(_)
            | LDCLR(_)
            | LDCLRB(_)
            | LDCLRH(_)
            | LDEOR(_)
            | LDEORB(_)
            | LDEORH(_)
            | LDSET(_)
            | LDSETB(_)
            | LDSETH(_)
            | LDSMAX(_)
            | LDSMAXB(_)
            | LDSMAXH(_)
            | LDSMIN(_)
            | LDSMINB(_)
            | LDSMINH(_)
            | LDUMAX(_)
            | LDUMAXB(_)
            | LDUMAXH(_)
            | LDUMIN(_)
            | LDUMINB(_)
            | LDUMINH(_)
    )
}

/// Registers an opcode reads or writes without naming them as operands.
fn implicit_registers(opcode: Opcode) -> &'static [usize] {
    use Opcode::*;
    match opcode {
        PACIA1716 | PACIB1716 | AUTIA1716 | AUTIB1716 => &[16, 17],
        PACIA171615 | PACIB171615 | AUTIA171615 | AUTIB171615 => &[15, 16, 17],
        PACIASP | PACIBSP | PACIAZ | PACIBZ | AUTIASP | AUTIBSP | AUTIAZ | AUTIBZ | XPACLRI
        | PACIASPPC | PACIBSPPC | PACNBIASPPC | PACNBIBSPPC | AUTIASPPC | AUTIBSPPC
        | AUTIASPPCR | AUTIBSPPCR | RETAASPPC | RETABSPPC | RETAASPPCR | RETABSPPCR | RETAA
        | RETAB | ERETAA | ERETAB => &[30],
        _ => &[],
    }
}

/// The general-purpose registers `operand` names, `sp`/`xzr` left out.
fn operand_registers(operand: &Operand) -> Vec<usize> {
    let regs: &[u16] = match *operand {
        Operand::Register(_, r)
        | Operand::RegisterOrSP(_, r)
        | Operand::RegShift(_, _, _, r)
        | Operand::RegPreIndex(r, _, _)
        | Operand::RegPostIndex(r, _) => &[r],
        Operand::RegisterPair(_, r) => &[r, r + 1],
        Operand::RegRegOffset(base, index, ..) => &[base, index],
        Operand::RegPostIndexReg(base, index) => &[base, index],
        _ => &[],
    };
    regs.iter()
        .map(|&r| r as usize)
        .filter(|&r| r < GPRS)
        .collect()
}

/// What a `:lo12:`-shaped word does with its registers.
struct Lo12Form {
    /// The base register, which an `adrp` page arrives in.
    base: usize,
    /// The register the instruction writes, if a general-purpose one.
    writes: Option<usize>,
    /// The register a store stores, if a general-purpose one.
    stores: Option<usize>,
    /// The power of two the immediate is scaled by.
    scale: u32,
}

fn lo12_form(word: u32) -> Option<Lo12Form> {
    let scale = lo12_scale(word)?;
    let base = ((word >> 5) & 31) as usize;
    let rt = (word & 31) as usize;
    let gpr = |r: usize| (r < GPRS).then_some(r);
    let is_add = word & 0x7fc0_0000 == 0x1100_0000;
    let simd = word & (1 << 26) != 0;
    let size = word >> 30;
    let opc = (word >> 22) & 0b11;
    let (writes, stores) = if is_add {
        (gpr(rt), None)
    } else if simd || (size == 3 && opc == 0b10) {
        // A SIMD&FP register, or `prfm`'s prefetch operation.
        (None, None)
    } else if opc == 0 {
        (None, gpr(rt))
    } else {
        (gpr(rt), None)
    };
    Some(Lo12Form {
        base: gpr(base)?,
        writes,
        stores,
        scale,
    })
}

/// Follows every `adrp` page through the code of one function.
struct PageFlow {
    words: Vec<u32>,
    insns: Vec<Option<Instruction>>,
    vaddr: u64,
}

impl PageFlow {
    fn pc(&self, i: usize) -> u64 {
        self.vaddr + (i * INSN_LEN) as u64
    }

    /// The word index `target` is at, if it is inside this code.
    fn index_of(&self, target: u64) -> Option<usize> {
        let offset = target.checked_sub(self.vaddr)?;
        let i = usize::try_from(offset / INSN_LEN as u64).ok()?;
        (offset % INSN_LEN as u64 == 0 && i < self.words.len()).then_some(i)
    }

    fn describe(&self, origins: &Origins) -> String {
        origins
            .iter()
            .flatten()
            .map(|&i| format!("0x{:x}", self.pc(i)))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Run instruction `i` on `regs`: the registers after it, the
    /// instructions control can go to next, and whether it is an indirect
    /// branch. An instruction that reads a page in a way this module does not
    /// rewrite is an error.
    fn step(&self, i: usize, regs: &Regs) -> Result<(Regs, Vec<usize>, bool)> {
        let word = self.words[i];
        let pc = self.pc(i);
        let Some(insn) = &self.insns[i] else {
            // Not an instruction, so nothing runs past it.
            return Ok((regs.clone(), Vec::new(), false));
        };
        let mut out = regs.clone();
        let refuse = |r: usize, what: &str| {
            anyhow!(
                "0x{word:08x} at 0x{pc:x} {what} x{r}, which holds the page of the adrp at {}; \
                 solder can only follow an adrp page into the :lo12: add, load or store that \
                 completes it",
                self.describe(&regs[r])
            )
        };
        let next = (i + 1 < self.words.len()).then_some(i + 1);

        if Field::AdrpPage.fits(word) {
            out[(word & 31) as usize] = BTreeSet::from([Some(i)]);
            return Ok((out, next.into_iter().collect(), false));
        }

        if let Some(form) = lo12_form(word) {
            if let Some(r) = form.stores.filter(|&r| holds_page(&regs[r])) {
                return Err(refuse(r, "stores"));
            }
            let base = &regs[form.base];
            if holds_page(base) && base.contains(&None) {
                return Err(refuse(
                    form.base,
                    "is reached both with and without a page in",
                ));
            }
            if let Some(r) = form.writes {
                out[r] = BTreeSet::from([None]);
            }
            return Ok((out, next.into_iter().collect(), false));
        }

        // `mov xd, xs` (`orr xd, xzr, xs`): the page, if any, moves with it.
        if let (
            Opcode::ORR,
            [
                Operand::Register(SizeCode::X, d),
                Operand::Register(SizeCode::X, 31),
                Operand::RegShift(ShiftStyle::LSL, 0, SizeCode::X, s),
                _,
            ],
        ) = (insn.opcode, &insn.operands)
        {
            let (d, s) = (*d as usize, *s as usize);
            if d < GPRS {
                out[d] = if s < GPRS {
                    regs[s].clone()
                } else {
                    BTreeSet::from([None])
                };
            }
            return Ok((out, next.into_iter().collect(), false));
        }

        // Every register the instruction names, with whether that operand is
        // one it only writes.
        let mut named = Vec::new();
        for (k, operand) in insn.operands.iter().enumerate() {
            let written = (k == 0 && writes_first_operand(insn.opcode))
                || (k == 1 && writes_second_operand(insn.opcode));
            for r in operand_registers(operand) {
                named.push((r, written));
            }
        }
        for &r in implicit_registers(insn.opcode) {
            named.push((r, false));
        }
        for &(r, _) in &named {
            if !holds_page(&regs[r]) {
                continue;
            }
            // A page is only dropped by an instruction that overwrites its
            // register without looking at it; any other mention uses it.
            if named.iter().any(|&(other, written)| other == r && !written) {
                return Err(refuse(r, "reads"));
            }
        }
        for &(r, written) in &named {
            if written {
                out[r] = BTreeSet::from([None]);
            }
        }

        let branch_target = || {
            insn.operands.iter().find_map(|op| match op {
                Operand::PCOffset(off) => self.index_of(pc.wrapping_add(*off as u64)),
                _ => None,
            })
        };
        use Opcode::*;
        let (succs, indirect) = match insn.opcode {
            // A target outside this code is a tail call.
            B => (branch_target().into_iter().collect(), false),
            Bcc(_) | BCcc(_) | CBZ | CBNZ | TBZ | TBNZ => {
                (next.into_iter().chain(branch_target()).collect(), false)
            }
            BL | BLR | BLRAA | BLRAAZ | BLRAB | BLRABZ => {
                // The call writes the return address. The callee may
                // overwrite the caller-saved registers too, but it need not:
                // GCC's -fipa-ra keeps values in the ones a local callee is
                // known to leave alone, pages included, so a page survives
                // the call until something overwrites it here.
                //
                // Except in x0 and x1, which hold what the callee returns if
                // it returns anything. Whether a page there survived is not
                // knowable from here, so either answer is kept: using it
                // afterwards is then refused rather than paired by a guess.
                for r in [0, 1] {
                    out[r].insert(None);
                }
                out[30] = BTreeSet::from([None]);
                (next.into_iter().collect(), false)
            }
            BR | BRAA | BRAAZ | BRAB | BRABZ => (Vec::new(), true),
            RET | RETAA | RETAB | RETAASPPC | RETABSPPC | RETAASPPCR | RETABSPPCR | ERET
            | ERETAA | ERETAB | DRPS | UDF | BRK | HLT | Invalid => (Vec::new(), false),
            SVC => {
                out[0] = BTreeSet::from([None]);
                (next.into_iter().collect(), false)
            }
            _ => (next.into_iter().collect(), false),
        };
        Ok((out, succs, indirect))
    }
}

/// Pair every `:lo12:` instruction in one function's code with the `adrp`s
/// whose page it completes.
///
/// `bytes` is the function, loaded at `vaddr`. Each `adrp`'s destination
/// register is followed forwards along every path, through branches and
/// loops, until it is overwritten; an `add #imm` or unsigned-offset load or
/// store that takes it as the base is the other half of the pair. A 64-bit
/// `mov` carries the page to its destination, and a call does not end it
/// (see the `BL` arm of `PageFlow::step`).
///
/// Code control never falls or branches into from the entry (a switch case
/// only its jump table reaches, or a local function only ever called) is
/// still followed: it starts from what the function's indirect branches
/// carried, which is where a jump table sends it.
///
/// Anything this cannot account for is an error, not a guess: a page that is
/// stored (spilled to the stack included), compared, truncated, or used any
/// other way than as a `:lo12:` base or `mov` source; a base that holds a
/// page on some paths and not on others, or the pages of two `adrp`s that
/// disagree; and a `:lo12:` offset of 4 KiB or more. A merge that moves the
/// code with such a reference in it would leave it pointing at the wrong
/// address.
pub fn pair_lo12_refs(bytes: &[u8], vaddr: u64) -> Result<Vec<Lo12Ref>> {
    let words: Vec<u32> = bytes
        .chunks_exact(INSN_LEN)
        .map(|c| u32::from_le_bytes(c.try_into().expect("chunks_exact")))
        .collect();
    let flow = PageFlow {
        insns: words.iter().map(|&w| decode(w)).collect(),
        words,
        vaddr,
    };
    let n = flow.words.len();
    let context = |i: usize| {
        format!(
            "pairing adrp pages in code at 0x{vaddr:x}, offset 0x{:x}",
            i * INSN_LEN
        )
    };

    let mut ins: Vec<Option<Regs>> = vec![None; n];
    // What indirect branches carry: the state code reached only through one
    // starts from.
    let mut indirect: Regs = vec![Origins::new(); GPRS];
    let mut roots: Vec<usize> = Vec::new();
    let mut work: Vec<usize> = Vec::new();
    if n > 0 {
        // On entry no register holds a page this function's adrps took.
        ins[0] = Some(vec![BTreeSet::from([None]); GPRS]);
        work.push(0);
    }
    loop {
        while let Some(i) = work.pop() {
            let regs = ins[i].as_ref().expect("queued with a state");
            let (out, succs, is_indirect) = flow.step(i, regs).with_context(|| context(i))?;
            if is_indirect && join(&mut indirect, &out) {
                for &root in &roots {
                    if join(ins[root].as_mut().expect("seeded"), &indirect) {
                        work.push(root);
                    }
                }
            }
            for s in succs {
                match &mut ins[s] {
                    Some(state) => {
                        if join(state, &out) {
                            work.push(s);
                        }
                    }
                    slot @ None => {
                        *slot = Some(out.clone());
                        work.push(s);
                    }
                }
            }
        }
        let Some(root) = (0..n).find(|&i| ins[i].is_none() && flow.insns[i].is_some()) else {
            break;
        };
        roots.push(root);
        ins[root] = Some(indirect.clone());
        work.push(root);
    }

    let mut pairs = Vec::new();
    for (i, regs) in ins.iter().enumerate() {
        let (Some(regs), Some(form)) = (regs, lo12_form(flow.words[i])) else {
            continue;
        };
        if flow.insns[i].is_none() || !holds_page(&regs[form.base]) {
            continue;
        }
        let word = flow.words[i];
        let pc = flow.pc(i);
        let adrps: Vec<usize> = regs[form.base].iter().flatten().copied().collect();
        let pages: BTreeSet<u64> = adrps
            .iter()
            .map(|&a| {
                pc_relative_ref(flow.words[a], flow.pc(a))
                    .ok()
                    .flatten()
                    .expect("an adrp decodes to its page")
                    .target
            })
            .collect();
        if pages.len() > 1 {
            bail!(
                "0x{word:08x} at 0x{pc:x} completes the adrps at {}, which take different pages",
                flow.describe(&regs[form.base])
            );
        }
        let lo12 = u64::from((word >> 10) & 0xfff) << form.scale;
        if lo12 >= ADRP_PAGE {
            bail!(
                "0x{word:08x} at 0x{pc:x} adds 0x{lo12:x} to the page of the adrp at {}, \
                 past the 4 KiB a :lo12: offset can reach",
                flow.describe(&regs[form.base])
            );
        }
        pairs.push(Lo12Ref {
            offset: i * INSN_LEN,
            adrps: adrps.iter().map(|a| a * INSN_LEN).collect(),
            target: pages.first().expect("at least one adrp") + lo12,
        });
    }
    Ok(pairs)
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

    fn code(words: &[u32]) -> Vec<u8> {
        words.iter().copied().flat_map(u32::to_le_bytes).collect()
    }

    /// A program GNU as assembled and `ld -Ttext=0x400000 -Tdata=0x410ff0`
    /// linked, as `objdump -d` shows it. The data symbols are `a` (0x410ff0)
    /// and `a2` (0x410ff8), on one page, `b` (0x413000) and `v` (0x414020).
    const PAIRS: &[u32] = &[
        0x9000_0080, // 0x00  adrp x0, a
        0x913f_c000, // 0x04  add x0, x0, :lo12:a
        0xf000_0081, // 0x08  adrp x1, b
        0xf940_0022, // 0x0c  ldr x2, [x1, :lo12:b]
        0xb940_0823, // 0x10  ldr w3, [x1, :lo12:b+8]
        0x3940_0c24, // 0x14  ldrb w4, [x1, :lo12:b+3]
        0x3d80_0425, // 0x18  str q5, [x1, :lo12:b+16]
        0x9000_00b3, // 0x1c  adrp x19, v
        0xb400_0062, // 0x20  cbz x2, 0x2c
        0x9000_0094, // 0x24  adrp x20, a
        0x1400_0002, // 0x28  b 0x30
        0x9000_0094, // 0x2c  adrp x20, a2
        0x913f_c295, // 0x30  add x21, x20, :lo12:a
        0xb940_2266, // 0x34  ldr w6, [x19, :lo12:v]     <- loop
        0x9400_0008, // 0x38  bl f
        0x1100_04c6, // 0x3c  add w6, w6, #1
        0xb900_2266, // 0x40  str w6, [x19, :lo12:v]
        0xf100_0442, // 0x44  subs x2, x2, #1
        0x54ff_ff61, // 0x48  b.ne 0x34
        0xd280_00a0, // 0x4c  mov x0, #5
        0x9100_2000, // 0x50  add x0, x0, #8
        0xd65f_03c0, // 0x54  ret
        0xf000_0089, // 0x58  f: adrp x9, b
        0xf940_0120, // 0x5c  ldr x0, [x9, :lo12:b]
        0xd65f_03c0, // 0x60  ret
    ];

    fn lo12(offset: usize, adrps: &[usize], target: u64) -> Lo12Ref {
        Lo12Ref {
            offset,
            adrps: adrps.to_vec(),
            target,
        }
    }

    #[test]
    fn every_lo12_half_is_paired_with_the_adrp_the_assembler_meant() {
        let pairs = pair_lo12_refs(&code(PAIRS), BASE).unwrap();
        assert_eq!(
            pairs,
            [
                lo12(0x04, &[0x00], 0x41_0ff0),
                // One page, four access sizes, a store among them.
                lo12(0x0c, &[0x08], 0x41_3000),
                lo12(0x10, &[0x08], 0x41_3008),
                lo12(0x14, &[0x08], 0x41_3003),
                lo12(0x18, &[0x08], 0x41_3010),
                // Two adrps of the same page meet before their add.
                lo12(0x30, &[0x24, 0x2c], 0x41_0ff0),
                // Hoisted out of the loop, and kept in a callee-saved
                // register across the call in it.
                lo12(0x34, &[0x1c], 0x41_4020),
                lo12(0x40, &[0x1c], 0x41_4020),
                // `f` is only reached by the `bl`.
                lo12(0x5c, &[0x58], 0x41_3000),
            ]
        );
        // Neither `add x0, x0, #8` after `mov x0, #5` nor `add w6, w6, #1`
        // is an address, and the `adrp`s' own fields stay with
        // `pc_relative_ref`.
    }

    /// Each pair keeps the address the program was linked with, so moving
    /// both halves and re-encoding them through [`Field::patch`] reproduces
    /// the words the linker wrote.
    #[test]
    fn a_pair_patched_with_its_target_reproduces_both_words() {
        for pair in pair_lo12_refs(&code(PAIRS), BASE).unwrap() {
            let word = PAIRS[pair.offset / INSN_LEN];
            assert_eq!(Field::Lo12.patch(word, pair.target, 0, 0).unwrap(), word);
            for adrp in pair.adrps {
                let word = PAIRS[adrp / INSN_LEN];
                let pc = BASE + adrp as u64;
                assert_eq!(
                    Field::AdrpPage.patch(word, pair.target, 0, pc).unwrap(),
                    word
                );
            }
        }
    }

    fn pairing_error(words: &[u32]) -> String {
        format!("{:#}", pair_lo12_refs(&code(words), BASE).unwrap_err())
    }

    const ADRP_X0: u32 = 0x9000_0080; // adrp x0, 0x410000
    const ADD_X0_LO12: u32 = 0x913f_c000; // add x0, x0, #0xff0
    const RET: u32 = 0xd65f_03c0;

    /// A page that goes anywhere but into a `:lo12:` base would be left
    /// pointing into the old page once the code moves.
    #[test]
    fn a_page_used_any_other_way_is_refused() {
        for (use_, what) in [
            (0x2a00_03e1, "reads"),  // mov w1, w0
            (0x8b02_0001, "reads"),  // add x1, x0, x2
            (0xf100_041f, "reads"),  // cmp x0, #1
            (0xd63f_0000, "reads"),  // blr x0
            (0xf800_8420, "reads"),  // str x0, [x1], #8
            (0xf842_8401, "reads"),  // ldr x1, [x0], #40
            (0xf862_7801, "reads"),  // ldr x1, [x0, x2, lsl #3]
            (0xf900_0020, "stores"), // str x0, [x1]
            (0xf800_0000, "reads"),  // stur x0, [x0]
        ] {
            let err = pairing_error(&[ADRP_X0, use_, RET]);
            assert!(err.contains(&format!("{what} x0")), "{use_:08x}: {err}");
            assert!(err.contains("adrp at 0x400000"), "{use_:08x}: {err}");
        }
    }

    /// Overwriting the register ends the page, which is not a use of it.
    #[test]
    fn a_page_overwritten_unread_is_dropped() {
        for kill in [
            0xd280_00a0, // mov x0, #5
            0xf940_0420, // ldr x0, [x1, #8]
            0xa940_07e0, // ldp x0, x1, [sp]
        ] {
            assert_eq!(
                pair_lo12_refs(&code(&[ADRP_X0, kill, ADD_X0_LO12, RET]), BASE).unwrap(),
                [],
                "{kill:08x}"
            );
        }
    }

    /// GCC's -fipa-ra keeps values in caller-saved registers across a call
    /// to a local function it knows leaves them alone, and a copy carries
    /// the page to another register.
    #[test]
    fn a_page_is_followed_across_a_call_and_a_copy() {
        let pairs = pair_lo12_refs(
            &code(&[
                0x9000_008e, // adrp x14, 0x410000
                0x9400_0000, // bl .
                0xaa0e_03e1, // mov x1, x14
                0x913f_c025, // add x5, x1, #0xff0
                RET,
            ]),
            BASE,
        )
        .unwrap();
        assert_eq!(pairs, [lo12(0x0c, &[0x00], 0x41_0ff0)]);
    }

    /// A page left in x0 before a call may have been replaced by the return
    /// value: the load after it could be through either.
    #[test]
    fn a_page_in_a_return_register_across_a_call_is_refused() {
        let err = pairing_error(&[
            ADRP_X0,     // adrp x0, 0x410000
            0x9400_0000, // bl .
            0xf940_0402, // ldr x2, [x0, #8]
            RET,
        ]);
        assert!(err.contains("both with and without a page in x0"), "{err}");
    }

    /// `add` takes the page in x0 down one path and another value down the
    /// other: whichever it rewrites, one path ends up wrong.
    #[test]
    fn a_base_with_a_page_on_only_some_paths_is_refused() {
        let err = pairing_error(&[
            0xb400_0042, // cbz x2, 0x400008
            ADRP_X0,     // adrp x0, 0x410000
            ADD_X0_LO12, // add x0, x0, #0xff0
            RET,
        ]);
        assert!(err.contains("both with and without a page"), "{err}");
    }

    #[test]
    fn adrps_of_different_pages_meeting_at_one_lo12_are_refused() {
        let err = pairing_error(&[
            0xb400_0062, // cbz x2, 0x40000c
            ADRP_X0,     // adrp x0, 0x410000
            0x1400_0002, // b 0x400010
            0xf000_0080, // adrp x0, 0x413000
            ADD_X0_LO12, // add x0, x0, #0xff0
            RET,
        ]);
        assert!(err.contains("different pages"), "{err}");
    }

    /// `ldr x1, [x0, #0x1000]` reaches past the page: no linker writes that
    /// for a `:lo12:`.
    #[test]
    fn an_offset_past_the_page_is_refused() {
        let err = pairing_error(&[ADRP_X0, 0xf948_0001, RET]);
        assert!(err.contains("past the 4 KiB"), "{err}");
    }

    /// A switch: the page is taken before the `br`, and used in a case only
    /// the jump table reaches.
    #[test]
    fn a_page_is_followed_through_an_indirect_branch() {
        let pairs = pair_lo12_refs(
            &code(&[
                0x9000_00b3, // adrp x19, 0x414000
                0xd61f_0020, // br x1
                0xb940_2266, // ldr w6, [x19, #32]
                RET,
                0xd280_0013, // mov x19, #0
                0xb940_2266, // ldr w6, [x19, #32]
                RET,
            ]),
            BASE,
        )
        .unwrap();
        // The second case overwrote x19 before its load.
        assert_eq!(pairs, [lo12(0x08, &[0x00], 0x41_4020)]);
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
