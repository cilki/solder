//! aarch64: its descriptor, the instruction forms that carry an address, and
//! how to rewrite one when the code or its target moves (#97, stage 3).
//!
//! An x86-64 reference is a little-endian rel8/rel32 displacement at the tail
//! of the instruction, which a [`Word`](super::Word) overwrites whole. An
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
//! Calls into a library's PLT, and the trampolines the merge puts in their
//! place, are `adrp`/`ldr`/`br` sequences through a GOT slot:
//! [`plt_stub_slot`] reads the slot out of a stub, and [`trampoline`] writes
//! one. [`ends_the_function`] checks the claim unwind info makes about where
//! a function stops.
//!
//! The decoder is `yaxpeax-arm`. It says which instruction a word is and
//! where its PC-relative operand points; this module adds what the decoder
//! does not, which is where in the word that operand is kept.
//!
//! The extractor reads an aarch64 library's references and PLT stubs through
//! [`AARCH64`]'s [`MachineCode`], the relocator writes their [`InsnField`]s
//! through [`Site::Aarch64`](super::Site::Aarch64), and the writer emits its
//! trampolines through the descriptor.
//! `arch::SUPPORTED` still refuses aarch64 executables.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, bail};

use super::{
    Arch, CodeRef, DynRelocTypes, GnuProperties, MachineCode, Reach, RefSite, TextUnit, TlsAbi,
    TlsLayout, TlsSlot, Trampoline, UnitScan, Unliftable,
};
use crate::types::ExtractedReloc;
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

/// An address kept in an aarch64 instruction word, and what has to agree with
/// it once it is rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsnField {
    /// Which bits of the word carry the address.
    pub field: Field,
    /// For a `:lo12:` half, the unit offsets of the `adrp`s whose page it
    /// completes. The `:lo12:` bits only say where in a page the target is;
    /// [`InsnField::check_placed`] checks that each of these `adrp`s was
    /// pointed at the target's page, since one `adrp` is often shared by
    /// several objects and the merge need not keep them on one page. Empty
    /// for every other field.
    pub adrps: Vec<u64>,
}

impl InsnField {
    /// Rewrite the address the instruction word at `offset` of `bytes` keeps
    /// to reach `S + A` from `P`, leaving the rest of the word alone.
    pub fn write(&self, bytes: &mut [u8], offset: usize, s: u64, a: i64, p: u64) -> Result<()> {
        let unit_len = bytes.len();
        let site = offset
            .checked_add(INSN_LEN)
            .and_then(|end| bytes.get_mut(offset..end))
            .with_context(|| {
                format!("instruction at offset {offset} overflows unit of size {unit_len}")
            })?;
        let word = u32::from_le_bytes(site.try_into().expect("one word"));
        site.copy_from_slice(&self.field.patch(word, s, a, p)?.to_le_bytes());
        Ok(())
    }

    /// Check that each `adrp` this `:lo12:` half completes, in the unit at
    /// `base` whose bytes are `bytes`, now takes the page of `target`, which
    /// the instruction at `offset` was written to reach.
    ///
    /// The `:lo12:` bits were written from `target` and are right on their
    /// own; what can be wrong is the page. One `adrp` serves every object its
    /// function reaches in one 4 KiB page, but its relocation can only aim it
    /// at one of them, and the merge is free to put the others somewhere else.
    /// Patching on would make the instruction read or write the right offset
    /// in the wrong page.
    pub fn check_placed(&self, bytes: &[u8], base: u64, offset: usize, target: u64) -> Result<()> {
        let want = target & !(ADRP_PAGE - 1);
        for &adrp in &self.adrps {
            let at = adrp as usize;
            let word = bytes
                .get(at..at + INSN_LEN)
                .map(|w| u32::from_le_bytes(w.try_into().expect("one word")))
                .with_context(|| {
                    format!("adrp at offset {at} overflows unit of size {}", bytes.len())
                })?;
            let page = pc_relative_ref(word, base + adrp)?
                .filter(|r| r.field == Field::AdrpPage)
                .with_context(|| format!("0x{word:08x} at offset 0x{at:x} is not an adrp"))?
                .target;
            if page != want {
                bail!(
                    "the instruction at offset 0x{offset:x} reaches 0x{target:x}, but the adrp \
                     at offset 0x{at:x} that supplies its page takes page 0x{page:x}: the merge \
                     placed objects that share one adrp in different pages"
                );
            }
        }
        Ok(())
    }
}

/// `b .`, the unconditional branch a short-range branch is sent through once
/// its own field may not reach (see [`is_short_branch`]). Its `imm26` is left
/// zero for the relocator to fill in.
pub const VENEER: u32 = 0x1400_0000;

/// Whether `word` is a branch that reaches less far than `b`: `b.cond` and
/// `bc.cond`, `cbz`/`cbnz` (`imm19`, ±1 MiB) or `tbz`/`tbnz` (`imm14`,
/// ±32 KiB). The load-literal forms share `imm19` but are not branches, so no
/// `b` can stand in for them.
pub fn is_short_branch(word: u32) -> bool {
    let load_literal = word & 0x3b00_0000 == 0x1800_0000;
    Field::Imm14.fits(word) || Field::Imm19.fits(word) && !load_literal
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

/// Where `sp` or a frame pointer in `x29` points, as a byte offset from the
/// `sp` the function was entered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// No path has reached here yet.
    Unreached,
    /// The same offset on every path.
    At(i64),
    /// Moved by an amount not followed, or by different amounts on different
    /// paths.
    Unknown,
}

impl Frame {
    fn known(self) -> Option<i64> {
        match self {
            Frame::At(at) => Some(at),
            _ => None,
        }
    }

    /// Join `from` into `self`, reporting whether `self` changed.
    fn join(&mut self, from: Frame) -> bool {
        let joined = match (*self, from) {
            (Frame::Unreached, other) | (other, Frame::Unreached) => other,
            (Frame::At(a), Frame::At(b)) if a == b => Frame::At(a),
            _ => Frame::Unknown,
        };
        let changed = joined != *self;
        *self = joined;
        changed
    }
}

/// What [`PageFlow::step`] knows before an instruction: which registers may
/// hold a page, and which eight-byte stack slots a page was spilled to.
#[derive(Debug, Clone)]
struct PageState {
    /// Whether any path has reached here. The state that indirect branches
    /// carry starts out unreached.
    reached: bool,
    regs: Regs,
    /// `sp`, which the function is entered with at offset 0.
    sp: Frame,
    /// `x29`, once the function makes it a frame pointer by setting it from
    /// `sp`.
    fp: Frame,
    /// The slots that may hold a page, by the offset of their first byte
    /// from the entry `sp`. A slot not in here holds no page on any path.
    slots: BTreeMap<i64, Origins>,
}

impl PageState {
    fn entry() -> PageState {
        PageState {
            reached: true,
            regs: vec![BTreeSet::from([None]); GPRS],
            sp: Frame::At(0),
            fp: Frame::Unknown,
            slots: BTreeMap::new(),
        }
    }

    fn unreached() -> PageState {
        PageState {
            reached: false,
            regs: vec![Origins::new(); GPRS],
            sp: Frame::Unreached,
            fp: Frame::Unreached,
            slots: BTreeMap::new(),
        }
    }

    /// Join `from` into `self`, reporting whether `self` grew.
    fn join(&mut self, from: &PageState) -> bool {
        if !from.reached {
            return false;
        }
        if !self.reached {
            *self = from.clone();
            return true;
        }
        let mut grew = join(&mut self.regs, &from.regs);
        grew |= self.sp.join(from.sp);
        grew |= self.fp.join(from.fp);
        // A slot one side has no page in holds something else there.
        let keys: BTreeSet<i64> = self
            .slots
            .keys()
            .chain(from.slots.keys())
            .copied()
            .collect();
        for key in keys {
            let slot = self
                .slots
                .entry(key)
                .or_insert_with(|| BTreeSet::from([None]));
            let before = slot.len();
            match from.slots.get(&key) {
                Some(origins) => slot.extend(origins.iter().copied()),
                None => {
                    slot.insert(None);
                }
            }
            grew |= slot.len() != before;
        }
        grew
    }

    /// Every page any slot may hold, and `None`: what a load from a slot
    /// that cannot be placed may bring back.
    fn any_slot(&self) -> Origins {
        let mut any: Origins = self.slots.values().flatten().copied().collect();
        any.insert(None);
        any
    }

    /// The slot facts once something may have overwritten any of them: each
    /// may still hold its page, or may not, so a reload of one is refused if
    /// it is used as a page.
    fn clobber_slots(&mut self) {
        for slot in self.slots.values_mut() {
            slot.insert(None);
        }
    }

    /// Move `sp` to `to`. The slots it leaves behind, below it, are free for
    /// any callee or signal handler to reuse.
    fn set_sp(&mut self, to: Frame) {
        if let Frame::At(at) = to {
            self.slots.retain(|&slot, _| slot >= at);
        }
        self.sp = to;
    }
}

/// A load or store whose address is a base register plus an immediate: the
/// forms through which code spills a register to the stack and reloads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ImmAccess {
    load: bool,
    /// The base register; 31 is `sp`.
    base: usize,
    /// Where the access starts, from the base before any writeback.
    offset: i64,
    /// How far writeback moves the base, if the form has it.
    writeback: Option<i64>,
    /// The registers transferred, in the order they occupy memory, each
    /// `len` bytes; register 31 is `xzr`/`wzr` in a general-purpose access.
    regs: Vec<usize>,
    len: i64,
    /// Whether `regs` are general-purpose registers rather than SIMD&FP ones.
    gpr: bool,
}

/// The [`ImmAccess`] `word` makes, if it is a single or pair load or store
/// with an immediate offset. Prefetches, which touch nothing, are an access
/// of no registers.
fn imm_access(word: u32) -> Option<ImmAccess> {
    let field = |lo: u32, bits: u32| (word >> lo) & ((1 << bits) - 1);
    let signed = |lo: u32, bits: u32| i64::from(((word << (32 - lo - bits)) as i32) >> (32 - bits));
    let rt = field(0, 5) as usize;
    let base = field(5, 5) as usize;
    let simd = word & (1 << 26) != 0;

    // Single register: the unsigned-offset form, and the unscaled, post-,
    // unprivileged and pre-indexed ones with a signed nine-bit offset.
    let unsigned = word & 0x3b00_0000 == 0x3900_0000;
    let imm9 = word & 0x3b20_0000 == 0x3800_0000;
    if unsigned || imm9 {
        let size = field(30, 2);
        let opc = field(22, 2);
        let scale = if simd && size == 0 && opc & 0b10 != 0 {
            4
        } else {
            size
        };
        if simd && scale == size && opc & 0b10 != 0 {
            // No SIMD&FP access other than the 128-bit one sets opc<1>.
            return None;
        }
        let len = 1i64 << scale;
        let load = if simd { opc & 1 != 0 } else { opc != 0 };
        let prfm = !simd && size == 3 && opc == 0b10;
        let (offset, writeback) = if unsigned {
            (i64::from(field(10, 12)) << scale, None)
        } else {
            let imm = signed(12, 9);
            match field(10, 2) {
                0b01 => (0, Some(imm)),
                0b11 => (imm, Some(imm)),
                _ => (imm, None),
            }
        };
        return Some(ImmAccess {
            load,
            base,
            offset,
            writeback,
            regs: if prfm { Vec::new() } else { vec![rt] },
            len,
            gpr: !simd,
        });
    }

    // Register pair, with a signed seven-bit offset scaled by the size.
    if word & 0x3a00_0000 == 0x2800_0000 {
        let opc = field(30, 2);
        let load = word & (1 << 22) != 0;
        let len = match (simd, opc) {
            (false, 0b00) => 4,
            // ldpsw; with L clear it is stgp, which stores allocation tags.
            (false, 0b01) if load => 4,
            (false, 0b10) => 8,
            (true, 0b00) => 4,
            (true, 0b01) => 8,
            (true, 0b10) => 16,
            _ => return None,
        };
        let imm = signed(15, 7) * len;
        let (offset, writeback) = match field(23, 2) {
            0b01 => (0, Some(imm)),
            0b11 => (imm, Some(imm)),
            _ => (imm, None),
        };
        return Some(ImmAccess {
            load,
            base,
            offset,
            writeback,
            regs: vec![rt, field(10, 5) as usize],
            len,
            gpr: !simd,
        });
    }
    None
}

/// The `add`/`sub xd, xn, #imm` that `word` is, as `(d, n, imm)` with `imm`
/// negative for a `sub`. Register 31 is `sp` in either place.
fn add_sub_imm(word: u32) -> Option<(usize, usize, i64)> {
    let sub = match word & 0xff80_0000 {
        0x9100_0000 => false,
        0xd100_0000 => true,
        _ => return None,
    };
    let imm = i64::from((word >> 10) & 0xfff) << if word & (1 << 22) != 0 { 12 } else { 0 };
    Some((
        (word & 31) as usize,
        ((word >> 5) & 31) as usize,
        if sub { -imm } else { imm },
    ))
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

/// How many bytes the `:lo12:` instruction `word` reads or writes at the
/// address its pair forms: the access size of a load or store, and `None` for
/// an `add`, which only takes the address, and for a `prfm`, which touches
/// nothing. The aarch64 counterpart of `extractor::rip_access_len`.
pub fn lo12_access_len(word: u32) -> Option<u64> {
    let is_add = is_lo12_add(word);
    let is_prfm = word & (1 << 26) == 0 && word >> 30 == 3 && (word >> 22) & 0b11 == 0b10;
    if is_add || is_prfm {
        return None;
    }
    lo12_scale(word).map(|scale| 1 << scale)
}

/// Whether `word` is an `add xd, xn, #imm12` (32- or 64-bit, unshifted): the
/// `:lo12:` form that takes an address rather than accessing it.
fn is_lo12_add(word: u32) -> bool {
    word & 0x7fc0_0000 == 0x1100_0000
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
    /// The function `bytes`, loaded at `vaddr`, decoded a word at a time. A
    /// trailing partial word is not code.
    fn new(bytes: &[u8], vaddr: u64) -> PageFlow {
        let words: Vec<u32> = bytes
            .chunks_exact(INSN_LEN)
            .map(|c| u32::from_le_bytes(c.try_into().expect("chunks_exact")))
            .collect();
        PageFlow {
            insns: words.iter().map(|&w| decode(w)).collect(),
            words,
            vaddr,
        }
    }

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

    /// Where control can go after instruction `i`, and whether it leaves
    /// through an indirect branch. A word that is not an instruction goes
    /// nowhere, and a branch target outside this code is a tail call.
    fn successors(&self, i: usize) -> (Vec<usize>, bool) {
        let Some(insn) = &self.insns[i] else {
            return (Vec::new(), false);
        };
        let pc = self.pc(i);
        let next = (i + 1 < self.words.len()).then_some(i + 1);
        let branch_target = || {
            insn.operands.iter().find_map(|op| match op {
                Operand::PCOffset(off) => self.index_of(pc.wrapping_add(*off as u64)),
                _ => None,
            })
        };
        use Opcode::*;
        match insn.opcode {
            B => (branch_target().into_iter().collect(), false),
            Bcc(_) | BCcc(_) | CBZ | CBNZ | TBZ | TBNZ => {
                (next.into_iter().chain(branch_target()).collect(), false)
            }
            BR | BRAA | BRAAZ | BRAB | BRABZ => (Vec::new(), true),
            RET | RETAA | RETAB | RETAASPPC | RETABSPPC | RETAASPPCR | RETABSPPCR | ERET
            | ERETAA | ERETAB | DRPS | UDF | BRK | HLT | Invalid => (Vec::new(), false),
            _ => (next.into_iter().collect(), false),
        }
    }

    /// Run a forward dataflow over the code: `entry` is the state on entry,
    /// `empty` the state no path has reached yet, `step` runs one instruction
    /// on the state before it, and `join` merges a state into the one already
    /// at word `at` (`None` for what indirect branches carry), reporting
    /// whether it grew. Returns the state before each word, `None` for a word
    /// nothing reaches.
    ///
    /// Code control never falls or branches into from the entry (a switch case
    /// only its jump table reaches, or a local function only ever called) is
    /// still followed: it starts from what the function's indirect branches
    /// carried, which is where a jump table sends it.
    fn solve<S: Clone>(
        &self,
        entry: S,
        empty: S,
        mut step: impl FnMut(usize, &S) -> Result<S>,
        mut join: impl FnMut(Option<usize>, &mut S, &S) -> bool,
    ) -> Result<Vec<Option<S>>> {
        let n = self.words.len();
        let mut ins: Vec<Option<S>> = vec![None; n];
        let mut indirect = empty;
        let mut roots: Vec<usize> = Vec::new();
        let mut work: Vec<usize> = Vec::new();
        if n > 0 {
            ins[0] = Some(entry);
            work.push(0);
        }
        loop {
            while let Some(i) = work.pop() {
                let out = step(i, ins[i].as_ref().expect("queued with a state"))?;
                let (succs, is_indirect) = self.successors(i);
                if is_indirect && join(None, &mut indirect, &out) {
                    for &root in &roots {
                        if join(Some(root), ins[root].as_mut().expect("seeded"), &indirect) {
                            work.push(root);
                        }
                    }
                }
                for s in succs {
                    match &mut ins[s] {
                        Some(state) => {
                            if join(Some(s), state, &out) {
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
            let Some(root) = (0..n).find(|&i| ins[i].is_none() && self.insns[i].is_some()) else {
                break;
            };
            roots.push(root);
            ins[root] = Some(indirect.clone());
            work.push(root);
        }
        Ok(ins)
    }

    /// Run instruction `i` on `state`: the state after it. An instruction
    /// that uses a page in a way this module does not rewrite is an error.
    fn step(&self, i: usize, state: &PageState) -> Result<PageState> {
        let mut out = state.clone();
        out.reached = true;
        let Some(insn) = &self.insns[i] else {
            // Not an instruction, so nothing runs past it.
            return Ok(out);
        };
        let word = self.words[i];
        if let Some(access) = imm_access(word) {
            let frame = match access.base {
                31 => Some(state.sp),
                29 if state.fp != Frame::Unknown => Some(state.fp),
                _ => None,
            };
            if let Some(frame) = frame {
                self.frame_access(i, &access, frame.known(), state, &mut out)?;
                if access.load && access.regs.contains(&29) && access.gpr {
                    out.fp = Frame::Unknown;
                }
                return Ok(out);
            }
        }
        out.regs = self.step_regs(i, insn, &state.regs)?;
        self.track_frame(insn, word, state, &mut out);
        Ok(out)
    }

    /// Run the load or store `access` at word `i`, whose base is `sp` or the
    /// frame pointer, at `frame` from the entry `sp` if known, writing what
    /// it changes into `out`.
    ///
    /// A 64-bit store of a page-holding register puts the page in the slot,
    /// and a 64-bit load of exactly that slot takes it back out. Anything
    /// else that touches the slot is refused while it may hold a page, and a
    /// store overwrites it. A slot that cannot be placed because the base
    /// has moved by an amount not followed may be any of them: storing a page
    /// there is refused, storing anything else may overwrite each of them,
    /// and loading from there may bring back any of them.
    fn frame_access(
        &self,
        i: usize,
        access: &ImmAccess,
        frame: Option<i64>,
        state: &PageState,
        out: &mut PageState,
    ) -> Result<()> {
        let word = self.words[i];
        let pc = self.pc(i);
        let base = if access.base == 31 {
            "sp".to_string()
        } else {
            format!("x{}", access.base)
        };
        let page_in = |r: usize| access.gpr && r < GPRS && holds_page(&state.regs[r]);
        let Some(frame) = frame else {
            if access.load {
                for &r in access.regs.iter().filter(|&&r| access.gpr && r < GPRS) {
                    out.regs[r] = if state.slots.is_empty() {
                        BTreeSet::from([None])
                    } else {
                        state.any_slot()
                    };
                }
            } else if let Some(&r) = access.regs.iter().find(|&&r| page_in(r)) {
                bail!(
                    "0x{word:08x} at 0x{pc:x} stores x{r}, which holds the page of the adrp at \
                     {}, to the stack through {base}, which has moved by an amount solder does \
                     not follow",
                    self.describe(&state.regs[r])
                );
            } else {
                out.clobber_slots();
            }
            return Ok(());
        };

        let start = frame + access.offset;
        for (k, &r) in access.regs.iter().enumerate() {
            let at = start + k as i64 * access.len;
            let overlapping: Vec<i64> = state
                .slots
                .range(at - 7..at + access.len)
                .map(|(&slot, _)| slot)
                .collect();
            if access.load {
                let value = match overlapping[..] {
                    [] => BTreeSet::from([None]),
                    [slot] if slot == at && access.len == 8 && access.gpr => {
                        state.slots[&slot].clone()
                    }
                    [slot, ..] => bail!(
                        "0x{word:08x} at 0x{pc:x} loads from the stack slot at {base}{:+}, which \
                         holds the page of the adrp at {}, other than as the whole 64-bit page; \
                         solder can only follow a page reloaded into the register it was \
                         spilled from",
                        slot - frame,
                        self.describe(&state.slots[&slot])
                    ),
                };
                if access.gpr && r < GPRS {
                    out.regs[r] = value;
                }
            } else {
                for slot in overlapping {
                    out.slots.remove(&slot);
                }
                if page_in(r) {
                    if access.len != 8 {
                        return Err(self.refuse(i, &state.regs, r, "stores part of"));
                    }
                    out.slots.insert(at, state.regs[r].clone());
                }
            }
        }

        if let Some(by) = access.writeback {
            let moved = Frame::At(frame + by);
            if access.base == 31 {
                out.set_sp(moved);
            } else {
                out.fp = moved;
            }
        }
        Ok(())
    }

    /// Follow what instruction `insn` (word `word`), which is not a load or
    /// store [`PageFlow::frame_access`] ran, does to `sp`, the frame pointer
    /// and the stack slots, from `state` into `out`.
    fn track_frame(&self, insn: &Instruction, word: u32, state: &PageState, out: &mut PageState) {
        let frame_of = |r: usize| match r {
            31 => state.sp,
            29 => state.fp,
            _ => Frame::Unknown,
        };
        let add_sub = add_sub_imm(word);
        // `add`/`sub` of an immediate to `sp` or the frame pointer, and the
        // `mov`s between the two, which are `add #0`.
        let moved = |n: usize, by: i64| match frame_of(n) {
            Frame::At(at) => Frame::At(at + by),
            Frame::Unreached => Frame::Unreached,
            Frame::Unknown => Frame::Unknown,
        };
        let writes = |r: usize| {
            insn.operands.iter().enumerate().any(|(k, operand)| {
                let written = (k == 0 && writes_first_operand(insn.opcode))
                    || (k == 1 && writes_second_operand(insn.opcode));
                match *operand {
                    Operand::RegPreIndex(b, _, true)
                    | Operand::RegPostIndex(b, _)
                    | Operand::RegPostIndexReg(b, _) => b as usize == r,
                    // Register 31 is `sp` only where the operand says so,
                    // and `xzr` everywhere else.
                    Operand::RegisterOrSP(_, d) => written && d as usize == r,
                    Operand::Register(_, d) => written && r < GPRS && d as usize == r,
                    Operand::RegisterPair(_, d) => {
                        written && (d as usize == r || d as usize + 1 == r)
                    }
                    _ => false,
                }
            })
        };

        match add_sub {
            Some((31, n, by)) => out.set_sp(moved(n, by)),
            Some((29, n @ (29 | 31), by)) => out.fp = moved(n, by),
            _ => {
                if writes(31) {
                    out.set_sp(Frame::Unknown);
                }
                if writes(29) {
                    out.fp = Frame::Unknown;
                }
            }
        }

        // A load or store through `sp` or the frame pointer in some other
        // form, with a register index, an atomic, an exclusive: a store may
        // land on any slot. Compilers spill and reload through the immediate
        // forms only, so a load this way is not a reload.
        let through_frame = insn.operands.iter().any(|operand| match *operand {
            Operand::RegPreIndex(b, ..)
            | Operand::RegPostIndex(b, _)
            | Operand::RegRegOffset(b, ..)
            | Operand::RegPostIndexReg(b, _) => b == 31 || (b == 29 && state.fp != Frame::Unknown),
            _ => false,
        });
        let plain_load = writes_first_operand(insn.opcode)
            && !matches!(
                insn.opcode,
                Opcode::STXR
                    | Opcode::STXRB
                    | Opcode::STXRH
                    | Opcode::STLXR
                    | Opcode::STLXRB
                    | Opcode::STLXRH
                    | Opcode::STXP
                    | Opcode::STLXP
            );
        if through_frame && !plain_load {
            out.clobber_slots();
        }
    }

    /// The error for instruction `i` using `r`, which holds a page in `regs`,
    /// in a way only described by `what`.
    fn refuse(&self, i: usize, regs: &Regs, r: usize, what: &str) -> anyhow::Error {
        anyhow!(
            "0x{:08x} at 0x{:x} {what} x{r}, which holds the page of the adrp at {}; solder can \
             only follow an adrp page into the :lo12: add, load or store that completes it, or \
             into a stack slot and back",
            self.words[i],
            self.pc(i),
            self.describe(&regs[r])
        )
    }

    /// Run instruction `insn`, word `i`, on `regs`: the registers after it.
    /// An instruction that reads a page in a way this module does not rewrite
    /// is an error.
    fn step_regs(&self, i: usize, insn: &Instruction, regs: &Regs) -> Result<Regs> {
        let word = self.words[i];
        let mut out = regs.clone();
        let refuse = |r: usize, what: &str| self.refuse(i, regs, r, what);

        if Field::AdrpPage.fits(word) {
            out[(word & 31) as usize] = BTreeSet::from([Some(i)]);
            return Ok(out);
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
            return Ok(out);
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
            return Ok(out);
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

        if is_call(insn.opcode) {
            // The call writes the return address. The callee may overwrite
            // the caller-saved registers too, but it need not: GCC's -fipa-ra
            // keeps values in the ones a local callee is known to leave
            // alone, pages included, so a page survives the call until
            // something overwrites it here.
            //
            // Except in x0 and x1, which hold what the callee returns if it
            // returns anything. Whether a page there survived is not knowable
            // from here, so either answer is kept: using it afterwards is
            // then refused rather than paired by a guess.
            for r in [0, 1] {
                out[r].insert(None);
            }
            out[30] = BTreeSet::from([None]);
        } else if insn.opcode == Opcode::SVC {
            out[0] = BTreeSet::from([None]);
        }
        Ok(out)
    }
}

impl PageFlow {
    /// Run instruction `i` on `regs` for [`address_reaches`]: the registers
    /// after it, with each use it makes of a formed address added to `uses`.
    fn address_step(
        &self,
        i: usize,
        regs: &AddrRegs,
        formers: &BTreeSet<usize>,
        uses: &mut BTreeSet<Use>,
    ) -> AddrRegs {
        let word = self.words[i];
        let Some(insn) = &self.insns[i] else {
            return regs.clone();
        };
        let mut out = regs.clone();
        let addrs = |r: usize| regs[r].iter().flatten().copied().collect::<Vec<_>>();
        let moved = |r: usize, by: i64| -> AddrOrigins {
            if r >= GPRS {
                return BTreeSet::from([None]);
            }
            regs[r]
                .iter()
                .map(|o| o.map(|(a, off)| (a, off.wrapping_add(by))))
                .collect()
        };

        // An `adr` or `:lo12:` `add` puts its address in its destination.
        if formers.contains(&i) {
            let rd = (word & 31) as usize;
            if rd < GPRS {
                out[rd] = BTreeSet::from([Some((i, 0))]);
            }
            return out;
        }

        // `add`/`sub xd, xn, #imm`: the address moves on, offset adjusted.
        if let (
            op @ (Opcode::ADD | Opcode::SUB),
            [
                Operand::RegisterOrSP(SizeCode::X, d),
                Operand::RegisterOrSP(SizeCode::X, n),
                imm @ (Operand::Immediate(_) | Operand::ImmShift(..)),
                Operand::Nothing,
            ],
        ) = (insn.opcode, &insn.operands)
        {
            let imm = match *imm {
                Operand::Immediate(v) => i64::from(v),
                Operand::ImmShift(v, shift) => i64::from(v) << shift,
                _ => unreachable!("matched above"),
            };
            if (*d as usize) < GPRS {
                out[*d as usize] = moved(*n as usize, if op == Opcode::SUB { -imm } else { imm });
            }
            return out;
        }

        // `mov xd, xs` (`orr xd, xzr, xs`).
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
            if (*d as usize) < GPRS {
                out[*d as usize] = moved(*s as usize, 0);
            }
            return out;
        }

        // A load or store's access size, where its encoding gives one.
        let access_len = lo12_scale(word)
            .filter(|_| word & 0x3b00_0000 == 0x3900_0000)
            .map(|scale| 1u64 << scale);
        let mut written = Vec::new();
        let mut writeback = Vec::new();
        for (k, operand) in insn.operands.iter().enumerate() {
            match *operand {
                Operand::RegPreIndex(r, imm, wb) => {
                    let r = r as usize;
                    if r < GPRS {
                        for (a, off) in addrs(r) {
                            uses.insert((a, off.wrapping_add(imm.into()), access_len));
                        }
                        if wb {
                            writeback.push((r, i64::from(imm)));
                        }
                    }
                }
                Operand::RegPostIndex(r, imm) => {
                    let r = r as usize;
                    if r < GPRS {
                        for (a, off) in addrs(r) {
                            uses.insert((a, off, access_len));
                        }
                        writeback.push((r, i64::from(imm)));
                    }
                }
                _ => {
                    let writes = (k == 0 && writes_first_operand(insn.opcode))
                        || (k == 1 && writes_second_operand(insn.opcode));
                    for r in operand_registers(operand) {
                        if writes {
                            written.push(r);
                        } else {
                            for (a, off) in addrs(r) {
                                uses.insert((a, off, None));
                            }
                        }
                    }
                    if let Operand::RegPostIndexReg(base, _) = *operand {
                        written.push(base as usize);
                    }
                }
            }
        }
        for &r in implicit_registers(insn.opcode) {
            for (a, off) in addrs(r) {
                uses.insert((a, off, None));
            }
        }
        for (r, by) in writeback {
            out[r] = moved(r, by);
        }
        for r in written.into_iter().filter(|&r| r < GPRS) {
            out[r] = BTreeSet::from([None]);
        }
        if is_call(insn.opcode) {
            // As in `step`: a value may survive a call, except in the
            // registers it returns in and the link register.
            for r in [0, 1] {
                out[r].insert(None);
            }
            out[30] = BTreeSet::from([None]);
        } else if insn.opcode == Opcode::SVC {
            out[0] = BTreeSet::from([None]);
        }
        out
    }
}

/// Whether `opcode` is a call: a branch that writes the return address.
fn is_call(opcode: Opcode) -> bool {
    use Opcode::*;
    matches!(opcode, BL | BLR | BLRAA | BLRAAZ | BLRAB | BLRABZ)
}

/// Pair every `:lo12:` instruction in one function's code with the `adrp`s
/// whose page it completes.
///
/// `bytes` is the function, loaded at `vaddr`. Each `adrp`'s destination
/// register is followed forwards along every path, through branches and
/// loops, until it is overwritten; an `add #imm` or unsigned-offset load or
/// store that takes it as the base is the other half of the pair. A 64-bit
/// `mov` carries the page to its destination, and a call does not end it
/// (see the call in `PageFlow::step_regs`). Code only a jump table reaches is
/// followed too; see `PageFlow::solve`.
///
/// A page GCC spills to the stack under register pressure is followed there
/// and back. `sp`, and `x29` once it is set from `sp`, are tracked as
/// offsets from the `sp` the function was entered with, so a 64-bit store
/// of a page through either with an immediate offset (`str`, `stur`, `stp`,
/// writeback included) puts it in a slot, and a 64-bit load of that slot
/// takes it back out; see `PageFlow::frame_access`. A callee, or a store
/// through any other pointer, is taken to leave the slot alone: a spill
/// slot is not an object the program can name.
///
/// Anything this cannot account for is an error, not a guess: a page that is
/// stored anywhere but such a slot, compared, truncated, or used any other
/// way than as a `:lo12:` base or `mov` source; a slot read other than as
/// the whole page, or that cannot be told apart from its neighbours because
/// `sp` moved by a register; a base that holds a page on some paths and not
/// on others, or the pages of two `adrp`s that disagree; and a `:lo12:`
/// offset of 4 KiB or more. A merge that moves the code with such a
/// reference in it would leave it pointing at the wrong address.
pub fn pair_lo12_refs(bytes: &[u8], vaddr: u64) -> Result<Vec<Lo12Ref>> {
    let flow = PageFlow::new(bytes, vaddr);
    let context = |i: usize| {
        format!(
            "pairing adrp pages in code at 0x{vaddr:x}, offset 0x{:x}",
            i * INSN_LEN
        )
    };

    // On entry no register holds a page this function's adrps took.
    let ins = flow.solve(
        PageState::entry(),
        PageState::unreached(),
        |i, state| flow.step(i, state).with_context(|| context(i)),
        |_, into, from| into.join(from),
    )?;

    let mut pairs = Vec::new();
    for (i, state) in ins.iter().enumerate() {
        let (Some(PageState { regs, .. }), Some(form)) = (state, lo12_form(flow.words[i])) else {
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

/// Where an address one of the function's own instructions formed may be in
/// one register, over every path that reaches an instruction: `Some((i,
/// off))` is the address the instruction at word `i` formed plus `off`,
/// `None` anything else. Empty means no path has reached it yet.
type AddrOrigins = BTreeSet<Option<(usize, i64)>>;
type AddrRegs = Vec<AddrOrigins>;

/// How many addresses one register may hold where paths meet before its
/// offsets stop being followed there. A pointer stepped through a loop takes
/// a new offset on every trip round it, so without a bound the offsets would
/// never stop growing.
const MAX_ADDRS: usize = 8;

/// One use of a formed address: the instruction that formed it (by word),
/// the constant added to it, and how many bytes were accessed there.
type Use = (usize, i64, Option<u64>);

/// Follow the addresses the instructions at `formers` (byte offsets of `adr`s
/// and `:lo12:` `add`s in `bytes`, loaded at `vaddr`) form through the code,
/// and report for each one the constant offsets from it that the code reads,
/// writes or otherwise uses ([`Reach`]).
///
/// This is what GCC's section anchors need. With them, which aarch64 GCC
/// turns on by default at `-O1` and above, a function that touches several
/// static objects of one section takes the address of the first (the
/// anchor) once and reaches the others as constant offsets from it:
///
/// ```text
/// adrp x2, .LANCHOR0
/// add  x3, x2, :lo12:.LANCHOR0   ; a
/// ldr  w5, [x3, #48]             ; c, 48 bytes on
/// add  x2, x3, #0x10             ; b, indexed below
/// ldr  w6, [x2, w5, sxtw #2]
/// ```
///
/// Nothing in the `add` says that it reaches past `a`; only following its
/// register does. An `add`/`sub` of an immediate or a `mov` carries the
/// address on with the offset adjusted; a load or store through it with an
/// immediate offset is a use at that offset, of the access size where the
/// encoding gives it (an unsigned-offset form); with writeback the base moves
/// by the offset. Any other read — an index register added to it, the address
/// passed on, stored, compared — is a use of unknown length at the offset it
/// has, which reaches as far as the object there goes. So is every offset of
/// a register past [`MAX_ADDRS`] of them at a join.
///
/// Calls are handled the way [`pair_lo12_refs`] handles them, and so is code
/// only a jump table reaches.
pub fn address_reaches(bytes: &[u8], vaddr: u64, formers: &[usize]) -> BTreeMap<usize, Vec<Reach>> {
    let flow = PageFlow::new(bytes, vaddr);
    let formers: BTreeSet<usize> = formers.iter().map(|&off| off / INSN_LEN).collect();
    if formers.is_empty() {
        return BTreeMap::new();
    }
    let uses: RefCell<BTreeSet<Use>> = RefCell::default();
    // Per word, and one more for what indirect branches carry, the registers
    // whose offsets are no longer followed there.
    let widened = RefCell::new(vec![0u32; flow.words.len() + 1]);

    let solved = flow.solve(
        vec![BTreeSet::from([None]); GPRS],
        vec![AddrOrigins::new(); GPRS],
        |i, regs| Ok(flow.address_step(i, regs, &formers, &mut uses.borrow_mut())),
        |at, into, from| {
            let mask = &mut widened.borrow_mut()[at.unwrap_or(flow.words.len())];
            let mut uses = uses.borrow_mut();
            let mut grew = false;
            for (r, (into, from)) in into.iter_mut().zip(from).enumerate() {
                if *mask & (1 << r) == 0 {
                    let before = into.len();
                    into.extend(from.iter().copied());
                    grew |= into.len() != before;
                    if into.iter().flatten().count() <= MAX_ADDRS {
                        continue;
                    }
                    *mask |= 1 << r;
                }
                // Widened: every address arriving here is used from here on
                // in ways no longer followed.
                for &(a, off) in into.iter().chain(from).flatten() {
                    uses.insert((a, off, None));
                }
                if into.len() != 1 || !into.contains(&None) {
                    *into = BTreeSet::from([None]);
                    grew = true;
                }
            }
            grew
        },
    );
    debug_assert!(solved.is_ok(), "address_step does not fail");

    let mut reaches: BTreeMap<usize, Vec<Reach>> = BTreeMap::new();
    for (a, offset, access_len) in uses.into_inner() {
        // The formed address itself, used some way or other: what the
        // reference says on its own already.
        if offset == 0 && access_len.is_none() {
            continue;
        }
        reaches
            .entry(a * INSN_LEN)
            .or_default()
            .push(Reach { offset, access_len });
    }
    reaches
}

/// `bti c`: the landing pad an indirect call, or a `br` through `x16`/`x17`,
/// may branch to on a page the loader mapped `PROT_BTI`.
const BTI_C: u32 = 0xd503_245f;
/// `autia1716`/`autib1716`: authenticate `x17` with `x16` as the modifier,
/// which `ld -z pac-plt` puts in front of a stub's `br`.
const AUTIA1716: u32 = 0xd503_219f;
const AUTIB1716: u32 = 0xd503_21df;
/// `adrp x16, 0`.
const ADRP_X16: u32 = 0x9000_0010;
/// `ldr x17, [x16, #0]` and `add x16, x16, #0`, with the immediate masked
/// off by [`IMM12_MASK`] where a stub is matched.
const LDR_X17_X16: u32 = 0xf940_0211;
const ADD_X16_X16: u32 = 0x9100_0210;
const IMM12_MASK: u32 = 0xfff << 10;
/// `br x17`.
const BR_X17: u32 = 0xd61f_0220;

/// The GOT slot the PLT stub at the start of `bytes`, loaded at `vaddr`,
/// jumps through, or `None` when `bytes` does not start with one — the PLT0
/// header that calls the lazy resolver, for one.
///
/// Every stub GNU ld writes is one shape, give or take two optional words:
///
/// ```text
/// [bti c]                        ; -z force-bti, in an executable's PLT
/// adrp x16, slot
/// ldr  x17, [x16, :lo12:slot]
/// add  x16, x16, :lo12:slot      ; the slot's address, for the lazy resolver
/// [autia1716 | autib1716]        ; -z pac-plt
/// br   x17
/// ```
///
/// There is no `.plt.got` or `.plt.sec` on aarch64: a function only ever
/// called through a GLOB_DAT slot (`__cxa_finalize`) gets an ordinary stub,
/// so the slot found here is looked up the same way whichever relocation
/// fills it. A stub whose `ldr` and `add` name different slots is not one
/// the linker wrote, and is not taken for one.
///
/// Like `extractor::plt_target`, this is only asked about an address code
/// branches to. PLT0 from its `adrp` on is stub-shaped too — it jumps to the
/// resolver through the slot `ld.so` reserves for it — but nothing branches
/// into the middle of PLT0.
pub fn plt_stub_slot(bytes: &[u8], vaddr: u64) -> Option<u64> {
    let mut words = bytes
        .chunks_exact(INSN_LEN)
        .map(|c| u32::from_le_bytes(c.try_into().expect("chunks_exact")));
    let mut word = words.next()?;
    let mut pc = vaddr;
    if word == BTI_C {
        word = words.next()?;
        pc += INSN_LEN as u64;
    }
    if !Field::AdrpPage.fits(word) || word & 31 != 16 {
        return None;
    }
    let page = pc_relative_ref(word, pc).ok()??.target;

    let ldr = words.next()?;
    let add = words.next()?;
    if ldr & !IMM12_MASK != LDR_X17_X16 || add & !IMM12_MASK != ADD_X16_X16 {
        return None;
    }
    // The load's immediate counts eight-byte words, the add's bytes.
    let lo12 = u64::from((ldr & IMM12_MASK) >> 10) << 3;
    if u64::from((add & IMM12_MASK) >> 10) != lo12 {
        return None;
    }

    let mut word = words.next()?;
    if word == AUTIA1716 || word == AUTIB1716 {
        word = words.next()?;
    }
    (word == BR_X17).then_some(page + lo12)
}

/// Size of a trampoline: see [`trampoline`].
pub const TRAMPOLINE_LEN: usize = 16;

/// The trampoline at `vaddr` that jumps to the function whose address the
/// loader writes into the GOT slot at `slot`: the aarch64 counterpart of the
/// x86-64 `jmp [rip+disp32]` the writer emits for a symbol the merged code
/// still reaches at runtime.
///
/// ```text
/// bti c
/// adrp x16, slot
/// ldr  x17, [x16, :lo12:slot]
/// br   x17
/// ```
///
/// It is a PLT stub without the `add` only the lazy resolver reads, and it
/// branches through `x17` for the same reason a stub does: a `br` through
/// `x16` or `x17` is one a `bti c` accepts, and `bti c` is the pad a
/// function built for BTI starts with. Through any other register the
/// target would need a `bti j` it does not have and the branch would fault.
/// The leading `bti c` is the trampoline's own pad, in case the merged code
/// takes its address rather than calling it; on a core without BTI it is a
/// `nop`.
///
/// `slot` has to be within ±4 GiB of `vaddr` and eight-byte aligned, which a
/// GOT slot always is; anything else is an error rather than a trampoline
/// that loads from somewhere else.
pub fn trampoline(vaddr: u64, slot: u64) -> Result<[u8; TRAMPOLINE_LEN]> {
    let adrp = Field::AdrpPage
        .patch(ADRP_X16, slot, 0, vaddr + INSN_LEN as u64)
        .with_context(|| format!("trampoline at 0x{vaddr:x} for the GOT slot at 0x{slot:x}"))?;
    let ldr = Field::Lo12
        .patch(LDR_X17_X16, slot, 0, vaddr + 2 * INSN_LEN as u64)
        .with_context(|| format!("trampoline at 0x{vaddr:x} for the GOT slot at 0x{slot:x}"))?;
    let mut out = [0; TRAMPOLINE_LEN];
    for (dst, word) in out
        .chunks_exact_mut(INSN_LEN)
        .zip([BTI_C, adrp, ldr, BR_X17])
    {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    Ok(out)
}

/// Whether `code`, the bytes of a function as far as its unwind info claims
/// it runs, ends the way a function does: in whole instructions, the last
/// of which does not fall through to whatever follows.
///
/// The aarch64 counterpart of `extractor::ends_the_function`. Instructions
/// are all one size, so the only way a bound can cut one is by not being a
/// multiple of it; what is left to check is the last word. A `bl` to a
/// `noreturn` function does not count, as a `call` does not on x86-64: the
/// decode cannot tell it from a call that returns.
pub fn ends_the_function(code: &[u8]) -> bool {
    use Opcode::*;

    if code.is_empty() || !code.len().is_multiple_of(INSN_LEN) {
        return false;
    }
    let last = &code[code.len() - INSN_LEN..];
    let word = u32::from_le_bytes(last.try_into().expect("one word"));
    decode(word).is_some_and(|insn| {
        matches!(
            insn.opcode,
            B | BR
                | BRAA
                | BRAAZ
                | BRAB
                | BRABZ
                | RET
                | RETAA
                | RETAB
                | RETAASPPC
                | RETABSPPC
                | RETAASPPCR
                | RETABSPPCR
                | UDF
                | BRK
                | HLT
        )
    })
}

/// [`trampoline`], as the descriptor's [`Trampoline::encode`].
fn encode_trampoline(vaddr: u64, slot: u64) -> Result<Vec<u8>> {
    trampoline(vaddr, slot).map(Vec::from)
}

/// [`plt_stub_slot`], as the descriptor's [`MachineCode::plt_stub_slot`].
fn plt_stub_slot_at(sec_data: &[u8], sec_addr: u64, addr: u64) -> Option<u64> {
    plt_stub_slot(
        sec_data.get(usize::try_from(addr - sec_addr).ok()?..)?,
        addr,
    )
}

/// aarch64 (`EM_AARCH64`), LP64, per the ARM ELF ABI (AAELF64) and glibc's
/// `sysdeps/aarch64`.
///
/// Not in [`SUPPORTED`](super::SUPPORTED) yet, so an aarch64 executable is
/// still refused at the gate; opening it, and turning round the tests that
/// check it refuses aarch64, is the step left. Until then this is what the
/// per-architecture tables of the search, the reader, the extractor, the
/// patcher and the writer are tested against.
#[cfg_attr(not(test), allow(dead_code))]
pub static AARCH64: Arch = {
    use Unliftable::{Copy, Ifunc};
    use object::elf::{
        EM_AARCH64, GNU_PROPERTY_AARCH64_FEATURE_1_AND, R_AARCH64_COPY, R_AARCH64_GLOB_DAT,
        R_AARCH64_IRELATIVE, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE, R_AARCH64_TLS_DTPMOD,
        R_AARCH64_TLS_DTPREL, R_AARCH64_TLS_TPREL, R_AARCH64_TLSDESC,
    };

    Arch {
        name: "aarch64",
        e_machine: EM_AARCH64.0,
        reloc: DynRelocTypes {
            relative: R_AARCH64_RELATIVE.0,
            glob_dat: R_AARCH64_GLOB_DAT.0,
            jump_slot: R_AARCH64_JUMP_SLOT.0,
            copy: R_AARCH64_COPY.0,
        },
        // Every dynamic relocation AAELF64 defines other than the three above
        // and the TLS ones below. Unlike x86-64 there is no SIZE relocation,
        // and the static TLS forms (`TLSGD_ADR_PAGE21` and the rest) are
        // resolved by the linker into instruction fields and GOT slots
        // carrying the dynamic ones, so they never reach a shared library's
        // dynamic tables.
        unliftable_relocs: &[
            (R_AARCH64_IRELATIVE.0, "R_AARCH64_IRELATIVE", Ifunc),
            (R_AARCH64_COPY.0, "R_AARCH64_COPY", Copy),
        ],
        // The names are the ones readelf prints; `object` and glibc's `elf.h`
        // drop the `64`. glibc's aarch64 `TLS_TCB_SIZE` is the two-word
        // `tcbhead_t`.
        tls: TlsAbi {
            layout: TlsLayout::AboveTp { tcb_size: 16 },
            relocs: [
                (
                    R_AARCH64_TLS_DTPMOD.0,
                    "R_AARCH64_TLS_DTPMOD64",
                    TlsSlot::Module,
                ),
                (
                    R_AARCH64_TLS_DTPREL.0,
                    "R_AARCH64_TLS_DTPREL64",
                    TlsSlot::Offset,
                ),
                (
                    R_AARCH64_TLS_TPREL.0,
                    "R_AARCH64_TLS_TPREL64",
                    TlsSlot::ThreadPointer,
                ),
                (
                    R_AARCH64_TLSDESC.0,
                    "R_AARCH64_TLSDESC",
                    TlsSlot::Descriptor,
                ),
            ],
        },
        // `FLAG_AARCH64_LIB64 | FLAG_ELF_LIBC6`, glibc's
        // `sysdeps/unix/sysv/linux/aarch64/dl-cache.h`. As on x86-64,
        // `_dl_cache_check_flags` accepts exactly this value, so an ILP32
        // (`FLAG_AARCH64_LIB32`) or foreign entry is never loaded.
        ldso_cache_flags: 0x0a03,
        // glibc's aarch64 `configure` puts LP64 libraries in `/lib64`, the
        // same as x86-64, so `$LIB` expands the same way.
        lib_token: "lib64",
        default_lib_dirs: &[
            "/lib64",
            "/usr/lib64",
            "/lib",
            "/usr/lib",
            "/lib/aarch64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
        ],
        // aarch64 kernels run with 4, 16 or 64 KiB pages, which is why
        // distribution linkers default to `-z max-page-size=0x10000`.
        max_page_size: 0x10000,
        gnu_properties: GnuProperties {
            feature_1_and: GNU_PROPERTY_AARCH64_FEATURE_1_AND.0,
            feature_1_family: "BTI/PAC/GCS",
            // `GNU_PROPERTY_AARCH64_FEATURE_1_{BTI,PAC,GCS}`. BTI is the one
            // that faults: the loader maps the executable's code guarded, and
            // a merged function without a `bti c` landing pad is entered
            // through the trampoline's `br`. GCS (binutils 2.44, glibc 2.41)
            // is AND-combined the same way, and glibc checks it against every
            // object it loads.
            feature_1_bits: &[(1 << 0, "BTI"), (1 << 1, "PAC"), (1 << 2, "GCS")],
            // aarch64 has no ISA-level property.
            isa_1_needed: None,
        },
        trampoline: Trampoline {
            len: TRAMPOLINE_LEN as u64,
            encode: encode_trampoline,
        },
        code: MachineCode {
            scan,
            plt_stub_slot: plt_stub_slot_at,
            veneer_short_branches,
        },
        // GCC's `-fsection-anchors`, on by default at `-O1` and above: see
        // `address_reaches`.
        anchored_data: true,
    }
};

/// [`MachineCode::scan`]: how far the function's code runs, then every
/// address it keeps ([`scan_refs`]). aarch64 code is read a word at a time,
/// so there is no decoded stream to share, and no jump table to relocate: a
/// switch table's entries are offsets from a label inside the function that
/// indexes it, so they move with it.
fn scan(unit: &TextUnit<'_, '_>) -> Result<UnitScan> {
    let len = code_len(unit.bytes, unit.vaddr, unit.fde_end);
    Ok(UnitScan {
        refs: scan_refs(&unit.bytes[..len], unit.vaddr)?,
        jump_tables: Vec::new(),
    })
}

/// How many of a text unit's leading bytes are its function's code: as far
/// as the function's FDE claims, if [`ends_the_function`] agrees that the
/// code stops there, and the whole unit otherwise. See [`TextUnit::fde_end`].
fn code_len(bytes: &[u8], vaddr: u64, fde_end: Option<u64>) -> usize {
    fde_end
        .and_then(|end| end.checked_sub(vaddr))
        .map(|len| len as usize)
        .filter(|&len| len < bytes.len() && ends_the_function(&bytes[..len]))
        .unwrap_or(bytes.len())
}

/// Every address the aarch64 function in `code`, loaded at `vaddr`, keeps in
/// its instructions: each branch, `adr` and literal load
/// ([`scan_pc_relative_refs`]), and each `adrp` pair
/// ([`pair_lo12_refs`]).
///
/// A pair is two references to one address. The `:lo12:` half carries it
/// whole and comes first; each `adrp` follows as a [`RefSite::AdrpOf`] the
/// first `:lo12:` it pairs with, which is the only place its full target is
/// known. An `adrp` nothing completes reaches no address and is left alone.
///
/// A reference the scanners cannot account for — a page used other than as a
/// `:lo12:` base, a PC-relative form with no field to rewrite — fails the
/// extraction, since copying it as it is would leave it aimed at wherever the
/// old offset lands.
fn scan_refs(code: &[u8], vaddr: u64) -> Result<Vec<CodeRef>> {
    let mut refs = Vec::new();
    let pairs = pair_lo12_refs(code, vaddr)?;
    let pc_rel = scan_pc_relative_refs(code, vaddr)?;
    let word_at = |offset: usize| {
        u32::from_le_bytes(
            code[offset..offset + INSN_LEN]
                .try_into()
                .expect("one word"),
        )
    };

    // The instructions that put a whole address in a register: a `:lo12:`
    // `add` and an `adr` of data. What the code adds to that address is how
    // far past the object at it the reference reaches.
    let formers: Vec<usize> = pairs
        .iter()
        .map(|pair| pair.offset)
        .filter(|&offset| is_lo12_add(word_at(offset)))
        .chain(
            pc_rel
                .iter()
                .filter(|(_, r)| r.field == Field::Adr && !r.is_code_ref)
                .map(|&(offset, _)| offset),
        )
        .collect();
    let mut reaches = address_reaches(code, vaddr, &formers);

    for pair in &pairs {
        let word = word_at(pair.offset);
        refs.push(CodeRef {
            offset: pair.offset,
            target_vaddr: pair.target,
            is_code_ref: false,
            access_len: lo12_access_len(word),
            site: RefSite::Insn(InsnField {
                field: Field::Lo12,
                adrps: pair.adrps.iter().map(|&a| a as u64).collect(),
            }),
            reaches: reaches.remove(&pair.offset).unwrap_or_default(),
        });
    }
    for (offset, r) in pc_rel {
        let (site, target_vaddr) = if r.field == Field::AdrpPage {
            let Some(pair) = pairs.iter().find(|p| p.adrps.contains(&offset)) else {
                continue;
            };
            (RefSite::AdrpOf(pair.offset), pair.target)
        } else {
            let site = RefSite::Insn(InsnField {
                field: r.field,
                adrps: Vec::new(),
            });
            (site, r.target)
        };
        refs.push(CodeRef {
            offset,
            target_vaddr,
            is_code_ref: r.is_code_ref,
            access_len: None,
            site,
            reaches: reaches.remove(&offset).unwrap_or_default(),
        });
    }
    Ok(refs)
}

/// Send each aarch64 short-range branch that leaves its unit through a `b`
/// veneer appended to the unit, the aarch64 counterpart of the x86-64 rel8
/// veneers (see [`MachineCode::veneer_short_branches`]).
///
/// A `b.cond`, `cbz` or `tbz` reaches ±1 MiB or ±32 KiB, and nothing keeps its
/// target that close once the merge has placed the units: the library had it
/// nearby, the merged segment may not, and the relocator could then only
/// refuse the merge. A linker in the same position cannot help either, since
/// AAELF64 only lets it insert veneers for `b`/`bl`. So the branch is pointed
/// at a `b` at the end of its own unit, which moves with it and so never goes
/// out of reach, and the relocation moves to that `b`, whose ±128 MiB covers
/// any merged segment. Compilers do not branch conditionally into another
/// function, but hand-written assembly (glibc's string functions, OpenSSL's
/// primitives) does.
///
/// A branch inside its own unit carries no relocation (see
/// [`CodeRef::moves_with_its_unit`](super::CodeRef::moves_with_its_unit)) and is left alone.
fn veneer_short_branches(
    bytes: &mut Vec<u8>,
    relocations: &mut [ExtractedReloc],
    sym: &str,
) -> Result<()> {
    for reloc in relocations.iter_mut() {
        let super::Site::Aarch64(insn) = &mut reloc.site else {
            continue;
        };
        if !matches!(insn.field, Field::Imm19 | Field::Imm14) {
            continue;
        }
        let at = reloc.offset_within_unit as usize;
        let word = u32::from_le_bytes(
            bytes[at..at + INSN_LEN]
                .try_into()
                .expect("an instruction word"),
        );
        if !is_short_branch(word) {
            continue;
        }

        // A unit may stop short of a word boundary when a symbol's size
        // does; the bytes in between are never executed.
        bytes.resize(bytes.len().next_multiple_of(INSN_LEN), 0);
        let veneer = bytes.len();
        bytes.extend_from_slice(&VENEER.to_le_bytes());

        let branch = insn
            .field
            .patch(word, veneer as u64, 0, at as u64)
            .with_context(|| {
                format!(
                    "branch at offset {at:#x} in '{sym}' cannot reach a veneer at the \
                     end of the unit"
                )
            })?;
        bytes[at..at + INSN_LEN].copy_from_slice(&branch.to_le_bytes());

        // The target and addend stay as they were: an aarch64 field's addend
        // is the offset into the target, with no width folded in.
        reloc.offset_within_unit = veneer as u64;
        insn.field = Field::Imm26;
    }
    Ok(())
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

    /// The short branches are exactly the code references `b`/`bl` cannot
    /// stand for: every one but `b`/`bl` themselves, and no load literal.
    #[test]
    fn short_branches_are_the_branches_narrower_than_b() {
        for &(word, field, _, is_code_ref) in SAMPLES {
            let short = is_code_ref && field != Field::Imm26;
            assert_eq!(is_short_branch(word), short, "0x{word:08x}");
        }
        for &word in NO_REFS {
            assert!(!is_short_branch(word), "0x{word:08x}");
        }
        assert!(Field::Imm26.fits(VENEER) && !is_short_branch(VENEER));
        assert_eq!(decode(VENEER).map(|i| i.opcode), Some(Opcode::B));
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

    /// What `address_reaches` says of the address the instruction at
    /// `former` forms in `words`, as `(offset, access_len)`.
    fn reaches_of(words: &[u32], former: usize) -> Vec<(i64, Option<u64>)> {
        address_reaches(&code(words), BASE, &[former])
            .remove(&former)
            .unwrap_or_default()
            .into_iter()
            .map(|r| (r.offset, r.access_len))
            .collect()
    }

    /// A section anchor: the `add` takes the address of the first object,
    /// and the code reaches the rest at constant offsets from it, directly,
    /// through a derived pointer it indexes, and below it. Handing the address
    /// on to a store is a use of the anchor itself, which the reference says
    /// already.
    #[test]
    fn the_offsets_code_adds_to_a_formed_address_are_its_reaches() {
        let words = [
            0x9000_0002, // adrp x2, 0x400000
            0x913f_c043, // add  x3, x2, #0xff0
            0xb940_3065, // ldr  w5, [x3, #48]
            0x9100_4062, // add  x2, x3, #0x10
            0xb865_d846, // ldr  w6, [x2, w5, sxtw #2]
            0xd100_2067, // sub  x7, x3, #0x8
            0xa940_24e8, // ldp  x8, x9, [x7]
            0xaa03_03ea, // mov  x10, x3
            0xf900_07ea, // str  x10, [sp, #8]
            RET,
        ];
        assert_eq!(
            reaches_of(&words, 0x4),
            [(-8, None), (16, None), (48, Some(4))]
        );
    }

    /// An `adr` forms an address too. Writeback moves the base on, and the
    /// address survives a call in a register the callee is taken to leave
    /// alone.
    #[test]
    fn a_writeback_moves_the_base_and_a_call_keeps_it() {
        let words = [
            0x1000_0004, // adr  x4, .
            0xf841_0c80, // ldr  x0, [x4, #16]!
            0x3940_0c81, // ldrb w1, [x4, #3]
            0x97ff_fffd, // bl   .-12
            0xb840_1081, // ldur w1, [x4, #1]
            RET,
        ];
        assert_eq!(
            reaches_of(&words, 0x0),
            [(16, None), (17, None), (19, Some(1))]
        );
    }

    /// A pointer stepped through a loop takes a new offset every trip round
    /// it. The offsets stop being followed once there are too many of them
    /// at the loop head, so the analysis ends, and every one it saw is still
    /// reported as reached.
    #[test]
    fn a_pointer_stepped_through_a_loop_is_widened() {
        let words = [
            0x9000_0002, // adrp x2, 0x400000
            0x913f_c043, // add  x3, x2, #0xff0
            0xb840_4460, // ldr  w0, [x3], #4      <- loop
            0x35ff_ffe0, // cbnz w0, loop
            RET,
        ];
        let reaches = reaches_of(&words, 0x4);
        let offsets: Vec<i64> = reaches.iter().map(|&(off, _)| off).collect();
        let bound = 4 * (MAX_ADDRS as i64 + 1);
        assert!(offsets.contains(&4) && offsets.len() > 1, "{reaches:?}");
        assert!(
            offsets
                .iter()
                .all(|&off| off > 0 && off <= bound && off % 4 == 0),
            "{reaches:?}"
        );
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

    const STR_X0_SP_24: u32 = 0xf900_0fe0; // str x0, [sp, #24]
    const LDR_X0_SP_24: u32 = 0xf940_0fe0; // ldr x0, [sp, #24]

    /// GCC's spill of a page across calls, as in libcrypto's
    /// `CMS_add1_signer`: stored to the stack, reloaded, then completed.
    /// Through `sp`, through the frame pointer `mov x29, sp` sets up (one
    /// slot, reached both ways), and as one half of a pair, with the frame
    /// set up and torn down around it.
    #[test]
    fn a_page_spilled_to_the_stack_is_paired_where_it_is_reloaded() {
        let pairs = pair_lo12_refs(
            &code(&[
                0xa9bd_7bfd,  // 0x00  stp  x29, x30, [sp, #-48]!
                0x9100_03fd,  // 0x04  mov  x29, sp
                0xd100_83ff,  // 0x08  sub  sp, sp, #0x20
                ADRP_X0,      // 0x0c  adrp x0, 0x410000
                STR_X0_SP_24, // 0x10  str  x0, [sp, #24]
                0xf81f_83a0,  // 0x14  stur x0, [x29, #-8]
                0xa900_87e0,  // 0x18  stp  x0, x1, [sp, #8]
                0x9400_0000,  // 0x1c  bl   .
                LDR_X0_SP_24, // 0x20  ldr  x0, [sp, #24]
                0x913f_c001,  // 0x24  add  x1, x0, #0xff0
                0xf85f_83a2,  // 0x28  ldur x2, [x29, #-8]
                0xf940_0443,  // 0x2c  ldr  x3, [x2, #8]
                0xa940_97e4,  // 0x30  ldp  x4, x5, [sp, #8]
                0x913f_c084,  // 0x34  add  x4, x4, #0xff0
                0x9100_83ff,  // 0x38  add  sp, sp, #0x20
                0xa8c3_7bfd,  // 0x3c  ldp  x29, x30, [sp], #48
                RET,
            ]),
            BASE,
        )
        .unwrap();
        assert_eq!(
            pairs,
            [
                lo12(0x24, &[0x0c], 0x41_0ff0),
                lo12(0x2c, &[0x0c], 0x41_0008),
                lo12(0x34, &[0x0c], 0x41_0ff0),
            ]
        );
    }

    /// A page taken back out of its slot any other way than whole, into a
    /// 64-bit general-purpose register, or put there only in part, is not
    /// one a `:lo12:` can be followed from.
    #[test]
    fn a_spilled_page_reloaded_or_spilled_in_part_is_refused() {
        for (use_, what) in [
            (0xb940_1be0, "loads from the stack slot at sp+24"), // ldr w0, [sp, #24]
            (0xfd40_0fe0, "loads from the stack slot at sp+24"), // ldr d0, [sp, #24]
            (0xf841_43e1, "loads from the stack slot at sp+24"), // ldur x1, [sp, #20]
            (0xb900_1be0, "stores part of x0"),                  // str w0, [sp, #24]
        ] {
            let err = pairing_error(&[ADRP_X0, STR_X0_SP_24, use_, RET]);
            assert!(err.contains(what), "{use_:08x}: {err}");
            assert!(err.contains("adrp at 0x400000"), "{use_:08x}: {err}");
        }
    }

    /// A slot overwritten, even in part, or left behind below `sp`, no longer
    /// holds the page: what is reloaded from it is not completed.
    #[test]
    fn a_spilled_page_overwritten_or_popped_is_dropped() {
        for words in [
            // str xzr, [sp, #24]
            &[
                ADRP_X0,
                STR_X0_SP_24,
                0xf900_0fff,
                LDR_X0_SP_24,
                ADD_X0_LO12,
                RET,
            ][..],
            // str w1, [sp, #24]
            &[
                ADRP_X0,
                STR_X0_SP_24,
                0xb900_1be1,
                LDR_X0_SP_24,
                ADD_X0_LO12,
                RET,
            ],
            // sub sp, sp, #0x20 ... add sp, sp, #0x20; sub sp, sp, #0x20
            &[
                ADRP_X0,
                0xd100_83ff,
                STR_X0_SP_24,
                0x9100_83ff,
                0xd100_83ff,
                LDR_X0_SP_24,
                ADD_X0_LO12,
                RET,
            ],
        ] {
            assert_eq!(
                pair_lo12_refs(&code(words), BASE).unwrap(),
                [],
                "{words:08x?}"
            );
        }
    }

    /// Where the slot a page was spilled to cannot be told apart from the
    /// ones around it, a reload from it may or may not be the page, and
    /// completing it is refused rather than guessed.
    #[test]
    fn a_spilled_page_that_cannot_be_placed_is_refused() {
        const SUB_SP_X1: u32 = 0xcb21_63ff; // sub sp, sp, x1
        let err = pairing_error(&[ADRP_X0, SUB_SP_X1, STR_X0_SP_24, RET]);
        assert!(err.contains("has moved by an amount"), "{err}");

        for words in [
            // The slot holds the page down one path only.
            &[
                0xb400_0062,
                ADRP_X0,
                STR_X0_SP_24,
                LDR_X0_SP_24,
                ADD_X0_LO12,
                RET,
            ][..],
            // Reloaded after `sp` moved by a register.
            &[
                ADRP_X0,
                STR_X0_SP_24,
                SUB_SP_X1,
                LDR_X0_SP_24,
                ADD_X0_LO12,
                RET,
            ],
            // A store with a register index may have landed on it.
            &[
                ADRP_X0,
                STR_X0_SP_24,
                0xf821_6be2, // str x2, [sp, x1]
                LDR_X0_SP_24,
                ADD_X0_LO12,
                RET,
            ],
        ] {
            let err = format!("{:#}", pair_lo12_refs(&code(words), BASE).unwrap_err());
            assert!(
                err.contains("both with and without a page in x0"),
                "{words:08x?}: {err}"
            );
        }
    }

    #[test]
    fn immediate_loads_and_stores_are_decoded_with_their_slots() {
        let access = |load, base, offset, writeback, regs: &[usize], len, gpr| ImmAccess {
            load,
            base,
            offset,
            writeback,
            regs: regs.to_vec(),
            len,
            gpr,
        };
        for (word, expected) in [
            (STR_X0_SP_24, access(false, 31, 24, None, &[0], 8, true)),
            (0xf85f_83a2, access(true, 29, -8, None, &[2], 8, true)), // ldur x2, [x29, #-8]
            (
                0xa9bd_7bfd,
                access(false, 31, -48, Some(-48), &[29, 30], 8, true),
            ), // stp x29, x30, [sp, #-48]!
            (
                0xa8c3_7bfd,
                access(true, 31, 0, Some(48), &[29, 30], 8, true),
            ), // ldp x29, x30, [sp], #48
            (0xb940_1be0, access(true, 31, 24, None, &[0], 4, true)), // ldr w0, [sp, #24]
            (0x3d80_0425, access(false, 1, 16, None, &[5], 16, false)), // str q5, [x1, #16]
            (0xad7f_07e0, access(true, 31, -32, None, &[0, 1], 16, false)), // ldp q0, q1, [sp, #-32]
            (0xf842_8401, access(true, 0, 0, Some(40), &[1], 8, true)),     // ldr x1, [x0], #40
        ] {
            assert_eq!(imm_access(word), Some(expected), "{word:08x}");
        }
        for word in [
            0xf821_6be2, // str x2, [sp, x1]
            0x913f_c001, // add x1, x0, #0xff0
            0xc85f_7c20, // ldxr x0, [x1]
        ] {
            assert_eq!(imm_access(word), None, "{word:08x}");
        }
    }

    /// The `.plt` of a shared library GCC built and GNU ld 2.46 linked with no
    /// options, at 0x580, as `objdump -d` shows it. Its JUMP_SLOTs are
    /// `__cxa_finalize` (0x20000), `malloc`, `__gmon_start__` and `puts`.
    const LIB_PLT: u64 = 0x580;
    const LIB_PLT_WORDS: &[u32] = &[
        0xa9bf_7bf0, // stp x16, x30, [sp, #-16]!
        0xf000_00f0, // adrp x16, 1f000
        0xf947_fe11, // ldr x17, [x16, #4088]
        0x913f_e210, // add x16, x16, #0xff8
        0xd61f_0220, // br x17
        0xd503_201f, // nop
        0xd503_201f, // nop
        0xd503_201f, // nop
        0x9000_0110, // __cxa_finalize@plt: adrp x16, 20000
        0xf940_0211, // ldr x17, [x16]
        0x9100_0210, // add x16, x16, #0x0
        0xd61f_0220, // br x17
        0x9000_0110, // malloc@plt
        0xf940_0611, // ldr x17, [x16, #8]
        0x9100_2210, // add x16, x16, #0x8
        0xd61f_0220,
        0x9000_0110, // __gmon_start__@plt
        0xf940_0a11,
        0x9100_4210,
        0xd61f_0220,
        0x9000_0110, // puts@plt
        0xf940_0e11,
        0x9100_6210,
        0xd61f_0220,
    ];

    #[test]
    fn every_plt_stub_is_matched_to_the_slot_its_jump_slot_fills() {
        let plt = code(LIB_PLT_WORDS);
        // Where the symbol table says each entry starts, PLT0 first.
        let slots: Vec<_> = [0x00, 0x20, 0x30, 0x40, 0x50]
            .into_iter()
            .map(|off: usize| plt_stub_slot(&plt[off..], LIB_PLT + off as u64))
            .collect();
        assert_eq!(
            slots,
            [
                None,
                Some(0x2_0000),
                Some(0x2_0008),
                Some(0x2_0010),
                Some(0x2_0018)
            ]
        );
    }

    /// The optional words: `-z force-bti` puts a `bti c` in front of an
    /// executable's stubs, `-z pac-plt` an `autia1716` before the `br`; and in
    /// a PIE the slots are in the page below, with a nonzero `:lo12:`.
    #[test]
    fn every_stub_flavor_the_linker_writes_is_recognised() {
        for (vaddr, words, slot) in [
            // -z force-bti, a non-PIE executable: abort@plt's neighbour.
            (
                0x40_0648u64,
                &[
                    0xd503_245f,
                    0x9000_0110,
                    0xf940_0611,
                    0x9100_2210,
                    0xd61f_0220,
                ][..],
                0x42_0008u64,
            ),
            // -z pac-plt, a shared library: malloc@plt.
            (
                0x5b8,
                &[
                    0x9000_0110,
                    0xf940_0611,
                    0x9100_2210,
                    0xd503_219f,
                    0xd61f_0220,
                ],
                0x2_0008,
            ),
            // Both, the authentication with the B key.
            (
                0x5b8,
                &[
                    0xd503_245f,
                    0x9000_0110,
                    0xf940_0611,
                    0x9100_2210,
                    0xd503_21df,
                    0xd61f_0220,
                ],
                0x2_0008,
            ),
            // A PIE linked with -z now: __cxa_finalize@plt.
            (
                0x6e0,
                &[0xf000_00f0, 0xf947_da11, 0x913e_c210, 0xd61f_0220],
                0x1_ffb0,
            ),
        ] {
            assert_eq!(plt_stub_slot(&code(words), vaddr), Some(slot), "{vaddr:x}");
        }
    }

    #[test]
    fn what_is_not_a_stub_is_not_taken_for_one() {
        let malloc = [0x9000_0110, 0xf940_0611, 0x9100_2210, 0xd61f_0220];
        let with = |i: usize, word: u32| {
            let mut words = malloc;
            words[i] = word;
            code(&words)
        };
        for (what, bytes) in [
            ("PLT0", code(&LIB_PLT_WORDS[..8])),
            ("cut short", code(&malloc[..3])),
            ("adrp x17", with(0, 0x9000_0111)),
            ("ldr x16", with(1, 0xf940_0610)),
            ("ldr w17", with(1, 0xb940_0a11)),
            ("add of another slot", with(2, 0x9100_4210)),
            ("br x16", with(3, 0xd61f_0200)),
            ("blr x17", with(3, 0xd63f_0220)),
        ] {
            assert_eq!(plt_stub_slot(&bytes, 0x5b0), None, "{what}");
        }
    }

    /// What GNU as and ld make of the same four instructions with `slot` at
    /// 0x534448 and the trampoline at 0x400000.
    #[test]
    fn a_trampoline_is_what_the_assembler_writes_for_it() {
        assert_eq!(
            trampoline(BASE, 0x53_4448).unwrap(),
            code(&[0xd503_245f, 0x9000_09b0, 0xf942_2611, 0xd61f_0220])[..]
        );
    }

    /// A trampoline is a stub without the `add`, so putting it back gives a
    /// stub that `plt_stub_slot` reads the same slot out of, wherever the two
    /// are within reach.
    #[test]
    fn a_trampoline_loads_from_the_slot_it_was_given() {
        let vaddr = 0x2_0000_0000u64;
        for slot in [
            vaddr + 0x40,
            vaddr - 0x1000,
            vaddr + 0xffff_f000,
            vaddr - 0x1_0000_0000,
            vaddr + 0x1234_5678,
        ] {
            let t = trampoline(vaddr, slot).unwrap();
            let ldr = u32::from_le_bytes(t[8..12].try_into().unwrap());
            let add = ADD_X16_X16 | (ldr & IMM12_MASK) << 3;
            let mut stub = t[..12].to_vec();
            stub.extend_from_slice(&add.to_le_bytes());
            stub.extend_from_slice(&t[12..]);
            assert_eq!(plt_stub_slot(&stub, vaddr), Some(slot), "{slot:x}");
        }
    }

    #[test]
    fn a_trampoline_to_a_slot_it_cannot_load_is_refused() {
        let vaddr = 0x2_0000_0000u64;
        // Past adrp's reach, and not a pointer-aligned slot.
        assert!(trampoline(vaddr, vaddr + 0x1_0000_0000).is_err());
        assert!(trampoline(vaddr, vaddr + 0x44).is_err());
    }

    #[test]
    fn a_function_ends_on_a_word_that_does_not_fall_through() {
        for (what, last) in [
            ("ret", 0xd65f_03c0u32),
            ("retaa", 0xd65f_0bff),
            ("b", 0x17ff_ffff),
            ("br x16", 0xd61f_0200),
            ("brk #1000", 0xd420_7d00),
            ("udf #0", 0x0000_0000),
        ] {
            assert!(ends_the_function(&code(&[0xd503_201f, last])), "{what}");
        }
        for (what, bytes) in [
            ("bl", code(&[0xd65f_03c0, 0x97ff_ffff])),
            ("b.ne", code(&[0xd65f_03c0, 0x54ff_ffe1])),
            ("cbz", code(&[0xd65f_03c0, 0xb4ff_ffe0])),
            ("blr x1", code(&[0xd65f_03c0, 0xd63f_0020])),
            ("nop", code(&[0xd65f_03c0, 0xd503_201f])),
            ("empty", Vec::new()),
        ] {
            assert!(!ends_the_function(&bytes), "{what}");
        }
        // A bound that cuts the last word.
        let mut cut = code(&[RET]);
        cut.extend_from_slice(&[0xc0, 0x03]);
        assert!(!ends_the_function(&cut));
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

    /// A veneer that the branch itself cannot reach, as for a `tbz` near the
    /// start of a unit longer than 32 KiB, is refused rather than written
    /// wrong.
    #[test]
    fn a_veneer_out_of_the_short_branchs_reach_is_an_error() {
        const TBNZ_W0_31: u32 = 0x37f8_0000;
        let mut bytes = TBNZ_W0_31.to_le_bytes().to_vec();
        bytes.resize(1 << 15, 0);
        let mut relocs = vec![ExtractedReloc {
            offset_within_unit: 0,
            site: crate::arch::Site::Aarch64(InsnField {
                field: Field::Imm14,
                adrps: Vec::new(),
            }),
            addend: 0,
            target: crate::types::RelocTarget::External("far".into()),
        }];
        let err = veneer_short_branches(&mut bytes, &mut relocs, "long")
            .expect_err("the end of the unit is 32 KiB away");
        assert!(
            format!("{err:#}").contains("cannot reach a veneer"),
            "{err:#}"
        );

        // One word shorter, the veneer is within reach.
        let mut bytes = TBNZ_W0_31.to_le_bytes().to_vec();
        bytes.resize((1 << 15) - 4, 0);
        veneer_short_branches(&mut bytes, &mut relocs, "long").expect("in reach");
        assert_eq!(relocs[0].offset_within_unit, (1 << 15) - 4);
    }
}
