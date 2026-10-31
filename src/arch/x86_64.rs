//! x86-64: its descriptor, and how the extractor reads and rewrites its code.
//!
//! A reference is a little-endian rel8/rel32 displacement at the tail of the
//! instruction, found by decoding the function with `iced-x86`
//! ([`scan_rip_relative_refs`]). The same decode feeds the jump-table
//! detector ([`jump_table`]), so it is done once per unit.

mod jump_table;

use anyhow::{Result, bail};
use iced_x86::Instruction;

use super::{
    Arch, CodeRef, DynRelocTypes, GnuProperties, MachineCode, RefSite, Site, TextUnit, Trampoline,
    UnitScan, Unliftable, Word,
};
use crate::types::ExtractedReloc;

/// x86-64 (`EM_X86_64`), per the System V AMD64 psABI and glibc's
/// `sysdeps/x86_64`.
pub static X86_64: Arch = {
    use Unliftable::{Copy, Ifunc, Size, Tls};
    use object::elf::{
        EM_X86_64, GNU_PROPERTY_X86_FEATURE_1_AND, GNU_PROPERTY_X86_ISA_1_NEEDED, R_X86_64_COPY,
        R_X86_64_DTPMOD64, R_X86_64_DTPOFF32, R_X86_64_DTPOFF64, R_X86_64_GLOB_DAT,
        R_X86_64_GOTPC32_TLSDESC, R_X86_64_GOTTPOFF, R_X86_64_IRELATIVE, R_X86_64_JUMP_SLOT,
        R_X86_64_RELATIVE, R_X86_64_SIZE32, R_X86_64_SIZE64, R_X86_64_TLSDESC,
        R_X86_64_TLSDESC_CALL, R_X86_64_TLSGD, R_X86_64_TLSLD, R_X86_64_TPOFF32, R_X86_64_TPOFF64,
    };

    Arch {
        name: "x86-64",
        e_machine: EM_X86_64.0,
        reloc: DynRelocTypes {
            relative: R_X86_64_RELATIVE.0,
            glob_dat: R_X86_64_GLOB_DAT.0,
            jump_slot: R_X86_64_JUMP_SLOT.0,
            copy: R_X86_64_COPY.0,
        },
        unliftable_relocs: &[
            (R_X86_64_DTPMOD64.0, "R_X86_64_DTPMOD64", Tls),
            (R_X86_64_DTPOFF64.0, "R_X86_64_DTPOFF64", Tls),
            (R_X86_64_TPOFF64.0, "R_X86_64_TPOFF64", Tls),
            (R_X86_64_TLSGD.0, "R_X86_64_TLSGD", Tls),
            (R_X86_64_TLSLD.0, "R_X86_64_TLSLD", Tls),
            (R_X86_64_DTPOFF32.0, "R_X86_64_DTPOFF32", Tls),
            (R_X86_64_GOTTPOFF.0, "R_X86_64_GOTTPOFF", Tls),
            (R_X86_64_TPOFF32.0, "R_X86_64_TPOFF32", Tls),
            (R_X86_64_GOTPC32_TLSDESC.0, "R_X86_64_GOTPC32_TLSDESC", Tls),
            (R_X86_64_TLSDESC_CALL.0, "R_X86_64_TLSDESC_CALL", Tls),
            (R_X86_64_TLSDESC.0, "R_X86_64_TLSDESC", Tls),
            (R_X86_64_IRELATIVE.0, "R_X86_64_IRELATIVE", Ifunc),
            (R_X86_64_SIZE32.0, "R_X86_64_SIZE32", Size),
            (R_X86_64_SIZE64.0, "R_X86_64_SIZE64", Size),
            (R_X86_64_COPY.0, "R_X86_64_COPY", Copy),
        ],
        // `FLAG_X8664_LIB64 | FLAG_ELF_LIBC6`. On x86-64
        // `_dl_cache_check_flags` accepts this value and nothing else, so an
        // entry with any other `flags` is one the loader would never load.
        ldso_cache_flags: 0x0303,
        lib_token: "lib64",
        default_lib_dirs: &[
            "/lib64",
            "/usr/lib64",
            "/lib",
            "/usr/lib",
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
        ],
        // x86-64 pages are 4 KiB. A 2 MiB `p_align`, which binutils used as
        // the default `max-page-size` before 2.31, is for huge pages.
        max_page_size: 0x1000,
        gnu_properties: GnuProperties {
            feature_1_and: GNU_PROPERTY_X86_FEATURE_1_AND.0,
            feature_1_family: "CET",
            feature_1_bits: &[
                (1 << 0, "IBT"),
                (1 << 1, "SHSTK"),
                (1 << 2, "LAM_U48"),
                (1 << 3, "LAM_U57"),
            ],
            isa_1_needed: Some(GNU_PROPERTY_X86_ISA_1_NEEDED.0),
        },
        // The stub is six bytes; the other eight of the fourteen reserved
        // are left zero, where an absolute address once followed it.
        trampoline: Trampoline {
            len: 14,
            encode: trampoline,
        },
        code: MachineCode {
            scan,
            plt_stub_slot,
            veneer_short_branches,
        },
    }
};

/// `jmp qword ptr [rip + disp32]`, the indirect jump a PLT stub makes: the CPU
/// reads the function pointer the loader wrote into the GOT slot at `slot` and
/// jumps there. Being RIP-relative it needs no rebasing under PIE.
fn trampoline(vaddr: u64, slot: u64) -> anyhow::Result<Vec<u8>> {
    const LEN: u64 = 6;
    let rel = (slot as i64).wrapping_sub(vaddr.wrapping_add(LEN) as i64);
    let rel = i32::try_from(rel).map_err(|_| {
        anyhow::anyhow!(
            "GOT slot offset 0x{rel:x} does not fit in i32 \
             (stub at 0x{vaddr:x}, target at 0x{slot:x})"
        )
    })?;
    let mut out = vec![0xff, 0x25];
    out.extend_from_slice(&rel.to_le_bytes());
    Ok(out)
}

/// [`MachineCode::scan`]: decode the unit once, as far as its code runs, and
/// read both its references and its jump tables out of that one stream.
/// Decoding is what extraction spends most of its time on.
fn scan(unit: &TextUnit<'_, '_>) -> Result<UnitScan> {
    let code = decode_to_code_bound(unit.bytes, unit.vaddr, unit.fde_end);
    let refs = scan_rip_relative_refs(&code.instrs, unit.bytes, unit.vaddr);
    // A table the detector cannot read is left as it is, as it always was:
    // detection is a best effort over a pattern, not a claim the code makes.
    let jump_tables = jump_table::detect_jump_tables(
        &code.instrs,
        code.len as u64,
        unit.vaddr,
        unit.sym,
        unit.elf,
    )
    .unwrap_or_default();
    Ok(UnitScan { refs, jump_tables })
}

/// A text unit's instruction stream, and how many of the unit's leading bytes
/// those instructions cover.
struct UnitCode {
    /// The unit's first `len` bytes, decoded.
    instrs: Vec<Instruction>,
    /// How many of a text unit's leading bytes are instructions of the function
    /// it was extracted for.
    len: usize,
}

/// Decode a text unit's code, stopping where the function's instructions do.
///
/// A unit covers the function plus everything the linker left between its last
/// instruction and the bound extraction stopped at: alignment padding, and —
/// in the hand-written assembly libcrypto is full of — the constants the module
/// keeps in `.text` next to the code that uses them (CRYPTOGAMS' banner
/// strings, RC4's option strings). Decoding that tail as code invents
/// relocations, extraction dependencies and short-branch veneers out of
/// constant data: `.solder.anon.0x20db00` in `test/libs/libcrypto.so.3` is a
/// 0x63-byte function followed by 0x4d bytes of banner string, which decodes
/// into seven bogus rel8 branches and a reference 0x20 MiB outside the library.
/// One such invention — a rel8 branch with nowhere to put its veneer — is a
/// hard error, so the fiction is not merely wasteful.
///
/// `.eh_frame` says where the function ends. Trust it only where the
/// instruction stream agrees: the last instruction inside the FDE has to end
/// exactly at the FDE's end and has to be one that does not fall through.
/// Hand-written assembly whose unwind info covers only part of its function
/// fails that test and keeps being scanned to the end of the unit, since
/// missing a relocation in real code is far worse than inventing one in data.
fn decode_to_code_bound(bytes: &[u8], vaddr: u64, fde_end: Option<u64>) -> UnitCode {
    // A bound at or past the end of the unit leaves nothing to cut.
    let claimed = fde_end
        .and_then(|end| end.checked_sub(vaddr))
        .map(|len| len as usize)
        .filter(|&len| len < bytes.len());

    // Decode only as far as the unwind info claims the function runs. Where the
    // claim holds, the tail — which is not code — is never decoded at all,
    // which is the point of cutting there in the first place.
    let Some(len) = claimed else {
        return UnitCode {
            instrs: decode_instructions(bytes, vaddr),
            len: bytes.len(),
        };
    };

    let mut instrs = decode_instructions(&bytes[..len], vaddr);
    if ends_the_function(&instrs, vaddr + len as u64) {
        return UnitCode { instrs, len };
    }

    // The claim was rejected, so the scanners get the whole unit. Decoding one
    // instruction does not depend on what follows it, so what has been decoded
    // already stands — bar a last instruction the cut may have run through the
    // middle of — and the decode picks up after it instead of starting over.
    instrs.pop();
    let resume = instrs.last().map_or(vaddr, |i| i.next_ip());
    instrs.extend(decode_instructions(
        &bytes[(resume - vaddr) as usize..],
        resume,
    ));
    UnitCode {
        instrs,
        len: bytes.len(),
    }
}

/// Whether the decode agrees that a function ends at `end`: the last
/// instruction has to end exactly on it and has to be one that does not fall
/// through. Anything else — unwind info that stops mid-function, a bound that
/// lands inside an instruction — is not an ending.
fn ends_the_function(instrs: &[Instruction], end: u64) -> bool {
    use iced_x86::FlowControl;

    instrs.last().is_some_and(|last| {
        !last.is_invalid()
            && last.next_ip() == end
            && matches!(
                last.flow_control(),
                FlowControl::Return
                    | FlowControl::UnconditionalBranch
                    | FlowControl::IndirectBranch
                    | FlowControl::Exception
            )
    })
}

/// How many bytes `instr` touches at its RIP-relative memory operand, or
/// `None` where the instruction does not say.
///
/// A memory operand's width is the whole of what the instruction reads or
/// writes, which is what makes it a bound on the object: `movdqa [rip+d],
/// %xmm0` reads sixteen bytes and cannot reach the seventeenth. Two kinds of
/// instruction do not bound anything:
///
///   * `lea`, which computes the address and leaves what lives there to
///     whatever uses it — the base of a string, of a table indexed by a
///     register, of a struct read field by field. iced reports its memory size
///     as unknown, which is exactly right.
///   * the bit-test family with a register bit offset (`bt %rax, [rip+d]`),
///     where the operand width is the unit the offset counts in and not the
///     extent touched: the accessed word is `offset / width` of them along.
fn rip_access_len(instr: &Instruction) -> Option<u64> {
    use iced_x86::{Mnemonic, OpKind};

    if matches!(
        instr.mnemonic(),
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
    ) && instr.op_count() > 1
        && instr.op_kind(1) != OpKind::Immediate8
    {
        return None;
    }
    Some(instr.memory_size().size() as u64).filter(|&len| len > 0)
}

/// Decode `bytes`, loaded at `vaddr`, into an instruction stream.
pub(crate) fn decode_instructions(bytes: &[u8], vaddr: u64) -> Vec<Instruction> {
    use iced_x86::{Decoder, DecoderOptions};

    let mut decoder = Decoder::with_ip(64, bytes, vaddr, DecoderOptions::NONE);
    // An `Instruction` is forty bytes and x86-64 instructions average rather
    // under four, so growing the vector from nothing copies the stream several
    // times over on the way up — and the stream is every text byte solder
    // extracts, 3.6 MB of it for `test/md5sum` against `libcrypto.so.3`. Three
    // bytes an instruction is a deliberate under-estimate of the length: it
    // leaves room for the densest real code without over-allocating by much on
    // the rest, and a stream that beats it still only grows the once.
    let mut instrs = Vec::with_capacity(bytes.len() / 3 + 1);
    while decoder.can_decode() {
        // Decoding into the vector's own slot is one forty-byte copy rather
        // than two: `decode` returns by value and `push` then moves it in.
        instrs.push(Instruction::default());
        decoder.decode_out(instrs.last_mut().expect("just pushed"));
    }
    instrs
}

/// Scan decoded machine code for all RIP-relative references (calls, jumps, and
/// data accesses). Returns a list of references with their offsets and target
/// addresses.
///
/// `bytes` is the unit the instructions were decoded from, needed to locate the
/// encoded displacement inside each instruction; `instrs` may cover only a
/// prefix of it.
fn scan_rip_relative_refs(instrs: &[Instruction], bytes: &[u8], base_vaddr: u64) -> Vec<CodeRef> {
    use iced_x86::{FlowControl, OpKind};

    let mut refs = Vec::new();

    for instr in instrs {
        let instr_offset = (instr.ip() - base_vaddr) as usize;

        match instr.flow_control() {
            FlowControl::Call
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch => {
                // Near call/jmp/jcc. rel32 forms carry the displacement in the
                // last 4 bytes; short (rel8) jmp/jcc forms in the last byte.
                // Verify the encoded bytes actually match before recording, so
                // an unexpected encoding is skipped instead of corrupted.
                if instr.op_count() >= 1 && instr.op_kind(0) == OpKind::NearBranch64 {
                    let target = instr.near_branch_target();
                    let rel = target.wrapping_sub(instr.next_ip()) as i64;
                    let instr_bytes = &bytes[instr_offset..instr_offset + instr.len()];
                    let is_rel32 = instr.len() >= 5
                        && i32::try_from(rel)
                            .is_ok_and(|r| instr_bytes[instr.len() - 4..] == r.to_le_bytes());
                    let is_rel8 = !is_rel32
                        && i8::try_from(rel).is_ok_and(|r| instr_bytes[instr.len() - 1] == r as u8);
                    if is_rel32 || is_rel8 {
                        let word = if is_rel32 { Word::Pc32 } else { Word::Pc8 };
                        refs.push(CodeRef {
                            offset: instr_offset + instr.len() - word.width(),
                            target_vaddr: target,
                            is_code_ref: true,
                            access_len: None,
                            site: RefSite::Disp {
                                word,
                                addend: -(word.width() as i64),
                            },
                        });
                    }
                }
            }
            // `is_ip_rel_memory_operand` describes the instruction and not any
            // one of its operands, so an instruction that addresses nothing
            // through RIP has no operand worth looking at. Asking once settles
            // the great majority of the stream — the scan sees every text byte
            // the merge extracts, 3.6 MB of it for `test/md5sum` against
            // `libcrypto.so.3` — where asking inside the loop walked the
            // operands of each of them first.
            _ if !instr.is_ip_rel_memory_operand() => {}
            _ => {
                // Check all operands for RIP-relative memory references
                for op_idx in 0..instr.op_count() {
                    if instr.op_kind(op_idx) == OpKind::Memory {
                        let target = instr.ip_rel_memory_address();
                        // Find the displacement bytes within the instruction.
                        // The disp32 encodes (target - next_ip) as a signed 32-bit value.
                        let disp32 = (target as i64 - instr.next_ip() as i64) as i32;
                        let disp_bytes = disp32.to_le_bytes();
                        let instr_bytes = &bytes[instr_offset..instr_offset + instr.len()];
                        // Search backwards — the displacement is near the end
                        let disp_pos = instr_bytes.windows(4).rposition(|w| w == disp_bytes);
                        if let Some(pos) = disp_pos {
                            refs.push(CodeRef {
                                offset: instr_offset + pos,
                                target_vaddr: target,
                                is_code_ref: false,
                                access_len: rip_access_len(instr),
                                site: RefSite::Disp {
                                    word: Word::Pc32,
                                    addend: -((instr.len() - pos) as i64),
                                },
                            });
                        }
                        break; // Only one memory operand per instruction
                    }
                }
            }
        }
    }

    refs
}

/// The GOT slot the x86-64 PLT stub at `addr` in a PLT section loaded at
/// `sec_addr` jumps through. Every flavor (.plt, .plt.got, .plt.sec) starts
/// with an optional endbr64 and/or bnd prefix followed by `ff 25 <disp32>`
/// (jmp [rip+disp32]) through its GOT slot.
fn plt_stub_slot(sec_data: &[u8], sec_addr: u64, addr: u64) -> Option<u64> {
    let mut off = (addr - sec_addr) as usize;
    if sec_data.len() >= off + 4 && sec_data[off..off + 4] == [0xf3, 0x0f, 0x1e, 0xfa] {
        off += 4; // endbr64
    }
    if sec_data.get(off) == Some(&0xf2) {
        off += 1; // bnd prefix
    }
    if sec_data.len() < off + 6 || sec_data[off] != 0xff || sec_data[off + 1] != 0x25 {
        return None; // not an indirect-jump stub (e.g. the PLT0 resolver)
    }
    let disp = i32::from_le_bytes(sec_data[off + 2..off + 6].try_into().expect("4 bytes"));
    Some((sec_addr + off as u64 + 6).wrapping_add(disp as i64 as u64))
}

/// Rewrite each short (rel8) branch relocation through a 5-byte `jmp rel32`
/// veneer. A 1-byte displacement can rarely reach its real target once units
/// are repacked. The veneer goes at the end of the unit when the short jump
/// can reach it; for larger units (over-extended anonymous units in stripped
/// libraries), it overwrites the never-executed inter-function alignment
/// padding that follows the branch instead.
fn veneer_short_branches(
    bytes: &mut Vec<u8>,
    relocs: &mut [ExtractedReloc],
    sym: &str,
) -> Result<()> {
    for reloc in relocs.iter_mut() {
        if reloc.site != Site::Word(Word::Pc8) {
            continue;
        }
        let disp_off = reloc.offset_within_unit as usize;
        let end_off = bytes.len();
        let veneer_off = if end_off as i64 - (disp_off as i64 + 1) <= i8::MAX as i64 {
            bytes.extend_from_slice(&[0xe9, 0, 0, 0, 0]);
            end_off
        } else if let Some(slot) = find_padding_slot(bytes, disp_off + 1, 5) {
            bytes[slot..slot + 5].copy_from_slice(&[0xe9, 0, 0, 0, 0]);
            slot
        } else {
            bail!(
                "short jump at offset {:#x} in '{}' has no reachable spot for a \
                 rel32 veneer (unit end {} bytes away, no padding after the jump)",
                disp_off,
                sym,
                end_off - disp_off
            );
        };
        bytes[disp_off] = (veneer_off as i64 - (disp_off as i64 + 1)) as i8 as u8;
        reloc.offset_within_unit = veneer_off as u64 + 1;
        reloc.site = Site::Word(Word::Pc32);
        // The addend of a scanned branch is -(displacement width) plus the
        // target's offset into its unit. Only the width changes here, from the
        // rel8 field to the veneer's rel32 one; the target offset must survive.
        reloc.addend -= 3;
    }
    Ok(())
}

/// Find a run of at least `need` bytes of alignment padding starting at
/// `start`: nop-family instructions or int3 fill emitted between functions,
/// which is never executed and can be overwritten by a branch veneer.
fn find_padding_slot(bytes: &[u8], start: usize, need: usize) -> Option<usize> {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

    if start >= bytes.len() {
        return None;
    }
    let mut decoder = Decoder::with_ip(64, &bytes[start..], 0, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut run = 0usize;
    while decoder.can_decode() && run < need {
        decoder.decode_out(&mut instr);
        match instr.mnemonic() {
            Mnemonic::Nop | Mnemonic::Int3 => run += instr.len(),
            _ => break,
        }
    }
    (run >= need).then_some(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `lea` is the reference that cannot be bounded: it hands out an address
    /// and says nothing about what lives there, so the copy has to run to
    /// whatever the library itself names above it. A load of the same address
    /// through the same
    /// displacement does say, and iced is where both answers come from — so
    /// hold it to them rather than to the documentation.
    #[test]
    fn an_address_taken_by_lea_is_unbounded_and_a_load_of_it_is_not() {
        // 48 8d 05 10 00 00 00   lea  rax, [rip+0x10]
        // 48 8b 05 10 00 00 00   mov  rax, [rip+0x10]
        // 0f 10 05 10 00 00 00   movups xmm0, [rip+0x10]
        // 80 3d 10 00 00 00 00   cmp  byte [rip+0x10], 0
        // 48 0f a3 05 10 00 00 00  bt   [rip+0x10], rax
        let code: &[u8] = &[
            0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00,
            0x0f, 0x10, 0x05, 0x10, 0x00, 0x00, 0x00, 0x80, 0x3d, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x0f, 0xa3, 0x05, 0x10, 0x00, 0x00, 0x00,
        ];
        let instrs = decode_instructions(code, 0x1000);
        let lens: Vec<Option<u64>> = instrs.iter().map(rip_access_len).collect();
        assert_eq!(
            lens,
            vec![None, Some(8), Some(16), Some(1), None],
            "decoded as {:?}",
            instrs
                .iter()
                .map(|i| (i.mnemonic(), i.memory_size()))
                .collect::<Vec<_>>()
        );

        // And the scan passes that on: same displacement, different bound.
        let refs = scan_rip_relative_refs(&instrs, code, 0x1000);
        let bounds: Vec<Option<u64>> = refs.iter().map(|r| r.access_len).collect();
        assert_eq!(bounds, lens, "the scan dropped or reordered a bound");
    }

    /// The extent `decode_to_code_bound` settles on is what keeps the
    /// instruction scanners off the non-code tail of a text unit. It gets to
    /// cut only where the decode backs the unwind table up.
    mod instruction_extent_tests {
        const VA: u64 = 0x1000;

        /// How far `decode_to_code_bound` decodes, which is the extent the
        /// instruction scanners then get.
        fn instruction_extent(bytes: &[u8], vaddr: u64, fde_end: u64) -> usize {
            let code = super::super::decode_to_code_bound(bytes, vaddr, Some(fde_end));
            // Whatever the extent, the instructions handed on cover exactly it.
            assert_eq!(
                code.instrs.last().map_or(vaddr, |i| i.next_ip()),
                vaddr + code.len as u64,
                "decoded instructions do not span the reported extent"
            );
            code.len
        }

        /// `ret` followed by the kind of string constant hand-written assembly
        /// keeps next to its code. Everything after the `ret` is data.
        #[test]
        fn a_function_ending_in_ret_cuts_at_the_fde_end() {
            let mut bytes = vec![0x31, 0xc0, 0xc3]; // xor eax, eax; ret
            bytes.extend_from_slice(b"CRYPTOGAMS by <appro@openssl.org>\0");
            assert_eq!(instruction_extent(&bytes, VA, VA + 3), 3);
        }

        /// A tail call is just as much the end of the function as a `ret`.
        #[test]
        fn a_function_ending_in_a_jump_cuts_at_the_fde_end() {
            let mut bytes = vec![0xeb, 0x00]; // jmp .+0
            bytes.extend_from_slice(&[0x11; 16]);
            assert_eq!(instruction_extent(&bytes, VA, VA + 2), 2);
        }

        /// Unwind info that describes only a function's prologue — which
        /// hand-written assembly does carry — must not cost the rest of the
        /// function its relocations. A `ret` that reaches past the recorded end
        /// is the giveaway that real code continues.
        #[test]
        fn unwind_info_stopping_mid_function_scans_the_whole_unit() {
            // push rbp; mov rbp, rsp; ret — the FDE covers only the first two.
            let bytes = vec![0x55, 0x48, 0x89, 0xe5, 0xc3];
            assert_eq!(instruction_extent(&bytes, VA, VA + 4), bytes.len());
        }

        /// A fall-through last instruction means the function does not end at
        /// the recorded end either, however well the boundary lines up.
        #[test]
        fn a_fall_through_last_instruction_is_not_an_ending() {
            let bytes = vec![0x90, 0x90, 0x90, 0x90]; // nop * 4
            assert_eq!(instruction_extent(&bytes, VA, VA + 2), bytes.len());
        }

        /// A boundary the decode cannot land on exactly — here it falls inside
        /// the 4-byte `mov` — is not a boundary to cut on.
        #[test]
        fn a_boundary_inside_an_instruction_is_not_cut_on() {
            let bytes = vec![0x48, 0x89, 0xe5, 0xc3, 0x00]; // mov rbp, rsp; ret
            assert_eq!(instruction_extent(&bytes, VA, VA + 2), bytes.len());
        }

        /// An FDE that covers the unit (or more of it) leaves nothing to cut.
        #[test]
        fn an_fde_covering_the_whole_unit_changes_nothing() {
            let bytes = vec![0x31, 0xc0, 0xc3];
            assert_eq!(instruction_extent(&bytes, VA, VA + 3), bytes.len());
            assert_eq!(instruction_extent(&bytes, VA, VA + 0x100), bytes.len());
            assert_eq!(instruction_extent(&bytes, VA, VA - 1), bytes.len());
        }
    }
}
