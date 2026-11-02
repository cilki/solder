//! What the merge needs to know about the machine an executable was built for.
//!
//! Every fact here used to be an x86-64 literal at the place that needed it —
//! a relocation number in the writer, a cache flag in the library search, a
//! multiarch directory list, an `e_machine` comparison in each of the three
//! gates that refuse a foreign object. An [`Arch`] collects them into one
//! value, chosen once from the executable's `e_machine` by [`Arch::of_machine`]
//! and handed to every stage that reads one, so that supporting a second
//! architecture is adding a descriptor rather than finding every literal.
//!
//! Each architecture lives in a module of its own — [`x86_64`], [`aarch64`] —
//! which defines its descriptor and everything that reads or writes its
//! machine code: decoding a function and finding the addresses it keeps
//! ([`MachineCode::scan`]), reading a PLT stub
//! ([`MachineCode::plt_stub_slot`]), keeping short branches in reach
//! ([`MachineCode::veneer_short_branches`]) and writing a trampoline
//! ([`Trampoline`]). Each relocation carries a [`Site`] that writes its own
//! value: a little-endian [`Word`] on any architecture, or an instruction
//! field the architecture's module encodes. The stages outside this module go through the
//! descriptor and never name an architecture, so a third one is a new module
//! and an entry in [`SUPPORTED`].

pub mod aarch64;
mod site;
pub mod x86_64;

pub use aarch64::AARCH64;
pub use site::{Site, Word};
pub use x86_64::X86_64;

use crate::types::{ExtractedReloc, RelocTarget};
use aarch64::InsnField;

/// Why a dynamic relocation type cannot be lifted into the merged executable:
/// its slot is filled with something other than `S + A`. See
/// `extractor::reject_unliftable_dynamic_reloc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unliftable {
    /// A static-link TLS relocation, which the linker resolves into GOT slots
    /// carrying the dynamic ones in [`TlsAbi`] and so never leaves in a
    /// linked library.
    Tls,
    /// Whatever an ifunc resolver returns.
    Ifunc,
    /// The symbol's size.
    Size,
    /// An executable-only copy relocation.
    Copy,
}

/// The dynamic relocation types the merge itself reads or writes.
#[derive(Debug, Clone)]
pub struct DynRelocTypes {
    /// `*slot = B + A`: rebasing a pointer by the load address.
    pub relative: u32,
    /// `*slot = S`: a GOT slot holding a symbol's address.
    pub glob_dat: u32,
    /// `*slot = S`: a PLT GOT slot holding a function's address.
    pub jump_slot: u32,
    /// Copy the symbol's initial value into the executable's own storage.
    pub copy: u32,
}

/// What a dynamic thread-local-storage relocation asks the loader to put in
/// its slot. Each is relative to a module's TLS block, which is why the merge
/// can keep them dynamic: once a library's `PT_TLS` block is part of the
/// executable's, the same relocation against the executable's own module (no
/// symbol, the variable's offset in the merged block as the addend) gets the
/// value the library's copy would have got. See [`crate::tls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsSlot {
    /// The module id `__tls_get_addr` looks the block up by.
    Module,
    /// The variable's offset within its module's block.
    Offset,
    /// The variable's offset from the thread pointer, for static TLS.
    ThreadPointer,
    /// A two-word TLS descriptor: a resolver and the argument it is called
    /// with.
    Descriptor,
}

/// Where a thread's static TLS blocks sit relative to its thread pointer,
/// which decides where the executable's own block is, and so which end of a
/// merged block it has to keep. See [`crate::tls::plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsLayout {
    /// Variant I (aarch64): the blocks follow a thread control block of
    /// `tcb_size` bytes the thread pointer points at, the executable's first.
    AboveTp { tcb_size: u64 },
    /// Variant II (x86-64): the blocks end at the thread pointer, the
    /// executable's last.
    BelowTp,
}

/// How an architecture lays out thread-local storage and names the dynamic
/// relocations that reach it.
#[derive(Debug, Clone)]
pub struct TlsAbi {
    pub layout: TlsLayout,
    /// Each dynamic TLS relocation type, as readelf names it, and what it
    /// puts in its slot.
    pub relocs: [(u32, &'static str, TlsSlot); 4],
}

impl TlsAbi {
    /// The name and the meaning of TLS relocation type `r_type`, if it is one.
    pub fn slot(&self, r_type: u32) -> Option<(&'static str, TlsSlot)> {
        self.relocs
            .iter()
            .find(|(t, ..)| *t == r_type)
            .map(|&(_, name, slot)| (name, slot))
    }

    /// The relocation type that fills a slot of kind `slot`.
    pub fn r_type(&self, slot: TlsSlot) -> u32 {
        self.relocs
            .iter()
            .find(|(.., s)| *s == slot)
            .map(|&(t, ..)| t)
            .expect("every TlsSlot kind has a relocation")
    }
}

/// The processor-specific GNU properties (`.note.gnu.property`) that describe
/// the program as a whole and that the merge re-derives over the merged-in
/// code; see `patcher::update_gnu_properties`.
#[derive(Debug, Clone)]
pub struct GnuProperties {
    /// The `GNU_PROPERTY_*_FEATURE_1_AND` type: control-flow protection
    /// features the loader turns on only when *every* object of the process
    /// claims them, so a merged library lacking one withdraws the claim.
    pub feature_1_and: u32,
    /// What the features in `feature_1_and` are collectively called ("CET").
    pub feature_1_family: &'static str,
    /// The bits of `feature_1_and` with their names, for naming the ones
    /// being dropped.
    pub feature_1_bits: &'static [(u32, &'static str)],
    /// The `GNU_PROPERTY_*_ISA_1_NEEDED` type, if the architecture has one:
    /// ISA levels the code needs, the union of every object's.
    pub isa_1_needed: Option<u32>,
}

/// The stub the merged code calls in place of a function that stays in a
/// shared library: it jumps to whatever address the loader resolved into a
/// GOT slot. See `writer::build_merged_segment`.
#[derive(Debug, Clone)]
pub struct Trampoline {
    /// The bytes `layout` reserves for each stub, at a 16-byte boundary.
    pub len: u64,
    /// The stub at `vaddr` that jumps through the GOT slot at `slot`, at most
    /// `len` bytes; an error if it cannot reach the slot from there.
    pub encode: fn(vaddr: u64, slot: u64) -> anyhow::Result<Vec<u8>>,
}

/// One target architecture.
#[derive(Debug, Clone)]
pub struct Arch {
    /// How messages name the architecture ("x86-64").
    pub name: &'static str,
    /// `e_machine` of every object built for it.
    pub e_machine: u16,
    /// The dynamic relocation types the merge handles itself.
    pub reloc: DynRelocTypes,
    /// The dynamic relocation types the merge refuses to lift, with their
    /// names, for the error that says why.
    pub unliftable_relocs: &'static [(u32, &'static str, Unliftable)],
    /// Thread-local storage: the block layout and its dynamic relocations.
    pub tls: TlsAbi,
    /// `_DL_CACHE_DEFAULT_ID`: the `flags` value an `ld.so.cache` entry has to
    /// carry for this architecture's loader to use it.
    pub ldso_cache_flags: u32,
    /// What ld.so substitutes for `$LIB`.
    pub lib_token: &'static str,
    /// The loader's built-in search directories, searched after the cache.
    pub default_lib_dirs: &'static [&'static str],
    /// The largest page size a kernel for this architecture runs with. An
    /// executable's `p_align` past it is a request for huge-page alignment
    /// rather than a page size; see `elf_reader::page_size`.
    pub max_page_size: u64,
    /// The GNU properties the merge recomputes for the whole program.
    pub gnu_properties: GnuProperties,
    /// How merged code reaches a function still resolved at runtime.
    pub trampoline: Trampoline,
    /// How the extractor reads and rewrites this architecture's code.
    pub code: MachineCode,
    /// Whether its compilers reach a static object as an offset from another
    /// one in the same section, as GCC's section anchors do (on by default for
    /// aarch64). Every object in a library's data section then has to keep its
    /// place relative to the others, so the extractor resolves an address in
    /// one to the section's single copy, never to the object's own unit, and
    /// grows the copy over every [`CodeRef::reaches`].
    pub anchored_data: bool,
}

impl Arch {
    /// The supported architecture objects with this `e_machine` are built for.
    pub fn of_machine(e_machine: u16) -> Option<&'static Arch> {
        SUPPORTED.iter().copied().find(|a| a.e_machine == e_machine)
    }
}

/// Every architecture the merge accepts an executable for.
pub static SUPPORTED: &[&Arch] = &[&X86_64, &AARCH64];

/// The extractor's view of an architecture's machine code: the steps of
/// extracting a function that depend on how its instructions are encoded.
#[derive(Debug, Clone)]
pub struct MachineCode {
    /// Read a text unit's code: how far it runs, every address its
    /// instructions keep and the jump tables it indexes. An error where the
    /// code holds a reference the scanner cannot account for, since copying it
    /// as it is would leave it aimed at wherever the old offset lands.
    pub scan: fn(&TextUnit<'_, '_>) -> anyhow::Result<UnitScan>,
    /// The GOT slot the PLT stub at `addr`, inside a PLT section loaded at
    /// `sec_addr` whose bytes are `sec_data`, jumps through; `None` when
    /// there is no stub there (the PLT0 resolver, a misaligned address).
    pub plt_stub_slot: fn(sec_data: &[u8], sec_addr: u64, addr: u64) -> Option<u64>,
    /// Send each relocation the unit `bytes` of the symbol `sym` carries in a
    /// field too short to be sure of reaching another unit through a veneer
    /// in the unit that does, rewriting the branch and moving the relocation
    /// to the veneer. An error when a branch cannot reach anywhere a veneer
    /// could go.
    pub veneer_short_branches:
        fn(bytes: &mut Vec<u8>, relocs: &mut [ExtractedReloc], sym: &str) -> anyhow::Result<()>,
}

/// One text unit handed to [`MachineCode::scan`].
pub struct TextUnit<'a, 'data> {
    /// The unit: the function plus whatever sits between its last instruction
    /// and the next bound, which is not code.
    pub bytes: &'a [u8],
    /// Where `bytes` was loaded in the library.
    pub vaddr: u64,
    /// Where `.eh_frame` says the function ends, if an FDE starts at `vaddr`.
    /// A unit covers the function plus everything the linker left before the
    /// bound extraction stopped at: alignment padding and, in the hand-written
    /// assembly libcrypto is full of, constants kept in `.text`. Scanning that
    /// tail as code invents relocations out of data, so a scanner stops at
    /// this bound — but only where the code agrees that it ends there, since
    /// unwind info covering just part of a function is common in assembly and
    /// missing a relocation in real code is far worse than inventing one in
    /// data.
    pub fde_end: Option<u64>,
    /// The symbol the unit is extracted for, for messages.
    pub sym: &'a str,
    /// The library, for what the code reads out of other sections (a jump
    /// table's entries).
    pub elf: &'a object::read::elf::ElfFile64<'data>,
    /// What a direct call to an address calls. A scanner that follows values
    /// along the code's paths needs it to know what survives the call, and
    /// whether the path goes on past it at all.
    pub callee: &'a dyn Fn(u64) -> Callee,
}

/// What a call calls, as far as the registers the caller may rely on across
/// it go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Callee {
    /// One of the library's own functions. GCC's `-fipa-ra` lets the caller
    /// keep values in caller-saved registers that a callee it compiled is
    /// known to leave alone, so any of them may survive.
    Local,
    /// A function only known at run time: an import, called through its PLT
    /// stub, or the target of an indirect call. Nothing the caller-saved
    /// registers held survives in them as far as the compiler knows, and
    /// `x0`/`x1` hold whatever it returns.
    External,
    /// One of the [`NORETURN_IMPORTS`]: the path ends at the call.
    NoReturn,
}

/// Functions a library imports that never return to their caller, which
/// glibc, libgcc and libstdc++ declare `noreturn`. A compiler takes them at
/// their word and places unrelated code straight after the call, so code
/// following the call is only reached through some other branch.
///
/// Only imports are listed, as a PLT stub names the function it calls; a
/// library's own `noreturn` functions are not known by any mark in the
/// binary, and a call to one is taken to return, which is what the
/// scanners assumed for every call before.
pub const NORETURN_IMPORTS: &[&str] = &[
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "__stack_chk_fail",
    "__chk_fail",
    "__fortify_fail",
    "__assert_fail",
    "__assert_perror_fail",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "pthread_exit",
    "err",
    "errx",
    "verr",
    "verrx",
    "_Unwind_Resume",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_throw_bad_array_new_length",
    "_ZSt9terminatev",
];

/// What [`MachineCode::scan`] found in a text unit.
#[derive(Debug, Default)]
pub struct UnitScan {
    /// Every address the code keeps. An architecture whose references come in
    /// pairs lists the half carrying the full address first; see
    /// [`RefSite::AdrpOf`].
    pub refs: Vec<CodeRef>,
    /// The jump tables the code indexes.
    pub jump_tables: Vec<JumpTable>,
}

/// A table of 32-bit offsets, each the distance from the table's base to a
/// branch target inside the function that indexes it. The table and the
/// function move apart in the merge, so each entry is relocated.
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// Virtual address of the table base in the shared library.
    pub table_vaddr: u64,
    /// Target virtual addresses, one per 4-byte table entry.
    pub targets: Vec<u64>,
}

/// An address found in machine code: an x86-64 RIP-relative displacement, or
/// an aarch64 instruction field.
#[derive(Debug, Clone)]
pub struct CodeRef {
    /// Byte offset within the code of the patch site: where the displacement
    /// starts, or the instruction word that holds the field.
    pub offset: usize,
    /// Target virtual address this reference points to.
    pub target_vaddr: u64,
    /// Whether this is a code reference (call/jmp) vs data reference (lea/mov).
    pub is_code_ref: bool,
    /// How many bytes at `target_vaddr` the instruction reads or writes, where
    /// the instruction says: that bounds the object the reference reaches, and
    /// so bounds how much of a data section has to be copied for it (see
    /// `extractor::needed_prefix`). `None` for a code reference, and for the
    /// instructions that take an address without saying what is at it.
    pub access_len: Option<u64>,
    /// How the address is written into the code.
    pub site: RefSite,
    /// The further addresses the code reaches from `target_vaddr` by adding
    /// constants to it, for an architecture whose compilers do that across
    /// objects (see [`Arch::anchored_data`]). Empty everywhere else.
    pub reaches: Vec<Reach>,
}

/// An address code goes on to reach from a [`CodeRef`]'s target by adding a
/// constant to it. GCC's section anchors take the address of one static
/// object and reach the objects after it in its section at constant offsets
/// from it, so this is what says how much of the section the reference needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reach {
    /// How far from the reference's target, in bytes.
    pub offset: i64,
    /// How many bytes are read or written there, where the instruction says.
    /// `None` for any other use of the address (indexed, passed on, stored),
    /// which reaches as far as the object at it goes.
    pub access_len: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum RefSite {
    /// An x86-64 little-endian displacement.
    Disp {
        /// The displacement: [`Word::Pc32`], or [`Word::Pc8`] for a short
        /// jump.
        word: Word,
        /// Relocation addend: -(bytes from displacement start to instruction
        /// end). This is -4 when the displacement is the final field, but
        /// instructions like `cmpb $imm, [rip+d]` carry an immediate after the
        /// displacement, which shifts next_ip further and makes the addend
        /// more negative.
        addend: i64,
    },
    /// An aarch64 instruction field.
    Insn(InsnField),
    /// The `adrp` half of an aarch64 pair. It is relocated against whatever
    /// the `:lo12:` instruction at this unit offset resolved to: the page is
    /// all an `adrp` encodes, so that is the only way to know which object it
    /// is for.
    AdrpOf(usize),
}

impl CodeRef {
    /// Whether the reference stays right when the unit moves as a whole and
    /// its target moves with it. A displacement, or an aarch64 branch or `adr`,
    /// to somewhere inside the same function is; an `adrp` pair is not, since
    /// it names a 4 KiB page and the low twelve bits of an absolute address,
    /// and the unit is not placed at the same offset into a page.
    pub fn moves_with_its_unit(&self) -> bool {
        match &self.site {
            RefSite::Disp { .. } => true,
            RefSite::Insn(insn) => insn.field != aarch64::Field::Lo12,
            RefSite::AdrpOf(_) => false,
        }
    }

    /// Whether this is the `:lo12:` half of an aarch64 pair, which carries the
    /// full address that the `adrp`s of the pair name only the page of: what it
    /// resolves to is what they are relocated against.
    pub fn completes_a_page(&self) -> bool {
        matches!(&self.site, RefSite::Insn(insn) if insn.field == aarch64::Field::Lo12)
    }

    /// The relocation writing `target`, `extra` bytes into it, at this site.
    pub fn reloc(&self, extra: i64, target: RelocTarget) -> ExtractedReloc {
        let (site, addend) = match &self.site {
            RefSite::Disp { word, addend } => (Site::Word(*word), addend + extra),
            RefSite::Insn(insn) => (Site::Aarch64(insn.clone()), extra),
            RefSite::AdrpOf(_) => (
                Site::Aarch64(InsnField {
                    field: aarch64::Field::AdrpPage,
                    adrps: Vec::new(),
                }),
                extra,
            ),
        };
        ExtractedReloc {
            offset_within_unit: self.offset as u64,
            site,
            addend,
            target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_executable_is_matched_to_its_descriptor_by_e_machine() {
        let arch = Arch::of_machine(object::elf::EM_X86_64.0).expect("x86-64 is supported");
        assert!(std::ptr::eq(arch, &X86_64));
        let arch = Arch::of_machine(object::elf::EM_AARCH64.0).expect("aarch64 is supported");
        assert!(std::ptr::eq(arch, &AARCH64));
    }

    /// Opening the gate for a machine is what adding its descriptor to
    /// `SUPPORTED` does, so until there is one nothing else gets through.
    #[test]
    fn a_machine_without_a_descriptor_is_not_supported() {
        for e_machine in [object::elf::EM_386.0, object::elf::EM_RISCV.0] {
            assert!(Arch::of_machine(e_machine).is_none(), "{e_machine}");
        }
    }

    /// Every descriptor, supported or not yet.
    const DESCRIBED: [&Arch; 2] = [&X86_64, &AARCH64];

    /// A descriptor nothing lets through is code only the tests run.
    #[test]
    fn every_described_architecture_is_supported() {
        for arch in DESCRIBED {
            assert!(
                SUPPORTED.iter().any(|s| std::ptr::eq(*s, arch)),
                "{}",
                arch.name
            );
        }
    }

    /// The relocation types the merge handles itself are pointer slots it
    /// fills in; one that also turned up as unliftable would be refused by the
    /// gate meant to let it through.
    #[test]
    fn no_handled_relocation_is_also_unliftable() {
        for arch in DESCRIBED {
            let r = &arch.reloc;
            for handled in [r.relative, r.glob_dat, r.jump_slot] {
                assert!(
                    !arch.unliftable_relocs.iter().any(|(t, ..)| *t == handled),
                    "{}: {handled}",
                    arch.name
                );
            }
        }
    }

    /// Each architecture numbers its relocations from its own range, so a
    /// type copied from the wrong one would be silently ignored or, worse,
    /// match an unrelated relocation of this one.
    #[test]
    fn the_aarch64_dynamic_relocations_are_its_own() {
        let r = &AARCH64.reloc;
        // AAELF64 table "Dynamic relocations": 1024 upwards.
        assert_eq!(
            (r.copy, r.glob_dat, r.jump_slot, r.relative),
            (1024, 1025, 1026, 1027)
        );
        let unliftable: Vec<u32> = AARCH64.unliftable_relocs.iter().map(|(t, ..)| *t).collect();
        assert_eq!(unliftable, [1032, 1024]);
        let tls: Vec<u32> = AARCH64.tls.relocs.iter().map(|(t, ..)| *t).collect();
        assert_eq!(tls, [1028, 1029, 1030, 1031]);
        let names = AARCH64.unliftable_relocs.iter().map(|(t, n, _)| (t, n));
        for (t, name) in names.chain(AARCH64.tls.relocs.iter().map(|(t, n, _)| (t, n))) {
            assert!(name.starts_with("R_AARCH64_"), "{t}: {name}");
        }
    }

    /// A TLS relocation is lifted as a TLS slot, so one that was also listed
    /// as unliftable would be refused before it got there; and each kind of
    /// slot has exactly one relocation filling it.
    #[test]
    fn each_tls_relocation_is_lifted_and_names_one_kind_of_slot() {
        for arch in DESCRIBED {
            for (t, name, slot) in &arch.tls.relocs {
                assert!(
                    !arch.unliftable_relocs.iter().any(|(u, ..)| u == t),
                    "{}: {name}",
                    arch.name
                );
                assert_eq!(arch.tls.r_type(*slot), *t, "{}: {name}", arch.name);
                assert_eq!(arch.tls.slot(*t), Some((*name, *slot)), "{}", arch.name);
            }
        }
    }

    /// A descriptor's own tables have to be internally consistent: one
    /// relocation type, one feature bit, one directory each.
    #[test]
    fn no_descriptor_repeats_an_entry() {
        for arch in DESCRIBED {
            let mut types: Vec<u32> = arch.unliftable_relocs.iter().map(|(t, ..)| *t).collect();
            types.sort_unstable();
            types.dedup();
            assert_eq!(types.len(), arch.unliftable_relocs.len(), "{}", arch.name);

            let bits = &arch.gnu_properties.feature_1_bits;
            for (i, (bit, name)) in bits.iter().enumerate() {
                assert_eq!(bit.count_ones(), 1, "{}: {name}", arch.name);
                assert!(
                    bits[i + 1..].iter().all(|(other, _)| other != bit),
                    "{}: {name}",
                    arch.name
                );
            }

            let dirs = arch.default_lib_dirs;
            for (i, dir) in dirs.iter().enumerate() {
                assert!(!dirs[i + 1..].contains(dir), "{}: {dir}", arch.name);
            }
        }
    }
}
