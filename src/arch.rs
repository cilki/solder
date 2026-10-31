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
//! What is *not* here is the machine code itself — instruction decoding,
//! PLT stub recognition, trampolines, jump tables. The extractor reads
//! aarch64 code as well as x86-64 now, but the writer still only emits x86-64
//! trampolines, which is why [`SUPPORTED`] lists nothing else even though
//! [`AARCH64`] is described.

/// Why a dynamic relocation type cannot be lifted into the merged executable:
/// its slot is filled with something other than `S + A`. See
/// `extractor::reject_unliftable_dynamic_reloc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unliftable {
    /// A module id, or an offset from the thread pointer.
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
}

impl Arch {
    /// The supported architecture objects with this `e_machine` are built for.
    pub fn of_machine(e_machine: u16) -> Option<&'static Arch> {
        SUPPORTED.iter().copied().find(|a| a.e_machine == e_machine)
    }
}

/// Every architecture the merge accepts an executable for.
pub static SUPPORTED: &[&Arch] = &[&X86_64];

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
    }
};

/// aarch64 (`EM_AARCH64`), LP64, per the ARM ELF ABI (AAELF64) and glibc's
/// `sysdeps/aarch64`.
///
/// Not in [`SUPPORTED`] yet: the writer cannot emit aarch64 trampolines, so
/// an aarch64 executable is still refused at the gate. Until then this is
/// what the per-architecture tables of the search, the reader, the extractor
/// and the patcher are tested against.
#[cfg_attr(not(test), allow(dead_code))]
pub static AARCH64: Arch = {
    use Unliftable::{Copy, Ifunc, Tls};
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
        // Every dynamic relocation AAELF64 defines other than the three above.
        // Unlike x86-64 there is no SIZE relocation, and the static TLS forms
        // (`TLSGD_ADR_PAGE21` and the rest) are resolved by the linker into
        // instruction fields and GOT slots carrying the dynamic ones below, so
        // they never reach a shared library's dynamic tables. The TLS names
        // are the ones readelf prints; `object` and glibc's `elf.h` drop the
        // `64`.
        unliftable_relocs: &[
            (R_AARCH64_TLS_DTPMOD.0, "R_AARCH64_TLS_DTPMOD64", Tls),
            (R_AARCH64_TLS_DTPREL.0, "R_AARCH64_TLS_DTPREL64", Tls),
            (R_AARCH64_TLS_TPREL.0, "R_AARCH64_TLS_TPREL64", Tls),
            (R_AARCH64_TLSDESC.0, "R_AARCH64_TLSDESC", Tls),
            (R_AARCH64_IRELATIVE.0, "R_AARCH64_IRELATIVE", Ifunc),
            (R_AARCH64_COPY.0, "R_AARCH64_COPY", Copy),
        ],
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
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_executable_is_matched_to_its_descriptor_by_e_machine() {
        let arch = Arch::of_machine(object::elf::EM_X86_64.0).expect("x86-64 is supported");
        assert!(std::ptr::eq(arch, &X86_64));
    }

    /// Opening the gate for a machine is what adding its descriptor to
    /// `SUPPORTED` does, so until there is one nothing else gets through.
    #[test]
    fn a_machine_without_a_descriptor_is_not_supported() {
        for e_machine in [
            object::elf::EM_AARCH64.0,
            object::elf::EM_386.0,
            object::elf::EM_RISCV.0,
        ] {
            assert!(Arch::of_machine(e_machine).is_none(), "{e_machine}");
        }
    }

    /// Every descriptor, supported or not yet.
    const DESCRIBED: [&Arch; 2] = [&X86_64, &AARCH64];

    #[test]
    fn every_supported_architecture_is_described() {
        for arch in SUPPORTED {
            assert!(
                DESCRIBED.iter().any(|d| std::ptr::eq(*d, *arch)),
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
        assert_eq!(unliftable, [1028, 1029, 1030, 1031, 1032, 1024]);
        for (t, name, _) in AARCH64.unliftable_relocs {
            assert!(name.starts_with("R_AARCH64_"), "{t}: {name}");
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
