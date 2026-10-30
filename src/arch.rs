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
//! What is *not* here yet is the machine code itself — instruction decoding,
//! PLT stub recognition, trampolines, jump tables — which is still x86-64 only
//! and is the reason [`SUPPORTED`] lists nothing else.

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
#[derive(Debug)]
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

/// One target architecture.
#[derive(Debug)]
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
        EM_X86_64, R_X86_64_COPY, R_X86_64_DTPMOD64, R_X86_64_DTPOFF32, R_X86_64_DTPOFF64,
        R_X86_64_GLOB_DAT, R_X86_64_GOTPC32_TLSDESC, R_X86_64_GOTTPOFF, R_X86_64_IRELATIVE,
        R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE, R_X86_64_SIZE32, R_X86_64_SIZE64, R_X86_64_TLSDESC,
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

    /// The relocation types the merge handles itself are pointer slots it
    /// fills in; one that also turned up as unliftable would be refused by the
    /// gate meant to let it through.
    #[test]
    fn no_handled_relocation_is_also_unliftable() {
        for arch in SUPPORTED {
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
}
