//! Merging a library's thread-local storage into the executable's.
//!
//! A shared library's thread-local variables live in a block of its own, laid
//! out from the library's `PT_TLS` template, and every access to one goes
//! through a GOT slot the loader fills in from a dynamic relocation: a module
//! id and an offset in the block for `__tls_get_addr`, an offset from the
//! thread pointer for static TLS, or a TLS descriptor (see
//! [`crate::arch::TlsSlot`]). Each of those values is worked out by the loader
//! from the module the relocation names and an offset into that module's
//! block — and nothing about them is specific to *which* module that is.
//!
//! So the merge gives the executable one block holding its own variables and
//! every merged library's, and keeps each TLS relocation dynamic against the
//! executable itself (no symbol, the variable's offset in the merged block as
//! the addend), which is how a linker writes a TLS relocation against a
//! variable of the object's own. The loader then fills each copied slot with
//! what it would have put in the library's copy, on any architecture, with
//! static TLS, `__tls_get_addr` and TLS descriptors alike.
//!
//! What the merge must not do is move the executable's own variables: its code
//! reaches them at offsets from the thread pointer the linker fixed in the
//! instructions. Where the executable's block sits relative to the thread
//! pointer depends on the architecture's [`TlsLayout`], and [`plan`] lays the
//! libraries' blocks out on the side of it that leaves it where it was.

use anyhow::{Result, bail};
use object::read::elf::{ElfFile64, ProgramHeader};

use crate::arch::TlsLayout;
use crate::layout::align_up;

/// One object's `PT_TLS`: the template each thread's copy of its block starts
/// as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsBlock {
    /// The initialized part (`.tdata`), `p_filesz` bytes. The rest of the
    /// block, up to `memsz`, starts zeroed (`.tbss`).
    pub image: Vec<u8>,
    /// The size of the block, `p_memsz`.
    pub memsz: u64,
    /// `p_align`, at least 1.
    pub align: u64,
}

impl TlsBlock {
    /// The `PT_TLS` of `elf`, if it has one. `what` names the object for
    /// messages.
    pub fn of(elf: &ElfFile64<'_>, what: &str) -> Result<Option<TlsBlock>> {
        let endian = elf.endian();
        let Some(phdr) = elf
            .elf_program_headers()
            .iter()
            .find(|p| p.p_type(endian) == object::elf::PT_TLS)
        else {
            return Ok(None);
        };
        let (vaddr, filesz, memsz) = (
            phdr.p_vaddr(endian),
            phdr.p_filesz(endian),
            phdr.p_memsz(endian),
        );
        let align = phdr.p_align(endian).max(1);
        if !align.is_power_of_two() {
            bail!("{what}: PT_TLS alignment {align:#x} is not a power of two");
        }
        // The loader starts a block `p_vaddr % p_align` bytes into an aligned
        // run, so that its variables keep the alignment the linker gave them
        // relative to an address. Every linker aligns the segment, and a
        // block that does not start aligned cannot be moved to the start of
        // one without moving its variables off their alignment.
        if vaddr % align != 0 {
            bail!(
                "{what}: PT_TLS at {vaddr:#x} does not start on its own {align:#x}-byte \
                 alignment, which the merge cannot keep"
            );
        }
        if filesz > memsz {
            bail!("{what}: PT_TLS holds {filesz:#x} initialized bytes of a {memsz:#x}-byte block");
        }
        let image = phdr
            .data(endian, elf.data())
            .map_err(|_| anyhow::anyhow!("{what}: PT_TLS template is not in the file"))?;
        Ok(Some(TlsBlock {
            image: image.to_vec(),
            memsz,
            align,
        }))
    }
}

/// The executable's block once the merged libraries' blocks have joined it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedTls {
    /// Where each library's block starts within the merged block, in the
    /// order the libraries were given: the offset a variable at offset `v` of
    /// that library's block is at now.
    pub lib_offsets: Vec<u64>,
    /// Where the executable's own block starts within the merged block: 0
    /// unless the libraries went in front of it.
    pub exe_offset: u64,
    /// The merged template's initialized part: every block's `.tdata` at its
    /// place, with the `.tbss` of any block followed by another one written
    /// out as the zeros it starts as.
    pub image: Vec<u8>,
    /// The size of the merged block.
    pub memsz: u64,
    /// The merged block's alignment: the largest of its parts'.
    pub align: u64,
}

/// Lay out the executable's own block, `exe` if it has one, together with the
/// blocks of the libraries merged into it.
///
/// The executable's variables have to stay where its code expects them,
/// relative to the thread pointer; see the module documentation. glibc puts
/// the executable's block (`_dl_determine_tlsoffset`, which handles it first):
///
/// * [`TlsLayout::BelowTp`]: `roundup(p_memsz, p_align)` below the thread
///   pointer, so its *end* is what the code is fixed relative to. The
///   libraries go in front of it, and the space in front is sized so that the
///   merged block, rounded up to its alignment, still ends exactly where the
///   executable's did.
/// * [`TlsLayout::AboveTp`]: at `roundup(tcb_size, p_align)` above it, so its
///   *start* is. The libraries go after it. A library alignment that would
///   move that start — one larger than both the executable's and the TCB — is
///   refused.
///
/// The first library to go in thus lands at offset 0 whenever the executable
/// has no TLS of its own, and under `BelowTp` even when it has.
pub fn plan(layout: TlsLayout, exe: Option<&TlsBlock>, libs: &[&TlsBlock]) -> Result<MergedTls> {
    let align = libs
        .iter()
        .chain(exe.as_slice())
        .map(|b| b.align)
        .max()
        .unwrap_or(1);

    // Each library's block after the one before it, from `start`.
    let place_libs = |start: u64| {
        let mut end = start;
        let offsets: Vec<u64> = libs
            .iter()
            .map(|lib| {
                let at = align_up(end, lib.align);
                end = at + lib.memsz;
                at
            })
            .collect();
        (offsets, end)
    };

    let mut parts: Vec<(u64, &TlsBlock)> = Vec::new();
    let (lib_offsets, memsz) = match (layout, exe) {
        (_, None) => place_libs(0),
        (TlsLayout::BelowTp, Some(exe)) => {
            let (offsets, libs_end) = place_libs(0);
            // How far below the thread pointer the executable's block starts,
            // which the merged block's rounded size has to equal once the
            // libraries' space is taken off it.
            let below_tp = align_up(exe.memsz, exe.align);
            // `below_tp` is a multiple of the executable's alignment, and so is
            // `at` — every alignment is a power of two dividing `align` — so
            // the executable's variables keep theirs too.
            let at = align_up(libs_end + below_tp, align) - below_tp;
            parts.push((at, exe));
            (offsets, at + exe.memsz)
        }
        (TlsLayout::AboveTp { tcb_size }, Some(exe)) => {
            if align_up(tcb_size, align) != align_up(tcb_size, exe.align) {
                bail!(
                    "a merged library's thread-local storage is aligned to {align:#x} bytes, \
                     which would move the executable's own thread-local variables away from \
                     where its code expects them (its block is aligned to {:#x})",
                    exe.align
                );
            }
            parts.push((0, exe));
            place_libs(exe.memsz)
        }
    };
    let exe_offset = parts.first().map_or(0, |&(at, _)| at);
    parts.extend(lib_offsets.iter().copied().zip(libs.iter().copied()));

    let image_len = parts
        .iter()
        .map(|(at, b)| at + b.image.len() as u64)
        .max()
        .unwrap_or(0);
    let mut image = vec![0u8; image_len as usize];
    for (at, block) in parts {
        let at = at as usize;
        image[at..at + block.image.len()].copy_from_slice(&block.image);
    }

    Ok(MergedTls {
        lib_offsets,
        exe_offset,
        image,
        memsz,
        align,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(image: &[u8], memsz: u64, align: u64) -> TlsBlock {
        TlsBlock {
            image: image.to_vec(),
            memsz,
            align,
        }
    }

    /// glibc's `l_tls_offset` for the executable's block, which comes first:
    /// how far from the thread pointer the block starts, below it for
    /// `BelowTp` and above it for `AboveTp`.
    fn exe_tls_offset(layout: TlsLayout, memsz: u64, align: u64) -> u64 {
        match layout {
            TlsLayout::BelowTp => align_up(memsz, align),
            TlsLayout::AboveTp { tcb_size } => align_up(tcb_size, align),
        }
    }

    /// Where a variable at `offset` of a block placed `at` in a module whose
    /// block is `memsz` bytes aligned to `align` ends up, relative to the
    /// thread pointer.
    fn tp_relative(layout: TlsLayout, memsz: u64, align: u64, at: u64, offset: u64) -> i128 {
        let start = exe_tls_offset(layout, memsz, align) as i128;
        let module_offset = (at + offset) as i128;
        match layout {
            TlsLayout::BelowTp => module_offset - start,
            TlsLayout::AboveTp { .. } => start + module_offset,
        }
    }

    const LAYOUTS: [TlsLayout; 2] = [TlsLayout::BelowTp, TlsLayout::AboveTp { tcb_size: 16 }];

    /// The one thing the plan exists to guarantee: every variable of the
    /// executable is where its code reaches it, at the same offset from the
    /// thread pointer, whatever the libraries brought with them.
    #[test]
    fn the_executables_own_variables_stay_where_its_code_reaches_them() {
        for layout in LAYOUTS {
            for (exe_memsz, exe_align) in [(4, 4), (0x14, 8), (0x30, 16), (1, 1), (0x40, 64)] {
                for (lib_memsz, lib_align) in [(4, 4), (0x18, 8), (0x21, 16), (8, 32)] {
                    let exe = block(&[], exe_memsz, exe_align);
                    let lib = block(&[], lib_memsz, lib_align);
                    let Ok(merged) = plan(layout, Some(&exe), &[&lib, &lib]) else {
                        // Refused only where the alignment would move it.
                        assert!(matches!(layout, TlsLayout::AboveTp { .. }));
                        assert!(lib_align > exe_align.max(16));
                        continue;
                    };
                    let at = merged.exe_offset;
                    assert!(at + exe_memsz <= merged.memsz);
                    for v in [0, exe_memsz - 1] {
                        assert_eq!(
                            tp_relative(layout, merged.memsz, merged.align, at, v),
                            tp_relative(layout, exe_memsz, exe_align, 0, v),
                            "{layout:?}: exe {exe_memsz:#x}/{exe_align}, \
                             lib {lib_memsz:#x}/{lib_align}, variable {v}"
                        );
                    }
                    // Nothing overlaps the executable's block, and each
                    // library's keeps its alignment.
                    let exe_range = at..at + exe_memsz;
                    for &off in &merged.lib_offsets {
                        assert_eq!(off % lib_align, 0);
                        assert!(off + lib_memsz <= exe_range.start || off >= exe_range.end);
                        assert!(off + lib_memsz <= merged.memsz);
                    }
                }
            }
        }
    }

    #[test]
    fn a_library_merged_into_an_executable_without_tls_starts_the_block() {
        for layout in LAYOUTS {
            let lib = block(&[1, 2, 3, 4], 0x10, 8);
            let merged = plan(layout, None, &[&lib]).expect("nothing to keep in place");
            assert_eq!(merged.lib_offsets, [0]);
            assert_eq!(merged.image, [1, 2, 3, 4]);
            assert_eq!((merged.memsz, merged.align), (0x10, 8));
        }
    }

    /// Below the thread pointer the libraries go in front, so the first one
    /// still starts the block; the second follows the first's `.tbss`.
    #[test]
    fn below_the_thread_pointer_the_libraries_go_in_front_of_the_executable() {
        let exe = block(&[0xee; 4], 8, 8);
        let first = block(&[0xaa; 2], 6, 4);
        let second = block(&[0xbb; 4], 4, 4);
        let merged = plan(TlsLayout::BelowTp, Some(&exe), &[&first, &second]).unwrap();
        assert_eq!(merged.lib_offsets, [0, 8]);
        // The libraries take 12 bytes; the executable's block ends where an
        // 8-aligned block does.
        assert_eq!(merged.memsz, 24);
        let mut expected = vec![
            0xaa, 0xaa, 0, 0, 0, 0, 0, 0, 0xbb, 0xbb, 0xbb, 0xbb, 0, 0, 0, 0,
        ];
        expected.extend([0xee; 4]);
        assert_eq!(merged.image, expected);
    }

    /// Above the thread pointer the executable's block keeps its start, and
    /// its `.tbss` is written out as the zeros it starts as so that the
    /// library's `.tdata` can follow it.
    #[test]
    fn above_the_thread_pointer_the_libraries_follow_the_executable() {
        let exe = block(&[0xee; 2], 6, 4);
        let lib = block(&[0xaa; 3], 8, 8);
        let merged = plan(TlsLayout::AboveTp { tcb_size: 16 }, Some(&exe), &[&lib]).unwrap();
        assert_eq!(merged.lib_offsets, [8]);
        assert_eq!(merged.memsz, 16);
        assert_eq!(
            merged.image,
            [0xee, 0xee, 0, 0, 0, 0, 0, 0, 0xaa, 0xaa, 0xaa]
        );
    }

    #[test]
    fn an_alignment_that_would_move_the_executables_block_is_refused() {
        let exe = block(&[], 8, 8);
        let lib = block(&[], 8, 64);
        let err = plan(TlsLayout::AboveTp { tcb_size: 16 }, Some(&exe), &[&lib])
            .expect_err("the executable's block would move");
        assert!(format!("{err}").contains("0x40"), "{err}");
    }
}
