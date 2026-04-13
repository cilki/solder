use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use memmap2::Mmap;
use object::read::elf::ElfFile64;

/// A memory-mapped ELF file kept alive by its Mmap.
pub struct MappedElf {
    // Must be kept alive as long as `elf` borrows from it.
    _mmap: Mmap,
    pub path: PathBuf,
    elf_ptr: *const u8,
    elf_len: usize,
}

// SAFETY: Mmap is Send+Sync, and we only access elf_ptr while holding &self.
unsafe impl Send for MappedElf {}
unsafe impl Sync for MappedElf {}

impl MappedElf {
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("cannot mmap {}", path.display()))?;
        let ptr = mmap.as_ptr();
        let len = mmap.len();
        Ok(Self {
            _mmap: mmap,
            path: path.to_owned(),
            elf_ptr: ptr,
            elf_len: len,
        })
    }

    /// Borrow the raw bytes.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: ptr+len were derived from the Mmap which is still alive.
        unsafe { std::slice::from_raw_parts(self.elf_ptr, self.elf_len) }
    }

    /// Parse as a 64-bit ELF file.
    pub fn parse(&self) -> Result<ElfFile64<'_>> {
        ElfFile64::<object::Endianness>::parse(self.bytes())
            .with_context(|| format!("failed to parse ELF {}", self.path.display()))
    }
}

/// Convert a virtual address in a parsed ELF to a file offset.
/// Returns None if the VA is not covered by any PT_LOAD segment.
pub fn va_to_file_offset(elf: &ElfFile64<'_>, va: u64) -> Option<u64> {
    use object::read::elf::ProgramHeader;
    let endian = elf.endian();
    for seg in elf.elf_program_headers() {
        let p_type = seg.p_type(endian);
        if p_type != object::elf::PT_LOAD {
            continue;
        }
        let p_vaddr = seg.p_vaddr(endian);
        let p_filesz = seg.p_filesz(endian);
        let p_offset = seg.p_offset(endian);
        if va >= p_vaddr && va < p_vaddr + p_filesz {
            return Some(va - p_vaddr + p_offset);
        }
    }
    None
}

/// Find the virtual address of the last byte of the last PT_LOAD segment,
/// page-aligned up — used to find a free VA for the merged segment.
pub fn next_free_va(elf: &ElfFile64<'_>) -> u64 {
    use object::read::elf::ProgramHeader;
    let endian = elf.endian();
    let mut max_end: u64 = 0;
    for seg in elf.elf_program_headers() {
        if seg.p_type(endian) != object::elf::PT_LOAD {
            continue;
        }
        let end = seg.p_vaddr(endian).saturating_add(seg.p_memsz(endian));
        if end > max_end {
            max_end = end;
        }
    }
    // Page-align upward (4 KiB pages)
    (max_end + 0xfff) & !0xfff
}

/// Validate that the input ELF is a supported target:
/// - 64-bit ELF
/// - ET_EXEC or ET_DYN (PIE)
/// - EM_X86_64
/// - Has PT_DYNAMIC (dynamically linked)
///
/// Returns `true` if the executable is PIE (ET_DYN), `false` if non-PIE (ET_EXEC).
pub fn validate_executable(elf: &ElfFile64<'_>, path: &Path) -> Result<bool> {
    use object::elf::{ET_DYN, ET_EXEC};
    use object::read::elf::{FileHeader, ProgramHeader};

    let endian = elf.endian();
    let header = elf.elf_header();
    let e_type = header.e_type(endian);
    let e_machine = header.e_machine(endian);

    if e_machine != object::elf::EM_X86_64 {
        bail!(
            "{}: unsupported architecture e_machine=0x{:04x} (only EM_X86_64 is supported)",
            path.display(),
            e_machine
        );
    }

    let is_pie = if e_type == ET_DYN {
        true // PIE executable
    } else if e_type == ET_EXEC {
        false // Non-PIE executable
    } else {
        bail!(
            "{}: not an executable (e_type=0x{:04x})",
            path.display(),
            e_type
        );
    };

    // Check for PT_DYNAMIC
    let has_dynamic = elf.elf_program_headers().iter().any(
        |s: &object::elf::ProgramHeader64<object::Endianness>| {
            s.p_type(endian) == object::elf::PT_DYNAMIC
        },
    );
    if !has_dynamic {
        bail!(
            "{}: statically linked binary — nothing to merge",
            path.display()
        );
    }

    Ok(is_pie)
}

/// Convert a file offset to a virtual address in a parsed ELF.
/// Returns None if the offset is not covered by any PT_LOAD segment.
pub fn file_offset_to_va(elf: &ElfFile64<'_>, offset: u64) -> Option<u64> {
    use object::read::elf::ProgramHeader;
    let endian = elf.endian();
    for seg in elf.elf_program_headers() {
        let p_type = seg.p_type(endian);
        if p_type != object::elf::PT_LOAD {
            continue;
        }
        let p_offset = seg.p_offset(endian);
        let p_filesz = seg.p_filesz(endian);
        let p_vaddr = seg.p_vaddr(endian);
        if offset >= p_offset && offset < p_offset + p_filesz {
            return Some(offset - p_offset + p_vaddr);
        }
    }
    None
}
