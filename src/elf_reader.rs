use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
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

/// Size of an `Elf64_Dyn`: `d_tag` (8 bytes) followed by `d_val`/`d_ptr`.
pub const DYN_ENTRY_SIZE: usize = 16;

/// The `.dynamic` table of an ELF image, decoded from its raw bytes.
///
/// Nearly every stage of a merge reads `.dynamic`: import collection wants
/// `DT_NEEDED`/`DT_RPATH`/`DT_RUNPATH`, layout wants the executable's
/// init/fini arrays, the patcher rewrites `DT_NEEDED`/`DT_FLAGS`/`DT_VERNEED`
/// in place, and the writer repoints `DT_RELA`/`DT_STRTAB`/`DT_SYMTAB` at the
/// tables it rebuilds in the merged segment. A stage that *writes* an entry
/// needs its slot index as well as its value, which no ELF reader hands out,
/// so each of them used to locate `PT_DYNAMIC` and walk the entries itself.
/// This decodes the table once; a caller only names the tag it is after.
///
/// `PT_DYNAMIC` is the authority rather than the `.dynamic` section header,
/// because that is what the dynamic loader reads and because patching moves
/// entries around without touching section headers.
pub struct DynamicTable {
    /// File offset of the first `Elf64_Dyn` entry.
    offset: usize,
    /// Slots `PT_DYNAMIC` covers, including the `DT_NULL` terminator and any
    /// spare ones after it. New entries can only be appended at the
    /// terminator, so the spare slots are what bounds how many will fit.
    capacity: usize,
    /// `(d_tag, d_val)` of every entry before the `DT_NULL` terminator, in
    /// file order — so an entry's position here is also its slot index.
    entries: Vec<(u64, u64)>,
    /// File offset of `DT_STRTAB`, i.e. the base `string_at` resolves against.
    strtab_offset: Option<usize>,
}

impl DynamicTable {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        // Walk the program header table out of the raw bytes: `parse` is also
        // handed a partially patched image, which a full ELF reader would
        // have to re-validate.
        let phoff = read_u64(bytes, 0x20)? as usize;
        let phentsize = read_u16(bytes, 0x36)? as usize;
        let phnum = read_u16(bytes, 0x38)? as usize;
        if phentsize < 56 {
            bail!("ELF program header entries are {phentsize} bytes, expected at least 56");
        }

        let mut dynamic: Option<(usize, u64)> = None;
        // (p_vaddr, p_filesz, p_offset) of each PT_LOAD, for DT_STRTAB.
        let mut loads: Vec<(u64, u64, u64)> = Vec::new();
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            let p_offset = read_u64(bytes, ph + 8)?;
            let p_vaddr = read_u64(bytes, ph + 16)?;
            let p_filesz = read_u64(bytes, ph + 32)?;
            let p_type = read_u32(bytes, ph)?;
            if p_type == object::elf::PT_DYNAMIC.0 {
                dynamic = Some((p_offset as usize, p_filesz));
            } else if p_type == object::elf::PT_LOAD.0 {
                loads.push((p_vaddr, p_filesz, p_offset));
            }
        }

        let (offset, filesz) = dynamic.context("no PT_DYNAMIC segment")?;
        let capacity = filesz as usize / DYN_ENTRY_SIZE;

        let mut entries = Vec::with_capacity(capacity);
        for i in 0..capacity {
            let at = offset + i * DYN_ENTRY_SIZE;
            let tag = read_u64(bytes, at)?;
            if tag == goblin::elf::dynamic::DT_NULL {
                break;
            }
            entries.push((tag, read_u64(bytes, at + 8)?));
        }

        let strtab_offset = entries
            .iter()
            .find(|&&(tag, _)| tag == goblin::elf::dynamic::DT_STRTAB)
            .and_then(|&(_, va)| {
                loads
                    .iter()
                    .find(|&&(vaddr, filesz, _)| va >= vaddr && va < vaddr + filesz)
                    .map(|&(vaddr, _, off)| (va - vaddr + off) as usize)
            });

        Ok(Self {
            offset,
            capacity,
            entries,
            strtab_offset,
        })
    }

    /// Slots `PT_DYNAMIC` covers, terminator and spares included.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of entries before the `DT_NULL` terminator — equivalently, the
    /// terminator's own slot index.
    pub fn used(&self) -> usize {
        self.entries.len()
    }

    /// `(slot index, d_val)` of every entry tagged `tag`, in file order. Only
    /// `DT_NEEDED` legitimately repeats, so the other tags yield at most one.
    pub fn entries_of(&self, tag: u64) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter(move |&(_, &(t, _))| t == tag)
            .map(|(i, &(_, val))| (i, val))
    }

    /// Slot index of the first entry tagged `tag`.
    pub fn index_of(&self, tag: u64) -> Option<usize> {
        self.entries_of(tag).next().map(|(i, _)| i)
    }

    /// `d_val` of the first entry tagged `tag`.
    pub fn value_of(&self, tag: u64) -> Option<u64> {
        self.entries_of(tag).next().map(|(_, val)| val)
    }

    /// `d_val` of every entry tagged `tag`, in file order.
    pub fn values_of(&self, tag: u64) -> impl Iterator<Item = u64> + '_ {
        self.entries_of(tag).map(|(_, val)| val)
    }

    /// File offset of slot `index`'s `d_tag`.
    pub fn entry_offset(&self, index: usize) -> usize {
        self.offset + index * DYN_ENTRY_SIZE
    }

    /// File offset of slot `index`'s `d_val`.
    pub fn value_offset(&self, index: usize) -> usize {
        self.entry_offset(index) + 8
    }

    /// The `.dynstr` string at `d_val`, for the tags whose value is a string
    /// table index (`DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`, `DT_SONAME`).
    pub fn string_at<'b>(&self, bytes: &'b [u8], d_val: u64) -> Option<&'b str> {
        let start = self.strtab_offset?.checked_add(d_val as usize)?;
        let rest = bytes.get(start..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&rest[..end]).ok()
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = bytes
        .get(offset..offset + 2)
        .with_context(|| format!("u16 at file offset {offset:#x} is past the end"))?;
    Ok(u16::from_le_bytes(raw.try_into().expect("2 bytes")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .with_context(|| format!("u32 at file offset {offset:#x} is past the end"))?;
    Ok(u32::from_le_bytes(raw.try_into().expect("4 bytes")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw = bytes
        .get(offset..offset + 8)
        .with_context(|| format!("u64 at file offset {offset:#x} is past the end"))?;
    Ok(u64::from_le_bytes(raw.try_into().expect("8 bytes")))
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

#[cfg(test)]
mod dynamic_table_tests {
    use super::*;

    /// The committed `test/` executables are the ones solder actually patches.
    const TEST_BINARIES: [&str; 3] = ["grep", "bash", "md5sum"];

    fn read_test_binary(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test/").to_string() + name;
        std::fs::read(&path).expect("test binary")
    }

    /// Every stage that *writes* `.dynamic` addresses an entry by slot index
    /// and patches the file at `entry_offset`/`value_offset`, so a disagreement
    /// with an independent reader about either the ordering or the arithmetic
    /// silently corrupts a tag the loader then reads.
    #[test]
    fn slot_offsets_address_the_entry_an_independent_reader_sees() {
        for name in TEST_BINARIES {
            let bytes = read_test_binary(name);
            let table = DynamicTable::parse(&bytes).expect("parse .dynamic");
            let goblin = goblin::elf::Elf::parse(&bytes).expect("goblin parse");
            let dyns = &goblin.dynamic.as_ref().expect(".dynamic").dyns;

            // goblin keeps the DT_NULL terminator; `used()` stops before it.
            assert!(table.used() > 0, "{name}: empty .dynamic");
            assert_eq!(table.used() + 1, dyns.len(), "{name}: entry count");
            assert!(
                table.capacity() > table.used(),
                "{name}: capacity {} cannot hold {} entries plus a terminator",
                table.capacity(),
                table.used()
            );

            for (i, entry) in dyns[..table.used()].iter().enumerate() {
                let tag_at = table.entry_offset(i);
                let val_at = table.value_offset(i);
                assert_eq!(val_at, tag_at + 8, "{name}: d_val is not at d_tag + 8");
                assert_eq!(
                    u64::from_le_bytes(bytes[tag_at..tag_at + 8].try_into().unwrap()),
                    entry.d_tag,
                    "{name}: d_tag of slot {i}"
                );
                assert_eq!(
                    u64::from_le_bytes(bytes[val_at..val_at + 8].try_into().unwrap()),
                    entry.d_val,
                    "{name}: d_val of slot {i}"
                );
            }

            // The terminator sits in the slot `used()` names, which is where
            // `ensure_bind_now` and `update_dynamic_entries` append.
            let terminator = table.entry_offset(table.used());
            assert_eq!(
                u64::from_le_bytes(bytes[terminator..terminator + 8].try_into().unwrap()),
                goblin::elf::dynamic::DT_NULL,
                "{name}: slot {} is not the terminator",
                table.used()
            );
        }
    }

    #[test]
    fn needed_sonames_resolve_through_dynstr() {
        for name in TEST_BINARIES {
            let bytes = read_test_binary(name);
            let table = DynamicTable::parse(&bytes).expect("parse .dynamic");
            let goblin = goblin::elf::Elf::parse(&bytes).expect("goblin parse");

            let needed: Vec<&str> = table
                .values_of(goblin::elf::dynamic::DT_NEEDED)
                .map(|val| {
                    table
                        .string_at(&bytes, val)
                        .unwrap_or_else(|| panic!("{name}: unresolved DT_NEEDED at {val:#x}"))
                })
                .collect();
            assert_eq!(needed, goblin.libraries, "{name}");
            assert!(
                needed.iter().any(|s| s.starts_with("libc.so")),
                "{name}: {needed:?}"
            );
        }
    }

    /// A tag the executable has exactly one of must resolve to one slot, and a
    /// tag it has none of to none — `value_of` returning a stale `Some` would
    /// make the writer repoint an entry that does not exist.
    #[test]
    fn a_single_valued_tag_resolves_to_exactly_one_slot() {
        use goblin::elf::dynamic::{DT_NEEDED, DT_STRSZ, DT_STRTAB};

        let bytes = read_test_binary("grep");
        let table = DynamicTable::parse(&bytes).expect("parse .dynamic");

        for tag in [DT_STRTAB, DT_STRSZ] {
            assert_eq!(table.entries_of(tag).count(), 1, "tag {tag:#x}");
            let idx = table.index_of(tag).expect("index");
            assert_eq!(
                table.entries_of(tag).next(),
                Some((idx, table.value_of(tag).unwrap()))
            );
        }
        // DT_SONAME is an attribute of a shared object, not an executable.
        assert_eq!(table.value_of(goblin::elf::dynamic::DT_SONAME), None);
        assert!(table.entries_of(DT_NEEDED).count() >= 1);
    }

    #[test]
    fn a_truncated_image_is_an_error_rather_than_a_panic() {
        let bytes = read_test_binary("md5sum");
        assert!(DynamicTable::parse(&[]).is_err());
        assert!(DynamicTable::parse(&bytes[..64]).is_err());
        for len in (0..bytes.len()).step_by(997) {
            let _ = DynamicTable::parse(&bytes[..len]);
        }
    }
}
