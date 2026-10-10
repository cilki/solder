use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use memmap2::Mmap;
use object::read::elf::ElfFile64;

/// A memory-mapped ELF file. Everything that reads it borrows from `&self`,
/// so the mapping outlives every view handed out of it.
pub struct MappedElf {
    mmap: Mmap,
    path: PathBuf,
}

impl MappedElf {
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("cannot mmap {}", path.display()))?;
        Ok(Self {
            mmap,
            path: path.to_owned(),
        })
    }

    /// Borrow the mapped bytes. `Mmap` derefs to them, and the borrow is tied
    /// to `&self`, so the mapping cannot go away while they are held.
    pub fn bytes(&self) -> &[u8] {
        &self.mmap
    }

    /// Parse as a 64-bit ELF file.
    pub fn parse(&self) -> Result<ElfFile64<'_>> {
        ElfFile64::<object::Endianness>::parse(self.bytes())
            .with_context(|| format!("failed to parse ELF {}", self.path.display()))
    }
}

/// Where one `PT_LOAD` segment lives, in the file and in memory.
#[derive(Debug, Clone, Copy)]
pub struct Load {
    pub vaddr: u64,
    pub offset: u64,
    /// Bytes the segment occupies in the file. The address translations below
    /// are bounded by this rather than by `memsz`: the tail of a segment whose
    /// memory image outruns its file contents (`.bss`) has no file offset to
    /// translate to.
    pub filesz: u64,
    /// Bytes the segment occupies in memory, `filesz` plus any zero-fill.
    pub memsz: u64,
}

/// Every `PT_LOAD` segment of a parsed ELF, in program-header order.
///
/// Five callers want the loaded segments and nothing else — the two address
/// translations below, the image's base delta and end, and the extractor's
/// check that two addresses share a mapping. Each used to filter
/// `elf_program_headers()` itself and pull the fields out through the
/// `ProgramHeader` trait, which is five copies of the same six lines.
pub fn pt_loads<'a>(elf: &'a ElfFile64<'a>) -> impl Iterator<Item = Load> + 'a {
    use object::read::elf::ProgramHeader;
    let endian = elf.endian();
    elf.elf_program_headers()
        .iter()
        .filter(move |seg| seg.p_type(endian) == object::elf::PT_LOAD)
        .map(move |seg| Load {
            vaddr: seg.p_vaddr(endian),
            offset: seg.p_offset(endian),
            filesz: seg.p_filesz(endian),
            memsz: seg.p_memsz(endian),
        })
}

/// Convert a virtual address in a parsed ELF to a file offset.
/// Returns None if the VA is not covered by any PT_LOAD segment.
pub fn va_to_file_offset(elf: &ElfFile64<'_>, va: u64) -> Option<u64> {
    pt_loads(elf)
        .find(|seg| (seg.vaddr..seg.vaddr + seg.filesz).contains(&va))
        .map(|seg| va - seg.vaddr + seg.offset)
}

/// `p_vaddr - p_offset` of the `PT_LOAD` that starts the image — the one
/// mapping the ELF header, and in a linker's output the one holding the
/// program header table.
///
/// Later mappings are only congruent to this modulo the page size, not equal
/// to it, so this is not an image-wide constant. It is specifically the
/// difference that holds for the program header table, which is what makes it
/// the one the merged region has to reproduce (see `merged_load_address`).
pub fn image_base_delta(elf: &ElfFile64<'_>) -> u64 {
    pt_loads(elf)
        .min_by_key(|seg| seg.vaddr)
        .map(|seg| {
            seg.vaddr.saturating_sub(seg.offset)
                // Mappings are congruent modulo the page size, so the
                // difference is a whole number of pages; truncate anything
                // else rather than carry it into the merged region's address.
                & !0xfff
        })
        .unwrap_or(0)
}

/// Virtual address to place the merged region at.
///
/// It has to clear the executable's memory image, and it has to sit far enough
/// past it that the merged region's file offset — which the writer derives as
/// `load_address - image_base_delta` — lands past the executable's own bytes.
///
/// That second condition is why this is not simply the end of the memory
/// image. The merged region holds the rebuilt program header table, so
/// `PT_PHDR` ends up inside it and takes on the region's
/// `p_vaddr - p_offset`. A linker only ever emits that table in the first
/// `PT_LOAD`, and `patchelf` relies on it: to rewrite the table it moves it to
/// file offset `sizeof(Elf64_Ehdr)` and computes the address to claim for it as
/// `(PT_PHDR.p_vaddr - PT_PHDR.p_offset) + sizeof(Elf64_Ehdr)`. Read off a
/// merged region with a different difference, that address is wrong by the
/// difference — and since glibc takes the main map's load address to be
/// `AT_PHDR - PT_PHDR.p_vaddr`, the binary `patchelf` produced relocated itself
/// by that much and died before `main`. Every executable with a `.bss` was
/// affected, the memory image outrunning the file by the size of it. Matching
/// the executable's own difference costs that many zero bytes of unmapped
/// padding in the file and nothing at runtime.
pub fn merged_load_address(elf: &ElfFile64<'_>) -> u64 {
    let image_end = pt_loads(elf)
        .map(|seg| seg.vaddr.saturating_add(seg.memsz))
        .max()
        .unwrap_or(0);
    // The address the end of the file maps to if the image's difference holds.
    let past_file_end = (elf.data().len() as u64).saturating_add(image_base_delta(elf));
    // Page-align upward (4 KiB pages)
    (image_end.max(past_file_end) + 0xfff) & !0xfff
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

/// `VER_NDX_GLOBAL`: the `.gnu.version` index meaning "this symbol carries no
/// version requirement". The writer stamps it on the externals it injects, and
/// the patcher on the symbols whose required version it unlinks.
pub const VER_NDX_GLOBAL: u16 = 1;

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
        cstr_at(bytes, self.strtab_offset?.checked_add(d_val as usize)?)
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

/// `sizeof (Elf64_Shdr)`.
pub const SHDR_SIZE: usize = 64;
/// Field offsets within an `Elf64_Shdr`.
pub const SH_NAME: usize = 0;
pub const SH_TYPE: usize = 4;
pub const SH_FLAGS: usize = 8;
pub const SH_ADDR: usize = 16;
pub const SH_OFFSET: usize = 24;
pub const SH_SIZE: usize = 32;
/// `sh_info`, a `u32`. For `SHT_GNU_verneed` it is the number of Verneed
/// entries in the section's list, the section-header counterpart of
/// `DT_VERNEEDNUM`.
pub const SH_INFO: usize = 44;
pub const SH_ADDRALIGN: usize = 48;

/// `SHN_XINDEX` / `SHN_LORESERVE`: section counts and `e_shstrndx` values at or
/// above this are escapes into the extended-numbering fields of section 0.
const SHN_LORESERVE: usize = 0xff00;

/// One entry of the section header table, with its name already resolved
/// through `.shstrtab`.
pub struct SectionHeader {
    /// Index into the section header table, i.e. the section's number.
    pub index: usize,
    pub name: String,
    /// `sh_addr`. Only the writer's tests read it, to check the headers of the
    /// rebuilt sections against the addresses the loader is pointed at.
    #[cfg_attr(not(test), allow(dead_code))]
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
}

/// The section header table of an ELF image, decoded from its raw bytes.
///
/// Section headers are what everything other than the dynamic loader reads:
/// the writer repoints the headers of the tables it rebuilds and appends one
/// per mapping of the merged region, the patcher locates `.gnu.version_r`
/// through them, and the writer reads the `.dynsym`/`.gnu.version` sizes off
/// them because `.dynamic` carries no tag for either. Each of those used to
/// find a section by name its own way — two by parsing the whole file a second
/// time with goblin, two by walking the raw headers — so this decodes the
/// table once and a caller only names the section it is after.
pub struct SectionTable {
    /// File offset of the first `Elf64_Shdr`.
    pub offset: usize,
    /// `e_shstrndx`, the index of the `.shstrtab` header.
    pub shstrndx: usize,
    pub sections: Vec<SectionHeader>,
}

impl SectionTable {
    /// Decode the table, or `Ok(None)` when the image has none this can work
    /// with: an already-stripped table, extended section numbering, or no
    /// `.shstrtab` to name the entries against.
    pub fn parse(bytes: &[u8]) -> Result<Option<Self>> {
        let offset = read_u64(bytes, 0x28)? as usize;
        let entsize = read_u16(bytes, 0x3a)? as usize;
        let shnum = read_u16(bytes, 0x3c)? as usize;
        let shstrndx = read_u16(bytes, 0x3e)? as usize;

        // A stripped executable has no section headers to read or to keep in
        // sync; the loader never needed them.
        if offset == 0 || shnum == 0 {
            return Ok(None);
        }
        if entsize != SHDR_SIZE {
            bail!("section header entries are {entsize} bytes, expected {SHDR_SIZE}");
        }
        if shnum >= SHN_LORESERVE || shstrndx >= SHN_LORESERVE {
            tracing::warn!(
                sections = shnum,
                "extended section numbering is not supported; ignoring the section header table"
            );
            return Ok(None);
        }
        // Without a `.shstrtab` the headers have no names to match against.
        if shstrndx == 0 {
            tracing::warn!("executable has no .shstrtab; ignoring the section header table");
            return Ok(None);
        }
        if shstrndx >= shnum {
            bail!("e_shstrndx is {shstrndx} but the table holds {shnum} headers");
        }
        if offset + shnum * SHDR_SIZE > bytes.len() {
            bail!("section header table extends past the end of the file");
        }

        let names_hdr = offset + shstrndx * SHDR_SIZE;
        let names_at = read_u64(bytes, names_hdr + SH_OFFSET)? as usize;
        let names_len = read_u64(bytes, names_hdr + SH_SIZE)? as usize;
        let names = names_at
            .checked_add(names_len)
            .and_then(|end| bytes.get(names_at..end))
            .context(".shstrtab extends past the end of the file")?;

        let sections = (0..shnum)
            .map(|index| {
                let at = offset + index * SHDR_SIZE;
                let name_at = read_u32(bytes, at + SH_NAME)? as usize;
                Ok(SectionHeader {
                    index,
                    name: cstr_at(names, name_at).unwrap_or_default().to_owned(),
                    addr: read_u64(bytes, at + SH_ADDR)?,
                    offset: read_u64(bytes, at + SH_OFFSET)?,
                    size: read_u64(bytes, at + SH_SIZE)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Some(Self {
            offset,
            shstrndx,
            sections,
        }))
    }

    /// The first header named `name`, if the image has one.
    pub fn by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// The `.shstrtab` header, which `parse` has already checked exists.
    pub fn shstrtab(&self) -> &SectionHeader {
        &self.sections[self.shstrndx]
    }

    /// Bytes the table occupies in the file.
    pub fn byte_range(&self) -> std::ops::Range<usize> {
        self.offset..self.offset + self.sections.len() * SHDR_SIZE
    }
}

/// The NUL-terminated string starting at `offset` in a string table.
pub fn cstr_at(strings: &[u8], offset: usize) -> Option<&str> {
    let rest = strings.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

/// Convert a file offset to a virtual address in a parsed ELF.
/// Returns None if the offset is not covered by any PT_LOAD segment.
pub fn file_offset_to_va(elf: &ElfFile64<'_>, offset: u64) -> Option<u64> {
    pt_loads(elf)
        .find(|seg| (seg.offset..seg.offset + seg.filesz).contains(&offset))
        .map(|seg| offset - seg.offset + seg.vaddr)
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
