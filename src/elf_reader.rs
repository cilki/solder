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

/// The virtual addresses `PT_GNU_RELRO` covers, when the object has one.
///
/// These are the bytes `ld.so` writes while relocating and then `mprotect`s
/// read-only, before any code in the process runs — which is why a linker puts
/// `.got`, `.init_array` and `.fini_array` there: each of those words is
/// written exactly once, by the loader, and must never be written again.
///
/// An object gets one such range however many entries its program header table
/// lists, because glibc's phdr loop assigns `l_relro_addr`/`l_relro_size`
/// unconditionally and so keeps the last one. That is the one returned here,
/// and the reason a merge cannot simply append a second entry for the merged
/// region: doing so would unprotect the executable's own range rather than
/// protect the merged one.
pub fn gnu_relro(elf: &ElfFile64<'_>) -> Option<std::ops::Range<u64>> {
    use object::read::elf::ProgramHeader;
    let endian = elf.endian();
    elf.elf_program_headers()
        .iter()
        .rfind(|seg| seg.p_type(endian) == object::elf::PT_GNU_RELRO)
        .map(|seg| {
            let start = seg.p_vaddr(endian);
            start..start + seg.p_memsz(endian)
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

/// Validate that `bytes` is a shared library the merge can take code from: a
/// little-endian, 64-bit, x86-64 `ET_DYN` object.
///
/// [`validate_executable`] checks the file solder writes to. Nothing checked
/// the files it copies machine code *out of*, and a search path that names a
/// foreign build of a soname — a cross sysroot reached through `SYSROOT` or
/// `-L`, a multiarch directory, the 32-bit half of a multilib tree, where
/// `/usr/lib/libfoo.so.1` is the i686 build and only `/usr/lib64` holds the
/// x86-64 one — is reached by `resolve_library` like any other. Every way that
/// went wrong was worse than an error:
///
///   * an `EM_AARCH64` library is a well-formed 64-bit little-endian ELF, so
///     every stage ran to completion and solder exited 0 after planting
///     aarch64 instructions in an executable `PT_LOAD` of an x86-64 binary and
///     pointing the executable's GOT slots at them;
///   * an `ELFCLASS32` library parses as 32-bit for goblin, whose `.dynsym`
///     then yields none of the names the executable imports, so solder logged
///     "No mergeable imported symbols found" and exited 0 having merged
///     nothing at all;
///   * a big-endian one did fail, but as `bad offset 4611686018427387904`
///     from somewhere inside the extractor.
///
/// The header is read out of the raw bytes rather than through a parser
/// because the point is to reject the files a 64-bit little-endian reader
/// cannot describe in the first place.
pub fn validate_merge_library(bytes: &[u8], path: &Path) -> Result<()> {
    use object::elf::{ELFCLASS64, ELFDATA2LSB, ELFMAG, EM_X86_64, ET_DYN};

    /// `EI_CLASS`: whether the object is 32- or 64-bit.
    const EI_CLASS: usize = 4;
    /// `EI_DATA`: which endianness every multi-byte field is written in.
    const EI_DATA: usize = 5;
    /// `e_ident` (16 bytes), then `e_type` and `e_machine`.
    const HEADER_PREFIX: usize = 20;

    if !bytes.starts_with(&ELFMAG) || bytes.len() < HEADER_PREFIX {
        bail!(
            "{}: not an ELF shared library (no readable ELF header)",
            path.display()
        );
    }

    let hint = "solder copies a library's machine code into the executable, so only an \
                x86-64 shared object can be merged into one — check that the search path \
                (-L, DT_RPATH/DT_RUNPATH, SYSROOT, LD_LIBRARY_PATH) names the x86-64 build \
                of this soname";

    if bytes[EI_CLASS] != ELFCLASS64.0 {
        bail!(
            "{}: not a 64-bit library (EI_CLASS={}); {hint}",
            path.display(),
            bytes[EI_CLASS]
        );
    }
    if bytes[EI_DATA] != ELFDATA2LSB.0 {
        bail!(
            "{}: not a little-endian library (EI_DATA={}); {hint}",
            path.display(),
            bytes[EI_DATA]
        );
    }

    let e_type = read_u16(bytes, 0x10)?;
    let e_machine = read_u16(bytes, 0x12)?;

    if e_machine != EM_X86_64.0 {
        bail!(
            "{}: unsupported architecture e_machine=0x{e_machine:04x} (only EM_X86_64, \
             0x{:04x}, is supported); {hint}",
            path.display(),
            EM_X86_64.0
        );
    }
    if e_type != ET_DYN.0 {
        bail!(
            "{}: not a shared object (e_type=0x{e_type:04x}, expected ET_DYN 0x{:04x}) — \
             ld.so would not load this file as a dependency either",
            path.display(),
            ET_DYN.0
        );
    }

    Ok(())
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

        // `p_filesz` counts bytes of the file, so the segment has to be *in*
        // the file. Reading the entries below would catch one that is not —
        // `read_u64` is bounds-checked — but the table is sized from
        // `p_filesz` before the first of them is read, and an infallible
        // allocation of an unvalidated length aborts the process rather than
        // failing: one byte of `p_filesz` turned a merge into
        // `memory allocation of 288230376151711744 bytes failed`.
        let end = (offset as u64).checked_add(filesz);
        if end.is_none_or(|end| end > bytes.len() as u64) {
            bail!(
                "PT_DYNAMIC covers {filesz} bytes from file offset {offset:#x}, past the end \
                 of this {} byte file",
                bytes.len()
            );
        }
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
mod merge_library_tests {
    use super::*;

    /// The committed `test/libs/` libraries are the ones solder actually
    /// merges, so they have to pass the check they are gated by.
    const TEST_LIBS: [&str; 3] = ["libpcre2-8.so.0", "libcrypto.so.3", "libtinfo.so.6"];

    fn read_test_lib(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs/").to_string() + name;
        std::fs::read(&path).expect("test library")
    }

    /// A real library with one byte of its ELF header changed, which is how a
    /// foreign-architecture build differs from a mergeable one in everything
    /// the check looks at.
    fn with_header_byte(at: usize, value: u8) -> Vec<u8> {
        let mut bytes = read_test_lib(TEST_LIBS[0]);
        bytes[at] = value;
        bytes
    }

    fn rejection(bytes: &[u8]) -> String {
        let path = Path::new("/sysroot/lib/libpcre2-8.so.0");
        format!(
            "{:#}",
            validate_merge_library(bytes, path).expect_err("a foreign library must be refused")
        )
    }

    #[test]
    fn the_libraries_solder_merges_are_accepted() {
        for name in TEST_LIBS {
            validate_merge_library(&read_test_lib(name), Path::new(name))
                .unwrap_or_else(|e| panic!("{name} should be mergeable: {e:#}"));
        }
    }

    /// The one that used to merge: an aarch64 library is a well-formed 64-bit
    /// little-endian ELF, so nothing downstream objected and solder exited 0
    /// having put aarch64 instructions in an executable mapping of an x86-64
    /// binary.
    #[test]
    fn a_library_for_another_architecture_is_refused() {
        // e_machine at 0x12: EM_AARCH64 (183) and EM_RISCV (243).
        for machine in [183u16, 243] {
            let mut bytes = read_test_lib(TEST_LIBS[0]);
            bytes[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
            let err = rejection(&bytes);
            assert!(err.contains("e_machine"), "{err}");
            assert!(err.contains("/sysroot/lib/libpcre2-8.so.0"), "{err}");
        }
    }

    /// The one that used to merge *nothing*: goblin reads a 32-bit library as
    /// 32-bit, its `.dynsym` then matches none of the executable's imports, and
    /// the merge reported success having done nothing.
    #[test]
    fn a_32_bit_library_is_refused() {
        let err = rejection(&with_header_byte(4, 1)); // EI_CLASS = ELFCLASS32
        assert!(err.contains("64-bit"), "{err}");
    }

    #[test]
    fn a_big_endian_library_is_refused() {
        let err = rejection(&with_header_byte(5, 2)); // EI_DATA = ELFDATA2MSB
        assert!(err.contains("little-endian"), "{err}");
    }

    /// A `DT_NEEDED` entry has to name a shared object. An `ET_EXEC` file has
    /// no relocations for the code the merge moves to a new address, so its
    /// absolute references would keep pointing at where it was linked to load.
    #[test]
    fn a_file_that_is_not_a_shared_object_is_refused() {
        let mut bytes = read_test_lib(TEST_LIBS[0]);
        bytes[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        let err = rejection(&bytes);
        assert!(err.contains("shared object"), "{err}");
    }

    #[test]
    fn a_file_that_is_not_an_elf_at_all_is_refused() {
        for bytes in [
            b"#!/bin/sh\nexec something\n".to_vec(),
            Vec::new(),
            read_test_lib(TEST_LIBS[0])[..19].to_vec(),
        ] {
            let err = rejection(&bytes);
            assert!(err.contains("ELF"), "{err}");
        }
    }
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

    /// `p_filesz` counts bytes of the file, so `PT_DYNAMIC` has to be *in* the
    /// file. Every other length `parse` reads goes through the bounds-checked
    /// `read_*` helpers, and this one would have too — the entry loop reads
    /// each slot — but the table was sized from `p_filesz` before the first of
    /// them, and an infallible allocation of an unvalidated length does not
    /// fail, it aborts: one byte of `p_filesz` turned a merge into
    /// `memory allocation of 288230376151711744 bytes failed` with no
    /// unwinding and nothing naming the file.
    #[test]
    fn a_pt_dynamic_reaching_past_the_end_of_the_file_is_an_error_rather_than_an_abort() {
        for name in TEST_BINARIES {
            let mut bytes = read_test_binary(name);
            let used = DynamicTable::parse(&bytes).expect("parse .dynamic").used();

            // `p_filesz` of `PT_DYNAMIC`, found the way `parse` finds it.
            let phoff = read_u64(&bytes, 0x20).expect("e_phoff") as usize;
            let phentsize = read_u16(&bytes, 0x36).expect("e_phentsize") as usize;
            let phnum = read_u16(&bytes, 0x38).expect("e_phnum") as usize;
            let filesz_at = (0..phnum)
                .map(|i| phoff + i * phentsize)
                .find(|&ph| read_u32(&bytes, ph).expect("p_type") == object::elf::PT_DYNAMIC.0)
                .expect("PT_DYNAMIC")
                + 32;
            let real = read_u64(&bytes, filesz_at).expect("p_filesz");

            for filesz in [u64::MAX, 1 << 60, bytes.len() as u64] {
                bytes[filesz_at..filesz_at + 8].copy_from_slice(&filesz.to_le_bytes());
                let err = DynamicTable::parse(&bytes).err().unwrap_or_else(|| {
                    panic!(
                        "{name}: {filesz} bytes of .dynamic are not in a {} byte file",
                        bytes.len()
                    )
                });
                assert!(format!("{err:#}").contains("PT_DYNAMIC"), "{name}: {err:#}");
            }

            // The control: at its real size the same table still parses.
            bytes[filesz_at..filesz_at + 8].copy_from_slice(&real.to_le_bytes());
            assert_eq!(
                DynamicTable::parse(&bytes).expect("parse .dynamic").used(),
                used,
                "{name}"
            );
        }
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
