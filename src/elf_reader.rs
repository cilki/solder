use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use memmap2::Mmap;
use object::read::elf::ElfFile64;

use crate::arch::Arch;

/// A memory-mapped ELF file. Everything that reads it borrows from `&self`,
/// so the mapping outlives every view handed out of it.
///
/// This is how solder reads every input it does not have to modify — the
/// executable and each library the merge reads — because none of the passes
/// over a library wants all of it. Collecting its exports reads `.dynsym` and
/// `.dynstr`, extraction reads the sections its units come out of, the GNU
/// property pass reads one note; and a library is read by several of those
/// passes in turn, each a separate open. Pulling the whole file into a `Vec`
/// per pass copied megabytes nobody looked at: `test/md5sum` against the
/// 6.2 MB `libcrypto.so.3` spent a quarter of the merge in four such copies,
/// where a mapping faults in only the pages a pass actually touches and the
/// second pass over the file finds them already resident.
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
    /// `p_align`: the largest page size the linker laid the segment out for.
    pub align: u64,
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
            align: seg.p_align(endian),
        })
}

/// The smallest page size of any kernel solder targets, and so the least the
/// merged region's mappings are ever aligned to.
pub const MIN_PAGE_SIZE: u64 = 0x1000;

/// Page size the merged region's mappings have to be aligned to for this
/// executable.
///
/// The merge splits its region into separately-protected mappings (code,
/// constants, loader-written data, rebuilt tables), and that split only holds
/// if no two of them share a page at runtime. The runtime page size is not
/// in the file, but the linker recorded the largest one it laid the executable
/// out for as the `PT_LOAD`s' `p_align` — `-z max-page-size`, 64 KiB on
/// distribution aarch64 toolchains so the same binary loads under a 4K, 16K
/// or 64K kernel. Aligning to anything smaller would let a 64K kernel map the
/// merged code and the data after it as one page, with one set of
/// permissions.
///
/// That promise is capped at the architecture's largest page size
/// (`Arch::max_page_size`): x86-64 binaries from older binutils carry a 2 MiB
/// `p_align` for huge pages, and an x86-64 kernel's pages are 4 KiB whatever
/// the file says, so honouring it would only pad the file by megabytes. A
/// `p_align` that is not a power of two is no page size at all and is ignored,
/// as the kernel ignores it.
pub fn page_size(elf: &ElfFile64<'_>, arch: &Arch) -> u64 {
    page_size_for(pt_loads(elf).map(|seg| seg.align), arch.max_page_size)
}

fn page_size_for(aligns: impl Iterator<Item = u64>, max_page_size: u64) -> u64 {
    aligns
        .filter(|align| align.is_power_of_two())
        .map(|align| align.min(max_page_size))
        .fold(MIN_PAGE_SIZE, u64::max)
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

/// Whether a section is part of the loaded image (`SHF_ALLOC`).
///
/// One that is not has no virtual address at all, and says so by reporting
/// `sh_addr` as 0 — which in a shared library, where the image starts at 0, is
/// as ordinary an address as any other. So `.shstrtab`, `.symtab` and
/// `.gnu_debuglink` each claim the first `sh_size` addresses of the image
/// purely by being as long as they are, and anything resolving an address
/// against `sh_addr`/`sh_size` has to rule them out first.
pub fn is_alloc(section: &object::read::elf::ElfSection64<'_, '_>) -> bool {
    use object::ObjectSection;
    match section.flags() {
        object::SectionFlags::Elf { sh_flags, .. } => (sh_flags & object::elf::SHF_ALLOC).0 != 0,
        _ => false,
    }
}

/// The loaded section whose address range covers `addr`.
///
/// Five callers want exactly this and each used to walk `elf.sections()`
/// itself: the extractor's section lookup for a data address, its two checks
/// that an address is extractable code, and the jump-table scanner's
/// read-only-data test and its table lookup. Five copies of one loop, each
/// applying its own predicate to whatever came out, and each with its own idea
/// of whether a section with no address can own one — only the extractor's
/// ruled out the sections that are not in the loaded image, and only on the
/// path that handles an address no section contains.
pub fn section_at_address<'data, 'file>(
    elf: &'file ElfFile64<'data>,
    addr: u64,
) -> Option<object::read::elf::ElfSection64<'data, 'file>> {
    use object::Object;
    elf.sections()
        .find(|section| is_alloc(section) && covers(section, addr))
}

/// Whether `section` is laid out over `addr`.
fn covers(section: &object::read::elf::ElfSection64<'_, '_>, addr: u64) -> bool {
    use object::ObjectSection;
    let start = section.address();
    addr >= start && addr - start < section.size()
}

/// Convert a virtual address in a parsed ELF to a file offset.
/// Returns None if the VA is not covered by any PT_LOAD segment.
pub fn va_to_file_offset(elf: &ElfFile64<'_>, va: u64) -> Option<u64> {
    pt_loads(elf)
        .find(|seg| (seg.vaddr..seg.vaddr + seg.filesz).contains(&va))
        .map(|seg| va - seg.vaddr + seg.offset)
}

/// The `size` bytes of `bytes` holding a table `.dynamic` places at `va`,
/// together with the file offset they start at. `what` names the table in
/// errors.
///
/// Every table the loader is pointed at through a pair of `.dynamic` tags —
/// an address and a size — is located this way. Both values are the file's
/// own claims about itself, so neither is trusted: the address has to lie in
/// a `PT_LOAD`'s file contents and the whole length has to fit in the file,
/// checked without letting `offset + size` wrap. `bytes` is passed separately
/// from `elf` so a caller holding a patched copy of the image (same layout,
/// different contents) can slice that instead.
pub fn dynamic_table_bytes<'b>(
    elf: &ElfFile64<'_>,
    bytes: &'b [u8],
    what: &str,
    va: u64,
    size: u64,
) -> Result<(usize, &'b [u8])> {
    let offset = va_to_file_offset(elf, va).with_context(|| {
        format!("{what} is at {va:#x}, which no loaded segment's file contents cover")
    })?;
    usize::try_from(offset)
        .ok()
        .zip(usize::try_from(size).ok())
        .and_then(|(at, len)| Some((at, bytes.get(at..at.checked_add(len)?)?)))
        .with_context(|| {
            format!(
                "{what} covers {size} bytes from file offset {offset:#x}, past the end of this \
                 {}-byte file",
                bytes.len()
            )
        })
}

/// `p_vaddr - p_offset` of the `PT_LOAD` that starts the image — the one
/// mapping the ELF header, and in a linker's output the one holding the
/// program header table.
///
/// Later mappings are only congruent to this modulo the page size, not equal
/// to it, so this is not an image-wide constant. It is specifically the
/// difference that holds for the program header table, which is what makes it
/// the one the merged region has to reproduce (see `merged_load_address`).
///
/// `page_size` is the executable's [`page_size`].
pub fn image_base_delta(elf: &ElfFile64<'_>, page_size: u64) -> u64 {
    pt_loads(elf)
        .min_by_key(|seg| seg.vaddr)
        .map(|seg| {
            seg.vaddr.saturating_sub(seg.offset)
                // Mappings are congruent modulo the page size, so the
                // difference is a whole number of pages; truncate anything
                // else rather than carry it into the merged region's address.
                & !(page_size - 1)
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
///
/// The address is a multiple of `page_size`, the executable's [`page_size`],
/// so the first merged mapping starts on a page of its own.
pub fn merged_load_address(elf: &ElfFile64<'_>, page_size: u64) -> u64 {
    let image_end = pt_loads(elf)
        .map(|seg| seg.vaddr.saturating_add(seg.memsz))
        .max()
        .unwrap_or(0);
    // The address the end of the file maps to if the image's difference holds.
    let past_file_end = (elf.data().len() as u64).saturating_add(image_base_delta(elf, page_size));
    crate::layout::align_up(image_end.max(past_file_end), page_size)
}

/// The dynamic loader the executable names in `PT_INTERP`.
///
/// The interpreter is linked into every dynamic executable without ever being
/// named in `DT_NEEDED`, and it defines symbols of its own — `__tls_get_addr`,
/// `_dl_find_object` — so anything reasoning about what will resolve at load
/// time has to count it among the libraries the executable is linked against.
pub fn interpreter<'a>(elf: &'a ElfFile64<'a>) -> Option<&'a str> {
    use object::read::elf::ProgramHeader;

    let endian = elf.endian();
    elf.elf_program_headers()
        .iter()
        .find(|seg| seg.p_type(endian) == object::elf::PT_INTERP)
        .and_then(|seg| seg.data(endian, elf.data()).ok())
        .and_then(|path| {
            let path = path.split(|&b| b == 0).next().unwrap_or(path);
            std::str::from_utf8(path).ok().filter(|s| !s.is_empty())
        })
}

/// Validate that the input ELF is a supported target:
/// - 64-bit ELF
/// - ET_EXEC or ET_DYN (PIE)
/// - built for an architecture in [`arch::SUPPORTED`](crate::arch::SUPPORTED)
/// - Has PT_DYNAMIC (dynamically linked)
/// - Has a section header table the merge can read and keep in sync
///
/// Returns the executable's architecture, which every library merged into it
/// has to share, and whether it is PIE (ET_DYN) rather than non-PIE (ET_EXEC).
pub fn validate_executable(elf: &ElfFile64<'_>, path: &Path) -> Result<(&'static Arch, bool)> {
    use object::elf::{ET_DYN, ET_EXEC};
    use object::read::elf::{FileHeader, ProgramHeader};

    let endian = elf.endian();
    let header = elf.elf_header();
    let e_type = header.e_type(endian);
    let e_machine = header.e_machine(endian);

    let Some(arch) = Arch::of_machine(e_machine.0) else {
        bail!(
            "{}: unsupported architecture e_machine=0x{:04x} (only EM_X86_64 is supported)",
            path.display(),
            e_machine.0
        );
    };

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

    // The loader never reads section headers, but the merge does, in places
    // where nothing else carries the fact it needs: `.dynsym` and
    // `.gnu.version` have no length anywhere in `.dynamic` (there is no
    // `DT_SYMSZ` and no `DT_VERSYMSZ`), and `.gnu.version_r` has no extent
    // either, which is the only thing bounding the Verneed list the merge has
    // to unlink a merged library's version requirements from. Leaving a
    // requirement on a library no longer in `DT_NEEDED` is what makes ld.so
    // abort on `_dl_check_map_versions`, so a merge that cannot do that
    // surgery is a merge that cannot run.
    //
    // This used to be discovered by accident and misreported: the import scan
    // found `.rela.plt`/`.rela.dyn` through the section table too, so a
    // stripped executable yielded no imports at all and `solder` finished with
    // "No mergeable imported symbols found" and status 0, having changed
    // nothing — even when `-m` named the library it had been told to merge.
    if SectionTable::parse(elf.data())?.is_none() {
        bail!(
            "{}: no usable section header table. The merge needs it for the \
             .dynsym/.gnu.version lengths and to unlink .gnu.version_r entries, none of \
             which .dynamic records; merge a copy that still has its section headers",
            path.display()
        );
    }

    Ok((arch, is_pie))
}

/// Validate that `bytes` is a shared library the merge can take code from: a
/// little-endian, 64-bit `ET_DYN` object built for `arch`, the executable's
/// architecture.
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
pub fn validate_merge_library(bytes: &[u8], path: &Path, arch: &Arch) -> Result<()> {
    use object::elf::{ELFCLASS64, ELFDATA2LSB, ELFMAG, ET_DYN};

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

    let hint = format!(
        "solder copies a library's machine code into the executable, so only an \
         {0} shared object can be merged into one — check that the search path \
         (-L, DT_RPATH/DT_RUNPATH, SYSROOT, LD_LIBRARY_PATH) names the {0} build \
         of this soname",
        arch.name
    );

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

    if e_machine != arch.e_machine {
        bail!(
            "{}: unsupported architecture e_machine=0x{e_machine:04x} (only {}, \
             0x{:04x}, is supported); {hint}",
            path.display(),
            arch.name,
            arch.e_machine
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

/// `DT_RELR`: the address of the compact relative relocation table.
/// `goblin::elf::dynamic` does not name the tag, and `object` names it only as
/// a `DynamicTag` newtype, so both reach `DynamicTable` as a plain `u64`.
const DT_RELR: u64 = object::elf::DT_RELR.0 as u64;
/// `DT_RELRSZ`: that table's size in bytes.
const DT_RELRSZ: u64 = object::elf::DT_RELRSZ.0 as u64;

/// One `Elf64_Relr` word.
const RELR_ENTRY_SIZE: u64 = 8;

/// A bitmap word describes the 63 pointer slots following the address its
/// predecessor set, one per bit above bit 0.
const RELR_BITS_PER_WORD: u64 = 63;

/// A relative relocation decoded out of a `DT_RELR` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelrReloc {
    /// Virtual address of the 64-bit slot the loader rebases.
    pub vaddr: u64,
    /// The word that slot holds as linked, which is the address it points at.
    ///
    /// A `DT_RELR` entry has no addend field: the loader's whole action is
    /// `*slot += load_base`, so the in-place word is the library-relative
    /// address an `R_X86_64_RELATIVE` would have spelled out in `r_addend`.
    /// Reading it here is what lets a packed entry be lifted by the same code
    /// that lifts an explicit one.
    pub addend: u64,
}

/// Decode the relative relocations a library packs into `DT_RELR`, or an empty
/// list when it has none.
///
/// `ld -z pack-relative-relocs` replaces a library's `R_X86_64_RELATIVE`
/// entries with a `DT_RELR` bitmap that says the same thing in about a
/// hundredth of the space — the 1503 relative entries of `libtinfo.so.6`'s
/// `.rela.dyn`, 36072 bytes, pack into 216. Several distributions have linked
/// that way since 2023, so it is an ordinary shape for a library to arrive in.
///
/// Nothing but this reads it: extraction finds a library's relocations through
/// `object`'s `dynamic_relocations`, which walks `SHT_REL`/`SHT_RELA` sections
/// and skips `SHT_RELR`. Left undecoded, the invariant
/// [`collect_dynamic_range_relocs`](crate::extractor) rests on — that a linked
/// shared object carries its data relocations in `.rela.dyn` — quietly stops
/// holding, and the merge is not smaller but wrong in two ways: every pointer
/// in the data it copies keeps the address the library was linked at, with no
/// relocation to rebase it into the merged segment, and those same pointers
/// are what roots the rest of the extraction, so the units they point at are
/// never copied in either. `test/bash` merged against a `DT_RELR` build of
/// `libtinfo.so.6` used to come out six units short, with ten function
/// pointers in `.solder.data` still holding libtinfo's own offsets — addresses
/// that land in the middle of bash's `.text` once the merged binary loads.
///
/// The encoding (generic-abi `DT_RELR`) is a stream of 64-bit words. An even
/// word is an address: that slot is relocated, and the next word describes the
/// run starting eight bytes later. An odd word is a bitmap of the 63 slots
/// following that point, bit *n* standing for the slot `8 * n` bytes in. A
/// stream cannot open with a bitmap, since there is no address for it to be
/// relative to.
///
/// Anything unreadable here is an error rather than a skipped entry: a
/// relative relocation that goes missing is a stale pointer in the merged
/// binary, which is exactly what reading the table at all is for.
pub fn packed_relative_relocs(elf: &ElfFile64<'_>, path: &Path) -> Result<Vec<RelrReloc>> {
    let bytes = elf.data();
    let dynamic = DynamicTable::parse(bytes)
        .with_context(|| format!("reading {}'s .dynamic", path.display()))?;

    let Some(table_va) = dynamic.value_of(DT_RELR) else {
        return Ok(Vec::new());
    };
    // The `DT_RELR*` tags are emitted as a set, but it is `DT_RELRSZ` that
    // says whether the table relocates anything — and it is the size glibc
    // reads to decide the same thing, so a tag without one is an empty table
    // to the loader too.
    let size = dynamic.value_of(DT_RELRSZ).unwrap_or(0);
    if size == 0 {
        return Ok(Vec::new());
    }

    if !size.is_multiple_of(RELR_ENTRY_SIZE) {
        bail!(
            "{}: DT_RELRSZ is {size} bytes, not a whole number of {RELR_ENTRY_SIZE}-byte \
             DT_RELR entries",
            path.display()
        );
    }
    let (_, table) = dynamic_table_bytes(
        elf,
        bytes,
        &format!("{}'s DT_RELR table", path.display()),
        table_va,
        size,
    )?;

    let mut relocs = Vec::with_capacity(table.len());
    // Where the next bitmap word starts counting from. `None` until an address
    // word has set it.
    let mut cursor: Option<u64> = None;
    for word in table
        .chunks_exact(RELR_ENTRY_SIZE as usize)
        .map(|w| u64::from_le_bytes(w.try_into().expect("8 bytes")))
    {
        if word & 1 == 0 {
            relocs.push(relr_slot(elf, path, word)?);
            cursor = Some(word.saturating_add(RELR_ENTRY_SIZE));
            continue;
        }
        let base = cursor.with_context(|| {
            format!(
                "{}: the DT_RELR table at {table_va:#x} opens with the bitmap word \
                 {word:#x}, which has no address to be relative to",
                path.display()
            )
        })?;
        let mut bits = word >> 1;
        let mut slot = base;
        while bits != 0 {
            if bits & 1 != 0 {
                relocs.push(relr_slot(elf, path, slot)?);
            }
            bits >>= 1;
            slot = slot.saturating_add(RELR_ENTRY_SIZE);
        }
        cursor = Some(base.saturating_add(RELR_BITS_PER_WORD * RELR_ENTRY_SIZE));
    }

    Ok(relocs)
}

/// One slot a `DT_RELR` stream named, paired with the link-time address it
/// holds — see [`RelrReloc::addend`] for why that word is the addend.
fn relr_slot(elf: &ElfFile64<'_>, path: &Path, vaddr: u64) -> Result<RelrReloc> {
    if !vaddr.is_multiple_of(RELR_ENTRY_SIZE) {
        bail!(
            "{}: DT_RELR relocates {vaddr:#x}, which is not a {RELR_ENTRY_SIZE}-byte aligned \
             pointer slot",
            path.display()
        );
    }
    // The slot has to be backed by file contents, not just mapped: its own
    // word is the addend, so a `.bss` slot would relocate to nothing. The
    // linker never puts one there, exactly because of that.
    let at = va_to_file_offset(elf, vaddr).with_context(|| {
        format!(
            "{}: DT_RELR relocates {vaddr:#x}, which no loaded segment's file contents cover",
            path.display()
        )
    })?;
    let addend = read_u64(elf.data(), at as usize).with_context(|| {
        format!(
            "{}: reading the pointer DT_RELR relocates at {vaddr:#x}",
            path.display()
        )
    })?;
    Ok(RelrReloc { vaddr, addend })
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

    /// Overwrite the `d_val` of the first entry tagged `tag` in `bytes`, the
    /// image this table was parsed from. Returns whether there was one.
    pub fn set_value(&self, bytes: &mut [u8], tag: u64, val: u64) -> bool {
        let Some(idx) = self.index_of(tag) else {
            return false;
        };
        let at = self.value_offset(idx);
        bytes[at..at + 8].copy_from_slice(&val.to_le_bytes());
        true
    }

    /// Overwrite the `d_val` of the entry tagged `tag`, or append one if the
    /// table has none.
    pub fn set_or_append(&mut self, bytes: &mut [u8], tag: u64, val: u64) -> Result<()> {
        if self.set_value(bytes, tag, val) {
            return Ok(());
        }
        self.append(bytes, tag, val)
    }

    /// Append `(tag, val)` to the table in `bytes`, over the `DT_NULL`
    /// terminator, which moves down into the next slot. That slot has to be
    /// zeroed rather than assumed to be: the spare ones past the old
    /// terminator are not guaranteed to be. So appending needs a spare slot
    /// beyond the one the entry takes.
    pub fn append(&mut self, bytes: &mut [u8], tag: u64, val: u64) -> Result<()> {
        let idx = self.used();
        if idx + 1 >= self.capacity {
            bail!(
                "no room in PT_DYNAMIC to append dynamic tag {tag:#x} ({} slots, {idx} used)",
                self.capacity
            );
        }
        let at = self.entry_offset(idx);
        bytes[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&val.to_le_bytes());
        let next = self.entry_offset(idx + 1);
        bytes[next..next + DYN_ENTRY_SIZE].fill(0);
        self.entries.push((tag, val));
        Ok(())
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
pub const SH_ENTSIZE: usize = 56;

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
mod section_lookup_tests {
    use super::*;
    use object::{Object, ObjectSection};

    const TEST_LIBS: [&str; 3] = ["libpcre2-8.so.0", "libcrypto.so.3", "libtinfo.so.6"];

    fn read_test_lib(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs/").to_string() + name;
        std::fs::read(&path).expect("test library")
    }

    /// Every loaded section owns the addresses it is laid out over and the
    /// lookup finds it there. The extractor resolves a data address to the
    /// section it has to copy through this, so a disagreement with the section
    /// header table is a wrong blob or none at all.
    #[test]
    fn a_loaded_section_owns_its_own_addresses() {
        for name in TEST_LIBS {
            let bytes = read_test_lib(name);
            let elf = ElfFile64::<object::Endianness>::parse(bytes.as_slice()).expect("parse");
            let mut checked = 0;
            for section in elf.sections().filter(|s| is_alloc(s) && s.size() > 0) {
                let (start, size) = (section.address(), section.size());
                for addr in [start, start + size / 2, start + size - 1] {
                    let found = section_at_address(&elf, addr)
                        .unwrap_or_else(|| panic!("{name}: {addr:#x} resolved to no section"));
                    assert_eq!(
                        found.index(),
                        section.index(),
                        "{name}: {addr:#x} is in {:?}, not {:?}",
                        found.name(),
                        section.name()
                    );
                }
                checked += 1;
            }
            assert!(checked > 10, "{name}: only {checked} loaded sections");
        }
    }

    /// A section that is not part of the loaded image has no address of its
    /// own: `sh_addr` reads 0, which in a shared library is as ordinary an
    /// address as any other. Resolving an address by `sh_addr`/`sh_size`
    /// alone — which is what each of the four lookups this replaced did —
    /// therefore let `.shstrtab` and `.gnu_debuglink` claim every address
    /// below their own length, an area of the image no section covers at all.
    #[test]
    fn a_section_outside_the_loaded_image_claims_no_address() {
        for name in TEST_LIBS {
            let bytes = read_test_lib(name);
            let elf = ElfFile64::<object::Endianness>::parse(bytes.as_slice()).expect("parse");

            // How far an unloaded section would reach if its `sh_addr` of 0
            // were taken for an address.
            let reach = elf
                .sections()
                .filter(|s| !is_alloc(s))
                .map(|s| s.size())
                .max()
                .expect("an unloaded section");
            assert!(reach > 0, "{name}: no unloaded section has any length");

            // Those addresses are below every loaded section, so they are in
            // no section at all.
            let first_loaded = elf
                .sections()
                .filter(|s| is_alloc(s) && s.size() > 0)
                .map(|s| s.address())
                .min()
                .expect("a loaded section");
            assert!(
                first_loaded > reach,
                "{name}: the image starts at {first_loaded:#x}, inside the {reach:#x} \
                 bytes an unloaded section would claim"
            );
            for addr in [0, reach - 1, first_loaded - 1] {
                let found = section_at_address(&elf, addr);
                assert!(
                    found.is_none(),
                    "{name}: {addr:#x} resolved to {:?}",
                    found.and_then(|s| s.name().ok().map(str::to_owned))
                );
            }
        }
    }
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
            validate_merge_library(bytes, path, &crate::arch::X86_64)
                .expect_err("a foreign library must be refused")
        )
    }

    #[test]
    fn the_libraries_solder_merges_are_accepted() {
        for name in TEST_LIBS {
            validate_merge_library(&read_test_lib(name), Path::new(name), &crate::arch::X86_64)
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

    fn parse(bytes: &[u8]) -> ElfFile64<'_> {
        ElfFile64::<object::Endianness>::parse(bytes).expect("parse the library")
    }

    /// The explicit `R_X86_64_RELATIVE` entries of a library's `.rela.dyn`,
    /// read straight out of the table — the set a packed build has to decode
    /// back to, byte for byte.
    fn explicit_relative_relocs(bytes: &[u8]) -> Vec<RelrReloc> {
        let table = SectionTable::parse(bytes)
            .expect("section headers")
            .expect("a section header table");
        let rela = table
            .sections
            .iter()
            .find(|s| s.name == ".rela.dyn")
            .expect(".rela.dyn");
        let at = rela.offset as usize;
        let mut out = Vec::new();
        for i in 0..rela.size as usize / 24 {
            let entry = &bytes[at + i * 24..][..24];
            let r_info = u64::from_le_bytes(entry[8..16].try_into().expect("r_info"));
            // `r_info` of a relative entry is its type alone: it names no
            // symbol, so the symbol half of the field is zero.
            if r_info == u64::from(object::elf::R_X86_64_RELATIVE.0) {
                out.push(RelrReloc {
                    vaddr: u64::from_le_bytes(entry[0..8].try_into().expect("r_offset")),
                    addend: u64::from_le_bytes(entry[16..24].try_into().expect("r_addend")),
                });
            }
        }
        out.sort_unstable_by_key(|r| r.vaddr);
        out
    }

    /// A `DT_RELR` table decodes back to exactly the relocations it packs —
    /// the same slots, each with the same link-time address, as the
    /// `.rela.dyn` entries the pack replaced.
    ///
    /// This is the whole of what makes a packed library mergeable: a slot the
    /// decoder misses is a pointer in the merged binary that keeps the address
    /// the library was linked at, and a target it gets wrong is a pointer at
    /// the wrong byte. Holding it to real libraries rather than to a
    /// hand-written stream is what checks the bitmap runs the encoding spends
    /// its space on — libtinfo's 1503 entries come to 27 bitmap words.
    #[test]
    fn a_packed_table_decodes_to_the_relocations_it_replaced() {
        for name in TEST_LIBS {
            let original = read_test_lib(name);
            let (packed, expected) = relr_packing::pack_relative_relocs(&original);

            assert_eq!(
                expected,
                explicit_relative_relocs(&original),
                "{name}: the pack did not take the whole of .rela.dyn's relative entries"
            );
            assert!(
                expected.len() > 10,
                "{name}: only {} relative relocations to pack",
                expected.len()
            );
            assert_eq!(
                explicit_relative_relocs(&packed),
                Vec::new(),
                "{name}: .rela.dyn still spells out relative entries after packing"
            );

            let decoded = packed_relative_relocs(&parse(&packed), Path::new(name))
                .unwrap_or_else(|e| panic!("{name}: decoding DT_RELR: {e:#}"));
            assert_eq!(decoded, expected, "{name}");
        }
    }

    /// The committed fixtures keep their relative relocations in `.rela.dyn`,
    /// where `object` reads them, so there is no table to decode and nothing
    /// for this to add.
    #[test]
    fn a_library_with_no_dt_relr_yields_no_relocations() {
        for name in TEST_LIBS {
            let bytes = read_test_lib(name);
            let decoded = packed_relative_relocs(&parse(&bytes), Path::new(name))
                .unwrap_or_else(|e| panic!("{name} should be mergeable: {e:#}"));
            assert_eq!(decoded, Vec::new(), "{name}");
        }
    }

    /// A real library with the `DT_RELR` tags written over the spare
    /// `.dynamic` slots the linker leaves past `DT_NULL`, naming a table that
    /// is not there. The tags are the whole of how a packed build announces
    /// itself, so this is how a malformed one arrives.
    fn with_relr_tags(name: &str, table_va: u64, size: u64) -> Vec<u8> {
        let mut bytes = read_test_lib(name);
        let mut dynamic = DynamicTable::parse(&bytes).expect(".dynamic of a test library");
        for (tag, val) in [(DT_RELR, table_va), (DT_RELRSZ, size)] {
            dynamic
                .append(&mut bytes, tag, val)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        bytes
    }

    /// A table solder cannot read has to fail the merge, not yield the part of
    /// itself that decoded: the relocations it withholds are the pointers the
    /// merged binary would carry stale, which is the whole reason for reading
    /// it. Each of these is a shape a size or an address field can take —
    /// a length that is not a whole number of entries, and a table outside the
    /// loaded image.
    #[test]
    fn a_dt_relr_table_that_cannot_be_read_is_refused() {
        let name = TEST_LIBS[0];
        let path = PathBuf::from("/sysroot/lib").join(name);
        for (table_va, size, expected) in [
            (0x4518, 12, "not a whole number"),
            (0xdead_0000, 216, "no loaded segment"),
        ] {
            let bytes = with_relr_tags(name, table_va, size);
            let err = format!(
                "{:#}",
                packed_relative_relocs(&parse(&bytes), &path)
                    .expect_err("an unreadable DT_RELR table must be refused")
            );
            assert!(err.contains(expected), "{err}");
            assert!(err.contains(&path.display().to_string()), "{err}");
        }
    }

    /// A stream whose first word is a bitmap has no address for that bitmap to
    /// count from, so there is no reading it — the loader would take the
    /// relocated slots to start at 0.
    #[test]
    fn a_dt_relr_table_opening_with_a_bitmap_is_refused() {
        let name = TEST_LIBS[0];
        let original = read_test_lib(name);
        let (mut packed, _) = relr_packing::pack_relative_relocs(&original);

        let table_va = DynamicTable::parse(&packed)
            .expect(".dynamic")
            .value_of(DT_RELR)
            .expect("DT_RELR");
        let at = va_to_file_offset(&parse(&packed), table_va).expect("the table is file-backed");
        // Set bit 0 of the leading address word, which is what marks a word as
        // a bitmap.
        packed[at as usize] |= 1;

        let err = format!(
            "{:#}",
            packed_relative_relocs(&parse(&packed), Path::new(name))
                .expect_err("a stream cannot open with a bitmap word")
        );
        assert!(err.contains("no address to be relative to"), "{err}");
    }

    /// `DT_RELR` naming an empty table relocates nothing, so there is nothing
    /// to decode and nothing to refuse the library over.
    #[test]
    fn an_empty_dt_relr_table_yields_no_relocations() {
        let bytes = with_relr_tags(TEST_LIBS[0], 0x4518, 0);
        let decoded = packed_relative_relocs(&parse(&bytes), Path::new(TEST_LIBS[0]))
            .expect("an empty DT_RELR table withholds nothing");
        assert_eq!(decoded, Vec::new());
    }

    /// A size tag is the file's own claim, so one large enough to wrap
    /// `offset + size` has to come back as an error rather than a slice the
    /// wrapped bound let through — the writer used to add the two unchecked.
    #[test]
    fn a_dynamic_table_whose_size_wraps_the_file_offset_is_refused() {
        let bytes = read_test_lib(TEST_LIBS[0]);
        let elf = parse(&bytes);
        let strtab = DynamicTable::parse(&bytes)
            .expect(".dynamic")
            .value_of(goblin::elf::dynamic::DT_STRTAB)
            .expect("DT_STRTAB");

        let (_, whole) = dynamic_table_bytes(&elf, &bytes, ".dynstr", strtab, 1)
            .expect("a one-byte .dynstr prefix is in the file");
        assert_eq!(whole.len(), 1);

        for size in [u64::MAX, u64::MAX - strtab, bytes.len() as u64] {
            let err = format!(
                "{:#}",
                dynamic_table_bytes(&elf, &bytes, ".dynstr", strtab, size)
                    .expect_err("a table running past the file must be refused")
            );
            assert!(err.contains("past the end"), "{size:#x}: {err}");
        }
    }
}

/// Repacking a library's relative relocations the way
/// `ld -z pack-relative-relocs` does, so the decoder and extraction can both
/// be held to a real `DT_RELR` build without one being committed as a fixture.
///
/// A fixture would be the stronger input, but there is no linker in the test
/// environment to produce one and a hand-built stream would only check the
/// decoder against the encoder's idea of the format. Repacking a committed
/// library keeps the relocated set provably the same — the `.rela.dyn` entries
/// it replaces are right there to compare against — which is what makes
/// "extracting the packed build gives the same units as the unpacked one" an
/// assertion about solder and not about the fixture.
#[cfg(test)]
pub(crate) mod relr_packing {
    use super::*;

    /// `sizeof (Elf64_Rela)`.
    const RELA_ENTRY_SIZE: usize = 24;

    /// Move every `R_X86_64_RELATIVE` entry of `bytes`' `.rela.dyn` into a
    /// `DT_RELR` table, returning the repacked image and the relocations that
    /// table now carries, in address order.
    ///
    /// A packed entry has no addend field — the loader's whole action is
    /// `*slot += load_base` — so each relocated slot is given the `r_addend`
    /// its explicit entry spelled out, which is what the linker writes there
    /// when it packs them. The entries that survive are compacted to the front
    /// of `.rela.dyn`, the table goes in the space that frees up, and the
    /// section's `sh_size` and `DT_RELASZ` are cut to the survivors — so
    /// `object`'s `dynamic_relocations`, which reads the section, sees exactly
    /// what it would see of a packed build: the relative entries gone.
    pub(crate) fn pack_relative_relocs(bytes: &[u8]) -> (Vec<u8>, Vec<RelrReloc>) {
        let elf = ElfFile64::<object::Endianness>::parse(bytes).expect("parse the library");
        let mut out = bytes.to_vec();

        let table = SectionTable::parse(bytes)
            .expect("section headers")
            .expect("a section header table");
        let rela = table
            .sections
            .iter()
            .find(|s| s.name == ".rela.dyn")
            .expect(".rela.dyn");
        let shdr_at = table.offset + rela.index * SHDR_SIZE;
        let rela_at = rela.offset as usize;
        let rela_size = rela.size as usize;
        assert_eq!(
            rela_size % RELA_ENTRY_SIZE,
            0,
            ".rela.dyn is not a whole number of entries"
        );

        let mut packed: Vec<RelrReloc> = Vec::new();
        let mut kept: Vec<u8> = Vec::new();
        for i in 0..rela_size / RELA_ENTRY_SIZE {
            let entry = &bytes[rela_at + i * RELA_ENTRY_SIZE..][..RELA_ENTRY_SIZE];
            let r_info = u64::from_le_bytes(entry[8..16].try_into().expect("r_info"));
            if r_info == u64::from(object::elf::R_X86_64_RELATIVE.0) {
                packed.push(RelrReloc {
                    vaddr: u64::from_le_bytes(entry[0..8].try_into().expect("r_offset")),
                    addend: u64::from_le_bytes(entry[16..24].try_into().expect("r_addend")),
                });
            } else {
                kept.extend_from_slice(entry);
            }
        }
        packed.sort_unstable_by_key(|r| r.vaddr);
        assert!(
            !packed.is_empty(),
            "the library has no relative relocations to pack"
        );

        let stream = encode(&packed);
        let stream_bytes = stream.len() * RELR_ENTRY_SIZE as usize;
        assert!(
            kept.len() + stream_bytes <= rela_size,
            "the packed table does not fit in the {rela_size} bytes .rela.dyn frees up"
        );

        // The word in the slot is a packed entry's only addend.
        for reloc in &packed {
            let at = va_to_file_offset(&elf, reloc.vaddr).expect("a relocated slot is file-backed");
            out[at as usize..][..8].copy_from_slice(&reloc.addend.to_le_bytes());
        }

        out[rela_at..][..kept.len()].copy_from_slice(&kept);
        let stream_at = rela_at + kept.len();
        for (i, word) in stream.iter().enumerate() {
            out[stream_at + i * RELR_ENTRY_SIZE as usize..][..8]
                .copy_from_slice(&word.to_le_bytes());
        }
        out[stream_at + stream_bytes..rela_at + rela_size].fill(0);
        out[shdr_at + SH_SIZE..][..8].copy_from_slice(&(kept.len() as u64).to_le_bytes());

        let mut dynamic = DynamicTable::parse(bytes).expect(".dynamic of a test library");
        dynamic.set_value(&mut out, object::elf::DT_RELASZ.0 as u64, kept.len() as u64);
        // `DT_RELACOUNT` counts the relative entries `.rela.dyn` opens with,
        // and there are none left.
        dynamic.set_value(&mut out, object::elf::DT_RELACOUNT.0 as u64, 0);

        // The `DT_RELR*` tags go over the spare slots the linker leaves past
        // `DT_NULL`.
        for (tag, val) in [
            (DT_RELR, rela.addr + kept.len() as u64),
            (DT_RELRSZ, stream_bytes as u64),
            (object::elf::DT_RELRENT.0 as u64, RELR_ENTRY_SIZE),
        ] {
            dynamic
                .append(&mut out, tag, val)
                .expect("a spare .dynamic slot");
        }

        (out, packed)
    }

    /// Encode `relocs`, in address order, as a `DT_RELR` stream: an address
    /// word for the slot that opens each run, then one bitmap word per 63
    /// slots the run goes on to cover.
    ///
    /// This is the linker's side of the format that
    /// [`packed_relative_relocs`](super::packed_relative_relocs) reads, and
    /// the only reason it is spelled out here rather than taken from a
    /// reference encoder: the decoder has to be checked against a stream it
    /// did not produce.
    fn encode(relocs: &[RelrReloc]) -> Vec<u64> {
        let slots: Vec<u64> = relocs.iter().map(|r| r.vaddr).collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < slots.len() {
            out.push(slots[i]);
            let mut base = slots[i] + RELR_ENTRY_SIZE;
            i += 1;
            loop {
                let mut bits = 0u64;
                while let Some(&slot) = slots.get(i) {
                    let Some(bit) = slot
                        .checked_sub(base)
                        .map(|d| d / RELR_ENTRY_SIZE)
                        .filter(|&d| d < RELR_BITS_PER_WORD)
                    else {
                        break;
                    };
                    assert_eq!(slot % RELR_ENTRY_SIZE, 0, "{slot:#x} is not a pointer slot");
                    bits |= 1 << bit;
                    i += 1;
                }
                if bits == 0 {
                    break;
                }
                out.push((bits << 1) | 1);
                base += RELR_BITS_PER_WORD * RELR_ENTRY_SIZE;
            }
        }
        out
    }
}

#[cfg(test)]
mod executable_tests {
    use super::*;

    const GREP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/grep");

    fn validate(bytes: &[u8]) -> Result<bool> {
        let elf = object::read::elf::ElfFile64::<object::Endianness>::parse(bytes)
            .expect("parse the fixture");
        validate_executable(&elf, Path::new(GREP)).map(|(_, is_pie)| is_pie)
    }

    #[test]
    fn the_executables_solder_merges_into_are_accepted() {
        for name in ["grep", "bash", "md5sum"] {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test/").to_string() + name;
            let bytes = std::fs::read(&path).expect("test binary");
            assert!(
                validate(&bytes).unwrap_or_else(|e| panic!("{name} should be mergeable: {e:#}")),
                "{name} is a PIE executable"
            );
        }
    }

    /// An executable with no section header table is not something the merge
    /// can finish — `.dynsym`/`.gnu.version` have no length in `.dynamic` and
    /// the Verneed list has no extent — and the refusal has to come from here,
    /// before any work is done.
    ///
    /// It used to be noticed much later and reported as something else
    /// entirely: `RelaTables::read` looked `.rela.plt` and `.rela.dyn` up by
    /// section name, so a stripped executable produced two empty relocation
    /// tables, the import scan found nothing to merge out of any library, and
    /// `solder` exited 0 saying "No mergeable imported symbols found" having
    /// left the binary untouched — the same answer it gives for an executable
    /// that genuinely imports nothing.
    #[test]
    fn an_executable_without_a_section_header_table_is_refused() {
        let mut bytes = std::fs::read(GREP).expect("read test/grep");
        // e_shoff, e_shnum and e_shstrndx: what `sstrip` and friends clear.
        bytes[0x28..0x30].fill(0);
        bytes[0x3c..0x40].fill(0);

        let err = format!(
            "{:#}",
            validate(&bytes).expect_err("a section-header-less executable must be refused")
        );
        assert!(err.contains("section header"), "{err}");
        assert!(err.contains("/test/grep"), "{err}");
    }
}

/// Rewrite the `p_align` of every `PT_LOAD` in a little-endian ELF64 image, to
/// stand in for an executable linked with a different `-z max-page-size`.
#[cfg(test)]
pub(crate) fn set_load_alignment(bytes: &mut [u8], align: u64) {
    fn word(bytes: &[u8], at: usize, len: usize) -> usize {
        let mut buf = [0u8; 8];
        buf[..len].copy_from_slice(&bytes[at..at + len]);
        u64::from_le_bytes(buf) as usize
    }
    let phoff = word(bytes, 0x20, 8);
    let phentsize = word(bytes, 0x36, 2);
    let phnum = word(bytes, 0x38, 2);
    for i in 0..phnum {
        let at = phoff + i * phentsize;
        if word(bytes, at, 4) == object::elf::PT_LOAD.0 as usize {
            bytes[at + 48..at + 56].copy_from_slice(&align.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod page_size_tests {
    use super::*;

    const GREP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/grep");

    /// The fixtures were linked for 4 KiB pages, and that is what they get.
    #[test]
    fn a_4k_executable_gets_4k_pages() {
        let mapped = MappedElf::open(Path::new(GREP)).expect("open test/grep");
        let elf = mapped.parse().expect("parse test/grep");
        assert_eq!(page_size(&elf, &crate::arch::X86_64), 0x1000);
    }

    /// An executable linked with `-z max-page-size=0x10000`, as distribution
    /// aarch64 toolchains do, has to have its merged mappings 64 KiB apart, or
    /// a 64K kernel maps the merged code and the data after it as one page.
    #[test]
    fn the_executables_p_align_is_the_page_size() {
        assert_eq!(
            page_size_for([0x10000, 0x10000].into_iter(), 0x10000),
            0x10000
        );
        // The largest one counts: no mapping may share a page under any of
        // the page sizes the linker allowed for.
        assert_eq!(page_size_for([0x1000, 0x4000].into_iter(), 0x10000), 0x4000);
    }

    /// A 2 MiB `p_align` on x86-64 asks for huge-page alignment, not 2 MiB
    /// pages; honouring it would pad the file by megabytes for nothing.
    #[test]
    fn a_p_align_past_the_architectures_largest_page_is_capped() {
        let mut bytes = std::fs::read(GREP).expect("read test/grep");
        set_load_alignment(&mut bytes, 0x20_0000);
        let elf = ElfFile64::<object::Endianness>::parse(&*bytes).expect("parse");
        assert_eq!(page_size(&elf, &crate::arch::X86_64), 0x1000);
        assert_eq!(page_size_for([0x20_0000].into_iter(), 0x10000), 0x10000);
    }

    /// Anything that is not a power of two, or is below the smallest page —
    /// including the 0 and 1 that mean "no constraint" — leaves the floor.
    #[test]
    fn a_p_align_that_is_no_page_size_is_ignored() {
        for align in [0, 1, 0x800, 0x3000, 0x10001] {
            assert_eq!(
                page_size_for([align].into_iter(), 0x10000),
                MIN_PAGE_SIZE,
                "{align:#x}"
            );
        }
        assert_eq!(page_size_for(std::iter::empty(), 0x10000), MIN_PAGE_SIZE);
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

    /// `append` fills the spare slots past `DT_NULL`, which the linker does not
    /// promise to have zeroed, so each entry it writes has to leave a fresh
    /// terminator behind it; and the last slot has to stay that terminator, so
    /// an append that would take it is refused.
    #[test]
    fn append_keeps_the_table_terminated_and_refuses_the_last_slot() {
        use goblin::elf::dynamic::{DT_DEBUG, DT_NULL};

        let mut bytes = read_test_binary("grep");
        let mut table = DynamicTable::parse(&bytes).expect("parse .dynamic");
        let (used, capacity) = (table.used(), table.capacity());
        assert!(capacity > used + 1, "no spare slot to append into");
        // Garbage in every spare slot, so a terminator only exists if written.
        let spare = table.entry_offset(used + 1)..table.entry_offset(capacity);
        bytes[spare].fill(0xa5);

        for i in 0..capacity - used - 1 {
            table
                .append(&mut bytes, DT_DEBUG, i as u64)
                .expect("a spare slot");
            let reparsed = DynamicTable::parse(&bytes).expect("reparse .dynamic");
            assert_eq!(reparsed.used(), used + i + 1);
            assert_eq!(reparsed.values_of(DT_DEBUG).last(), Some(i as u64));
        }

        let err = table
            .append(&mut bytes, DT_DEBUG, 0)
            .expect_err("the last slot is the terminator's");
        assert!(format!("{err}").contains("no room"), "{err}");
        let last = table.entry_offset(capacity - 1);
        assert_eq!(
            u64::from_le_bytes(bytes[last..last + 8].try_into().unwrap()),
            DT_NULL
        );
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
