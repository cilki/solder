use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context, Result, anyhow, bail};
use iced_x86::Instruction;
use object::{Object, ObjectSection, ObjectSymbol, SectionKind as ObjSectionKind};
use tracing::{debug, warn};

use crate::elf_reader::MappedElf;
use crate::types::{
    DATA_BLOB_ALIGNMENT, DataSectionCopy, ExtractedReloc, ExtractedUnit, GotSlotFixup,
    InitFiniArrays, InitFiniEntry, RelocTarget, SectionKind, UnboundedEnd, UnitId,
};

/// The map the extractor's own caches are kept in.
///
/// Those caches are what extraction spends its time in: a merge of
/// `libcrypto.so.3` into `test/md5sum` asks them about 69k references into
/// 10k units, and the profile put a sixth of the whole run inside
/// `std::collections::HashMap` — most of it SipHash, which is built to be
/// unpredictable rather than quick and processes its key a byte at a time.
///
/// What that buys is resistance to an adversary who can choose keys that
/// collide, and these keys are chosen by the library being merged: symbol
/// names out of its `.dynsym`, addresses out of its relocations. The attack
/// it would mount is a merge that takes longer than it should, against an
/// attacker who, by the time solder reads the file, has already been handed
/// something strictly better — solder's whole job is to copy that library's
/// machine code into the executable and run it. Nothing about the merge's
/// output depends on the hasher, so the trade is a sixth of the runtime
/// against a slow merge of a file you are about to execute anyway.
///
/// Only the extractor's internal tables are built this way; nothing crossing
/// a module boundary changes type.
type FastMap<K, V> = rustc_hash::FxHashMap<K, V>;
/// The set counterpart of [`FastMap`], for the same reasons.
type FastSet<T> = rustc_hash::FxHashSet<T>;

/// Relocation type names we explicitly reject with a helpful error.
fn describe_reloc(
    kind: object::RelocationKind,
    encoding: object::RelocationEncoding,
) -> &'static str {
    match (kind, encoding) {
        (object::RelocationKind::Got, _) => "GOT-relative (GOTPCREL/GOTPCRELX)",
        (object::RelocationKind::GotRelative, _) => "GOT-relative",
        (object::RelocationKind::GotBaseRelative, _) => "GOT-base-relative",
        _ => "unsupported",
    }
}

/// One of the libraries extraction is reading, named by position in
/// [`ExtractionState::lib_paths`] rather than by path.
///
/// Every key extraction hashes names a library, and the merge of a single
/// large library hashes those keys hundreds of thousands of times: once per
/// reference resolved ([`ExtractionState::reserve`]) and once per address
/// attributed to a data section ([`ensure_data_blob_extracted`]). Hashing a
/// `PathBuf` walks the whole path string every time, which made hashing alone
/// a quarter of the run on `test/md5sum` + `libcrypto.so.3`. Interning the
/// path once leaves a `u32` to hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LibId(u32);

/// Key used to deduplicate units during BFS.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UnitKey {
    lib: LibId,
    sym: String,
}

/// Key for data blob deduplication: (library, section index, blob base).
///
/// The section is identified by its index rather than its name for the same
/// reason the library is: the name has to be read out of `.shstrtab` and
/// copied before it can be hashed, and this key is built for every address a
/// scanned reference or a dynamic relocation points at.
///
/// `base` is the address the copied range starts at. It is the section's own
/// address for every section the merge copies a prefix of, and the slot
/// address for a GOT, which is copied one slot at a time (see
/// [`got_slot_at`]): every address in a slot maps to the same base, so an
/// exact lookup on this key still finds the blob a later reference into the
/// same slot wants.
///
/// A section's copy is anchored at the section's own first byte for as long as
/// extraction runs and only ever grows forward (see [`grow_data_blob`]), which
/// is what keeps the base out of the lookup: however much of the section ends
/// up copied, there is one copy of it and every reference into it resolves to
/// the same blob at the same offset. Once the closure is complete the copy is
/// moved up to the lowest byte anything references
/// ([`trim_unreferenced_prefixes`]), which is the last thing to touch a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DataBlobKey {
    lib: LibId,
    section: object::SectionIndex,
    base: u64,
}

/// Info about an extracted data section blob.
#[derive(Clone, Copy)]
struct DataBlobInfo {
    id: UnitId,
    base_vaddr: u64,
    /// How many bytes from `base_vaddr` have been copied into the blob so far.
    copied: u64,
    /// The lowest offset from `base_vaddr` anything has referenced, which is
    /// where the copy can start once nothing more will be resolved against it
    /// (see [`trim_unreferenced_prefixes`]).
    first_ref: u64,
    /// The lowest offset from `base_vaddr` whose dynamic relocations have been
    /// resolved, and so the low end of the one contiguous range
    /// `[rooted_from, copied)` they have been collected over. `u64::MAX` until
    /// the first collection.
    ///
    /// Only the bytes that can still reach the output are worth resolving: a
    /// pointer below the first reference is in a run the copy gives back, and
    /// rooting it would extract what it names for nothing — and pin the run it
    /// sits in, since a relocation's bytes have to be kept (see
    /// [`grow_data_blob`]).
    rooted_from: u64,
    /// How far from `base_vaddr` the references that say how much they read
    /// reach, and how far the ones that say nothing reach through
    /// [`needed_prefix`]'s fallback — the next object the library names, or the
    /// section. The copy's extent is the larger of the two; *which* of them it
    /// is, is what [`DataSectionCopy::unbounded_end`] reports, and a tie goes
    /// to the reads, since they justify the end on their own.
    read_to: u64,
    fallback_to: u64,
    /// Where the blob's entry in [`ExtractionState::data_section_copies`] is,
    /// so growing the copy can keep the reported cost current. `None` for a
    /// GOT slice, which is exactly bounded and is not reported.
    report: Option<usize>,
}

/// State threaded through the BFS.
struct ExtractionState {
    /// The id reserved for each unit the closure has reached, whether or not it
    /// has been extracted yet (see [`ExtractionState::reserve`]).
    reserved: FastMap<UnitKey, UnitId>,
    /// Units whose id has been reserved but which have not been extracted yet,
    /// each with the id reserved for it. Reserving an id and queueing the
    /// extraction that fulfills it are the same step, so nothing can hand out
    /// an id for a unit it then forgets to build — and the extraction is handed
    /// the id rather than looking the key up again to find it.
    worklist: VecDeque<(UnitKey, UnitId)>,
    units: Vec<ExtractedUnit>,
    /// Where in `units` each registered unit lives. A unit is reached by its
    /// `UnitId` from elsewhere — the jump-table scanner appends relocations to
    /// a `.rodata` blob extracted for another function — and `units` is not in
    /// id order, because a data blob's relocations can pull in another blob
    /// that gets pushed first. Scanning `units` for a matching id instead made
    /// every one of those lookups O(units), which with ~10k units
    /// (md5sum + libcrypto.so.3) was most of a second of pure comparisons.
    unit_index: FastMap<UnitId, usize>,
    next_id: u32,
    /// Symbols that stay external (glibc etc.). Maps name → known.
    external_syms: FastSet<String>,
    /// Symbols exported by any merged library, mapped to the library that
    /// defines them. Used to redirect cross-library PLT calls (e.g. libssl
    /// calling into libcore) to direct merged-unit references instead of
    /// leaving the original library-relative PLT offset in place.
    cross_lib_syms: FastMap<String, LibId>,
    /// Symbols the executable actually DEFINES (subset of `external_syms`,
    /// which also contains the executable's undefined imports).
    exe_defined_syms: FastSet<String>,
    /// Symbols the executable copy-relocates, whose storage is therefore the
    /// executable's and not the defining library's (see
    /// `RelaTables::copy_reloc_symbols`).
    exe_copy_relocated: FastSet<String>,
    /// Libraries we've already extracted init/fini arrays from.
    processed_libs: FastSet<LibId>,
    /// Accumulated init/fini entries from all processed libraries.
    init_fini: InitFiniArrays,
    /// Extracted data section blobs: maps (lib, section index) → blob info
    data_blobs: FastMap<DataBlobKey, DataBlobInfo>,
    /// Every data section copied for want of a symbol naming the object a
    /// reference landed in, in the order the copies happened (see
    /// [`DataSectionCopy`]).
    data_section_copies: Vec<DataSectionCopy>,
    /// Which offsets of an extracted data blob already carry a relocation, for
    /// the jump-table pass and for a copy that grew after it was registered
    /// (see [`ExtractionState::claim_blob_offset`]).
    blob_reloc_offsets: FastMap<UnitId, FastSet<u64>>,
    /// What each address a reference pointed at resolved to, so the resolution
    /// is done once per address rather than once per reference to it (see
    /// [`reserve_unit_at`]).
    units_at: FastMap<(LibId, u64), Option<UnitRef>>,
    /// What the PLT stub at each address resolved to, so a stub is resolved
    /// once rather than once per call site (see [`plt_reference`]).
    plt_refs: FastMap<(LibId, u64), Option<RelocTarget>>,
    /// Copied GOT slots that need a GLOB_DAT in the output (see GotSlotFixup).
    got_slot_fixups: Vec<GotSlotFixup>,
    /// Every library extraction has touched, in the order it first saw them;
    /// a [`LibId`] is a position in here (see [`ExtractionState::lib_id`]).
    lib_paths: Vec<Rc<Path>>,
    /// The reverse of `lib_paths`, consulted only when a path first turns up.
    lib_ids: FastMap<Rc<Path>, LibId>,
    /// Cache of library images, indexed by [`LibId`]. `process_symbol` runs
    /// once per extracted symbol, and a large library (e.g. libcrypto.so.3 at
    /// ~6MB) can yield thousands of symbols; re-opening the whole file each
    /// time dominated the runtime. The parse itself is lazy and cheap, so only
    /// the image needs caching.
    lib_bytes_cache: Vec<Option<Rc<MappedElf>>>,
    /// Precomputed symbol lookups per library (see `LibIndex`).
    lib_index_cache: Vec<Option<Rc<LibIndex>>>,
}

impl ExtractionState {
    fn alloc_id(&mut self) -> UnitId {
        let id = UnitId(self.next_id);
        self.next_id += 1;
        id
    }

    /// The id the merged copy of `key` will have, reserving one and queueing
    /// the extraction that fulfills it if nothing has asked for `key` yet.
    ///
    /// A reference to a unit can be resolved the moment it is found, because
    /// the id does not depend on anything extraction has yet to discover — only
    /// on whether this key has been seen before. That is what lets a
    /// relocation's target be filled in as it is collected instead of in a
    /// second pass over the whole closure: with ~69k references into ~10k units
    /// (`test/md5sum` + `libcrypto.so.3`) the pass was 69k hash lookups of a
    /// `(PathBuf, String)` key, and recording the references cost a clone of
    /// that key apiece on top.
    fn reserve(&mut self, key: UnitKey) -> UnitId {
        if let Some(&id) = self.reserved.get(&key) {
            return id;
        }
        let id = self.alloc_id();
        self.worklist.push_back((key.clone(), id));
        self.reserved.insert(key, id);
        id
    }

    /// Record that the relocation being collected needs `dep` merged, and hand
    /// back the target to store in it.
    fn depend_on(&mut self, dep: UnitKey) -> RelocTarget {
        RelocTarget::MergedUnit(self.reserve(dep))
    }

    /// Register a finished unit so it can be found again by its id.
    fn push_unit(&mut self, unit: ExtractedUnit) {
        self.unit_index.insert(unit.id, self.units.len());
        self.units.push(unit);
    }

    /// The registered unit with `id`.
    ///
    /// `None` for an id that has been reserved but not yet extracted.
    fn unit(&self, id: UnitId) -> Option<&ExtractedUnit> {
        let idx = *self.unit_index.get(&id)?;
        self.units.get(idx)
    }

    /// The registered unit with `id`, mutably. See [`ExtractionState::unit`]
    /// for when there is none.
    fn unit_mut(&mut self, id: UnitId) -> Option<&mut ExtractedUnit> {
        let idx = *self.unit_index.get(&id)?;
        self.units.get_mut(idx)
    }

    /// Take the offset `offset` within data blob `id` for a relocation, or
    /// report `false` because one is already there.
    ///
    /// The blob holding a jump table is reached again by every function that
    /// branches through one, and two tables detected from different functions
    /// can overlap on the same entries, so each entry has to be checked
    /// against what the blob already holds. Searching the blob's relocation
    /// list for that made the pass quadratic: `libcrypto.so.3` keeps every
    /// jump table in one `.rodata`, whose blob ends up with tens of thousands
    /// of relocations, and each candidate entry walked all of them — a tenth
    /// of the whole run on `test/md5sum` + `libcrypto.so.3`.
    ///
    /// The set is seeded from the blob's own relocations the first time it is
    /// asked about, and both things that append to a registered blob's list go
    /// through it: the jump-table pass, and `grow_data_blob` when a later
    /// reference extends the copy. Either order is therefore safe — whichever
    /// reaches a given offset first keeps it.
    fn claim_blob_offset(&mut self, id: UnitId, offset: u64) -> bool {
        if !self.blob_reloc_offsets.contains_key(&id) {
            let taken = self
                .unit(id)
                .map(|unit| {
                    unit.relocations
                        .iter()
                        .map(|r| r.offset_within_unit)
                        .collect()
                })
                .unwrap_or_default();
            self.blob_reloc_offsets.insert(id, taken);
        }
        self.blob_reloc_offsets
            .get_mut(&id)
            .expect("the entry was just inserted")
            .insert(offset)
    }

    /// The id `path` is interned under, assigning it one on first sight.
    fn lib_id(&mut self, path: &Path) -> LibId {
        if let Some(&id) = self.lib_ids.get(path) {
            return id;
        }
        let id = LibId(self.lib_paths.len() as u32);
        let path: Rc<Path> = Rc::from(path);
        self.lib_paths.push(Rc::clone(&path));
        self.lib_ids.insert(path, id);
        self.lib_bytes_cache.push(None);
        self.lib_index_cache.push(None);
        id
    }

    /// The path `lib` was interned from.
    fn lib_path(&self, lib: LibId) -> Rc<Path> {
        Rc::clone(&self.lib_paths[lib.0 as usize])
    }

    /// Return the image of `lib`, mapping and caching it on first use.
    fn lib_bytes(&mut self, lib: LibId) -> Result<Rc<MappedElf>> {
        if let Some(bytes) = &self.lib_bytes_cache[lib.0 as usize] {
            return Ok(Rc::clone(bytes));
        }
        let path = self.lib_path(lib);
        let bytes =
            Rc::new(MappedElf::open(&path).with_context(|| format!("reading {}", path.display()))?);
        // First sight of a library the merge takes code or data out of, and the
        // one place every extracted byte comes through — including a library
        // reached only by a cross-library reference, which the executable
        // imports nothing from and no earlier stage looks at. A library whose
        // relative relocations solder cannot see has to be refused here, before
        // any of its data is copied.
        crate::elf_reader::refuse_packed_relative_relocs(bytes.bytes(), &path)?;
        self.lib_bytes_cache[lib.0 as usize] = Some(Rc::clone(&bytes));
        Ok(bytes)
    }

    /// Return the symbol index for `lib`, building and caching it on first use.
    fn lib_index(&mut self, lib: LibId, elf: &object::read::elf::ElfFile64<'_>) -> Rc<LibIndex> {
        if let Some(idx) = &self.lib_index_cache[lib.0 as usize] {
            return Rc::clone(idx);
        }
        let idx = Rc::new(LibIndex::build(elf));
        debug!(
            lib = %self.lib_path(lib).display(),
            symbols = idx.by_name.len(),
            fdes = idx.fdes.fde_count(),
            "Indexed library"
        );
        self.lib_index_cache[lib.0 as usize] = Some(Rc::clone(&idx));
        idx
    }

    /// Zero the copied GOT slots at `slots` within `bytes` and register a fixup
    /// for each: the copied bytes hold stale library VAs, and ld.so's GLOB_DAT
    /// overwrites them at startup anyway (see `GotSlotFixup`).
    fn register_got_slot_fixups(
        &mut self,
        unit: UnitId,
        bytes: &mut [u8],
        slots: Vec<(u64, String, bool)>,
    ) {
        for (offset, name, weak) in slots {
            let off = offset as usize;
            if off + 8 <= bytes.len() {
                bytes[off..off + 8].fill(0);
            }
            self.got_slot_fixups.push(GotSlotFixup {
                unit,
                offset,
                name,
                weak,
            });
        }
    }

    /// Finish the relocations collected for unit `id`: zero and record the
    /// copied GOT slots in `bytes` that ld.so has to fill in, and hand back the
    /// unit's relocation list for the caller to store. Extracting a symbol and
    /// extracting a data section blob both end this way.
    fn take_unit_relocs(
        &mut self,
        id: UnitId,
        bytes: &mut [u8],
        relocs: UnitRelocs,
    ) -> Vec<ExtractedReloc> {
        self.register_got_slot_fixups(id, bytes, relocs.got_fixups);
        relocs.relocations
    }
}

/// Everything one run of [`extract_units`] produces.
pub struct Extraction {
    /// The extracted units, in the order they were built.
    pub units: Vec<ExtractedUnit>,
    /// Init/fini array entries from every library a unit came out of.
    pub init_fini: InitFiniArrays,
    /// Copied GOT slots that ld.so has to re-resolve at startup.
    pub got_slot_fixups: Vec<GotSlotFixup>,
    /// The data sections that had to be copied whole, which is where an
    /// extraction far larger than the symbols asked for comes from (see
    /// [`DataSectionCopy`]).
    pub data_section_copies: Vec<DataSectionCopy>,
}

/// Extract all symbols transitively reachable from `seeds` (direct imports).
pub fn extract_units(
    seeds: &[crate::types::ImportedSymbol],
    exe_elf: &object::read::elf::ElfFile64<'_>,
    merged_lib_syms: &HashMap<String, PathBuf>,
    exe_copy_relocated: &HashSet<String>,
) -> Result<Extraction> {
    // Collect symbol names from the executable's .dynsym that merged library code
    // can reference. This includes both defined symbols (callable directly) and
    // undefined/imported symbols (callable through the executable's PLT).
    let exe_dynsym_names: FastSet<String> = exe_elf
        .dynamic_symbols()
        .filter_map(|s| s.name().ok().map(String::from))
        .filter(|name| !name.is_empty())
        .collect();
    let exe_defined_syms: FastSet<String> = exe_elf
        .dynamic_symbols()
        .filter(|s| !s.is_undefined())
        .filter_map(|s| s.name().ok().map(String::from))
        .filter(|name| !name.is_empty())
        .collect();

    let mut state = ExtractionState {
        reserved: FastMap::default(),
        worklist: VecDeque::new(),
        units: Vec::new(),
        unit_index: FastMap::default(),
        next_id: 0,
        external_syms: exe_dynsym_names,
        cross_lib_syms: FastMap::default(),
        exe_defined_syms,
        exe_copy_relocated: exe_copy_relocated.iter().cloned().collect(),
        processed_libs: FastSet::default(),
        init_fini: InitFiniArrays::default(),
        data_blobs: FastMap::default(),
        data_section_copies: Vec::new(),
        blob_reloc_offsets: FastMap::default(),
        units_at: FastMap::default(),
        plt_refs: FastMap::default(),
        got_slot_fixups: Vec::new(),
        lib_paths: Vec::new(),
        lib_ids: FastMap::default(),
        lib_bytes_cache: Vec::new(),
        lib_index_cache: Vec::new(),
    };

    // Interning the defining library of every symbol the merged libraries
    // export up front is what keeps the lookup on the hot path a `LibId`
    // comparison rather than a path hash.
    let cross_lib_syms = merged_lib_syms
        .iter()
        .map(|(sym, path)| (sym.clone(), state.lib_id(path)))
        .collect();
    state.cross_lib_syms = cross_lib_syms;

    for imp in seeds {
        let lib = state.lib_id(&imp.source_library);
        state.reserve(UnitKey {
            lib,
            sym: imp.name.clone(),
        });
    }

    // Every key on the worklist had an id reserved for it when it was queued,
    // and `process_symbol` registers the unit under that id — so the queue
    // running dry means every id handed out has a unit behind it, and every
    // relocation already points at the right one.
    while let Some((key, id)) = state.worklist.pop_front() {
        let lib = state.lib_path(key.lib);
        process_symbol(&key, id, &mut state)
            .with_context(|| format!("extracting '{}' from {}", key.sym, lib.display()))?;
    }

    // That is the invariant the whole scheme rests on: a `MergedUnit` target
    // naming an id nothing built would be a reference into the middle of
    // whatever the layout put at that id's place, with nothing to say so.
    if let Some((key, id)) = state
        .reserved
        .iter()
        .find(|(_, id)| !state.unit_index.contains_key(id))
    {
        bail!(
            "internal error: id {} was reserved for '{}' in {} but no unit was \
             extracted under it",
            id.0,
            key.sym,
            state.lib_path(key.lib).display()
        );
    }

    // Nothing will be resolved against a data blob again, so each copied
    // section can give back the run below the first byte anything references.
    trim_unreferenced_prefixes(&mut state);

    Ok(Extraction {
        units: state.units,
        init_fini: state.init_fini,
        got_slot_fixups: state.got_slot_fixups,
        data_section_copies: state.data_section_copies,
    })
}

/// Everything collecting one unit's relocations produces: the relocations
/// themselves and the copied GOT slots they turned up.
///
/// The two have to travel together, because zeroing a copied slot means
/// reaching into the unit's bytes once the relocations over them are settled.
/// Carrying them as separate out-parameters is what took
/// `collect_dynamic_range_relocs` to eleven arguments.
#[derive(Default)]
struct UnitRelocs {
    /// The unit's relocations, in the order they were collected.
    relocations: Vec<ExtractedReloc>,
    /// `(offset within the unit, symbol name, weak)` per copied GOT slot that
    /// ld.so has to fill in (see `GotSlotFixup`).
    got_fixups: Vec<(u64, String, bool)>,
}

/// A synthetic PC-relative relocation over a displacement the instruction
/// scanner found, at `offset` bytes into the unit being extracted. Every
/// scanned reference is patched the same way — only the displacement width,
/// the addend and the target differ.
fn pcrel_reloc(offset: u64, size: u8, addend: i64, target: RelocTarget) -> ExtractedReloc {
    ExtractedReloc {
        offset_within_unit: offset,
        kind: object::RelocationKind::Relative,
        encoding: object::RelocationEncoding::Generic,
        size,
        addend,
        target,
    }
}

/// Reject relocation kinds that need a GOT we cannot reproduce. `ctx` names the
/// symbol or section being extracted.
fn reject_got_reloc(
    kind: object::RelocationKind,
    encoding: object::RelocationEncoding,
    ctx: &str,
    lib: &Path,
) -> Result<()> {
    if matches!(
        kind,
        object::RelocationKind::Got
            | object::RelocationKind::GotRelative
            | object::RelocationKind::GotBaseRelative
            | object::RelocationKind::GotBaseOffset
    ) {
        bail!(
            "'{}' in {}: {} relocation is not supported in Tier 1; \
             recompile the library with an older toolchain or wait for Tier 2 support",
            ctx,
            lib.display(),
            describe_reloc(kind, encoding)
        );
    }
    Ok(())
}

/// The `r_type` of a relocation the `object` crate read out of an ELF file.
fn elf_r_type(reloc: &object::Relocation) -> Option<u32> {
    match reloc.flags() {
        object::RelocationFlags::Elf { r_type } => Some(r_type.0),
        _ => None,
    }
}

/// The x86-64 name of a dynamic relocation type solder cannot lift, and what
/// the loader was supposed to put in its slot.
fn describe_unliftable_reloc(r_type: u32) -> (String, &'static str) {
    use object::elf::{
        R_X86_64_COPY, R_X86_64_DTPMOD64, R_X86_64_DTPOFF32, R_X86_64_DTPOFF64,
        R_X86_64_GOTPC32_TLSDESC, R_X86_64_GOTTPOFF, R_X86_64_IRELATIVE, R_X86_64_SIZE32,
        R_X86_64_SIZE64, R_X86_64_TLSDESC, R_X86_64_TLSDESC_CALL, R_X86_64_TLSGD, R_X86_64_TLSLD,
        R_X86_64_TPOFF32, R_X86_64_TPOFF64,
    };

    const TLS: &str = ": the slot holds a module id or an offset from the thread \
                       pointer, not an address. Merging a library that uses \
                       thread-local storage needs its PT_TLS block merged into the \
                       executable's and an offset assigned in it, which solder does \
                       not do yet — exclude this library from the merge";
    const IFUNC: &str = ": the slot holds the address of an ifunc resolver that only \
                         ld.so can call, and what belongs in it is whatever that \
                         resolver returns — exclude this library from the merge";
    const SIZE: &str = ": the slot holds the symbol's size, not its address";
    const COPY: &str = ": a copy relocation only appears in an executable, never in a \
                         shared library";

    let named: &[(u32, &str, &str)] = &[
        (R_X86_64_DTPMOD64.0, "R_X86_64_DTPMOD64", TLS),
        (R_X86_64_DTPOFF64.0, "R_X86_64_DTPOFF64", TLS),
        (R_X86_64_TPOFF64.0, "R_X86_64_TPOFF64", TLS),
        (R_X86_64_TLSGD.0, "R_X86_64_TLSGD", TLS),
        (R_X86_64_TLSLD.0, "R_X86_64_TLSLD", TLS),
        (R_X86_64_DTPOFF32.0, "R_X86_64_DTPOFF32", TLS),
        (R_X86_64_GOTTPOFF.0, "R_X86_64_GOTTPOFF", TLS),
        (R_X86_64_TPOFF32.0, "R_X86_64_TPOFF32", TLS),
        (R_X86_64_GOTPC32_TLSDESC.0, "R_X86_64_GOTPC32_TLSDESC", TLS),
        (R_X86_64_TLSDESC_CALL.0, "R_X86_64_TLSDESC_CALL", TLS),
        (R_X86_64_TLSDESC.0, "R_X86_64_TLSDESC", TLS),
        (R_X86_64_IRELATIVE.0, "R_X86_64_IRELATIVE", IFUNC),
        (R_X86_64_SIZE32.0, "R_X86_64_SIZE32", SIZE),
        (R_X86_64_SIZE64.0, "R_X86_64_SIZE64", SIZE),
        (R_X86_64_COPY.0, "R_X86_64_COPY", COPY),
    ];

    named
        .iter()
        .find(|(t, ..)| *t == r_type)
        .map(|(_, name, note)| ((*name).to_string(), *note))
        .unwrap_or_else(|| (format!("relocation type {r_type}"), ""))
}

/// Refuse a dynamic relocation whose slot is not something solder can fill in
/// by writing `S + A` into eight bytes.
///
/// Everything lifted out of a library's `.rela.dyn`/`.rela.plt` ends up in
/// `relocator::apply_one_reloc`, which computes `S + A` and truncates it into
/// the field. For `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT` and
/// `R_X86_64_RELATIVE` that is exactly right — all three name a 64-bit slot
/// holding the target's address, which is why `collect_dynamic_range_relocs`
/// forces their reported width to 64 bits.
///
/// The catch is that the `object` crate's x86-64 table names none of those
/// three, so they arrive as `RelocationKind::Unknown` with a reported size of
/// 0 — and so does every *other* dynamic relocation type, none of which is a
/// pointer slot. Widening those to 64 bits as well made the relocator patch
/// them as `R_X86_64_64`, silently and with no diagnostic:
///
///   * a TLS slot (`R_X86_64_DTPMOD64`/`DTPOFF64`/`TPOFF64`, or a `TLSDESC`
///     pair) received a link-time address where ld.so was meant to store a
///     module id or an offset from the thread pointer. The merged code then
///     indexed `%fs` by that address, so the first access to the thread-local
///     read or wrote whatever happened to be that far from the thread
///     pointer.
///   * an `R_X86_64_IRELATIVE` slot received the address of the ifunc
///     *resolver* rather than the implementation the resolver picks, so every
///     indirect call through it called the resolver in its place — a call that
///     returns a function pointer where the caller expects the function's own
///     result.
///
/// Neither is a matter of patching the slot differently: TLS needs the
/// library's `PT_TLS` block merged into the executable's, and `IRELATIVE`
/// needs ld.so to run the resolver. Failing the merge keeps the problem at
/// merge time instead of turning it into a wild access in the merged binary.
///
/// `ctx` names the symbol or section being extracted.
fn reject_unliftable_dynamic_reloc(
    kind: object::RelocationKind,
    r_type: Option<u32>,
    ctx: &str,
    lib: &Path,
) -> Result<()> {
    use object::elf::{R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE};

    // Anything the `object` crate does name carries a real kind and width, and
    // `apply_one_reloc` either implements that form or rejects it by name.
    if kind != object::RelocationKind::Unknown {
        return Ok(());
    }
    // A non-ELF relocation cannot reach here; solder only reads ELF.
    let Some(r_type) = r_type else {
        return Ok(());
    };
    if [
        R_X86_64_GLOB_DAT.0,
        R_X86_64_JUMP_SLOT.0,
        R_X86_64_RELATIVE.0,
    ]
    .contains(&r_type)
    {
        return Ok(());
    }

    let (name, note) = describe_unliftable_reloc(r_type);
    bail!(
        "'{}' in {}: {} is not a 64-bit pointer slot, so the merged copy cannot \
         reproduce it{}",
        ctx,
        lib.display(),
        name,
        note
    )
}

/// Process a single symbol: extract its bytes under the id reserved for it and
/// parse its relocations, reserving an id for each unit they reach.
///
/// `id` is the id the queue reserved for this unit, under which everything
/// already pointing at it expects to find it. Having it passed in is also what
/// lets the unit's own relocations — a jump table's entries, a recursive call —
/// point at it as they are collected.
fn process_symbol(key: &UnitKey, id: UnitId, state: &mut ExtractionState) -> Result<()> {
    let lib_path = state.lib_path(key.lib);
    let lib_bytes = state.lib_bytes(key.lib)?;

    let object_file = object::File::parse(lib_bytes.bytes())
        .with_context(|| format!("object parse {}", lib_path.display()))?;

    let object::File::Elf64(elf64) = &object_file else {
        bail!("{}: not a 64-bit ELF shared library", lib_path.display());
    };

    let lib_index = state.lib_index(key.lib, elf64);
    let lib = Lib {
        id: key.lib,
        path: &lib_path,
        elf: elf64,
        index: &lib_index,
    };

    let mut relocs = UnitRelocs::default();

    // Extract init/fini arrays from this library if we haven't already. Each
    // constructor/destructor becomes an extraction root of its own: when the
    // library is dynamically linked, ld.so runs every one of these at load/exit,
    // so a merged binary must include them (and their closure) to behave
    // identically. Provably no-op CRT glue is skipped inside
    // extract_init_fini_arrays.
    if !state.processed_libs.contains(&key.lib) {
        state.processed_libs.insert(key.lib);
        let lib_init_fini = extract_init_fini_arrays(lib)?;
        for entry in lib_init_fini
            .init_entries
            .iter()
            .chain(&lib_init_fini.fini_entries)
        {
            let lib = state.lib_id(&entry.source_lib);
            state.reserve(UnitKey {
                lib,
                sym: entry.unit_name.clone(),
            });
        }
        state
            .init_fini
            .init_entries
            .extend(lib_init_fini.init_entries);
        state
            .init_fini
            .fini_entries
            .extend(lib_init_fini.fini_entries);
    }

    // Find the symbol in .symtab first, fall back to .dynsym.
    let sym = find_symbol(lib, &key.sym)
        .with_context(|| format!("symbol '{}' in {}", key.sym, lib_path.display()))?;

    // Determine symbol size.
    let sym_size = if sym.size > 0 {
        sym.size as usize
    } else {
        // Infer from the next symbol in the same section by address.
        infer_symbol_size(lib, &sym)?
    };

    if sym_size == 0 {
        bail!(
            "cannot determine size of symbol '{}' in {} (st_size=0 and no adjacent symbol)",
            key.sym,
            lib_path.display()
        );
    }

    let section = elf64
        .section_by_index(sym.section)
        .with_context(|| format!("symbol '{}' has no section", key.sym))?;

    let section_kind = match section.kind() {
        ObjSectionKind::Text => SectionKind::Text,
        ObjSectionKind::ReadOnlyData | ObjSectionKind::ReadOnlyString => SectionKind::ReadOnlyData,
        ObjSectionKind::Data | ObjSectionKind::UninitializedData => SectionKind::Data,
        other => bail!("symbol '{}': unsupported section kind {:?}", key.sym, other),
    };

    let section_data = section.data().context("section data")?;
    let sym_vaddr = sym.vaddr;
    let section_vaddr = section.address();
    let offset_in_section = (sym_vaddr - section_vaddr) as usize;

    // A symbol cannot reach past the section that defines it, and `st_size`
    // is only as trustworthy as any other number in the file. The file-backed
    // case has always been bounded by the bytes it slices; `.bss` has no bytes
    // to slice, so its length was unbounded — a doctored `st_size` on a `.bss`
    // symbol went straight into `vec![0u8; st_size]` and ended the run as
    // `memory allocation of 1152921504606846976 bytes failed`, an abort naming
    // neither the symbol nor the library it came from.
    let nobits = section.kind() == ObjSectionKind::UninitializedData;
    let declared = if nobits {
        section.size() as usize
    } else {
        section_data.len()
    };
    let sym_end = offset_in_section
        .checked_add(sym_size)
        .filter(|end| *end <= declared)
        .with_context(|| {
            format!(
                "symbol '{}' byte range [{}, {}) overflows section of size {}",
                key.sym,
                offset_in_section,
                offset_in_section.saturating_add(sym_size),
                declared
            )
        })?;

    let bytes = if nobits {
        // .bss has no file-backed data — emit zero-filled bytes
        zero_fill(sym_size as u64).with_context(|| format!("zero-filling symbol '{}'", key.sym))?
    } else {
        section_data[offset_in_section..sym_end].to_vec()
    };
    let alignment = unit_alignment(sym_vaddr, section.align());

    // Data symbol units: pick up .rela.dyn entries within the symbol's range
    // (e.g. __dso_handle's self-pointing RELATIVE, function pointers in .data).
    //
    // The dynamic table is the *only* one an extracted unit can draw from. A
    // linked shared object — all solder merges, since `validate_merge_library`
    // insists on `ET_DYN` — keeps its relocations in `.rela.dyn`/`.rela.plt`,
    // whose `sh_link` names `.dynsym`; the section-attached `.rela.<section>`
    // tables, which name `.symtab`, were consumed by the link. And `object`
    // maps a section to a relocation table only when that table is linked to
    // `.symtab` (`RelocationSections::parse`), so `ObjectSection::relocations`
    // is empty for every section of every library solder reads — see
    // `a_linked_library_has_no_section_attached_relocations`.
    //
    // `process_symbol` used to walk that empty iterator and resolve its
    // targets through rules of its own: a second copy of the resolution
    // below, which knew nothing of a copied GOT slot or of a symbol the
    // executable copy-relocates, and which answered a relocation with no
    // symbol with a `UnitId(u32::MAX)` that nothing ever extracts — a
    // `MergedUnit` target the relocator could only fail on.
    if section_kind != SectionKind::Text {
        collect_dynamic_range_relocs(
            lib,
            &key.sym,
            sym_vaddr..sym_vaddr + sym_size as u64,
            sym_vaddr,
            state,
            &mut relocs,
        )?;
    }

    // A text unit's bytes are the function plus whatever sits between its last
    // instruction and the next bound, which is not code (see
    // `decode_unit_code`). Decoding is what extraction spends most of its time
    // on, and the extent, the RIP-relative scan and the jump-table detector all
    // want the same instruction stream, so it is decoded once here and shared
    // rather than re-derived by each of the three.
    let code = if section_kind == SectionKind::Text {
        decode_unit_code(&bytes, sym_vaddr, lib.index)
    } else {
        UnitCode {
            instrs: Vec::new(),
            len: bytes.len(),
        }
    };
    let code_len = code.len;

    // Scan for RIP-relative references (calls, jumps, and data accesses).
    // Create synthetic relocations for each reference so they get patched correctly.
    if section_kind == SectionKind::Text {
        let rip_refs = scan_rip_relative_refs(&code.instrs, &bytes, sym_vaddr);
        for rip_ref in rip_refs {
            let target_addr = rip_ref.target_vaddr;

            // Skip references within our own function
            if target_addr >= sym_vaddr && target_addr < sym_vaddr + sym_size as u64 {
                continue;
            }

            if rip_ref.is_code_ref {
                // rel8 (short jump) displacements get an 8-bit relocation; the
                // relocator verifies the final offset still fits.
                let reloc_size: u8 = if rip_ref.disp_size == 1 { 8 } else { 32 };
                // First check if this is a PLT call (call to external symbol)
                if let Some(target) = plt_reference(lib, target_addr, state) {
                    relocs.relocations.push(pcrel_reloc(
                        rip_ref.offset as u64,
                        reloc_size,
                        rip_ref.addend,
                        target,
                    ));
                } else {
                    // Direct call/jmp to an internal address. Prefer a named
                    // symbol; otherwise synthesize an anonymous unit for a
                    // symbol-less local helper. Stripped libraries routinely
                    // reach such helpers via a plain `call` with no symbol of
                    // their own — e.g. OpenSSL's md5_block_asm_data_order, which
                    // MD5_Update/MD5_Final call directly. Without this, the call
                    // bytes were copied verbatim and the stale displacement
                    // pointed into unmapped memory, crashing at runtime.
                    let mut dep = reserve_unit_at(lib, target_addr, state);
                    if dep.is_none() && anon_target_is_extractable(lib, target_addr) {
                        dep = Some(UnitRef {
                            id: state.reserve(UnitKey {
                                lib: key.lib,
                                sym: anon_unit_name(target_addr),
                            }),
                            offset: 0,
                        });
                    }
                    if let Some(dep) = dep {
                        // The relocator computes S + A - P against the unit's
                        // base, so an interior target is reached through the
                        // addend.
                        relocs.relocations.push(pcrel_reloc(
                            rip_ref.offset as u64,
                            reloc_size,
                            rip_ref.addend + dep.offset as i64,
                            RelocTarget::MergedUnit(dep.id),
                        ));
                    } else {
                        warn!(
                            symbol = key.sym,
                            offset = format_args!("{:#x}", rip_ref.offset),
                            target = format_args!("{:#x}", target_addr),
                            "direct code ref to an unresolved internal target; \
                             merged binary may crash if this path executes"
                        );
                    }
                }
            } else {
                // Data reference (LEA/MOV) — could be loading the address of
                // data or of code (e.g. LEA of a function pointer, or of a
                // label inside the function doing the load). Resolve it to an
                // owning unit first; anything else falls through to the blob
                // path below.
                if let Some(dep) = reserve_unit_at(lib, target_addr, state) {
                    relocs.relocations.push(pcrel_reloc(
                        rip_ref.offset as u64,
                        32,
                        rip_ref.addend + dep.offset as i64,
                        RelocTarget::MergedUnit(dep.id),
                    ));
                    continue;
                }
                // Otherwise try to extract the data section
                if let Some((blob_id, blob_base)) = ensure_data_blob_extracted(
                    lib,
                    &key.sym,
                    target_addr,
                    rip_ref.access_len,
                    state,
                )? {
                    let offset_in_blob = target_addr - blob_base;
                    relocs.relocations.push(pcrel_reloc(
                        rip_ref.offset as u64,
                        32,
                        rip_ref.addend,
                        RelocTarget::DataBlobOffset(blob_id, offset_in_blob),
                    ));
                } else {
                    warn!(
                        symbol = key.sym,
                        offset = format_args!("{:#x}", rip_ref.offset),
                        target = format_args!("{:#x}", target_addr),
                        "RIP-relative data ref target not found"
                    );
                }
            }
        }
    }

    // Jump table detection via symbolic execution
    if section_kind == SectionKind::Text
        && let Ok(jump_tables) = crate::jump_table::detect_jump_tables(
            &code.instrs,
            code_len as u64,
            sym_vaddr,
            &key.sym,
            lib.elf,
        )
    {
        if !jump_tables.is_empty() {
            debug!(
                count = jump_tables.len(),
                symbol = key.sym,
                "Found jump tables"
            );
        }

        for table in jump_tables {
            // 1. Ensure .rodata blob containing table is extracted. The table
            // is as long as the entries detected in it, four bytes apiece, and
            // the relocations written below cover all of them — so that, and
            // not one entry, is what the copy has to reach.
            let table_len = Some(JUMP_TABLE_ENTRY_SIZE * table.targets.len() as u64);
            if let Some((blob_id, blob_base)) =
                ensure_data_blob_extracted(lib, &key.sym, table.table_vaddr, table_len, state)?
            {
                // 2. Create relocations for each table entry
                for (idx, target_addr) in table.targets.iter().enumerate() {
                    let entry_offset_in_blob =
                        (table.table_vaddr - blob_base) + idx as u64 * JUMP_TABLE_ENTRY_SIZE;

                    // Skip if a relocation already exists at this offset (from another
                    // function detecting an overlapping table at the same .rodata address)
                    if !state.claim_blob_offset(blob_id, entry_offset_in_blob) {
                        continue;
                    }

                    // 3. `detect_jump_tables` only keeps entries that branch into
                    // this unit, so the target is always an offset into it.
                    let offset_in_target = (*target_addr - sym_vaddr) as i64;

                    // Jump table entry format: target = table_base + *(i32*)entry
                    // Therefore: *(i32*)entry = target - table_base
                    //
                    // After relocation:
                    // - entry is at address P (= table_base_va + idx*4)
                    // - target is at address S + offset_in_target
                    // - We need: *(i32*)P = (S + offset_in_target) - table_base_va
                    //
                    // Relocation formula writes: *(i32*)P = S + A - P
                    // Since P = table_base_va + idx*4:
                    //   S + A - P = S + A - table_base_va - idx*4
                    // We need this to equal S + offset_in_target - table_base_va
                    // Therefore: A = offset_in_target + idx*4
                    let addend = offset_in_target + (idx * 4) as i64;

                    // 4. Add jump table entry relocation to the data blob. Its
                    // target is this very unit — `detect_jump_tables` keeps no
                    // other — and this unit's id is the one reserved for it at
                    // the top, so the entry needs no placeholder.
                    let Some(blob_unit) = state.unit_mut(blob_id) else {
                        continue;
                    };
                    blob_unit.relocations.push(pcrel_reloc(
                        entry_offset_in_blob,
                        32,
                        addend, // offset within target function, PC-relative
                        RelocTarget::MergedUnit(id),
                    ));
                }
            }
        }
    }

    // Rewrite short (rel8) branch relocations through 5-byte `jmp rel32`
    // veneers. A 1-byte displacement can rarely reach its real target once
    // units are repacked. The veneer goes at the end of the unit when the
    // short jump can reach it; for larger units (over-extended anonymous units
    // in stripped libraries), it overwrites the never-executed inter-function
    // alignment padding that follows the branch instead.
    let mut bytes = bytes;
    for reloc in relocs.relocations.iter_mut() {
        if reloc.size != 8 {
            continue;
        }
        let disp_off = reloc.offset_within_unit as usize;
        let end_off = bytes.len();
        let veneer_off = if end_off as i64 - (disp_off as i64 + 1) <= i8::MAX as i64 {
            bytes.extend_from_slice(&[0xe9, 0, 0, 0, 0]);
            end_off
        } else if let Some(slot) = find_padding_slot(&bytes, disp_off + 1, 5) {
            bytes[slot..slot + 5].copy_from_slice(&[0xe9, 0, 0, 0, 0]);
            slot
        } else {
            bail!(
                "short jump at offset {:#x} in '{}' has no reachable spot for a \
                 rel32 veneer (unit end {} bytes away, no padding after the jump)",
                disp_off,
                key.sym,
                end_off - disp_off
            );
        };
        bytes[disp_off] = (veneer_off as i64 - (disp_off as i64 + 1)) as i8 as u8;
        reloc.offset_within_unit = veneer_off as u64 + 1;
        reloc.size = 32;
        // The addend of a scanned branch is -(displacement width) plus the
        // target's offset into its unit. Only the width changes here, from the
        // rel8 field to the veneer's rel32 one; the target offset must survive.
        reloc.addend -= 3;
    }

    // Register this unit under the id reserved for it.
    let relocations = state.take_unit_relocs(id, &mut bytes, relocs);

    state.push_unit(ExtractedUnit {
        id,
        name: key.sym.clone(),
        source_lib: lib_path.to_path_buf(),
        bytes,
        section_kind,
        alignment,
        relocations,
    });

    Ok(())
}

/// How far a unit extracted at `sym_vaddr` has to be aligned in the merged
/// segment — which is *not* the alignment of the section it came out of.
///
/// `sh_addralign` constrains where the linker put the section's first byte and
/// says nothing about the symbols inside it. Debian's `libcrypto.so.3` has a
/// `.text` aligned to 4096, and taking that as every unit's own requirement
/// padded each of the 8858 units extracted from it up to a page boundary: 3.1
/// MB of merged code became a 36 MB executable run, over 90% of it zeroes,
/// because each function was rounded up to 4 KiB.
///
/// Whatever alignment the unit actually needs, the address the linker gave it
/// already satisfies — a function or constant that had to be 16-aligned sits at
/// a 16-aligned address — so the largest power of two dividing `sym_vaddr` is
/// an upper bound on the requirement, and keeping exactly that reproduces the
/// alignment the unit had in the library. (A shared object's `p_vaddr` is
/// congruent to its load address modulo the page size, so those low bits are
/// the ones the unit really ran at.) The section's own alignment still caps the
/// result: nothing inside it can need more than the section itself was given.
///
/// That bound covers what is *inside* the unit as well. A symbol's address
/// satisfies the strictest alignment anything in it asked for — a function
/// loading a 16-byte constant with `movaps` is itself placed so that constant
/// lands 16-aligned — so any interior requirement divides the alignment kept
/// here, and dividing it, it is satisfied wherever the unit is placed.
fn unit_alignment(sym_vaddr: u64, section_align: u64) -> u64 {
    let section_align = section_align.max(1);
    if sym_vaddr == 0 {
        // Nothing to infer from — every power of two divides 0.
        return section_align;
    }
    section_align.min(1u64 << sym_vaddr.trailing_zeros())
}

/// Reserve an id for `key` and extract it under that id, which is what the
/// worklist loop in [`extract_units`] does for every unit it reaches.
#[cfg(test)]
fn reserve_and_extract(key: &UnitKey, state: &mut ExtractionState) -> Result<()> {
    let id = state.reserve(key.clone());
    process_symbol(key, id, state)
}

/// Lightweight snapshot of a symbol we care about.
#[derive(Clone)]
struct SymInfo {
    vaddr: u64,
    size: u64,
    section: object::SectionIndex,
}

/// Precomputed per-library symbol lookups.
///
/// `process_symbol` runs once per extracted symbol, and each run performs many
/// name/address lookups (`find_symbol`, `find_symbol_at_address`,
/// `infer_symbol_size`). Done naively each of those linearly scans both the
/// full `.symtab` and `.dynsym` — an O(symbols) cost paid per lookup, which for
/// a large library like libcrypto.so.3 (tens of thousands of symbols, an
/// enormous extraction closure) turns the whole run quadratic. Building these
/// maps once per library collapses each lookup to O(1)/O(log n).
struct LibIndex {
    /// Defined symbols by name, preferring `.symtab` over `.dynsym` (the order
    /// the linear `find_symbol` used). Only symbols in a real section.
    by_name: FastMap<String, SymInfo>,
    /// First defined symbol name at a given address, `.symtab` before `.dynsym`.
    addr_to_name: FastMap<u64, String>,
    /// Every defined symbol address paired with its section index (as a plain
    /// `usize`, since `SectionIndex` isn't `Ord`), sorted by address, for
    /// `infer_symbol_size`'s "next symbol boundary" search.
    addrs_by_section: Vec<(u64, usize)>,
    /// The same for the symbols that have a size, which are the addresses at
    /// which the library is known to start an object of its own. A zero-size
    /// symbol is a boundary marker and owns nothing — `resolve_owning_unit`
    /// declines to let one own an address — so it is no evidence that an
    /// unnamed object ends there, which is what [`needed_prefix`] needs of a
    /// bound.
    object_addrs_by_section: Vec<(u64, usize)>,
    /// `(start address, size, section index)` of each PLT section, so a
    /// scanned code reference can be recognised as a stub (see `plt_target`).
    plt_spans: Vec<(u64, u64, object::SectionIndex)>,
    /// GOT slot address → the external symbol ld.so resolves into it, from the
    /// library's own dynamic relocations. A PLT stub jumps through such a
    /// slot, which is what names the stub (see `plt_target`).
    got_to_name: FastMap<u64, String>,
    /// Exact function bounds from `.eh_frame`, which cover code the symbol
    /// tables say nothing about (see `resolve_owning_unit`).
    fdes: crate::eh_frame::FdeTable,
}

impl LibIndex {
    fn build(elf: &object::read::elf::ElfFile64<'_>) -> Self {
        let mut by_name: FastMap<String, SymInfo> = FastMap::default();
        let mut addr_to_name: FastMap<u64, String> = FastMap::default();
        let mut addrs_by_section: Vec<(u64, usize)> = Vec::new();
        let mut object_addrs_by_section: Vec<(u64, usize)> = Vec::new();

        // Iterate .symtab first, then .dynsym, so first-writer-wins matches the
        // ".symtab preferred" order of the original linear scans.
        for sym in elf.symbols().chain(elf.dynamic_symbols()) {
            let object::SymbolSection::Section(si) = sym.section() else {
                continue;
            };
            let addr = sym.address();
            addrs_by_section.push((addr, si.0));
            if sym.size() > 0 {
                object_addrs_by_section.push((addr, si.0));
            }

            let Ok(name) = sym.name() else { continue };
            if name.is_empty() {
                continue;
            }

            if !sym.is_undefined() {
                by_name.entry(name.to_string()).or_insert(SymInfo {
                    vaddr: addr,
                    size: sym.size(),
                    section: si,
                });
            }
            addr_to_name.entry(addr).or_insert_with(|| name.to_string());
        }

        addrs_by_section.sort_unstable();
        addrs_by_section.dedup();
        object_addrs_by_section.sort_unstable();
        object_addrs_by_section.dedup();

        let plt_spans: Vec<(u64, u64, object::SectionIndex)> = elf
            .sections()
            .filter(|s| matches!(s.name().unwrap_or(""), ".plt" | ".plt.got" | ".plt.sec"))
            .map(|s| (s.address(), s.size(), s.index()))
            .collect();

        // `dynamic_relocations` covers every relocation table bound to
        // `.dynsym` — `.rela.plt`, whose JUMP_SLOTs name the classic PLT
        // stubs, and `.rela.dyn`, whose GLOB_DATs name the `.plt.got`-style
        // ones. The first entry naming a slot wins; nothing legitimately
        // relocates one slot twice.
        let mut got_to_name: FastMap<u64, String> = FastMap::default();
        for (got_vaddr, reloc) in elf.dynamic_relocations().into_iter().flatten() {
            let object::RelocationTarget::Symbol(si) = reloc.target() else {
                continue;
            };
            let Some(name) = dynamic_symbol_by_index(elf, si).and_then(|sym| sym.name().ok())
            else {
                continue;
            };
            if !name.is_empty() {
                got_to_name
                    .entry(got_vaddr)
                    .or_insert_with(|| name.to_owned());
            }
        }

        let fdes = elf
            .section_by_name(".eh_frame")
            .and_then(|s| s.data().ok().map(|d| (d, s.address())))
            .map(|(data, vaddr)| crate::eh_frame::FdeTable::parse(data, vaddr))
            .unwrap_or_default();

        LibIndex {
            by_name,
            addr_to_name,
            addrs_by_section,
            object_addrs_by_section,
            plt_spans,
            got_to_name,
            fdes,
        }
    }

    /// The PLT section covering `addr`, as `(section address, section index)`.
    ///
    /// A stub there is resolved to the symbol its GOT slot is relocated
    /// against ([`plt_target`]) rather than extracted as a unit of its own
    /// ([`anon_target_is_extractable`]), so both want the same question
    /// answered against the same list of PLT sections.
    fn plt_span_at(&self, addr: u64) -> Option<(u64, object::SectionIndex)> {
        self.plt_spans
            .iter()
            .find(|&&(start, size, _)| addr >= start && addr - start < size)
            .map(|&(start, _, section)| (start, section))
    }

    /// Smallest defined-symbol address greater than `addr` within `section`.
    fn next_addr_in_section(&self, addr: u64, section: object::SectionIndex) -> Option<u64> {
        next_in_section(&self.addrs_by_section, addr, section)
    }

    /// Smallest address greater than `addr` at which `section` holds an object
    /// the library both names and gives a size.
    fn next_object_in_section(&self, addr: u64, section: object::SectionIndex) -> Option<u64> {
        next_in_section(&self.object_addrs_by_section, addr, section)
    }
}

/// Smallest address in `addrs` greater than `addr` that belongs to `section`.
/// `addrs` is `(address, section index)` sorted by address.
fn next_in_section(
    addrs: &[(u64, usize)],
    addr: u64,
    section: object::SectionIndex,
) -> Option<u64> {
    let start = addrs.partition_point(|&(a, _)| a <= addr);
    addrs[start..]
        .iter()
        .find(|&&(_, s)| s == section.0)
        .map(|&(a, _)| a)
}

/// One library as extraction sees it: the file it came from, its parsed ELF,
/// and the lookups [`LibIndex`] precomputed over it.
///
/// The three are never wanted apart — a name is resolved through the index,
/// the bytes behind it read out of the ELF, and whatever comes out keyed by
/// the path — so they are threaded through as one handle rather than as three
/// parameters repeated down the call chain.
#[derive(Clone, Copy)]
struct Lib<'a, 'data> {
    /// The library's interned id, which is what the keys extraction builds
    /// name it by (see [`LibId`]). `path` is the same library spelled out,
    /// for the messages and unit names that want it in words.
    id: LibId,
    path: &'a Path,
    elf: &'a object::read::elf::ElfFile64<'data>,
    index: &'a LibIndex,
}

/// Find a symbol by name using the precomputed library index, falling back to
/// the ELF only for synthetic anonymous-unit names.
fn find_symbol(lib: Lib<'_, '_>, name: &str) -> Result<SymInfo> {
    // Synthetic anonymous unit: resolve the address encoded in the name to the
    // executable section that contains it. Size is left at 0 so the caller
    // infers it from the next symbol boundary.
    if let Some(hex) = name.strip_prefix(ANON_UNIT_PREFIX) {
        let addr = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .with_context(|| format!("malformed anonymous unit name '{name}'"))?;
        let section = crate::elf_reader::section_at_address(lib.elf, addr)
            .filter(|section| section.kind() == ObjSectionKind::Text)
            .with_context(|| {
                format!("anonymous unit address {addr:#x} not in any executable section")
            })?;
        return Ok(SymInfo {
            vaddr: addr,
            size: 0,
            section: section.index(),
        });
    }

    lib.index
        .by_name
        .get(name)
        .cloned()
        .with_context(|| format!("symbol '{name}' not found in .symtab or .dynsym"))
}

/// Whether a definition in a shared library can be preempted by one elsewhere
/// in the global scope — which is what lets a copy relocation move the storage
/// into the executable. Only a default-visibility definition can: ld.so binds
/// a reference to a protected one to the library's own copy, so that copy and
/// the executable's were already two objects before any merge.
fn is_preemptible(sym: &object::read::elf::ElfSymbol64<'_, '_>) -> bool {
    sym.elf_symbol().st_visibility() == object::elf::STV_DEFAULT
}

/// Look up a symbol by index in the dynamic symbol table. Symbol indices in
/// dynamic relocations (.rela.dyn) refer to .dynsym; resolving them with
/// `elf.symbol_by_index` would index .symtab and return an unrelated symbol.
fn dynamic_symbol_by_index<'data, 'file>(
    elf: &'file object::read::elf::ElfFile64<'data>,
    si: object::SymbolIndex,
) -> Option<object::read::elf::ElfSymbol64<'data, 'file>> {
    use object::ObjectSymbolTable;
    elf.dynamic_symbol_table()?.symbol_by_index(si).ok()
}

/// Find a symbol by virtual address in an ELF's .symtab (including local symbols).
/// Returns the symbol name if found, or None if no symbol starts at that address.
///
/// Only symbols that live in a real section are eligible: GNU version-node
/// pseudo-symbols (e.g. `NCURSESW6_5.8.20110226`) are `SHN_ABS` with value 0, so
/// a scanned reference that resolves to address 0 would otherwise match one of
/// them and then fail extraction with "not in a regular section".
fn find_symbol_at_address(index: &LibIndex, addr: u64) -> Option<String> {
    index.addr_to_name.get(&addr).cloned()
}

/// Reserved synthetic-name prefix for anonymous (symbol-less) code units. A
/// stripped library may reach a local helper function through a direct `call`
/// while exporting no symbol for it. We give that helper a synthetic name with
/// its address encoded so `find_symbol` can resolve it back to a location and
/// `infer_symbol_size` can bound it by the next symbol.
const ANON_UNIT_PREFIX: &str = ".solder.anon.";

fn anon_unit_name(addr: u64) -> String {
    format!("{ANON_UNIT_PREFIX}{addr:#x}")
}

/// Resolve `addr` to the unit that owns it: the name to extract that unit
/// under, and the offset of `addr` within it.
///
/// A reference does not have to land on a function entry: compilers branch to
/// and take the address of interior labels all the time, and in a stripped
/// library most branch targets have no symbol of their own. Resolving such an
/// address to the function that contains it — plus an offset — keeps one unit
/// per function instead of starting a fresh, over-extended unit at every
/// address that happens to be referenced.
///
/// Returns `None` when nothing is known to own `addr`; the caller decides
/// whether to fall back to an anonymous unit starting there.
fn resolve_owning_unit(lib: Lib<'_, '_>, addr: u64) -> Option<(String, u64)> {
    // A symbol defined at exactly this address, as long as it has a usable
    // size: zero-size boundary markers (e.g. `__TMC_END__`, which sits at the
    // exact end of .data with nothing after it) own nothing.
    if let Some(name) = find_symbol_at_address(lib.index, addr)
        && symbol_unit_size(lib, &name).is_some_and(|size| size > 0)
    {
        return Some((name, 0));
    }

    // Otherwise the function whose `.eh_frame` range covers the address. Prefer
    // a named symbol at that function's entry so the interior reference shares
    // the unit the function is already extracted as, instead of duplicating its
    // tail under an anonymous name.
    let (fde_start, _) = lib.index.fdes.containing(addr)?;
    let offset = addr - fde_start;
    if let Some(name) = find_symbol_at_address(lib.index, fde_start)
        && symbol_unit_size(lib, &name).is_some_and(|size| size as u64 > offset)
    {
        return Some((name, offset));
    }
    anon_target_is_extractable(lib, fde_start).then(|| (anon_unit_name(fde_start), offset))
}

/// [`resolve_owning_unit`] followed by the reservation of the unit it names,
/// memoized on the address.
///
/// Every reference the instruction scanner and the dynamic relocations turn up
/// ends here, and the same address is reached over and over: the whole point of
/// extracting a function once is that all its callers name it, so each `call`
/// of a hot helper in `libcrypto.so.3` resolves the same entry point again.
/// Resolving one is an `.eh_frame` binary search, a symbol lookup, a size
/// inference and a copy of the symbol's name, and that name is then hashed into
/// `reserved` only to come back with the id the last caller already got.
/// Merging `libcrypto.so.3` into `test/md5sum` asks this of 44742 addresses, of
/// which 30859 — just over two in three — have been asked before.
fn reserve_unit_at(lib: Lib<'_, '_>, addr: u64, state: &mut ExtractionState) -> Option<UnitRef> {
    if let Some(&hit) = state.units_at.get(&(lib.id, addr)) {
        return hit;
    }
    let resolved = resolve_owning_unit(lib, addr).map(|(name, offset)| UnitRef {
        id: state.reserve(UnitKey {
            lib: lib.id,
            sym: name,
        }),
        offset,
    });
    state.units_at.insert((lib.id, addr), resolved);
    resolved
}

/// The merged unit an address resolved to, and how far into it the address
/// lands.
#[derive(Clone, Copy)]
struct UnitRef {
    id: UnitId,
    offset: u64,
}

/// The size `process_symbol` would extract for `name`, or `None` if the symbol
/// cannot be resolved at all.
fn symbol_unit_size(lib: Lib<'_, '_>, name: &str) -> Option<usize> {
    let sym = find_symbol(lib, name).ok()?;
    if sym.size > 0 {
        Some(sym.size as usize)
    } else {
        infer_symbol_size(lib, &sym).ok()
    }
}

/// Whether `addr` points into executable code we can extract as an anonymous
/// unit. Excludes PLT sections (those are resolved via [`plt_target`]) so we
/// never mistake a PLT stub for a mergeable function.
fn anon_target_is_extractable(lib: Lib<'_, '_>, addr: u64) -> bool {
    lib.index.plt_span_at(addr).is_none()
        && crate::elf_reader::section_at_address(lib.elf, addr)
            .is_some_and(|section| section.kind() == ObjSectionKind::Text)
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
fn decode_unit_code(bytes: &[u8], vaddr: u64, index: &LibIndex) -> UnitCode {
    // Only an FDE that starts where the unit starts describes the unit's
    // function; one that merely contains `vaddr` belongs to a function the unit
    // begins partway into, and says nothing about where the unit's code ends.
    let fde_end = index
        .fdes
        .containing(vaddr)
        .filter(|&(start, _)| start == vaddr)
        .map(|(_, end)| end);
    decode_to_code_bound(bytes, vaddr, fde_end)
}

/// `decode_unit_code` with the unwind bound supplied rather than looked up.
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

/// A RIP-relative reference found in machine code.
#[derive(Debug, Clone)]
struct RipRelativeRef {
    /// Byte offset within the code where the displacement starts.
    offset: usize,
    /// Target virtual address this reference points to.
    target_vaddr: u64,
    /// Whether this is a code reference (call/jmp) vs data reference (lea/mov).
    is_code_ref: bool,
    /// Size of the encoded displacement in bytes: 4 (rel32) or 1 (rel8, short
    /// jumps only).
    disp_size: u8,
    /// Relocation addend: -(bytes from displacement start to instruction end).
    /// This is -4 when the displacement is the final field, but instructions
    /// like `cmpb $imm, [rip+d]` carry an immediate after the displacement,
    /// which shifts next_ip further and makes the addend more negative.
    addend: i64,
    /// How many bytes at `target_vaddr` the instruction reads or writes, where
    /// the instruction says: that bounds the object the reference reaches, and
    /// so bounds how much of a data section has to be copied for it (see
    /// [`needed_prefix`]). `None` for a code reference, and for the
    /// instructions that take an address without saying what is at it.
    access_len: Option<u64>,
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
pub fn decode_instructions(bytes: &[u8], vaddr: u64) -> Vec<Instruction> {
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
fn scan_rip_relative_refs(
    instrs: &[Instruction],
    bytes: &[u8],
    base_vaddr: u64,
) -> Vec<RipRelativeRef> {
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
                        let disp_size: u8 = if is_rel32 { 4 } else { 1 };
                        refs.push(RipRelativeRef {
                            offset: instr_offset + instr.len() - disp_size as usize,
                            target_vaddr: target,
                            is_code_ref: true,
                            disp_size,
                            addend: -(disp_size as i64),
                            access_len: None,
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
                            refs.push(RipRelativeRef {
                                offset: instr_offset + pos,
                                target_vaddr: target,
                                is_code_ref: false,
                                disp_size: 4,
                                addend: -((instr.len() - pos) as i64),
                                access_len: rip_access_len(instr),
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

/// The external symbol the PLT stub at `addr` jumps to, or `None` when `addr`
/// is not a stub.
///
/// The stub is decoded rather than looked up by entry index: every flavor
/// (.plt, .plt.got, .plt.sec) starts with an optional endbr64 and/or bnd
/// prefix followed by `ff 25 <disp32>` (jmp [rip+disp32]) through its GOT
/// slot, and the dynamic relocation against that slot — JUMP_SLOT for classic
/// PLT entries, GLOB_DAT for .plt.got-style stubs like `__cxa_finalize@plt` —
/// names the symbol. Both halves of that lookup come out of the library's
/// [`LibIndex`], built once per library.
fn plt_target(lib: Lib<'_, '_>, addr: u64) -> Option<String> {
    let (sec_addr, section) = lib.index.plt_span_at(addr)?;
    let sec_data = lib.elf.section_by_index(section).ok()?.data().ok()?;

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
    let got_va = (sec_addr + off as u64 + 6).wrapping_add(disp as i64 as u64);

    if let Some(name) = lib.index.got_to_name.get(&got_va) {
        return Some(name.clone());
    }
    // Fallback: a symbol defined at this exact address.
    find_symbol_at_address(lib.index, addr)
}

/// The target a call to the PLT stub at `addr` gets, or `None` when `addr` is
/// not a stub at all and the caller has to resolve it as a direct internal
/// reference.
///
/// PLT call resolution order:
///   1. Another merged library defines the symbol, and the executable's own
///      `.dynsym` does not mention it → extract from that library and create a
///      direct merged-unit reference.
///   2. Otherwise the symbol stays external. Either the executable already
///      exports or imports it, in which case the reference trampolines through
///      the exe's GOT, or it is a libc/runtime symbol the executable does not
///      import yet, in which case the writer injects a `.dynsym` entry and a
///      `GLOB_DAT` relocation so ld.so resolves it at load time.
///
/// Every scanned code reference is asked about here, and the same addresses
/// arrive over and over: the whole point of a PLT stub is that every call site
/// of the symbol shares it, and the direct calls in between all name the same
/// handful of entry points. Merging `libcrypto.so.3` into `test/md5sum` asks
/// about 53810 addresses, of which 5532 are distinct. Answering one costs a
/// walk of the stub's encoding, a GOT-slot lookup, a copy of the symbol's name
/// and then two hashes of that name to decide between the two cases above — all
/// of it settled by the address alone, so it is settled once per address, "not
/// a stub" included.
fn plt_reference(lib: Lib<'_, '_>, addr: u64, state: &mut ExtractionState) -> Option<RelocTarget> {
    if let Some(hit) = state.plt_refs.get(&(lib.id, addr)) {
        return hit.clone();
    }
    let resolved = plt_target(lib, addr).map(|ext_name| {
        if !state.external_syms.contains(&ext_name)
            && let Some(other_lib) = state.cross_lib_syms.get(&ext_name).cloned()
        {
            state.depend_on(UnitKey {
                lib: other_lib,
                sym: ext_name,
            })
        } else {
            RelocTarget::External(ext_name)
        }
    });
    state.plt_refs.insert((lib.id, addr), resolved.clone());
    resolved
}

/// Where an address resolved to, without its contents.
///
/// The contents are deliberately not part of this: `ensure_data_blob_extracted`
/// consults every address a dynamic relocation points at, and nearly all of
/// those land in a section it has already copied or will not copy at all.
/// Handing back the bytes meant copying the whole of `.rodata` — several
/// megabytes in `libcrypto.so.3` — once per lookup only to drop it again, which
/// was two thirds of the entire run. `section_contents` materializes them once
/// the caller knows it needs them.
struct SectionInfo<'data> {
    index: object::SectionIndex,
    /// Borrowed out of the library's `.shstrtab`: this is built for every
    /// address a scanned reference or a dynamic relocation points at, and
    /// copying the name into a `String` each time was pure allocation.
    name: &'data str,
    /// Base virtual address; the caller reaches the address it asked about
    /// through `addr - vaddr`, which for the gap case is past the end of the
    /// contents.
    vaddr: u64,
    /// Length of what `section_contents` will return.
    size: u64,
    kind: SectionKind,
}

/// Find the section a given virtual address belongs to.
///
/// An address that no section contains, but that a `PT_LOAD` still covers,
/// belongs to the section it follows inside that segment. Such an address is
/// inter-section alignment padding, and the end markers the linker defines
/// there are referenced like any other symbol:
///
/// - `__TMC_LIST__` and `__TMC_END__` come from the empty `.tm_clone_table`
///   section of `crtbeginS.o`/`crtendS.o`, which the default linker script
///   places inside `.data` with 8-byte alignment. Both land on the first
///   8-aligned address at or after the end of `.data`'s contents without adding
///   anything to `sh_size`, so in `libtinfo.so.6` (contents ending at
///   `0x354a4`) they sit at `0x354a8`, four bytes past the section.
/// - `_edata` and `_end` are defined the same way, at the end of `.data` and
///   `.bss` respectively.
///
/// Nothing dereferences these — `register_tm_clones` subtracts one from the
/// other to find out whether there is a clone table to register — but the
/// addresses do get loaded into registers, and a reference left unresolved
/// keeps its library displacement, which now reaches whatever happens to sit
/// that far from the unit's new home. Resolving them to the merged copy keeps
/// the address meaningful, and the comparison between two of them exact.
///
/// Requiring one `PT_LOAD` to cover both the address and the end of the section
/// it is attributed to is what keeps this from reaching across a segment
/// boundary, and from attributing anything at all to an address outside the
/// image — a decoding artifact from a unit that ran past the end of its
/// function, say.
fn find_section_for_address<'data>(
    elf: &object::read::elf::ElfFile64<'data>,
    addr: u64,
) -> Option<SectionInfo<'data>> {
    if let Some(section) = crate::elf_reader::section_at_address(elf, addr) {
        return describe_section(&section);
    }

    // Nothing contains `addr`, so look for the loaded section that ends
    // closest below it.
    let mut preceding: Option<(u64, object::read::elf::ElfSection64<'_, '_>)> = None;
    for section in elf.sections() {
        let sec_addr = section.address();
        let sec_size = section.size();
        if sec_addr > addr || sec_size == 0 || !crate::elf_reader::is_alloc(&section) {
            continue;
        }
        let sec_end = sec_addr + sec_size;
        if preceding.as_ref().is_none_or(|(end, _)| sec_end > *end) {
            preceding = Some((sec_end, section));
        }
    }

    let (sec_end, section) = preceding?;
    loaded_together(elf, addr, sec_end).then(|| describe_section(&section))?
}

/// Whether one `PT_LOAD` segment covers both addresses.
fn loaded_together(elf: &object::read::elf::ElfFile64<'_>, a: u64, b: u64) -> bool {
    crate::elf_reader::pt_loads(elf).any(|seg| {
        let mapped = seg.vaddr..=seg.vaddr + seg.memsz;
        mapped.contains(&a) && mapped.contains(&b)
    })
}

/// A section's name, base vaddr, length and kind, or `None` if solder does not
/// extract that kind of section.
fn describe_section<'data>(
    section: &object::read::elf::ElfSection64<'data, '_>,
) -> Option<SectionInfo<'data>> {
    let name = section.name().ok()?;
    let obj_kind = section.kind();
    let kind = match obj_kind {
        ObjSectionKind::Text => SectionKind::Text,
        ObjSectionKind::ReadOnlyData | ObjSectionKind::ReadOnlyString => SectionKind::ReadOnlyData,
        ObjSectionKind::Data | ObjSectionKind::UninitializedData => SectionKind::Data,
        _ => return None, // Skip unsupported section types
    };
    // `data()` only slices what is already mapped, so asking for it here costs
    // nothing and tells us how long the contents are. It comes back empty for
    // two unrelated reasons, and only one of them leaves `sh_size` worth
    // believing. A NOBITS section (`.bss`, `.tbss`) genuinely holds none of its
    // bytes in the file and the loader zero-fills `sh_size` of them, so
    // `section_contents` does too. Any other section reads empty because its
    // `sh_offset`/`sh_size` describe bytes the file does not have — readelf
    // says "Size of section N is larger than the entire file!" of the same
    // header — which makes `sh_size` a length nothing backs. Zero-filling to it
    // put zeros where the section has real contents, and at the sizes a
    // corrupted header reaches it took the process down on the allocation.
    let size = match section.data() {
        Ok(d) if !d.is_empty() => d.len() as u64,
        _ if obj_kind == ObjSectionKind::UninitializedData => section.size(),
        _ => return None,
    };
    Some(SectionInfo {
        index: section.index(),
        name,
        vaddr: section.address(),
        size,
        kind,
    })
}

/// The bytes of the section `describe_section` described.
///
/// A NOBITS section (`.bss`, `.tbss`) has no contents in the file; the loader
/// zero-fills it, and so does the merge.
fn section_contents(
    elf: &object::read::elf::ElfFile64<'_>,
    info: &SectionInfo<'_>,
) -> Result<Vec<u8>> {
    let section = elf
        .section_by_index(info.index)
        .with_context(|| format!("section {} vanished between lookups", info.name))?;
    match section.data() {
        Ok(d) if !d.is_empty() => Ok(d.to_vec()),
        _ => zero_fill(info.size)
            .with_context(|| format!("zero-filling NOBITS section {}", info.name)),
    }
}

/// `len` zero bytes, or an error when that many cannot be had.
///
/// Only a NOBITS section ever needs this, and its length is the one number in
/// a library that no bytes in the file have to back: `.bss` costs the file
/// nothing however large its `sh_size` says it is, and the `st_size` of a
/// symbol inside it is bounded by that same `sh_size` and nothing else. So the
/// length reaching here is unvalidated input, and `vec![0u8; len]` is the
/// wrong way to spend it — an allocation failure there aborts the process
/// (`memory allocation of 281474976710656 bytes failed`) without unwinding,
/// so there is nothing to attach the library's name to and nothing a caller
/// can report.
fn zero_fill(len: u64) -> Result<Vec<u8>> {
    let len = usize::try_from(len)
        .ok()
        .with_context(|| format!("{len} bytes of zero fill do not fit in an address space"))?;
    let mut zeros: Vec<u8> = Vec::new();
    zeros
        .try_reserve_exact(len)
        .map_err(|_| anyhow!("cannot allocate {len} bytes of zero fill"))?;
    zeros.resize(len, 0);
    Ok(zeros)
}

/// Collect the dynamic relocations (.rela.dyn) that fall within `range` into
/// `relocs`, resolving their targets. Linked shared objects carry data
/// relocations only in .rela.dyn — there are no section-attached relocation
/// tables — so every extracted data range (whole-section blob or single-symbol
/// unit) must consult this table or its copied bytes hold stale library VAs.
///
/// `ctx` names the symbol or section being extracted. Offsets pushed into
/// `relocs` are relative to `unit_base`, which is `range.start` for a unit
/// collected in one go and the base of the whole blob when a data section copy
/// is being extended and `range` covers only the bytes just added.
fn collect_dynamic_range_relocs(
    lib: Lib<'_, '_>,
    ctx: &str,
    range: std::ops::Range<u64>,
    unit_base: u64,
    state: &mut ExtractionState,
    relocs: &mut UnitRelocs,
) -> Result<()> {
    let Some(dyn_relocs) = lib.elf.dynamic_relocations() else {
        return Ok(());
    };
    // Which offsets this pass has already filled, so two entries naming the
    // same slot leave the first resolution standing. Scanning `relocs` for
    // each candidate instead made this quadratic in the number of relocations
    // in range: `libcrypto.so.3`'s `.data.rel.ro` is half a megabyte of
    // pointers covered by ~25k `R_X86_64_RELATIVE` entries, and the pairwise
    // comparisons alone were most of the extraction.
    let mut occupied: FastSet<u64> = relocs
        .relocations
        .iter()
        .map(|r| r.offset_within_unit)
        .collect();
    for (roff, reloc) in dyn_relocs {
        if !range.contains(&roff) {
            continue;
        }
        let offset_within_unit = roff - unit_base;
        if occupied.contains(&offset_within_unit) {
            continue;
        }

        // Validate relocation kind (same as code extraction)
        let kind = reloc.kind();
        let encoding = reloc.encoding();
        reject_got_reloc(kind, encoding, ctx, lib.path)?;
        reject_unliftable_dynamic_reloc(kind, elf_r_type(&reloc), ctx, lib.path)?;

        // Resolve the relocation target symbol. Dynamic relocation symbol
        // indices refer to .dynsym, not .symtab.
        let target_sym = match reloc.target() {
            object::RelocationTarget::Symbol(si) => dynamic_symbol_by_index(lib.elf, si),
            _ => None,
        };

        // Set for relocations whose own addend was consumed while resolving the
        // target (see the RELATIVE case below); holds the offset into the
        // resolved unit, which is 0 unless the target is a unit interior.
        let mut resolved_addend: Option<i64> = None;
        let target = if let Some(ts) = target_sym {
            let ts_name = ts.name().unwrap_or("").to_owned();
            if ts.is_undefined() || ts_name.is_empty() {
                if ts_name.is_empty() {
                    RelocTarget::External(ts_name)
                } else if !state.exe_defined_syms.contains(&ts_name)
                    && let Some(other_lib) = state.cross_lib_syms.get(&ts_name).cloned()
                {
                    // Sole provider is another merged (removed) library —
                    // resolve directly to the merged copy, as ld.so would
                    // have resolved to that library.
                    state.depend_on(UnitKey {
                        lib: other_lib,
                        sym: ts_name,
                    })
                } else {
                    // A slot holding an external symbol's address (a copied
                    // GOT slot, or a data pointer to an external). Defer to
                    // ld.so with a GLOB_DAT in the output so the runtime value
                    // matches dynamic linking exactly — including 0 for
                    // unresolved weak symbols, which CRT code null-checks. A
                    // trampoline address here would break those checks.
                    relocs
                        .got_fixups
                        .push((offset_within_unit, ts_name, ts.is_weak()));
                    continue;
                }
            } else if state.exe_copy_relocated.contains(&ts_name) && is_preemptible(&ts) {
                // The library defines it, but the executable copy-relocates it,
                // so the executable owns the storage and ld.so resolved this
                // very slot to the copy in the executable's `.bss` rather than
                // to the definition here — the lookup walks the global scope,
                // where the executable comes first. Extracting the library's
                // definition and pointing the slot at that instead turns one
                // variable into two: ncurses' `tputs` reads the pad character
                // out of `PC`, which readline inside `test/bash` assigns, and
                // after the merge each was looking at its own copy. Defer to
                // ld.so with a GLOB_DAT, exactly as for a symbol the library
                // imports, and the merged code is back on the executable's
                // copy.
                relocs
                    .got_fixups
                    .push((offset_within_unit, ts_name, ts.is_weak()));
                continue;
            } else {
                // Internal to the library
                state.depend_on(UnitKey {
                    lib: lib.id,
                    sym: ts_name,
                })
            }
        } else {
            // RELATIVE relocation (no symbol, addend is the target)
            // For R_X86_64_RELATIVE: *(reloc_offset) = load_base + addend
            // The addend contains the original VA of the code/data being
            // pointed to. That VA is translated to a RelocTarget below, so
            // the extracted relocation's addend must drop to the offset of the
            // target within whatever unit ends up holding it — 0 unless the
            // target is a unit interior — or the old VA would be added on top
            // of the resolved new address.
            resolved_addend = Some(0);
            let addend_va = reloc.addend() as u64;

            if let Some(dep) = reserve_unit_at(lib, addend_va, state) {
                resolved_addend = Some(dep.offset as i64);
                RelocTarget::MergedUnit(dep.id)
            } else if let Some((blob_id, blob_base)) = ensure_data_blob_extracted(
                lib,
                ctx,
                addend_va,
                pointee_len(roff, addend_va),
                state,
            )? {
                // No symbol and no unwind info describe the target, but it does
                // live in a data section we can copy wholesale — most often a
                // string or a struct in .rodata that a pointer table in
                // .data.rel.ro points at (ncurses' `strnames` is a table of
                // several hundred of these). Pulling that section in and
                // retargeting the pointer at it is the only way the copied
                // table keeps working once the library is gone.
                RelocTarget::DataBlobOffset(blob_id, addend_va - blob_base)
            } else {
                warn!(
                    ctx,
                    lib = %lib.path.display(),
                    target = format_args!("{:#x}", addend_va),
                    "RELATIVE relocation target not resolvable; leaving stale"
                );
                continue;
            }
        };

        // The `object` crate does not name R_X86_64_RELATIVE/GLOB_DAT/JUMP_SLOT
        // and reports a size of 0 for them, but all three describe a 64-bit
        // slot. `reject_unliftable_dynamic_reloc` above is what makes widening
        // the 0 sound: it is the only reason the unnamed types reaching here
        // are those three and not, say, a TLS offset.
        let reloc_size = if reloc.size() == 0 { 64 } else { reloc.size() };

        occupied.insert(offset_within_unit);
        relocs.relocations.push(ExtractedReloc {
            offset_within_unit,
            kind,
            encoding,
            size: reloc_size,
            addend: resolved_addend.unwrap_or_else(|| reloc.addend()),
            target,
        });
    }
    Ok(())
}

/// An address is eight bytes wide on every target solder merges.
const POINTER_SIZE: u64 = 8;

/// A GOT entry is one pointer wide.
const GOT_SLOT_SIZE: u64 = POINTER_SIZE;

/// How many bytes of a data section a pointer slot at `slot` needs copied at
/// the `target` it points to, or `None` — the usual answer — where it says
/// nothing about the size of what is there.
///
/// A slot holding its own address is the exception, and the whole of it: the
/// object it points at *is* the slot, which is in the copy already by virtue
/// of being the slot being resolved, so the pointer is made correct by
/// retargeting it and not by copying anything further.
///
/// The slot in question is `__dso_handle`. Every shared library linked by GCC
/// has one at the start of its `.data`, holding its own address because that
/// is all it is: the token `__cxa_atexit` files a destructor under and
/// `__cxa_finalize` matches it against, compared and never dereferenced.
/// Taking the whole section for it is what used to make the destructor glue of
/// a stripped `libcrypto.so.3` — which loads `__dso_handle` to pass it to
/// `__cxa_finalize`, and has no symbol of its own to be bounded by — root all
/// 553 pointers of `.data`, and through them `.data.rel.ro` and most of the
/// library (issue #66).
fn pointee_len(slot: u64, target: u64) -> Option<u64> {
    (slot == target).then_some(POINTER_SIZE)
}

/// A jump table entry is a 32-bit offset from the table's own base (see the
/// relocation the jump-table pass writes for one).
const JUMP_TABLE_ENTRY_SIZE: u64 = 4;

/// The GOT slot holding `addr`, as `(slot address, slot length)`, if `sec` is a
/// global offset table at all.
///
/// A GOT is the one data section whose objects need no symbol to be bounded:
/// it is an array of pointer slots, each one written by the loader from its own
/// dynamic relocation and read by one `mov`/`jmp` naming that slot's address.
/// Nothing reads a slot as part of a larger object, so copying the eight bytes
/// a reference lands in is as correct as copying the whole table and much
/// cheaper — `libcrypto.so.3`'s `.got` is 27,504 bytes holding 3,247 pointers,
/// and rooting all of them is what turns three MD5 entry points into 91% of
/// the library (see the `.got` rows of issue #66).
///
/// `None` for anything else, including an address past the end of the section
/// (`find_section_for_address` attributes a gap address to the section before
/// it, which the caller reaches through an offset past the copied bytes).
fn got_slot_at(sec: &SectionInfo<'_>, addr: u64) -> Option<(u64, u64)> {
    if !matches!(sec.name, ".got" | ".got.plt") {
        return None;
    }
    let offset = addr.checked_sub(sec.vaddr)?;
    if offset >= sec.size {
        return None;
    }
    let slot = sec.vaddr + offset / GOT_SLOT_SIZE * GOT_SLOT_SIZE;
    // A table whose length is not a whole number of slots would otherwise have
    // its last slice run past the section.
    Some((slot, GOT_SLOT_SIZE.min(sec.vaddr + sec.size - slot)))
}

/// How much of `sec`, counted from its first byte, a reference to
/// `target_addr` needs copied.
///
/// `access_len` is how many bytes the reference reads, where that is known:
/// an instruction with a memory operand touches exactly the operand's width
/// and nothing beyond it, so copying up to the end of that operand is as
/// correct as copying the rest of the section and leaves the rest of the
/// section's pointers unrooted. `None` is a reference that says nothing about
/// the size of what it points at — an address taken by `lea`, or a pointer
/// slot holding one.
///
/// Such a reference is bounded by the next thing the library *does* name: two
/// distinct objects do not overlap, so the unnamed object at `target_addr`
/// cannot run into the one the next sized symbol in the section starts, and
/// that symbol's address is an end for it. It is the same bound
/// [`infer_symbol_size`] puts on a symbol whose own size the tables leave at
/// zero, and it is the only one available here. It holds for an address
/// *inside* a named object too — one `resolve_owning_unit` could not attribute
/// because no symbol starts there — since the next object after it is past the
/// end of the one that covers it, so the copy still reaches the whole of it.
///
/// A stripped library names nothing in its data sections and falls back to the
/// section, which is where an extraction far larger than the symbols asked for
/// comes from (issue #66). One that exports its variables does better:
/// `libtinfo.so.6` names nine objects in its 12,168-byte `.data.rel.ro`, and
/// the unnamed 96 bytes `test/bash` reaches between two of them used to copy
/// the 8,136 bytes from there to the section's end and root 1,003 pointers.
///
/// The copy runs from the section's first byte rather than from `target_addr`
/// so that one blob serves every reference into the section: anchored at the
/// section and growing forward, it can be extended for a later reference
/// without moving, which would invalidate the offsets of every reference
/// already resolved against it. The bytes between the objects that were
/// referenced are the price of that, and they root nothing — only the
/// relocations over the copied range do. The run below the lowest reference is
/// given back once the closure is complete and there is nothing left to
/// resolve (see [`trim_unreferenced_prefixes`]).
///
/// An address at or past the section's last byte needs nothing copied however
/// unbounded the reference is: there is nothing there to copy. Such an address
/// is an end marker — `__TMC_END__` at the end of `.data`, which the CRT's
/// clone-table glue subtracts from `__TMC_LIST__` — and an end marker is
/// compared and subtracted, never read through. `resolve_owning_unit` already
/// declines to let a zero-size symbol at the same place own anything, for the
/// same reason; this is the unnamed case of it.
fn needed_prefix(
    lib: Lib<'_, '_>,
    sec: &SectionInfo<'_>,
    target_addr: u64,
    access_len: Option<u64>,
) -> u64 {
    let sec_end = sec.vaddr.saturating_add(sec.size);
    if target_addr >= sec_end {
        return 0;
    }
    let end = match access_len {
        Some(len) => target_addr.saturating_add(len),
        None => lib
            .index
            .next_object_in_section(target_addr, sec.index)
            .unwrap_or(sec_end),
    };
    end.saturating_sub(sec.vaddr).min(sec.size)
}

/// Extract the data holding `target_addr` if it has not been extracted already.
/// Returns the blob's UnitId and the address its first byte had in the library.
///
/// The range copied is a prefix of the containing section long enough to hold
/// what the reference reads ([`needed_prefix`]), except for a GOT, where it is
/// the single slot the address falls in ([`got_slot_at`]).
///
/// `ctx` names what was being extracted when the reference was found. It is
/// only used to report the section copies ([`DataSectionCopy`]), which are the
/// expensive case and the one worth being able to attribute.
fn ensure_data_blob_extracted(
    lib: Lib<'_, '_>,
    ctx: &str,
    target_addr: u64,
    access_len: Option<u64>,
    state: &mut ExtractionState,
) -> Result<Option<(UnitId, u64)>> {
    // Find the section containing this address
    let Some(sec) = find_section_for_address(lib.elf, target_addr) else {
        return Ok(None); // Address not in any extractable section
    };

    // Skip .text section - code references are handled separately
    if sec.kind == SectionKind::Text {
        return Ok(None);
    }

    // What to copy: one GOT slot, or a long enough prefix of the section for
    // everything else.
    let (base_vaddr, needed, alignment, report_copy) = match got_slot_at(&sec, target_addr) {
        Some((slot, len)) => (slot, len, GOT_SLOT_SIZE, false),
        None => (
            sec.vaddr,
            needed_prefix(lib, &sec, target_addr, access_len),
            DATA_BLOB_ALIGNMENT,
            true,
        ),
    };

    let blob_key = DataBlobKey {
        lib: lib.id,
        section: sec.index,
        base: base_vaddr,
    };

    let info = match state.data_blobs.get(&blob_key) {
        Some(&info) => info,
        // Claim the blob's id and register it *before* any of its bytes are
        // copied. Resolving the relocations over those bytes can lead back to
        // this same section — directly (a pointer in .data to the start of
        // .data) or through another section whose own pointers come back here —
        // and the lookup above has to be able to see the blob while that
        // happens. Registering afterwards made such a target look unresolvable,
        // and the copied bytes kept the library's own load-time VA, which
        // points into unmapped memory once the library is dropped from
        // DT_NEEDED.
        None => {
            let id = state.alloc_id();

            // A section copy is where an output a hundred times the size of
            // its input comes from: each pointer in the copied range is an
            // extraction root one reference brought in. Record it so the cost
            // can be reported and attributed instead of only showing up in the
            // output's size (see `DataSectionCopy`).
            //
            // Recorded before the bytes are copied, because collecting their
            // relocations copies further sections — reached through this one —
            // and those have to be reported after it, not before: the records
            // then read as the chain they are, each naming the section or
            // symbol above it.
            let report = report_copy.then(|| {
                state.data_section_copies.push(DataSectionCopy {
                    library: lib.path.to_path_buf(),
                    section: sec.name.to_string(),
                    bytes: 0,
                    section_bytes: sec.size as usize,
                    start_offset: 0,
                    unreferenced_prefix: sec.size as usize,
                    pointers: 0,
                    unbounded_end: None,
                    address: target_addr,
                    reached_from: ctx.to_string(),
                });
                state.data_section_copies.len() - 1
            });

            let info = DataBlobInfo {
                id,
                base_vaddr,
                copied: 0,
                first_ref: u64::MAX,
                rooted_from: u64::MAX,
                read_to: 0,
                fallback_to: 0,
                report,
            };
            state.data_blobs.insert(blob_key, info);
            state.push_unit(ExtractedUnit {
                id,
                name: blob_unit_name(lib.path, sec.name, base_vaddr, sec.vaddr),
                source_lib: lib.path.to_path_buf(),
                bytes: Vec::new(),
                section_kind: sec.kind,
                alignment,
                relocations: Vec::new(),
            });
            info
        }
    };

    // How far into the section the earliest reference landed. With the copy
    // anchored at the section while the closure is being built, everything
    // before that is carried for nothing — which is what
    // `trim_unreferenced_prefixes` gives back once there is nothing left to
    // resolve against the blob, and what
    // `DataSectionCopy::unreferenced_prefix` reports of whatever it could not.
    let offset = target_addr - base_vaddr;
    let (first_ref, end_unbounded, reaches_furthest) = {
        let info = state
            .data_blobs
            .get_mut(&blob_key)
            .expect("the blob is registered above");
        info.first_ref = info.first_ref.min(offset);
        // Whichever kind of reference reaches furthest is the one that decides
        // where the copy ends, and so the one the report is about: a read
        // reaching past an unbounded reference's fallback end bounds the copy
        // after all, and an unbounded one reaching past every read takes the
        // report back.
        let mut reaches_furthest = false;
        if access_len.is_some() {
            info.read_to = info.read_to.max(needed);
        } else if needed > info.fallback_to {
            info.fallback_to = needed;
            reaches_furthest = true;
        }
        (
            info.first_ref,
            info.fallback_to > info.read_to,
            reaches_furthest,
        )
    };

    grow_data_blob(lib, &sec, blob_key, needed, state)?;

    if let Some(at) = info.report {
        let copy = &mut state.data_section_copies[at];
        // A reference can land past the copied bytes — an end marker sits past
        // the section's last byte and asks for nothing copied — and what
        // precedes the first reference is then no part of the copy.
        copy.unreferenced_prefix = first_ref.min(copy.bytes as u64) as usize;
        // Name the reference the end actually comes from, which is this one
        // only when it is the unbounded reference reaching furthest. An earlier
        // one still holds the record otherwise, so it is left where it is
        // rather than overwritten: the first reference into a section is
        // routinely a bounded read, and reporting that one blamed the bytes on
        // an instruction that asked for a handful of them.
        //
        // A read can only take the record away, never move it. The one thing
        // that can leave the end unbounded again after a read has justified it
        // is an unbounded reference past that read — and such a reference is
        // past every earlier fallback too, since reads only ever grow
        // `read_to` above them, so it arrives here as `reaches_furthest` and
        // brings the record back with it.
        if !end_unbounded {
            copy.unbounded_end = None;
        } else if reaches_furthest {
            copy.unbounded_end = Some(UnboundedEnd {
                address: target_addr,
                reached_from: ctx.to_string(),
            });
        }
    }

    Ok(Some((info.id, info.base_vaddr)))
}

/// Copy enough of `sec` into the blob `key` names that it holds `needed` bytes
/// from its base, collecting the dynamic relocations over the bytes that can
/// still reach the output.
///
/// Nothing is removed and nothing moves: the blob only ever gains bytes at its
/// end, so the offsets of the references already resolved against it — and of
/// the relocations already collected for it — stay what they were.
///
/// The relocations are collected over the bytes from the copy's eventual start
/// up, not over every byte copied. The run below the first reference is carried
/// only so that the copy can be anchored at the section while the closure is
/// being built, and [`trim_unreferenced_prefixes`] gives it back at the end —
/// so resolving a pointer down there would extract what it names for nothing,
/// and worse, pin the run it sits in: a relocation describes bytes the copy has
/// to keep, which is what stopped the trim short of exactly the pointer-dense
/// sections it would help most. `test/bash` + `libtinfo.so.6` rooted all 1,500
/// pointers of a `.data.rel.ro` first referenced 4,032 bytes in, and then had
/// to keep every byte below that reference because of them (issue #66).
///
/// That start only ever moves down, and whenever it does the run it exposes is
/// collected then: a later, lower reference is the one thing that can turn a
/// pointer the copy was going to give back into one it has to keep.
fn grow_data_blob(
    lib: Lib<'_, '_>,
    sec: &SectionInfo<'_>,
    key: DataBlobKey,
    needed: u64,
    state: &mut ExtractionState,
) -> Result<()> {
    let info = *state
        .data_blobs
        .get(&key)
        .expect("the blob is registered before it is grown");
    let id = info.id;
    let want = info.copied.max(needed);
    let align = state
        .unit(id)
        .expect("the blob unit was pushed with the blob")
        .alignment;
    // Where the copy will start once the run below its first reference is
    // given back, which is the lowest byte of it that can reach the output.
    // The trim moves in multiples of the blob's alignment, so this does too.
    let kept_from = (info.first_ref / align * align).min(want);
    // A relocation is passed over only when every byte it describes is below
    // that: one straddling the cut still writes bytes the copy keeps, so it
    // has to be resolved — and the bytes it needs held — like any other.
    let root_from = kept_from.saturating_sub(POINTER_SIZE - 1);
    // A reference at or past the section's last byte asks for nothing copied,
    // and a blob with no bytes has neither bytes to resolve nor a run to give
    // back (see [`needed_prefix`]).
    if want == 0 || (info.copied >= needed && info.rooted_from <= root_from) {
        return Ok(());
    }

    // Publish the longer extent before reading the bytes, for the same reason
    // the id is published before the relocations are collected: resolving them
    // can lead back into this very range, and the lookup has to find it rather
    // than start a second copy of the same bytes. It also bounds the mutual
    // recursion with `collect_dynamic_range_relocs` at one visit per range.
    state.data_blobs.get_mut(&key).expect("just read").copied = want;

    // Only now that the section is known to need copying are its bytes worth
    // materializing: most of the addresses `ensure_data_blob_extracted` is
    // asked about never reach here.
    //
    // The range copied is held to the bytes the section actually has:
    // `describe_section` reports the length of those and not `sh_size`, so a
    // header claiming more than the file holds cannot make this read past them.
    let sec_data = section_contents(lib.elf, sec)?;
    let from = (info.base_vaddr - sec.vaddr) as usize;
    let start = (from + info.copied as usize).min(sec_data.len());
    let end = (from + want as usize).min(sec_data.len());
    let added = &sec_data[start..end];
    let held = info.copied + added.len() as u64;
    state
        .unit_mut(id)
        .expect("the blob unit was pushed with the blob")
        .bytes
        .extend_from_slice(added);

    // The two runs of kept bytes whose relocations nothing has resolved yet:
    // the one just copied onto the end, and — when this call is what lowered
    // the start — the one that reference exposed underneath. Everything outside
    // them is resolved already, or describes bytes this unit does not hold, or
    // describes bytes it does not keep.
    //
    // They meet the range already resolved from either side and overlap neither
    // it nor each other: a relocation collected twice would be deduplicated as
    // a relocation but counted twice as a GOT slot the loader has to write.
    //
    // The section's own name is the context for what its pointers reach, not
    // the caller's: a copy pulled in through this one is reported as having
    // been reached from here, which is what makes the records read as a chain.
    let base = info.base_vaddr;
    let resolved_from = info.rooted_from.min(info.copied).min(held);
    let exposed = base + root_from.min(resolved_from)..base + resolved_from;
    let appended = base + info.copied.max(root_from)..base + held;
    // Published before either range is collected, because collecting can lead
    // back here — and only once there are bytes, so that a blob still waiting
    // for its first byte does not read as having had them resolved.
    if held > 0 {
        let info = state.data_blobs.get_mut(&key).expect("just read");
        info.rooted_from = info.rooted_from.min(root_from);
    }
    let mut relocs = UnitRelocs::default();
    for range in [exposed, appended] {
        if range.is_empty() {
            continue;
        }
        collect_dynamic_range_relocs(lib, sec.name, range, base, state, &mut relocs)?;
    }
    let got_fixups = relocs.got_fixups.len();

    // `register_got_slot_fixups` zeroes the slots it records, so the bytes have
    // to be handed over mutably. They are taken out of the unit and put back
    // rather than written before the append, because the collection above can
    // have grown this same blob further and those bytes belong after these.
    let mut bytes = std::mem::take(
        &mut state
            .unit_mut(id)
            .expect("the blob unit is still registered")
            .bytes,
    );
    let new_relocs = state.take_unit_relocs(id, &mut bytes, relocs);

    // Claiming each offset is what keeps the jump-table pass and a copy that
    // grew after it from writing two relocations into the same slot — in
    // either order, since the claim both consults what the unit already holds
    // and records what is being added to it.
    let new_relocs: Vec<ExtractedReloc> = new_relocs
        .into_iter()
        .filter(|r| state.claim_blob_offset(id, r.offset_within_unit))
        .collect();
    let pointers = new_relocs.len() + got_fixups;

    let unit = state
        .unit_mut(id)
        .expect("the blob unit is still registered");
    unit.bytes = bytes;
    unit.relocations.extend(new_relocs);
    let (copied, relocations) = (unit.bytes.len(), unit.relocations.len());

    if relocations > 0 {
        debug!(section = sec.name, relocations, "Extracted data blob");
    }

    if let Some(at) = info.report {
        let copy = &mut state.data_section_copies[at];
        copy.bytes = copied;
        copy.pointers += pointers;
    }

    Ok(())
}

/// Move every copied data section up to the lowest byte anything references,
/// dropping the bytes underneath it.
///
/// A copy has to be anchored at its section's first byte while the closure is
/// being built, because that is the one anchor a later reference can extend it
/// from without moving it, and moving it would invalidate the offset of every
/// reference already resolved against it (see [`needed_prefix`]). Once the
/// worklist has drained nothing more will be resolved against a blob, so the
/// anchor has done its job and the run below the lowest reference is pure
/// weight: on `test/md5sum`, the sixteen-byte constant `MD5_Init` loads sits
/// 198,544 bytes into a stripped `libcrypto.so.3`'s `.rodata`, and carrying
/// the run below it was the whole of what that merge still copied (issue #66).
///
/// There are exactly three places an offset into a blob is held, and this
/// rewrites all of them: [`RelocTarget::DataBlobOffset`] in any unit's
/// relocation, the `offset_within_unit` of the blob's own relocations, and
/// [`GotSlotFixup::offset`]. The blob map itself is left as it was — its keys
/// are the anchors the lookups used, and there are no lookups left.
///
/// Two things bound how far up a copy can start:
///
/// * the blob's alignment, which every object in it is placed relative to, so
///   the start moves in multiples of it and each object keeps the alignment it
///   was copied with;
/// * the lowest pointer the copy carries. A relocation describes bytes the
///   copy holds, and whatever it names is in the merge *because* of it, so
///   dropping those bytes would leave that extraction reachable from nothing
///   rather than remove it. [`grow_data_blob`] is what keeps that from
///   stopping the trim at a pointer nothing reaches: a pointer below the first
///   reference is never resolved in the first place, so the only relocation
///   this bound can still find is one straddling the cut.
fn trim_unreferenced_prefixes(state: &mut ExtractionState) {
    let mut lowest_fixup: FastMap<UnitId, u64> = FastMap::default();
    for fixup in &state.got_slot_fixups {
        let at = lowest_fixup.entry(fixup.unit).or_insert(u64::MAX);
        *at = (*at).min(fixup.offset);
    }

    // `report` is what tells a copied section from a GOT slice, which is
    // exactly the slot it was asked for and has nothing to give back.
    let trims: Vec<(UnitId, u64, usize, u64)> = state
        .data_blobs
        .values()
        .filter_map(|info| {
            let report = info.report?;
            let unit = state.unit(info.id)?;
            let lowest_reloc = unit
                .relocations
                .iter()
                .map(|r| r.offset_within_unit)
                .min()
                .unwrap_or(u64::MAX);
            let cut = info
                .first_ref
                .min(lowest_reloc)
                .min(lowest_fixup.get(&info.id).copied().unwrap_or(u64::MAX))
                .min(unit.bytes.len() as u64);
            let trim = cut / unit.alignment * unit.alignment;
            (trim > 0).then_some((info.id, trim, report, info.first_ref))
        })
        .collect();
    if trims.is_empty() {
        return;
    }
    let trim_of: FastMap<UnitId, u64> = trims.iter().map(|&(id, trim, ..)| (id, trim)).collect();

    for unit in &mut state.units {
        let own = trim_of.get(&unit.id).copied().unwrap_or(0);
        for reloc in &mut unit.relocations {
            if let RelocTarget::DataBlobOffset(id, offset) = &mut reloc.target
                && let Some(trim) = trim_of.get(id)
            {
                *offset = offset
                    .checked_sub(*trim)
                    .expect("a copy starts at or below every offset referenced in it");
            }
            reloc.offset_within_unit = reloc
                .offset_within_unit
                .checked_sub(own)
                .expect("a copy starts at or below every relocation it holds");
        }
        if own > 0 {
            unit.bytes.drain(..own as usize);
            // The name is what a log line or a unit dump identifies the blob
            // by, and it no longer starts where the section does.
            unit.name.push_str(&format!("+{own:#x}"));
        }
    }

    for fixup in &mut state.got_slot_fixups {
        if let Some(trim) = trim_of.get(&fixup.unit) {
            fixup.offset = fixup
                .offset
                .checked_sub(*trim)
                .expect("a copy starts at or below every GOT slot it holds");
        }
    }

    for (id, trim, report, first_ref) in trims {
        let bytes = state.unit(id).map_or(0, |u| u.bytes.len());
        let copy = &mut state.data_section_copies[report];
        copy.start_offset = trim as usize;
        copy.bytes = bytes;
        copy.unreferenced_prefix = (first_ref - trim).min(bytes as u64) as usize;
        debug!(
            section = copy.section.as_str(),
            start_offset = trim,
            bytes,
            "Moved a copied section up to its first reference"
        );
    }
}

/// What an extracted blob is called in the merge's own reporting: the library
/// file and the section it came from, plus the address it starts at when the
/// blob is only part of that section, so two slots of the same GOT are told
/// apart in a log line or a dump of the merged units.
fn blob_unit_name(path: &Path, sec_name: &str, base_vaddr: u64, sec_addr: u64) -> String {
    let file = path.file_name().unwrap_or_default().to_string_lossy();
    if base_vaddr == sec_addr {
        format!("{file}:{sec_name}")
    } else {
        format!("{file}:{sec_name}+{:#x}", base_vaddr - sec_addr)
    }
}

/// Infer the size of a symbol whose `st_size` is 0, by bounding it with the
/// tightest safe end marker: the start of the next function with unwind info,
/// the next symbol in the same section, or the end of the section.
///
/// The next symbol alone is a poor bound in a stripped library, where the run
/// between two exported symbols can hold dozens of local functions: the whole
/// run would be copied once for every one of them that gets referenced, and a
/// unit that long also breaks short-branch veneering.
fn infer_symbol_size(lib: Lib<'_, '_>, sym: &SymInfo) -> Result<usize> {
    let sym_vaddr = sym.vaddr;
    let sym_section = sym.section;

    let next_addr = lib.index.next_addr_in_section(sym_vaddr, sym_section);

    let section = lib
        .elf
        .section_by_index(sym_section)
        .context("section lookup")?;
    let section_end = section.address() + section.size();
    let mut limit = next_addr.unwrap_or(section_end);

    // The start of the next function with unwind info is a far tighter bound
    // than the next symbol in a stripped library, where one run between two
    // exported symbols can hold dozens of local functions.
    //
    // It is the *next* FDE's start rather than the containing FDE's end
    // because the two are not always the same: hand-written assembly
    // (OpenSSL's RC4_options, for one) carries unwind info for only part of
    // the function, and cutting the unit at that FDE's end would drop real
    // code. Padding between functions can be copied; missing instructions
    // cannot. Unwind ranges only describe code, so this is consulted only for
    // symbols in an executable section.
    if section.kind() == ObjSectionKind::Text
        && let Some(next_fde) = lib.index.fdes.next_start_after(sym_vaddr)
    {
        limit = limit.min(next_fde);
    }

    if limit <= sym_vaddr {
        return Ok(0);
    }
    Ok((limit - sym_vaddr) as usize)
}

/// Init-side CRT glue that crtbeginS.o places in every shared library's
/// .init_array. In a normally linked process these only touch weak symbols
/// that resolve to null (`_ITM_registerTMCloneTable`, `__register_frame_info`),
/// so they are no-ops for the merged binary and are skipped instead of dragged
/// in with their closure. In stripped libraries these have no symbol names and
/// are conservatively extracted as anonymous units, which is still
/// behaviorally correct.
///
/// `__do_global_dtors_aux` (fini side) is deliberately NOT in this list: it
/// calls `__cxa_finalize(&__dso_handle)`, which is what runs the library's
/// C++ static destructors at the correct point in the shutdown sequence.
fn is_crt_glue(name: &str) -> bool {
    matches!(name, "frame_dummy" | "register_tm_clones")
}

/// Extract init/fini array entries from a library, resolving each function
/// pointer to an extractable unit name.
///
/// The raw section bytes normally hold each function's link-time address, but
/// some linkers zero the slots and rely on the R_X86_64_RELATIVE addend
/// instead, so relocation addends take precedence over raw content.
/// Sentinel values (0 or -1) are skipped.
fn extract_init_fini_arrays(lib: Lib<'_, '_>) -> Result<InitFiniArrays> {
    let lib_path = lib.path;
    let mut result = InitFiniArrays::default();

    // Function addresses for init/fini slots, recovered from .rela.dyn:
    // R_X86_64_RELATIVE carries the address in its addend; a symbol-based
    // relocation (e.g. R_X86_64_64) resolves to symbol address + addend.
    let mut reloc_targets: HashMap<u64, u64> = HashMap::new();
    if let Some(dyn_relocs) = lib.elf.dynamic_relocations() {
        for (roff, reloc) in dyn_relocs {
            let func_vaddr = match reloc.target() {
                object::RelocationTarget::Symbol(si) => {
                    match dynamic_symbol_by_index(lib.elf, si) {
                        Some(sym) if !sym.is_undefined() => {
                            sym.address().wrapping_add(reloc.addend() as u64)
                        }
                        _ => continue,
                    }
                }
                _ => reloc.addend() as u64,
            };
            reloc_targets.insert(roff, func_vaddr);
        }
    }

    for section in lib.elf.sections() {
        let sname = section.name().unwrap_or("");
        let is_init = sname == ".init_array";
        let is_fini = sname == ".fini_array";
        if !is_init && !is_fini {
            continue;
        }

        let sec_addr = section.address();
        let section_data = section
            .data()
            .with_context(|| format!("{}: {} section data", lib_path.display(), sname))?;

        for (i, chunk) in section_data.as_chunks::<8>().0.iter().enumerate() {
            let slot_vaddr = sec_addr + (i * 8) as u64;
            let func_vaddr = match reloc_targets.get(&slot_vaddr) {
                Some(&target) => target,
                None => u64::from_le_bytes(*chunk),
            };

            // Skip sentinel values (0 or -1)
            if func_vaddr == 0 || func_vaddr == u64::MAX {
                continue;
            }

            let sym_name = find_symbol_at_address(lib.index, func_vaddr);
            if let Some(ref name) = sym_name
                && is_crt_glue(name)
            {
                debug!(
                    lib = %lib_path.display(),
                    name,
                    "Skipping no-op CRT glue in {}", sname
                );
                continue;
            }

            let unit_name = sym_name
                .filter(|n| find_symbol(lib, n).is_ok())
                .or_else(|| {
                    anon_target_is_extractable(lib, func_vaddr).then(|| anon_unit_name(func_vaddr))
                })
                .with_context(|| {
                    format!(
                        "{}: {} entry {:#x} is not extractable — the merged binary \
                         would skip a constructor/destructor and behave differently",
                        lib_path.display(),
                        sname,
                        func_vaddr
                    )
                })?;

            let entry = InitFiniEntry {
                source_lib: lib_path.to_path_buf(),
                unit_name,
            };

            if is_init {
                result.init_entries.push(entry);
            } else {
                result.fini_entries.push(entry);
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> ExtractionState {
        ExtractionState {
            reserved: FastMap::default(),
            worklist: VecDeque::new(),
            units: Vec::new(),
            unit_index: FastMap::default(),
            next_id: 0,
            external_syms: FastSet::default(),
            cross_lib_syms: FastMap::default(),
            exe_defined_syms: FastSet::default(),
            exe_copy_relocated: FastSet::default(),
            processed_libs: FastSet::default(),
            init_fini: InitFiniArrays::default(),
            data_blobs: FastMap::default(),
            data_section_copies: Vec::new(),
            blob_reloc_offsets: FastMap::default(),
            units_at: FastMap::default(),
            plt_refs: FastMap::default(),
            got_slot_fixups: Vec::new(),
            lib_paths: Vec::new(),
            lib_ids: FastMap::default(),
            lib_bytes_cache: Vec::new(),
            lib_index_cache: Vec::new(),
        }
    }

    fn test_lib(name: &str) -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs")).join(name)
    }

    /// The key for `sym` in `lib`, interning the path in `state` the way
    /// `extract_units` does before queueing a seed.
    fn key_in(state: &mut ExtractionState, lib: &Path, sym: &str) -> UnitKey {
        UnitKey {
            lib: state.lib_id(lib),
            sym: sym.to_string(),
        }
    }

    /// A linked shared object has no section-attached relocation table, so
    /// `.rela.dyn`/`.rela.plt` — reached through `dynamic_relocations` — is
    /// the only place an extracted unit's relocations can come from.
    ///
    /// This is the premise `collect_dynamic_range_relocs` rests on, and it is
    /// worth holding to the real libraries rather than to the ELF spec: an
    /// input that did carry a section-attached table would have the
    /// relocations in it silently dropped, so every pointer they cover would
    /// keep the stale library address it was copied with. The fixtures span
    /// what solder is pointed at — a 6 MB C library, a PCRE build, ncurses'
    /// terminfo — and none of them has one.
    #[test]
    fn a_linked_library_has_no_section_attached_relocations() {
        for name in ["libcrypto.so.3", "libpcre2-8.so.0", "libtinfo.so.6"] {
            let bytes = std::fs::read(test_lib(name)).expect("read the fixture");
            let elf = parse_lib(&bytes);

            // The fixture has to have dynamic relocations at all, or the
            // assertion below holds for the wrong reason.
            let dynamic = elf
                .dynamic_relocations()
                .expect("a shared library has dynamic relocations")
                .count();
            assert!(dynamic > 0, "{name} reports no dynamic relocations");

            for section in elf.sections() {
                assert_eq!(
                    section.relocations().count(),
                    0,
                    "{name}: section {:?} reports section-attached relocations, which \
                     `process_symbol` no longer reads",
                    section.name()
                );
            }
        }
    }

    /// Every R_X86_64_RELATIVE slot inside an extracted unit has to come out
    /// with a relocation of its own. The copied bytes still hold the library's
    /// link-time address, so a slot that keeps its original value points into
    /// memory that is no longer mapped once the library leaves DT_NEEDED.
    ///
    /// `strnames` is ncurses' table of 414 pointers into `.rodata`, none of
    /// which has a symbol or unwind info of its own — exactly the shape that
    /// used to resolve to nothing and get left stale.
    #[test]
    fn every_relative_slot_in_a_pointer_table_is_retargeted() {
        let lib = test_lib("libtinfo.so.6");
        let mut state = test_state();
        let key = key_in(&mut state, &lib, "strnames");
        reserve_and_extract(&key, &mut state).expect("extract strnames");

        let unit = state
            .units
            .iter()
            .find(|u| u.name == "strnames")
            .expect("strnames unit")
            .clone();
        assert_eq!(unit.bytes.len() % 8, 0);
        let slots = unit.bytes.len() / 8;
        assert!(slots > 400, "expected a large table, got {slots} slots");

        let bytes = std::fs::read(&lib).expect("read library");
        let elf = object::File::parse(&*bytes).expect("parse library");
        let object::File::Elf64(elf64) = &elf else {
            panic!("not ELF64")
        };
        let lib_id = state.lib_id(&lib);
        let sym_vaddr = state.lib_index(lib_id, elf64).by_name["strnames"].vaddr;

        let relative_slots: Vec<u64> = elf64
            .dynamic_relocations()
            .expect("dynamic relocations")
            .filter(|(roff, reloc)| {
                *roff >= sym_vaddr
                    && *roff < sym_vaddr + unit.bytes.len() as u64
                    && matches!(reloc.target(), object::RelocationTarget::Absolute)
            })
            .map(|(roff, _)| roff - sym_vaddr)
            .collect();
        assert!(
            relative_slots.len() > 400,
            "expected the table to be relocated, got {} entries",
            relative_slots.len()
        );

        for offset in relative_slots {
            let reloc = unit
                .relocations
                .iter()
                .find(|r| r.offset_within_unit == offset)
                .unwrap_or_else(|| {
                    panic!("slot {offset:#x} of strnames kept its stale library address")
                });
            // The target is a `.rodata` string, so it must land in the copied
            // blob rather than being deferred to ld.so as an external.
            assert!(
                matches!(reloc.target, RelocTarget::DataBlobOffset(..)),
                "slot {offset:#x} resolved to {:?}",
                reloc.target
            );
        }
    }

    /// `test/libs/libtinfo.so.6` under a path of its own, so that two
    /// libraries whose data sections sit at the same virtual addresses can be
    /// extracted side by side.
    ///
    /// Two libraries' addresses are not comparable: each is linked on its own
    /// and position-independent code starts low, so the same `.rodata` address
    /// names a different byte in each. Copying one fixture twice is the
    /// sharpest form of that — every address collides.
    fn lib_under_its_own_path() -> tempfile::NamedTempFile {
        let out = tempfile::Builder::new()
            .suffix(".so.6")
            .tempfile()
            .expect("temp library");
        std::fs::copy(test_lib("libtinfo.so.6"), out.path()).expect("copy the fixture");
        out
    }

    /// A reference found in one library has to resolve to a blob extracted
    /// from that library. Matching the address against every blob extracted so
    /// far, whichever library it came from, pointed the second library's
    /// `strnames` at the first library's copy of `.rodata` — every string the
    /// table names read out of the wrong library.
    #[test]
    fn a_data_reference_resolves_within_its_own_library() {
        let libs = [lib_under_its_own_path(), lib_under_its_own_path()];
        let mut state = test_state();

        for lib in &libs {
            let key = key_in(&mut state, lib.path(), "strnames");
            reserve_and_extract(&key, &mut state).expect("extract strnames");
        }

        for lib in &libs {
            let unit = state
                .units
                .iter()
                .find(|u| u.name == "strnames" && u.source_lib == lib.path())
                .unwrap_or_else(|| panic!("no strnames unit from {}", lib.path().display()));
            let blobs: Vec<UnitId> = unit
                .relocations
                .iter()
                .filter_map(|r| match r.target {
                    RelocTarget::DataBlobOffset(id, _) => Some(id),
                    _ => None,
                })
                .collect();
            assert!(!blobs.is_empty(), "strnames reached no blob at all");
            for id in blobs {
                let blob = &state.units[state.unit_index[&id]];
                assert_eq!(
                    blob.source_lib,
                    lib.path(),
                    "a pointer in {}'s strnames reaches '{}' extracted from {}",
                    lib.path().display(),
                    blob.name,
                    blob.source_lib.display()
                );
            }
        }
    }

    /// Whether anything extracted so far asked for the unit named `sym`.
    fn depends_on(state: &ExtractionState, sym: &str) -> bool {
        state.reserved.keys().any(|key| key.sym == sym)
    }

    /// A variable the executable copy-relocates lives in the executable's own
    /// `.bss`, and the lookup that resolved the library's GOT slot for it found
    /// that copy rather than the definition in the library — the executable
    /// comes first in the global scope. So the merge has to leave such a slot
    /// to ld.so: resolving it to an extracted copy of the library's definition
    /// gives the merged code a second, private copy of a variable the
    /// executable is still writing.
    ///
    /// `test/bash` copy-relocates ncurses' `UP`, `PC` and `BC` — readline
    /// assigns all three while setting the terminal up, and `tputs` reads them
    /// to pad its output — so merging `libtinfo.so.6` into it split every one
    /// of them, leaving `tputs` padding from a zeroed copy nothing ever wrote
    /// to.
    ///
    /// The two functions extracted here are the ones that read the slots: a GOT
    /// slot is copied for the code that reads it and not for the rest of the
    /// table (see [`got_slot_at`]), and `tputs` reaches these two through the
    /// PLT, which a single-symbol extraction leaves external.
    #[test]
    fn a_variable_the_executable_copy_relocates_is_left_to_ld_so() {
        let mut state = test_state();
        let lib = test_lib("libtinfo.so.6");
        state.exe_copy_relocated = ["UP", "PC", "BC"].iter().map(|s| (*s).to_owned()).collect();
        // `tgetent_sp` reads all three of the copy-relocated variables through
        // the GOT; `set_curterm_sp` reads `ospeed` through it, which is the
        // control below.
        for sym in ["tgetent_sp", "set_curterm_sp"] {
            let key = key_in(&mut state, &lib, sym);
            reserve_and_extract(&key, &mut state)
                .unwrap_or_else(|e| panic!("extract {sym}: {e:#}"));
        }

        let fixups: Vec<&str> = state
            .got_slot_fixups
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        for name in ["UP", "PC", "BC"] {
            assert!(
                fixups.contains(&name),
                "'{name}' got no GLOB_DAT, so the merged code is not on the \
                 executable's copy: {fixups:?}"
            );
            assert!(
                !depends_on(&state, name),
                "'{name}' was extracted from the library as well, splitting it in two"
            );
        }

        // The control: `ospeed` sits beside the three in the same `.bss` and is
        // reached through the same `.got`, but nothing copy-relocates it, so its
        // slot must keep pointing at the library's own copy.
        assert!(
            depends_on(&state, "ospeed"),
            "'ospeed' is not copy-relocated and has no copy but the library's"
        );
        assert!(!fixups.contains(&"ospeed"), "{fixups:?}");
    }

    /// `test/libs/libtinfo.so.6` with the first `.rela.dyn` entry inside
    /// `strnames` retyped to `r_type`, written to a temporary file.
    ///
    /// No committed fixture uses thread-local storage or an ifunc, and both
    /// show up in a library's dynamic relocation table as nothing but an
    /// `r_type` — so retyping one entry of a table solder is known to extract
    /// reproduces exactly the input that used to be patched as a pointer.
    fn lib_with_retyped_strnames_reloc(r_type: u32) -> tempfile::NamedTempFile {
        use object::read::elf::SectionHeader;

        let mut bytes = std::fs::read(test_lib("libtinfo.so.6")).expect("read libtinfo.so.6");
        let entry_offset = {
            let elf = parse_lib(&bytes);
            let endian = elf.endian();
            let sym = elf
                .symbols()
                .chain(elf.dynamic_symbols())
                .find(|s| s.name() == Ok("strnames") && s.size() > 0)
                .expect("strnames");
            let range = sym.address()..sym.address() + sym.size();

            elf.elf_section_table()
                .iter()
                .filter(|sec| sec.sh_type(endian) == object::elf::SHT_RELA)
                .find_map(|sec| {
                    let (relas, _) = sec.rela(endian, bytes.as_slice()).ok()??;
                    let i = relas
                        .iter()
                        .position(|r| range.contains(&r.r_offset.get(endian)))?;
                    // Elf64_Rela is r_offset(8) + r_info(8) + r_addend(8).
                    Some(sec.sh_offset(endian) as usize + i * 24 + 8)
                })
                .expect("a .rela.dyn entry inside strnames")
        };

        // r_info is (r_sym << 32) | r_type, and the entry found above is an
        // R_X86_64_RELATIVE with no symbol, so the whole field is the type.
        bytes[entry_offset..entry_offset + 8].copy_from_slice(&u64::from(r_type).to_le_bytes());

        let out = tempfile::Builder::new()
            .suffix(".so.6")
            .tempfile()
            .expect("temp library");
        std::fs::write(out.path(), &bytes).expect("write the retyped library");
        out
    }

    /// A relocation type that is not a 64-bit pointer slot has to fail the
    /// merge rather than be patched as if it were an address.
    ///
    /// The `object` crate names none of x86-64's dynamic relocation types, so
    /// a TLS slot and an ifunc slot reach the extractor looking exactly like
    /// the `R_X86_64_RELATIVE` entries it does lift — `RelocationKind::Unknown`
    /// with a reported size of 0. Widening that 0 to 64 bits turned both into
    /// `R_X86_64_64`: the TLS slot got a link-time address where ld.so was to
    /// store an offset from the thread pointer, so the merged code indexed
    /// `%fs` by it, and the ifunc slot got the resolver's address instead of
    /// the implementation it returns.
    #[test]
    fn a_relocation_that_is_not_a_pointer_slot_is_refused() {
        for (r_type, expected) in [
            (object::elf::R_X86_64_TPOFF64.0, "R_X86_64_TPOFF64"),
            (object::elf::R_X86_64_DTPMOD64.0, "R_X86_64_DTPMOD64"),
            (object::elf::R_X86_64_IRELATIVE.0, "R_X86_64_IRELATIVE"),
        ] {
            let lib = lib_with_retyped_strnames_reloc(r_type);
            let mut state = test_state();
            let key = key_in(&mut state, lib.path(), "strnames");
            let err = match reserve_and_extract(&key, &mut state) {
                Err(e) => e,
                Ok(_) => panic!("{expected} is not a pointer slot but extraction succeeded"),
            };
            let msg = format!("{err:#}");
            assert!(
                msg.contains(expected),
                "{expected} was not named in the error: {msg}"
            );
        }
    }

    /// The three types solder does lift are reported the same way as the ones
    /// it refuses, so the gate has to let them through — including
    /// `R_X86_64_JUMP_SLOT`, which `.rela.plt` is full of and which a copied
    /// `.got.plt` range therefore runs into.
    #[test]
    fn the_pointer_slot_relocations_still_extract() {
        for r_type in [
            object::elf::R_X86_64_RELATIVE.0,
            object::elf::R_X86_64_GLOB_DAT.0,
            object::elf::R_X86_64_JUMP_SLOT.0,
        ] {
            let lib = lib_with_retyped_strnames_reloc(r_type);
            let mut state = test_state();
            let key = key_in(&mut state, lib.path(), "strnames");
            reserve_and_extract(&key, &mut state)
                .unwrap_or_else(|e| panic!("r_type {r_type} should still extract: {e:#}"));
        }
    }

    /// `libtinfo.so.6` with the `DT_RELR` tags written over the spare
    /// `.dynamic` slots past `DT_NULL`, as a file extraction can open. To
    /// anything reading `.dynamic` this is a `-z pack-relative-relocs` build:
    /// the relocations themselves stay in `.rela.dyn`, which only makes the
    /// test stricter — extraction has to refuse the library on the tags alone,
    /// before it finds there is anything readable there.
    fn lib_with_packed_relr() -> tempfile::NamedTempFile {
        use crate::elf_reader::{DYN_ENTRY_SIZE, DynamicTable};

        let mut bytes = std::fs::read(test_lib("libtinfo.so.6")).expect("read libtinfo.so.6");
        let dynamic = DynamicTable::parse(&bytes).expect(".dynamic of libtinfo.so.6");
        let at = dynamic.used();
        assert!(
            at + 3 <= dynamic.capacity(),
            "libtinfo.so.6: {} spare .dynamic slots, need 3",
            dynamic.capacity() - at
        );

        let tags = [
            (object::elf::DT_RELR.0 as u64, 0x1000u64),
            (object::elf::DT_RELRSZ.0 as u64, 216),
        ];
        for (i, (tag, val)) in tags.into_iter().enumerate() {
            let o = dynamic.entry_offset(at + i);
            bytes[o..o + 8].copy_from_slice(&tag.to_le_bytes());
            bytes[o + 8..o + 16].copy_from_slice(&val.to_le_bytes());
        }
        let end = dynamic.entry_offset(at + 2);
        bytes[end..end + DYN_ENTRY_SIZE].fill(0);

        let out = tempfile::Builder::new()
            .suffix(".so.6")
            .tempfile()
            .expect("temp library");
        std::fs::write(out.path(), &bytes).expect("write the packed library");
        out
    }

    /// The refusal has to be reached from extraction, not merely available to
    /// be called: `lib_bytes` is where a library the merge takes code out of is
    /// first opened — including one reached only through a cross-library
    /// reference, which no earlier stage of the merge looks at — so it is the
    /// only gate every packed library is certain to pass through.
    #[test]
    fn a_library_with_packed_relative_relocs_does_not_extract() {
        let lib = lib_with_packed_relr();
        let mut state = test_state();
        let key = key_in(&mut state, lib.path(), "strnames");
        let err = match reserve_and_extract(&key, &mut state) {
            Err(e) => e,
            Ok(_) => panic!(
                "a DT_RELR library's relative relocations cannot be read, but \
                 extraction succeeded"
            ),
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("DT_RELR"), "{msg}");
    }

    /// Every committed fixture library, so a trait of the linker's output is
    /// checked against more than one build.
    const TEST_LIBS: [&str; 3] = ["libtinfo.so.6", "libpcre2-8.so.0", "libcrypto.so.3"];

    /// Every stub in a real library's `.plt` resolves to the symbol its
    /// `.rela.plt` entry names, and the `.plt.got` stub beside it to the one
    /// its `R_X86_64_GLOB_DAT` names.
    ///
    /// This lookup is what turns a call the extracted code makes through the
    /// PLT into a direct call to the merged copy of the callee, or into a
    /// trampoline for a callee that stays external. A stub it fails to
    /// recognise leaves the call with the displacement the library was linked
    /// with, which reaches nothing once the library is gone from `DT_NEEDED`.
    ///
    /// The linker lays `.plt` out as the PLT0 resolver thunk followed by one
    /// 16-byte stub per `.rela.plt` entry, in that table's order, so the
    /// relocations are an oracle for what each stub has to come back as that
    /// does not go through the stub's own bytes.
    #[test]
    fn every_plt_stub_names_the_symbol_its_relocation_does() {
        for name in TEST_LIBS {
            let path = test_lib(name);
            let bytes = std::fs::read(&path).expect("read the library");
            let elf = parse_lib(&bytes);
            let index = LibIndex::build(&elf);
            let lib = Lib {
                // Nothing under test here reaches an `ExtractionState`, so the
                // id this handle carries is never used to key anything.
                id: LibId(0),
                path: &path,
                elf: &elf,
                index: &index,
            };

            let relocated = |r_type: u32| -> Vec<(u64, String)> {
                elf.dynamic_relocations()
                    .expect("a shared library has dynamic relocations")
                    .filter(|(_, reloc)| elf_r_type(reloc) == Some(r_type))
                    .filter_map(|(slot, reloc)| match reloc.target() {
                        object::RelocationTarget::Symbol(si) => {
                            let sym = dynamic_symbol_by_index(&elf, si)?;
                            Some((slot, sym.name().ok()?.to_owned()))
                        }
                        _ => None,
                    })
                    .collect()
            };

            let jump_slots = relocated(object::elf::R_X86_64_JUMP_SLOT.0);
            assert!(
                jump_slots.len() > 10,
                "{name}: only {} JUMP_SLOT relocations",
                jump_slots.len()
            );

            let plt = elf.section_by_name(".plt").expect(".plt");
            assert_eq!(
                plt.size(),
                (jump_slots.len() as u64 + 1) * 16,
                "{name}: .plt is not PLT0 followed by one 16-byte stub per JUMP_SLOT"
            );
            assert_eq!(
                plt_target(lib, plt.address()),
                None,
                "{name}: PLT0 jumps through the loader's own slot, not a symbol's"
            );
            for (i, (_, expected)) in jump_slots.iter().enumerate() {
                let stub = plt.address() + (i as u64 + 1) * 16;
                assert_eq!(
                    plt_target(lib, stub).as_deref(),
                    Some(expected.as_str()),
                    "{name}: the stub at {stub:#x}"
                );
            }

            // A `.plt.got` stub is reached the same way but relocated with a
            // GLOB_DAT in `.rela.dyn`, which is the half of `got_to_name` the
            // `.plt` entries never exercise.
            let plt_got = elf.section_by_name(".plt.got").expect(".plt.got");
            let glob_dats = relocated(object::elf::R_X86_64_GLOB_DAT.0);
            let resolved = plt_target(lib, plt_got.address())
                .unwrap_or_else(|| panic!("{name}: the first .plt.got stub went unresolved"));
            assert!(
                glob_dats.iter().any(|(_, sym)| *sym == resolved),
                "{name}: '{resolved}' is not the symbol of any GLOB_DAT"
            );
        }
    }

    fn parse_lib(bytes: &[u8]) -> object::read::elf::ElfFile64<'_> {
        match object::File::parse(bytes).expect("parse library") {
            object::File::Elf64(elf64) => elf64,
            _ => panic!("not ELF64"),
        }
    }

    /// `test/libs/libpcre2-8.so.0` with one section header's `sh_size`
    /// overwritten.
    ///
    /// A section header is where every length the extractor allocates from
    /// comes from, and the only thing vouching for one is the file itself.
    fn lib_with_section_size(section: &str, sh_size: u64) -> Vec<u8> {
        use object::read::elf::FileHeader;

        let mut bytes = std::fs::read(test_lib("libpcre2-8.so.0")).expect("read libpcre2-8.so.0");
        let at = {
            let elf = parse_lib(&bytes);
            let endian = elf.endian();
            let header = elf.elf_header();
            let index = elf
                .section_by_name(section)
                .unwrap_or_else(|| panic!("libpcre2-8.so.0 has no {section} section"))
                .index()
                .0;
            header.e_shoff(endian) as usize
                + index * header.e_shentsize(endian) as usize
                + crate::elf_reader::SH_SIZE
        };
        bytes[at..at + 8].copy_from_slice(&sh_size.to_le_bytes());
        bytes
    }

    /// `test/libs/libpcre2-8.so.0` with one section header's `sh_addralign`
    /// overwritten, written to a temporary file.
    ///
    /// No committed fixture has a page-aligned `.text`, but Debian's
    /// `libcrypto.so.3` and `libssl.so.3` both do, and a section alignment is
    /// one number in one header — so raising a fixture's reproduces exactly the
    /// input whose every unit used to be padded up to 4 KiB.
    fn lib_with_section_alignment(section: &str, sh_addralign: u64) -> tempfile::NamedTempFile {
        use object::read::elf::FileHeader;

        let mut bytes = std::fs::read(test_lib("libpcre2-8.so.0")).expect("read libpcre2-8.so.0");
        let at = {
            let elf = parse_lib(&bytes);
            let endian = elf.endian();
            let header = elf.elf_header();
            let index = elf
                .section_by_name(section)
                .unwrap_or_else(|| panic!("libpcre2-8.so.0 has no {section} section"))
                .index()
                .0;
            header.e_shoff(endian) as usize
                + index * header.e_shentsize(endian) as usize
                + crate::elf_reader::SH_ADDRALIGN
        };
        bytes[at..at + 8].copy_from_slice(&sh_addralign.to_le_bytes());

        // The offset above is arithmetic on the file's own headers, so check it
        // landed where it was meant to rather than somewhere else entirely.
        assert_eq!(
            parse_lib(&bytes)
                .section_by_name(section)
                .expect(section)
                .align(),
            sh_addralign,
            "the doctored sh_addralign did not take"
        );

        let out = tempfile::Builder::new()
            .suffix(".so.0")
            .tempfile()
            .expect("temp library");
        std::fs::write(out.path(), &bytes).expect("write the realigned library");
        out
    }

    /// A unit's alignment is its own, not that of the section it came out of.
    ///
    /// `sh_addralign` says where the linker put the section's first byte, not
    /// what every symbol inside it needs. Taking it as each unit's requirement
    /// padded all 8858 units extracted from Debian's `libcrypto.so.3` — whose
    /// `.text` is aligned to 4096 — up to a page boundary each: merging it and
    /// `libssl.so.3` into `/usr/bin/openssl` laid out a 37,761,024-byte region
    /// for 3,601,340 bytes of extracted code and data, over 90% of it zeroes.
    #[test]
    fn a_units_alignment_is_its_own_and_not_its_sections() {
        const SYM: &str = "pcre2_maketables_8";
        const PAGE: u64 = 0x1000;

        let lib = lib_with_section_alignment(".text", PAGE);
        let bytes = std::fs::read(lib.path()).expect("read the realigned library");
        let vaddr = parse_lib(&bytes)
            .dynamic_symbols()
            .find(|s| s.name() == Ok(SYM))
            .expect(SYM)
            .address();
        let own = 1u64 << vaddr.trailing_zeros();
        assert!(
            own < PAGE,
            "{SYM} is at {vaddr:#x}, which is page aligned — it cannot show the difference"
        );

        let mut state = test_state();
        let key = key_in(&mut state, lib.path(), SYM);
        reserve_and_extract(&key, &mut state).unwrap_or_else(|e| panic!("extract {SYM}: {e:#}"));
        let unit = state
            .units
            .iter()
            .find(|u| u.name == SYM)
            .unwrap_or_else(|| panic!("{SYM} unit"));
        assert_eq!(
            unit.alignment, own,
            "{SYM} sits at {vaddr:#x} in a .text aligned to {PAGE:#x}, so {own} is all the \
             alignment it can need"
        );
    }

    /// The section's alignment is still a ceiling: a unit the linker happened
    /// to put at a well-aligned address does not thereby need that alignment,
    /// and a unit at address 0 says nothing at all about its requirement.
    #[test]
    fn a_units_alignment_is_capped_by_its_sections() {
        // 0x1000 divides the address, but .text only promised 64.
        assert_eq!(unit_alignment(0x3000, 64), 64);
        // 16 divides it, and that is less than the section's 64.
        assert_eq!(unit_alignment(0x3010, 64), 16);
        // Nothing to infer from, so the section's alignment stands.
        assert_eq!(unit_alignment(0, 64), 64);
        // A section that declares no alignment constrains nothing.
        assert_eq!(unit_alignment(0x3010, 0), 1);
    }

    /// `test/libs/libtinfo.so.6` with the `st_size` of the `.dynsym` entry for
    /// `sym` overwritten, written to a temporary file.
    fn lib_with_symbol_size(sym: &str, st_size: u64) -> tempfile::NamedTempFile {
        use object::read::elf::SectionHeader;

        let mut bytes = std::fs::read(test_lib("libtinfo.so.6")).expect("read libtinfo.so.6");
        let at = {
            let elf = parse_lib(&bytes);
            let endian = elf.endian();
            let index = elf
                .dynamic_symbols()
                .find(|s| s.name() == Ok(sym))
                .unwrap_or_else(|| panic!("libtinfo.so.6 has no {sym}"))
                .index()
                .0;
            let dynsym = elf
                .elf_section_table()
                .iter()
                .find(|sec| sec.sh_type(endian) == object::elf::SHT_DYNSYM)
                .expect(".dynsym");
            // Elf64_Sym is st_name(4), st_info(1), st_other(1), st_shndx(2),
            // st_value(8), st_size(8).
            dynsym.sh_offset(endian) as usize + index * 24 + 16
        };
        bytes[at..at + 8].copy_from_slice(&st_size.to_le_bytes());

        // The offset above is arithmetic on the file's own headers, so check it
        // landed where it was meant to rather than somewhere else entirely.
        assert_eq!(
            parse_lib(&bytes)
                .dynamic_symbols()
                .find(|s| s.name() == Ok(sym))
                .expect(sym)
                .size(),
            st_size,
            "the doctored st_size did not take"
        );

        let out = tempfile::Builder::new()
            .suffix(".so.6")
            .tempfile()
            .expect("temp library");
        std::fs::write(out.path(), &bytes).expect("write the doctored library");
        out
    }

    /// A `.bss` symbol's `st_size` is bounded by the section's own `sh_size`
    /// and nothing else, neither of them being backed by bytes in the file.
    /// The file-backed branch beside it has always checked that a symbol stays
    /// inside the section that defines it; the zero-filled one checked nothing
    /// and allocated `st_size` bytes, so a corrupted size ended the run as
    /// `memory allocation of 1152921504606846976 bytes failed` — an abort,
    /// naming neither the symbol nor the library.
    #[test]
    fn a_bss_symbol_reaching_past_its_section_is_an_error_rather_than_an_abort() {
        let lib = lib_with_symbol_size("ospeed", 1 << 60);
        let mut state = test_state();
        let key = key_in(&mut state, lib.path(), "ospeed");
        let err = match reserve_and_extract(&key, &mut state) {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("an exbibyte of .bss cannot be extracted from a 220K library"),
        };
        assert!(err.contains("ospeed"), "the symbol is not named: {err}");
        assert!(
            err.contains("overflows section"),
            "the section bound is not reported: {err}"
        );

        // The control: at its real size the same symbol still extracts, zero
        // filled to the length `.bss` declares for it.
        let mut state = test_state();
        let key = key_in(&mut state, &test_lib("libtinfo.so.6"), "ospeed");
        reserve_and_extract(&key, &mut state).expect("extract ospeed");
        let unit = state
            .units
            .iter()
            .find(|u| u.name == "ospeed")
            .expect("ospeed unit");
        assert_eq!(
            unit.bytes,
            vec![0u8; 2],
            "a .bss symbol is zero fill at its declared size"
        );
    }

    /// A NOBITS section's `sh_size` is the one length in a library that no
    /// bytes in the file have to back — `.bss` costs the file nothing however
    /// much of it the header claims — so a corrupted one is only caught where
    /// the zero fill is allocated. It was not caught there at all:
    /// `vec![0u8; sh_size]` aborted the process on the failed allocation
    /// (`memory allocation of 281474976710656 bytes failed`), without
    /// unwinding, so nothing named the library it came from.
    #[test]
    fn a_nobits_section_overstating_its_size_is_an_error_rather_than_an_abort() {
        let bytes = lib_with_section_size(".bss", 1 << 60);
        let elf = parse_lib(&bytes);
        let bss = elf.section_by_name(".bss").expect(".bss").address();

        let sec = find_section_for_address(&elf, bss).expect(".bss still owns its own address");
        assert_eq!(sec.name, ".bss");
        let err = section_contents(&elf, &sec)
            .expect_err("an exbibyte of zero fill is not allocatable anywhere");
        let msg = format!("{err:#}");
        assert!(msg.contains(".bss"), "the section is not named: {msg}");
    }

    /// `.got.plt` is PROGBITS: its bytes are in the file, so a `sh_size`
    /// running past the end of the file makes the header a liar rather than a
    /// description of zero fill — readelf says "Size of section 22 is larger
    /// than the entire file!" of the same header. The extractor read an empty
    /// `data()` as "NOBITS, synthesize the fill" whatever the section's type,
    /// so it copied `sh_size` zeros over a section that has a real GOT in it,
    /// and for the sizes a corrupted header reaches aborted on the allocation
    /// instead.
    #[test]
    fn a_section_whose_contents_are_not_in_the_file_is_not_extractable() {
        const SECTION: &str = ".got.plt";

        let pristine = std::fs::read(test_lib("libpcre2-8.so.0")).expect("read libpcre2-8.so.0");
        let elf = parse_lib(&pristine);
        let got = elf.section_by_name(SECTION).expect(SECTION);
        let (addr, size) = (got.address(), got.size());
        let sec = find_section_for_address(&elf, addr).expect("the section owns its own address");
        assert_eq!((sec.name, sec.size), (SECTION, size));
        assert_eq!(
            section_contents(&elf, &sec).expect("contents").len() as u64,
            size,
            "the pristine section's bytes come from the file"
        );

        for overstated in [size + 0x1000, 1 << 60] {
            let bytes = lib_with_section_size(SECTION, overstated);
            let elf = parse_lib(&bytes);
            assert!(
                find_section_for_address(&elf, addr).is_none(),
                "{SECTION} claiming {overstated} bytes describes contents the file does \
                 not have, so there is nothing to copy out of it"
            );
        }
    }

    /// An address in the alignment padding between two allocated sections
    /// belongs to the section it follows, since that is where the linker leaves
    /// the end markers of the section's contents. An address inside a section
    /// still belongs to that section, and one outside the image belongs to
    /// nothing — anchoring that to whatever section happens to lie lowest would
    /// turn a decoding artifact into a relocation.
    #[test]
    fn an_address_in_a_sections_trailing_gap_belongs_to_that_section() {
        for name in TEST_LIBS {
            let bytes = std::fs::read(test_lib(name)).expect("read library");
            let elf = parse_lib(&bytes);

            let data = elf.section_by_name(".data").expect(".data");
            let data_end = data.address() + data.size();
            let bss = elf.section_by_name(".bss").expect(".bss").address();
            assert!(
                bss > data_end,
                "{name}: expected padding between .data and .bss"
            );

            for addr in [data_end, bss - 1] {
                let sec = find_section_for_address(&elf, addr)
                    .unwrap_or_else(|| panic!("{name}: {addr:#x} resolved to no section"));
                assert_eq!(sec.name, ".data", "{name}: {addr:#x}");
                assert_eq!(sec.vaddr, data.address(), "{name}: {addr:#x}");
                assert_eq!(sec.kind, SectionKind::Data, "{name}: {addr:#x}");
                assert_eq!(sec.size, data.size(), "{name}: {addr:#x}");
                let contents = section_contents(&elf, &sec).expect(".data contents");
                assert_eq!(contents.len() as u64, data.size(), "{name}: {addr:#x}");
            }

            let bss_sec = find_section_for_address(&elf, bss).expect(".bss");
            assert_eq!(
                bss_sec.name, ".bss",
                "{name}: containment must win over a gap"
            );
            // `.bss` is NOBITS: the file holds none of it, so its contents have
            // to be synthesized at its full declared length.
            assert_eq!(
                section_contents(&elf, &bss_sec)
                    .expect(".bss contents")
                    .len() as u64,
                elf.section_by_name(".bss").expect(".bss").size(),
                "{name}: .bss must be zero-filled to its declared size"
            );

            let past_the_image = bss + elf.section_by_name(".bss").expect(".bss").size() + 0x1000;
            assert!(
                find_section_for_address(&elf, past_the_image).is_none(),
                "{name}: {past_the_image:#x} is outside every section"
            );

            // The gap between the read-only and the writable segment is not
            // padding of the section below it: the two are mapped separately,
            // and the merged copies land in separate mappings too.
            let eh_frame = elf.section_by_name(".eh_frame").expect(".eh_frame");
            let ro_end = eh_frame.address() + eh_frame.size();
            let rw_start = elf
                .section_by_name(".init_array")
                .expect(".init_array")
                .address();
            let between_segments = ro_end + (rw_start - ro_end) / 2;
            assert!(
                find_section_for_address(&elf, between_segments).is_none(),
                "{name}: {between_segments:#x} spans a segment boundary"
            );
        }
    }

    /// `crtbeginS.o` puts `register_tm_clones` in the `.init_array` of every
    /// shared library and `deregister_tm_clones` in its `.fini_array`, and both
    /// compare `__TMC_LIST__` against `__TMC_END__` to decide whether there is a
    /// transactional-memory clone table to register. The linker defines those
    /// two markers in the alignment padding past the end of `.data`, so nothing
    /// used to own their address and both `lea` displacements were copied
    /// verbatim — pointing, once the unit had moved into the executable, at
    /// whatever lay that far past its new home.
    #[test]
    fn the_crt_clone_table_markers_are_retargeted_at_the_merged_copy() {
        for name in TEST_LIBS {
            let lib = test_lib(name);
            let bytes = std::fs::read(&lib).expect("read library");
            let elf = parse_lib(&bytes);
            let data_size = elf.section_by_name(".data").expect(".data").size();

            let mut state = test_state();
            let lib_id = state.lib_id(&lib);
            let index = state.lib_index(lib_id, &elf);
            let arrays = extract_init_fini_arrays(Lib {
                id: lib_id,
                path: &lib,
                elf: &elf,
                index: &index,
            })
            .expect("init/fini arrays");
            assert!(
                !arrays.init_entries.is_empty() && !arrays.fini_entries.is_empty(),
                "{name}: expected CRT glue in both arrays"
            );

            // The markers are referenced by the clone-table helpers the array
            // entries call, so follow the entries' dependencies too — which is
            // what draining the worklist `process_symbol` reserves onto does.
            for entry in arrays.init_entries.iter().chain(&arrays.fini_entries) {
                state.reserve(UnitKey {
                    lib: lib_id,
                    sym: entry.unit_name.clone(),
                });
            }
            while let Some((key, id)) = state.worklist.pop_front() {
                if key.lib != lib_id {
                    continue; // another merged library, outside this test
                }
                process_symbol(&key, id, &mut state).expect("extract the CRT glue");
            }

            let data_section = elf.section_by_name(".data").expect(".data");
            let blob = state
                .data_blobs
                .get(&DataBlobKey {
                    lib: lib_id,
                    section: data_section.index(),
                    base: data_section.address(),
                })
                .expect(".data was not extracted")
                .id;

            // A marker sits at or past the last byte of `.data`, so the offset
            // the markers resolve to is never inside the copied contents.
            let markers = state
                .units
                .iter()
                .flat_map(|u| &u.relocations)
                .filter(|r| {
                    matches!(r.target,
                        RelocTarget::DataBlobOffset(id, off) if id == blob && off >= data_size)
                })
                .count();
            assert!(
                markers >= 2,
                "{name}: expected the clone-table markers to be retargeted, \
                 found {markers} such relocations"
            );
        }
    }

    /// A pointer in `.data` that points back into `.data` has to resolve to the
    /// blob being built, not fall through as unresolvable because the blob is
    /// not registered yet.
    #[test]
    fn a_data_section_pointing_into_itself_resolves_to_its_own_blob() {
        let lib = test_lib("libpcre2-8.so.0");
        let mut state = test_state();
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = object::File::parse(&*bytes).expect("parse library");
        let object::File::Elf64(elf64) = &elf else {
            panic!("not ELF64")
        };
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, elf64);
        let data = elf64.section_by_name(".data").expect(".data").address();

        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: elf64,
            index: &index,
        };
        let (blob_id, base) = ensure_data_blob_extracted(handle, ".data", data, None, &mut state)
            .expect("extract .data")
            .expect(".data is extractable");
        assert_eq!(base, data);

        let unit = state
            .units
            .iter()
            .find(|u| u.id == blob_id)
            .expect("blob unit");
        assert!(
            unit.relocations.iter().any(|r| matches!(
                r.target,
                RelocTarget::DataBlobOffset(id, _) if id == blob_id
            )),
            "no self-referential pointer resolved to the blob itself"
        );
    }

    /// Extracting one function copies the GOT slots that function reads and
    /// leaves the rest of the table in the library.
    ///
    /// The whole-table copy this replaces is the first half of the blow-up
    /// described in issue #66: every pointer in a copied section becomes an
    /// extraction root, so one function reading one slot used to root all of
    /// them — in `libcrypto.so.3` that is 3,247 pointers, and they reach 91% of
    /// the library. `_nc_setupterm` reads seven slots of ncurses' 206-slot
    /// `.got`, naming each by its own address, and that is all it needs.
    #[test]
    fn a_got_reference_copies_the_slot_it_names_and_not_the_table() {
        let lib = test_lib("libtinfo.so.6");
        let mut state = test_state();
        let key = key_in(&mut state, &lib, "_nc_setupterm");
        reserve_and_extract(&key, &mut state).expect("extract _nc_setupterm");

        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let got = elf.section_by_name(".got").expect(".got");
        let (got_addr, got_size) = (got.address(), got.size());

        let slots: Vec<(u64, UnitId)> = state
            .data_blobs
            .iter()
            .filter(|(key, _)| key.section == got.index())
            .map(|(key, info)| (key.base, info.id))
            .collect();
        assert_eq!(
            slots.len(),
            7,
            "expected the seven slots `_nc_setupterm` reads, got {:?}",
            slots
                .iter()
                .map(|(base, _)| base - got_addr)
                .collect::<Vec<_>>()
        );

        let mut copied = 0;
        for (base, id) in &slots {
            assert_eq!(
                (base - got_addr) % 8,
                0,
                "blob base {base:#x} is not a slot boundary"
            );
            let unit = state
                .units
                .iter()
                .find(|u| u.id == *id)
                .expect("the blob was registered but never pushed");
            assert_eq!(unit.bytes.len(), 8, "{} is not one slot", unit.name);
            assert!(
                unit.relocations.len()
                    + state
                        .got_slot_fixups
                        .iter()
                        .filter(|f| f.unit == *id)
                        .count()
                    <= 1,
                "{} carries more than the one pointer a slot holds",
                unit.name
            );
            copied += unit.bytes.len() as u64;
        }
        assert!(
            copied * 10 < got_size,
            "copied {copied} of the {got_size} bytes of .got"
        );
    }

    /// Two references into one GOT slot share its blob, and references to
    /// neighbouring slots get a blob each — the lookup is by slot, not by
    /// section. A section that is not a GOT is copied from its first byte, and
    /// an unbounded reference into it takes everything up to the next object
    /// the library names.
    #[test]
    fn a_got_is_blobbed_per_slot_and_every_other_section_from_its_start() {
        let lib = test_lib("libtinfo.so.6");
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let got = elf.section_by_name(".got").expect(".got");
        let data = elf.section_by_name(".data").expect(".data");

        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        };
        let blob_at = |addr: u64, access_len: Option<u64>, state: &mut ExtractionState| {
            ensure_data_blob_extracted(handle, "the test", addr, access_len, state)
                .expect("extract the blob")
                .expect("the address is in an extractable section")
        };

        // A slot in the middle of the table, so neither neighbour is outside it.
        let slot = got.address() + got.size() / 2 / 8 * 8;
        let (first, base) = blob_at(slot, Some(8), &mut state);
        assert_eq!(base, slot);
        // The four bytes above the slot's base belong to the same pointer.
        assert_eq!(blob_at(slot + 4, Some(4), &mut state), (first, slot));
        let (next, next_base) = blob_at(slot + 8, Some(8), &mut state);
        assert_ne!(next, first, "two slots came out as one blob");
        assert_eq!(next_base, slot + 8);

        let (data_blob, data_base) = blob_at(data.address() + 8, None, &mut state);
        assert_eq!(
            data_base,
            data.address(),
            "a reference into .data resolved against a slice of it"
        );
        let unit = state
            .units
            .iter()
            .find(|u| u.id == data_blob)
            .expect("the .data blob");
        let next = index
            .next_object_in_section(data.address() + 8, data.index())
            .expect("libtinfo names its variables, so .data has an object in it");
        assert_eq!(
            unit.bytes.len() as u64,
            next - data.address(),
            "{} does not stop at the next symbol in the section",
            unit.name
        );
        assert!(
            next < data.address() + data.size(),
            "the bound is the section's end, so nothing was proved"
        );
    }

    /// A reference that says how many bytes it reads takes only the bytes up
    /// to the end of what it read, and a later reference further into the same
    /// section extends that one copy rather than starting a second: the blob is
    /// anchored at the section and grows forward, so every offset already
    /// resolved against it still means the same byte.
    ///
    /// This is what keeps the pointers past the copy out of the closure, which
    /// is the whole of issue #66: on `libtinfo.so.6`'s `.data.rel.ro` the
    /// section holds 1,500 of them and the first eight bytes hold one.
    #[test]
    fn a_bounded_reference_copies_only_as_far_as_it_reads_and_a_later_one_extends_it() {
        let lib = test_lib("libtinfo.so.6");
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let sec = elf.section_by_name(".data.rel.ro").expect(".data.rel.ro");
        let (sec_addr, sec_size) = (sec.address(), sec.size());

        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        };
        let blob_at = |addr: u64, access_len: Option<u64>, state: &mut ExtractionState| {
            ensure_data_blob_extracted(handle, "a caller", addr, access_len, state)
                .expect("extract the blob")
                .expect("the address is in an extractable section")
        };
        let blob_len = |id: UnitId, state: &ExtractionState| {
            state
                .units
                .iter()
                .find(|u| u.id == id)
                .expect("the blob unit")
                .bytes
                .len() as u64
        };

        let (blob, base) = blob_at(sec_addr, Some(8), &mut state);
        assert_eq!(base, sec_addr);
        assert_eq!(
            blob_len(blob, &state),
            8,
            "an eight-byte read copied more than the eight bytes it reads"
        );
        let first_pointers = state.data_section_copies[0].pointers;

        // A reference the copy already covers neither grows it nor reports a
        // second copy.
        assert_eq!(blob_at(sec_addr + 4, Some(4), &mut state), (blob, base));
        assert_eq!(blob_len(blob, &state), 8);

        // One further in extends the same blob to reach it, and the relocations
        // over the bytes added come with it.
        let (again, base_again) = blob_at(sec_addr + 0x400, Some(8), &mut state);
        assert_eq!(
            (again, base_again),
            (blob, base),
            "extending the copy started a second blob"
        );
        assert_eq!(blob_len(blob, &state), 0x408);
        assert!(sec_size > 0x408, "the fixture's section is too short");

        let copy = state
            .data_section_copies
            .iter()
            .find(|c| c.section == ".data.rel.ro")
            .expect("the .data.rel.ro copy is recorded");
        assert!(
            !copy.is_whole_section() && copy.unbounded_end.is_none(),
            "{copy:?} is bounded by the bytes the reads touch"
        );
        assert_eq!(copy.bytes, 0x408);
        assert_eq!(copy.section_bytes as u64, sec_size);
        assert_eq!(
            copy.address, sec_addr,
            "the first reference is the one named"
        );
        assert!(
            copy.pointers > first_pointers,
            "the pointers over the bytes added were not counted: {copy:?}"
        );

        // The pointers reported are the pointers the blob holds, and the rest
        // of the section's 1,500 are not in the closure at all.
        let unit = state
            .units
            .iter()
            .find(|u| u.id == blob)
            .expect("the blob unit");
        let fixups = state
            .got_slot_fixups
            .iter()
            .filter(|f| f.unit == blob)
            .count();
        assert_eq!(copy.pointers, unit.relocations.len() + fixups);
    }

    /// A copy is built anchored at its section's first byte so that a later
    /// reference can extend it without moving it, and gives the run below the
    /// lowest reference back once the closure is complete and nothing will be
    /// resolved against it again.
    ///
    /// That run was the whole of what `test/md5sum` still merged. `MD5_Init`'s
    /// one reference into a stripped `libcrypto.so.3`'s `.rodata` is a
    /// sixteen-byte `movdqa` of the MD5 seed 198,544 bytes into the section,
    /// and the copy was all 198,560 bytes up to the end of it.
    #[test]
    fn a_copied_section_gives_back_the_run_below_its_first_reference() {
        let lib = test_lib("libcrypto.so.3");
        let mut state = test_state();
        let key = key_in(&mut state, &lib, "MD5_Init");
        reserve_and_extract(&key, &mut state).expect("extract MD5_Init");

        let blob = state
            .units
            .iter()
            .find(|u| u.name.ends_with(":.rodata"))
            .expect("MD5_Init's constant is in a .rodata copy");
        let (blob_id, alignment) = (blob.id, blob.alignment);
        let before = blob.bytes.clone();
        let reference = |state: &ExtractionState| {
            let offsets: Vec<u64> = state
                .units
                .iter()
                .flat_map(|u| &u.relocations)
                .filter_map(|r| match r.target {
                    RelocTarget::DataBlobOffset(id, off) if id == blob_id => Some(off),
                    _ => None,
                })
                .collect();
            let [offset] = offsets[..] else {
                panic!("expected the one reference into the copy, got {offsets:?}");
            };
            offset
        };
        let referenced = reference(&state);
        assert!(
            referenced > 100_000 && before.len() as u64 == referenced + 16,
            "fixture moved: a {} byte copy for a reference at {referenced:#x}",
            before.len()
        );

        trim_unreferenced_prefixes(&mut state);

        let moved = reference(&state);
        let unit = state
            .units
            .iter()
            .find(|u| u.id == blob_id)
            .expect("the .rodata copy");
        // The sixteen bytes the merged code reads are the sixteen bytes it read
        // before, and they are still aligned the way they were copied.
        assert_eq!(
            unit.bytes[moved as usize..moved as usize + 16],
            before[referenced as usize..referenced as usize + 16]
        );
        assert_eq!(
            (referenced - moved) % alignment,
            0,
            "the copy moved by {} bytes, which is not a multiple of its \
             {alignment}-byte alignment",
            referenced - moved
        );
        assert!(
            moved < alignment && unit.bytes.len() as u64 <= alignment + 16,
            "the copy kept {} bytes for a reference at {moved:#x}",
            unit.bytes.len()
        );
        assert!(
            unit.name.ends_with(&format!("+{:#x}", referenced - moved)),
            "{} does not say where it starts",
            unit.name
        );

        // And the report says what it now costs: a copy that is the bytes the
        // merged code reads, plus the padding that keeps them aligned, is not
        // worth a warning any more.
        let [copy] = &state.data_section_copies[..] else {
            panic!("expected the one copy: {:?}", state.data_section_copies);
        };
        assert_eq!(
            (copy.start_offset as u64, copy.bytes as u64),
            (referenced - moved, unit.bytes.len() as u64)
        );
        assert_eq!(copy.unreferenced_prefix as u64, moved);
        assert!(!copy.is_whole_section() && !copy.is_oversized(), "{copy:?}");
    }

    /// Where a data copy's pointers are, as offsets from its base: its own
    /// relocations and the GOT slots the loader has to write into it.
    fn blob_pointers(state: &ExtractionState, id: UnitId) -> Vec<u64> {
        let unit = state.units.iter().find(|u| u.id == id).expect("the blob");
        let mut offsets: Vec<u64> = unit
            .relocations
            .iter()
            .map(|r| r.offset_within_unit)
            .chain(
                state
                    .got_slot_fixups
                    .iter()
                    .filter(|f| f.unit == id)
                    .map(|f| f.offset),
            )
            .collect();
        offsets.sort_unstable();
        offsets
    }

    /// Check that every byte the copy keeps whose value the loader wrote is
    /// written by the merged binary too: for each dynamic relocation of the
    /// library inside the copy's extent there is a relocation or a GOT fixup at
    /// the matching offset. A pointer a copy keeps but does not resolve holds
    /// the library's own load-time VA, which addresses unmapped memory once the
    /// library is dropped from `DT_NEEDED` — and that is the one way skipping a
    /// pointer below a reference could go wrong.
    fn assert_no_stale_pointers(
        state: &ExtractionState,
        elf: &object::read::elf::ElfFile64<'_>,
        id: UnitId,
        start_vaddr: u64,
    ) {
        let unit = state.units.iter().find(|u| u.id == id).expect("the blob");
        let held = start_vaddr..start_vaddr + unit.bytes.len() as u64;
        let resolved: FastSet<u64> = blob_pointers(state, id).into_iter().collect();
        for (roff, _) in elf.dynamic_relocations().expect("dynamic relocations") {
            assert!(
                !held.contains(&roff) || resolved.contains(&(roff - start_vaddr)),
                "{}: the pointer at {roff:#x} is kept but left at its library VA",
                unit.name
            );
        }
    }

    /// A copy roots no pointer below the reference that reached into it. The
    /// run underneath is one [`trim_unreferenced_prefixes`] gives back, so a
    /// pointer down there names an extraction nothing in the merged binary can
    /// reach — and resolving it would pin the run it sits in, since a
    /// relocation describes bytes the copy has to keep.
    ///
    /// That is what used to stop the trim at exactly the sections it would help
    /// most: `libtinfo.so.6`'s `.data.rel.ro` is 12,168 bytes of pointers, and
    /// a reference 0x800 bytes in rooted every one of them and then had to keep
    /// every byte below itself for them (issue #66). A GOT slice is already
    /// exactly the slot it was asked for and must not move at all.
    #[test]
    fn a_copy_roots_no_pointer_below_the_reference_that_reached_into_it() {
        const REFERENCE: u64 = 0x800;

        let lib = test_lib("libtinfo.so.6");
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let sec = elf.section_by_name(".data.rel.ro").expect(".data.rel.ro");
        let sec_addr = sec.address();

        // What the copy is being let off: the pointers the section holds below
        // the reference, every one of them a root into the rest of the library.
        let below = elf
            .dynamic_relocations()
            .expect("dynamic relocations")
            .filter(|(roff, _)| (sec_addr..sec_addr + REFERENCE).contains(roff))
            .count();
        assert!(
            below > 100,
            "fixture moved: only {below} pointers below {REFERENCE:#x} of .data.rel.ro"
        );

        let mut state = test_state();
        let key = key_in(&mut state, &lib, "_nc_setupterm");
        reserve_and_extract(&key, &mut state).expect("extract _nc_setupterm");
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        };

        // A bounded reference a long way into the section, which is what makes
        // the run below it unreferenced.
        let (blob, base) = ensure_data_blob_extracted(
            handle,
            "the test",
            sec_addr + REFERENCE,
            Some(8),
            &mut state,
        )
        .expect("copy .data.rel.ro")
        .expect(".data.rel.ro is extractable");
        assert_eq!(base, sec_addr);

        let before = blob_pointers(&state, blob);
        assert_eq!(
            before.first().copied(),
            Some(REFERENCE),
            "the copy rooted a pointer below the reference that reached into it"
        );

        // Every GOT slice `_nc_setupterm` made, which the trim has no business
        // touching: a slot is the whole of its blob.
        let slots: Vec<(UnitId, Vec<u64>, usize)> = state
            .data_blobs
            .values()
            .filter(|info| info.report.is_none())
            .map(|info| {
                let unit = state.units.iter().find(|u| u.id == info.id).expect("slot");
                (info.id, blob_pointers(&state, info.id), unit.bytes.len())
            })
            .collect();
        assert!(!slots.is_empty(), "the symbol reads no GOT slot");

        trim_unreferenced_prefixes(&mut state);

        // Nothing is left below the reference to keep, so the copy is the eight
        // bytes the reference reads and the pointer in them moves with it.
        let unit = state
            .units
            .iter()
            .find(|u| u.id == blob)
            .expect("the .data.rel.ro copy");
        assert_eq!(unit.bytes.len(), 8);
        assert_eq!(blob_pointers(&state, blob), vec![0]);
        let section = find_section_for_address(&elf, sec_addr).expect("the section");
        let contents = section_contents(&elf, &section).expect("contents");
        assert_eq!(
            unit.bytes[..],
            contents[REFERENCE as usize..REFERENCE as usize + 8],
            "the copy does not hold the bytes the reference reads"
        );
        assert_no_stale_pointers(&state, &elf, blob, sec_addr + REFERENCE);

        let copy = state
            .data_section_copies
            .iter()
            .find(|c| c.section == ".data.rel.ro")
            .expect("the .data.rel.ro copy is recorded");
        assert_eq!(
            (copy.start_offset as u64, copy.bytes, copy.pointers),
            (REFERENCE, 8, 1)
        );
        assert!(
            !copy.is_oversized(),
            "a copy that is the bytes the reference reads is not worth a line: {copy:?}"
        );

        for (id, offsets, len) in slots {
            assert_eq!(
                blob_pointers(&state, id),
                offsets,
                "a GOT slot's pointer moved"
            );
            assert_eq!(
                state
                    .units
                    .iter()
                    .find(|u| u.id == id)
                    .expect("slot")
                    .bytes
                    .len(),
                len,
                "a GOT slot was trimmed"
            );
        }
    }

    /// A reference lower than every reference before it turns the pointers in
    /// the run it exposes from pointers the copy was going to give back into
    /// pointers it has to keep — so that run's relocations are collected when
    /// it is exposed, not left behind because the copy already reached over
    /// them.
    ///
    /// Missing them is the one way skipping the run below a reference could
    /// corrupt a merge: the bytes stay, and every pointer in them keeps the
    /// library's own load-time VA. The order is not hypothetical — `test/grep`
    /// reaches `libpcre2-8.so.0`'s `.data` 0x40 bytes in before it reaches its
    /// first byte, with three of the section's nine pointers in between.
    #[test]
    fn a_lower_reference_roots_the_pointers_in_the_run_it_exposes() {
        const FIRST: u64 = 0x800;

        let lib = test_lib("libtinfo.so.6");
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let sec_addr = elf
            .section_by_name(".data.rel.ro")
            .expect(".data.rel.ro")
            .address();

        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        };
        let blob_at = |addr: u64, state: &mut ExtractionState| {
            ensure_data_blob_extracted(handle, "the test", addr, Some(8), state)
                .expect("copy .data.rel.ro")
                .expect(".data.rel.ro is extractable")
                .0
        };

        let blob = blob_at(sec_addr + FIRST, &mut state);
        let reached_over = blob_pointers(&state, blob);
        assert_eq!(reached_over, vec![FIRST], "the run was not skipped");

        // The lower reference: everything from here up is kept now, pointers
        // included.
        assert_eq!(blob_at(sec_addr, &mut state), blob);
        let exposed = blob_pointers(&state, blob);
        assert!(
            exposed.len() > 100 && exposed.contains(&0) && exposed.ends_with(&reached_over),
            "the exposed run's pointers were not rooted: {} pointers up to {:?}",
            exposed.len(),
            exposed.last()
        );

        trim_unreferenced_prefixes(&mut state);
        assert_eq!(
            blob_pointers(&state, blob),
            exposed,
            "a copy referenced at its first byte has nothing to give back"
        );
        assert_no_stale_pointers(&state, &elf, blob, sec_addr);
    }

    /// An unnamed object between two the library *does* name is bounded above
    /// by the one over it: two distinct objects do not overlap, so an object
    /// with no symbol of its own cannot run into the address a symbol gives.
    /// That is the only end bound available for a reference that says nothing
    /// about the size of what it points at, and it is the one
    /// [`infer_symbol_size`] already puts on a symbol whose size the tables
    /// leave at zero.
    ///
    /// It is what `test/bash` costs: `libtinfo.so.6` pads between the nine
    /// tables it exports from `.data.rel.ro`, a pointer slot reaches into one
    /// of those gaps, and the copy used to run from there to the end of the
    /// section — 8,136 bytes rooting 1,003 pointers for a few unnamed words
    /// (issue #66).
    #[test]
    fn an_unnamed_object_is_bounded_by_the_next_symbol_in_its_section() {
        let lib = test_lib("libtinfo.so.6");
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let sec = elf.section_by_name(".data.rel.ro").expect(".data.rel.ro");
        let (sec_addr, sec_size, sec_index) = (sec.address(), sec.size(), sec.index());

        // The first byte of padding between two of the library's exported
        // tables: no symbol covers it, so a reference to it has to fall back on
        // the section's symbols for an end.
        let mut named: Vec<(u64, u64)> = elf
            .dynamic_symbols()
            .filter(|s| s.section_index() == Some(sec_index) && s.size() > 0)
            .map(|s| (s.address(), s.size()))
            .collect();
        named.sort_unstable();
        let gap = named
            .windows(2)
            .find_map(|w| (w[0].0 + w[0].1 < w[1].0).then_some(w[0].0 + w[0].1))
            .expect("fixture moved: libtinfo pads between its exported tables");

        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        };
        let (blob, base) = ensure_data_blob_extracted(handle, "the test", gap, None, &mut state)
            .expect("copy .data.rel.ro")
            .expect(".data.rel.ro is extractable");
        assert_eq!(base, sec_addr, "the copy is still anchored at the section");

        // The copy reaches the next symbol and stops there, rather than at the
        // section's end.
        let next = index
            .next_object_in_section(gap, sec_index)
            .expect("an object above the gap");
        assert!(
            gap < next && next < sec_addr + sec_size,
            "the gap at {gap:#x} is not between two symbols of a {sec_size}-byte section"
        );
        let blob_len = |state: &ExtractionState| {
            state
                .units
                .iter()
                .find(|u| u.id == blob)
                .expect("the .data.rel.ro copy")
                .bytes
                .len() as u64
        };
        assert_eq!(blob_len(&state), next - sec_addr);

        // And the run below the reference goes back as it does for a bounded
        // one, leaving the unnamed object itself plus its alignment padding.
        trim_unreferenced_prefixes(&mut state);
        assert!(
            blob_len(&state) <= next - gap + DATA_BLOB_ALIGNMENT,
            "the copy kept {} bytes for the {} unnamed ones at {gap:#x}",
            blob_len(&state),
            next - gap
        );

        // The pointers that buys: the section holds over a thousand, and what
        // the merge now has to make valid is the handful inside the copy.
        let in_section = elf
            .dynamic_relocations()
            .expect("dynamic relocations")
            .filter(|(roff, _)| (sec_addr..sec_addr + sec_size).contains(roff))
            .count();
        let rooted = blob_pointers(&state, blob).len();
        assert!(
            in_section > 1_000 && rooted * 100 < in_section,
            "{rooted} of the section's {in_section} pointers are still rooted"
        );

        let copy = state
            .data_section_copies
            .iter()
            .find(|c| c.section == ".data.rel.ro")
            .expect("the .data.rel.ro copy is recorded");
        assert!(
            copy.unbounded_end.is_some() && !copy.is_whole_section(),
            "a copy bounded by the next symbol is still a copy no reference \
             bounded: {copy:?}"
        );
        assert_no_stale_pointers(&state, &elf, blob, sec_addr + copy.start_offset as u64);
    }

    /// A zero-size symbol is a boundary marker rather than the start of an
    /// object, so it is no evidence that an unnamed object below it ends there
    /// and the copy has to reach the next object the library gives a size.
    /// Cutting at a marker is the one way bounding by the symbol table could
    /// truncate a live object; `resolve_owning_unit` declines to let such a
    /// symbol own an address for the same reason.
    #[test]
    fn a_zero_size_symbol_does_not_bound_a_copy() {
        const MARKER: &str = "numcodes";

        /// The object the copy stopped at, and how long it came out, for the
        /// unnamed padding immediately below `MARKER` in `.data.rel.ro`.
        fn bound_below_the_marker(path: &std::path::Path) -> (u64, u64) {
            let bytes = std::fs::read(path).expect("read the library");
            let elf = parse_lib(&bytes);
            let sec = elf.section_by_name(".data.rel.ro").expect(".data.rel.ro");
            let marker = elf
                .dynamic_symbols()
                .find(|s| s.name() == Ok(MARKER))
                .unwrap_or_else(|| panic!("libtinfo.so.6 has no {MARKER}"))
                .address();

            let mut state = test_state();
            let lib_id = state.lib_id(path);
            let index = state.lib_index(lib_id, &elf);
            let handle = Lib {
                id: lib_id,
                path,
                elf: &elf,
                index: &index,
            };
            let gap = marker - POINTER_SIZE;
            let (blob, base) =
                ensure_data_blob_extracted(handle, "the test", gap, None, &mut state)
                    .expect("copy .data.rel.ro")
                    .expect(".data.rel.ro is extractable");
            assert_eq!(base, sec.address());
            let len = state
                .units
                .iter()
                .find(|u| u.id == blob)
                .expect("the .data.rel.ro copy")
                .bytes
                .len() as u64;
            let next = index
                .next_object_in_section(gap, sec.index())
                .expect("an object above the gap");
            assert_eq!(len, next - sec.address(), "the copy overran its bound");
            (next, len)
        }

        let (next, len) = bound_below_the_marker(&test_lib("libtinfo.so.6"));
        let marker = next;

        // The same library with that object's size zeroed: the marker no longer
        // says anything ends there, so the bound is whatever the library sizes
        // above it.
        let doctored = lib_with_symbol_size(MARKER, 0);
        let (past, longer) = bound_below_the_marker(doctored.path());
        assert!(
            past > marker && longer > len,
            "a zero-size symbol at {marker:#x} bounded the copy at {longer} bytes \
             as if it owned something"
        );
    }

    /// The whole of issue #66, held to the closure it is about: the three MD5
    /// entry points `test/md5sum` imports, plus the constructors and
    /// destructors every merged library brings with it, against a stripped
    /// 6.5 MB `libcrypto.so.3`.
    ///
    /// What those three functions actually reach is about 3K of code. What used
    /// to come out was 10,218 units and 4.5 MB — 91% of the library's `.text`,
    /// the ASN.1 item accessors included — because the destructor glue's
    /// unnamed references into `.data` and `.bss` copied both sections whole,
    /// and `.data`'s 553 pointers then copied `.data.rel.ro`, whose 24,342
    /// reached the rest of the library.
    #[test]
    fn the_md5_entry_points_do_not_reach_the_rest_of_libcrypto() {
        let lib = test_lib("libcrypto.so.3");
        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let index = state.lib_index(lib_id, &elf);

        for sym in ["MD5_Init", "MD5_Update", "MD5_Final"] {
            let key = key_in(&mut state, &lib, sym);
            state.reserve(key);
        }
        let arrays = extract_init_fini_arrays(Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        })
        .expect("the library's init/fini arrays");
        let roots: Vec<String> = arrays
            .init_entries
            .iter()
            .chain(&arrays.fini_entries)
            .map(|e| e.unit_name.clone())
            .collect();
        assert!(
            !roots.is_empty(),
            "the fixture has no constructors or destructors to root the closure"
        );
        for name in roots {
            let key = key_in(&mut state, &lib, &name);
            state.reserve(key);
        }
        while let Some((key, id)) = state.worklist.pop_front() {
            process_symbol(&key, id, &mut state).expect("extract the closure");
        }
        trim_unreferenced_prefixes(&mut state);

        let extracted: usize = state.units.iter().map(|u| u.bytes.len()).sum();
        assert!(
            state.units.len() < 50 && extracted < 10_000,
            "the closure is {} units and {extracted} bytes; the sections copied \
             were {:?}",
            state.units.len(),
            state
                .data_section_copies
                .iter()
                .map(|c| (
                    c.section.as_str(),
                    c.bytes,
                    c.pointers,
                    c.reached_from.as_str()
                ))
                .collect::<Vec<_>>()
        );
        assert!(
            !state
                .data_section_copies
                .iter()
                .any(|c| c.section == ".data.rel.ro"),
            "`.data.rel.ro` is still being copied: {:?}",
            state.data_section_copies
        );
    }

    /// A pointer slot holding its own address needs nothing of its section
    /// beyond the slot, and an address at or past the end of a section's
    /// contents needs nothing at all — the two unnamed objects the CRT leaves
    /// in every shared library's `.data`, and between them the reason three MD5
    /// entry points used to merge to most of `libcrypto.so.3`.
    #[test]
    fn a_self_referential_slot_and_a_section_end_marker_bound_themselves() {
        let lib = test_lib("libcrypto.so.3");
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let data = elf.section_by_name(".data").expect(".data");
        let (data_addr, data_size) = (data.address(), data.size());

        // `__dso_handle` is the first word of `.data` and holds its own
        // address, which is the whole of what the fixture has to show for this
        // to be the rule being tested and not a coincidence.
        let self_pointer = elf
            .dynamic_relocations()
            .expect("dynamic relocations")
            .any(|(roff, reloc)| roff == data_addr && reloc.addend() as u64 == data_addr);
        assert!(
            self_pointer,
            "the fixture's .data does not start with a self-referential pointer"
        );
        assert_eq!(pointee_len(data_addr, data_addr), Some(8));
        assert_eq!(pointee_len(data_addr, data_addr + 8), None);

        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        };

        // An eight-byte load of `__dso_handle` — what the destructor glue does
        // with it — copies the eight bytes, and resolving the self-reference
        // inside them does not take the rest of the section with it.
        let (blob, base) =
            ensure_data_blob_extracted(handle, "the glue", data_addr, Some(8), &mut state)
                .expect("copy .data")
                .expect(".data is extractable");
        assert_eq!(base, data_addr);
        let unit = state
            .units
            .iter()
            .find(|u| u.id == blob)
            .expect("the .data blob");
        assert_eq!(
            unit.bytes.len(),
            8,
            "the self-referential first word took {} bytes of .data with it",
            unit.bytes.len()
        );
        assert!(
            unit.relocations.iter().any(|r| matches!(
                r.target,
                RelocTarget::DataBlobOffset(id, 0) if id == blob
            )),
            "the self-reference was not retargeted at the blob: {:?}",
            unit.relocations
        );

        // The end marker sits one past the last byte of `.data`, resolves to
        // this same blob, and asks for nothing: there is nothing there.
        let marker = data_addr + data_size;
        assert_eq!(
            ensure_data_blob_extracted(handle, "the glue", marker, None, &mut state)
                .expect("resolve the marker")
                .expect("the marker is attributed to .data"),
            (blob, base)
        );
        assert_eq!(
            state
                .units
                .iter()
                .find(|u| u.id == blob)
                .expect("the .data blob")
                .bytes
                .len(),
            8,
            "an end marker copied the section it marks the end of"
        );

        let [copy] = &state.data_section_copies[..] else {
            panic!(
                "expected the one .data copy: {:?}",
                state.data_section_copies
            );
        };
        assert!(!copy.is_whole_section());
        assert_eq!((copy.bytes, copy.section_bytes as u64), (8, data_size));
    }

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

    /// A copy whose end comes from [`needed_prefix`]'s fallback rather than
    /// from what the merged code reads is the only step of the merge with no
    /// bound of its own, and the pointers it roots are what turn a handful of
    /// imported symbols into most of a library (issue #66). Each such copy is
    /// recorded with the section, what it cost and what reached into it; a GOT
    /// slice is exactly bounded and is not one of them.
    #[test]
    fn a_section_copied_for_want_of_a_bound_is_recorded_and_a_got_slot_is_not() {
        let lib = test_lib("libtinfo.so.6");
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let got = elf.section_by_name(".got").expect(".got");
        let data = elf.section_by_name(".data").expect(".data");

        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        };

        // A GOT slot is sliced, so nothing is reported for it.
        ensure_data_blob_extracted(handle, "a caller", got.address(), None, &mut state)
            .expect("slice the GOT")
            .expect("the slot is extractable");
        assert!(
            state.data_section_copies.is_empty(),
            "a sliced GOT slot was reported as a whole-section copy: {:?}",
            state.data_section_copies
        );

        let addr = data.address() + 8;
        let (blob, _) = ensure_data_blob_extracted(handle, "a caller", addr, None, &mut state)
            .expect("copy .data")
            .expect(".data is extractable");

        let [copy] = &state.data_section_copies[..] else {
            panic!(
                "expected the one .data copy, got {:?}",
                state.data_section_copies
            );
        };
        assert_eq!(copy.library, lib);
        assert_eq!(copy.section, ".data");
        assert_eq!(copy.address, addr, "the copy names the address asked about");
        assert_eq!(copy.reached_from, "a caller");

        // The cost reported is the cost paid: the bytes the blob holds, and
        // every pointer in it — whether the merge resolved it to a unit of its
        // own or left it for ld.so to fill in.
        let unit = state
            .units
            .iter()
            .find(|u| u.id == blob)
            .expect("the .data blob");
        assert_eq!(copy.bytes, unit.bytes.len());
        assert!(
            copy.is_oversized(),
            "a reference that says nothing about what it points at is the case \
             this report exists for: {copy:?}"
        );
        assert_eq!(
            copy.unbounded_end
                .as_ref()
                .map(|u| (u.address, u.reached_from.as_str())),
            Some((addr, "a caller")),
            "the only reference so far is the unbounded one: {copy:?}"
        );
        let fixups = state
            .got_slot_fixups
            .iter()
            .filter(|f| f.unit == blob)
            .count();
        assert_eq!(copy.pointers, unit.relocations.len() + fixups);
        assert!(copy.pointers > 0, "libtinfo's .data holds pointers");
        let bytes_copied = copy.bytes;

        // A read that reaches exactly as far as the copy already does bounds
        // its end after all, and the line goes away: the bytes it holds are
        // bytes the merged code reads, whatever first asked for them.
        let last = data.address() + bytes_copied as u64 - 8;
        ensure_data_blob_extracted(handle, "a caller", last, Some(8), &mut state)
            .expect("read the last word of the copy")
            .expect(".data is extractable");
        let [copy] = &state.data_section_copies[..] else {
            panic!(
                "a second copy was reported: {:?}",
                state.data_section_copies
            );
        };
        assert_eq!(copy.bytes, bytes_copied, "the read extended the copy");
        assert!(
            copy.unbounded_end.is_none() && !copy.is_oversized(),
            "the copy is the bytes the merged code reads: {copy:?}"
        );
    }

    /// The reference that *creates* a copy and the reference that decides how
    /// far it runs are routinely different ones, and the warning is about the
    /// second: it says nothing bounds the object and that the reference says
    /// nothing about its size either. Naming the first one instead said that
    /// of a reference whose size is right there in the instruction — on
    /// `test/bash` the 1,104 bytes taken out of `libtinfo.so.6`'s `.bss` were
    /// blamed on a one-byte read of its first byte, which asks for one byte,
    /// while the reference 1,084 bytes further in that actually cost them went
    /// unnamed. Reading that warning to decide what to do about issue #66 sends
    /// you to the wrong instruction in the wrong function.
    #[test]
    fn a_copy_names_the_reference_its_end_comes_from_not_the_one_that_began_it() {
        let lib = test_lib("libtinfo.so.6");
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let sec = elf.section_by_name(".data").expect(".data");
        let (sec_addr, sec_size, sec_index) = (sec.address(), sec.size(), sec.index());

        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        };

        // Where an unbounded reference's fallback can land: the start of each
        // object the library both names and sizes in the section, taken from
        // the index rather than re-derived, so the test asks the same question
        // `needed_prefix` does.
        let mut objects = Vec::new();
        let mut at = sec_addr;
        while let Some(next) = index.next_object_in_section(at, sec_index) {
            if next >= sec_addr + sec_size {
                break;
            }
            objects.push(next);
            at = next;
        }
        let [first, second, .., last] = objects[..] else {
            panic!("fixture moved: libtinfo's .data names fewer than three objects");
        };
        // `first` reaches less far than `second`, and `last` has nothing above
        // it, so its fallback is the section's end.
        assert!(
            index.next_object_in_section(last, sec_index).is_none(),
            "fixture moved: libtinfo's .data names something above {last:#x}"
        );

        // A bounded read of the section's first word is what opens the copy.
        ensure_data_blob_extracted(handle, "the read", sec_addr, Some(8), &mut state)
            .expect("copy .data")
            .expect(".data is extractable");
        let copy = |state: &ExtractionState| state.data_section_copies[0].clone();
        assert_eq!(
            (copy(&state).address, copy(&state).reached_from),
            (sec_addr, "the read".to_owned())
        );
        assert!(
            copy(&state).unbounded_end.is_none(),
            "a read of eight bytes says how many it reads: {:?}",
            copy(&state)
        );

        // An unbounded one further in takes the copy to the next object the
        // library names, and is the reference the end now comes from. What
        // opened the copy is untouched: that is a different question, and the
        // other branch of the warning is the one that asks it.
        ensure_data_blob_extracted(handle, "the lea", second, None, &mut state)
            .expect("extend .data")
            .expect(".data is extractable");
        let reported = |state: &ExtractionState| {
            copy(state)
                .unbounded_end
                .map(|u| (u.address, u.reached_from))
        };
        assert_eq!(reported(&state), Some((second, "the lea".to_owned())));
        assert_eq!(
            (copy(&state).address, copy(&state).reached_from),
            (sec_addr, "the read".to_owned()),
            "the reference that opened the copy was overwritten"
        );

        // A second unbounded reference that reaches less far costs nothing, so
        // it does not take the record: the furthest one holds it, not the
        // latest.
        ensure_data_blob_extracted(handle, "a nearer lea", first, None, &mut state)
            .expect("extend .data")
            .expect(".data is extractable");
        assert_eq!(reported(&state), Some((second, "the lea".to_owned())));

        // A read reaching exactly as far justifies the end after all, and the
        // copy stops being one with no bound.
        let bounded_to = copy(&state).bytes as u64;
        ensure_data_blob_extracted(
            handle,
            "a longer read",
            sec_addr + bounded_to - 8,
            Some(8),
            &mut state,
        )
        .expect("read to the copy's end")
        .expect(".data is extractable");
        assert_eq!(reported(&state), None, "{:?}", copy(&state));

        // And an unbounded reference past that read takes it back, naming
        // itself: it is past every earlier fallback too, which is why the
        // record can be dropped above without losing the one that held it.
        ensure_data_blob_extracted(handle, "the last lea", last, None, &mut state)
            .expect("extend .data")
            .expect(".data is extractable");
        assert_eq!(reported(&state), Some((last, "the last lea".to_owned())));
        assert!(
            copy(&state).is_whole_section(),
            "nothing above the last named object bounds the copy: {:?}",
            copy(&state)
        );
    }

    /// A section reached through another copied section's pointers is recorded
    /// after it, and names it — so the records read as the chain they are
    /// rather than inside out. That chain is the whole diagnosis: on
    /// `test/md5sum` the three MD5 entry points reach none of the four million
    /// bytes extracted, a symbol-less destructor helper touches `.data`, and
    /// `.data`'s pointers are what bring in `.data.rel.ro`.
    #[test]
    fn a_section_reached_through_another_is_recorded_after_it() {
        let lib = test_lib("libtinfo.so.6");
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let rel_ro = elf
            .section_by_name(".data.rel.ro")
            .expect(".data.rel.ro")
            .address();

        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        let handle = Lib {
            id: lib_id,
            path: &lib,
            elf: &elf,
            index: &index,
        };
        ensure_data_blob_extracted(handle, "a caller", rel_ro, None, &mut state)
            .expect("copy .data.rel.ro")
            .expect(".data.rel.ro is extractable");

        let copies = &state.data_section_copies;
        assert_eq!(
            copies
                .first()
                .map(|c| (c.section.as_str(), c.reached_from.as_str())),
            Some((".data.rel.ro", "a caller")),
            "the section asked about is not the first one reported: {copies:?}"
        );
        let chained = copies
            .iter()
            .filter(|c| c.reached_from == ".data.rel.ro")
            .count();
        assert!(
            chained > 0,
            "`.data.rel.ro`'s 1,500 pointers reached no further section: {copies:?}"
        );
        for (i, copy) in copies.iter().enumerate() {
            if let Some(parent) = copies.iter().position(|c| c.section == copy.reached_from) {
                assert!(
                    parent < i,
                    "{copy:?} is reported before the section it was reached through"
                );
            }
        }
    }

    /// The copy is attributed to the unit that was being extracted when the
    /// reference into the section was found, which is the whole point of
    /// recording it: `.data.rel.ro` turning up in the report is only
    /// actionable once it says which symbol reached in there.
    #[test]
    fn a_section_merged_whole_names_the_symbol_that_reached_into_it() {
        let lib = test_lib("libtinfo.so.6");
        let mut state = test_state();
        let key = key_in(&mut state, &lib, "_nc_setupterm");
        reserve_and_extract(&key, &mut state).expect("extract _nc_setupterm");

        let direct: Vec<&str> = state
            .data_section_copies
            .iter()
            .filter(|c| c.reached_from == "_nc_setupterm")
            .map(|c| c.section.as_str())
            .collect();
        assert!(
            !direct.is_empty(),
            "no copy was attributed to the symbol that caused it: {:?}",
            state.data_section_copies
        );

        // Nothing else was extracted, so every copy is either one this symbol
        // asked for or one reached through another copied section's pointers —
        // never unattributed, and never a GOT, which is sliced.
        for copy in &state.data_section_copies {
            assert!(!copy.reached_from.is_empty(), "{copy:?} has no context");
            assert!(
                !matches!(copy.section.as_str(), ".got" | ".got.plt"),
                "a GOT was copied whole: {copy:?}"
            );
        }
    }

    /// A reference out of one unit into another is resolved the moment it is
    /// found, against an id reserved for a unit that does not exist yet — so
    /// what every such reference has to name is the unit the closure goes on to
    /// build for that key, and nothing else.
    ///
    /// `pcre2_config_8` exercises both halves of that in one symbol. Its two
    /// switch tables live in a `.rodata` blob whose entries have to branch back
    /// into `pcre2_config_8` itself, which is only reachable through the id the
    /// function reserved before its own extraction began; and the functions it
    /// calls are reserved as the scan finds them and extracted afterwards.
    #[test]
    fn every_reference_into_the_closure_names_the_unit_that_was_built_for_it() {
        let lib = test_lib("libpcre2-8.so.0");
        let mut state = test_state();
        let lib_id = state.lib_id(&lib);
        state.reserve(UnitKey {
            lib: lib_id,
            sym: "pcre2_config_8".to_string(),
        });
        while let Some((key, id)) = state.worklist.pop_front() {
            if key.lib != lib_id {
                continue; // another merged library, outside this test
            }
            process_symbol(&key, id, &mut state)
                .unwrap_or_else(|e| panic!("extracting '{}': {e:#}", key.sym));
        }

        let by_id: HashMap<UnitId, &ExtractedUnit> =
            state.units.iter().map(|u| (u.id, u)).collect();
        let mut refs = 0;
        for unit in &state.units {
            for reloc in &unit.relocations {
                let RelocTarget::MergedUnit(target) = reloc.target else {
                    continue;
                };
                refs += 1;
                let target = by_id.get(&target).unwrap_or_else(|| {
                    panic!(
                        "'{}' points at UnitId({}), which no unit was built for",
                        unit.name, target.0
                    )
                });
                let target_lib = state.lib_ids[target.source_lib.as_path()];
                assert_eq!(
                    state.reserved.get(&UnitKey {
                        lib: target_lib,
                        sym: target.name.clone(),
                    }),
                    Some(&target.id),
                    "'{}' in '{}' is not the unit its key reserved",
                    target.name,
                    unit.name
                );
            }
        }
        assert!(
            state.units.len() > 5 && refs > 25,
            "expected a real closure, found {} units and {refs} references",
            state.units.len()
        );

        // The jump-table entries are the references whose target is the unit
        // being extracted when they are recorded. Both tables are 16 entries.
        let owner = state
            .units
            .iter()
            .find(|u| u.name == "pcre2_config_8")
            .expect("pcre2_config_8 unit")
            .id;
        let entries = state
            .units
            .iter()
            .filter(|u| u.name.ends_with(":.rodata"))
            .flat_map(|u| &u.relocations)
            .filter(|r| matches!(r.target, RelocTarget::MergedUnit(id) if id == owner))
            .count();
        assert_eq!(entries, 32, "the switch tables lost their entries");
    }

    /// Two jump tables can overlap in `.rodata`, and each is found again by
    /// the function that branches through it, so the blob holding both is
    /// offered the shared entries twice. The second offer has to be refused:
    /// an entry with two relocations over its four bytes is patched twice, and
    /// whichever function relocated last takes the branch for both.
    ///
    /// `libpcre2-8.so.0` has the case. Two symbol-less helpers at `0x63d0` and
    /// `0x6070` switch through tables at `0x7e8a4` and `0x7e6c8`, which run
    /// into each other, and both tables land in the one `.rodata` blob.
    #[test]
    fn an_entry_two_overlapping_jump_tables_share_is_relocated_once() {
        let path = test_lib("libpcre2-8.so.0");
        let mut state = test_state();
        let mut owners = Vec::new();
        for addr in [0x63d0u64, 0x6070] {
            let key = key_in(&mut state, &path, &anon_unit_name(addr));
            let id = state.reserve(key.clone());
            process_symbol(&key, id, &mut state)
                .unwrap_or_else(|e| panic!("extracting the helper at {addr:#x}: {e:#}"));
            owners.push(id);
        }

        let blob = state
            .units
            .iter()
            .find(|u| u.name.ends_with(":.rodata"))
            .expect("the switch tables pull in a .rodata blob");

        // Both helpers put entries in it, or the overlap under test never
        // happened and the assertion below would pass on nothing.
        for (addr, owner) in [0x63d0u64, 0x6070].iter().zip(&owners) {
            assert!(
                blob.relocations
                    .iter()
                    .any(|r| matches!(r.target, RelocTarget::MergedUnit(id) if id == *owner)),
                "the table of the helper at {addr:#x} left no entry in {}",
                blob.name
            );
        }

        let mut seen: FastSet<u64> = FastSet::default();
        for reloc in &blob.relocations {
            assert!(
                seen.insert(reloc.offset_within_unit),
                "{} carries two relocations over offset {}",
                blob.name,
                reloc.offset_within_unit
            );
        }
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

    /// The constants hand-written assembly keeps in `.text` are not code, and
    /// a unit's byte range runs from its function's entry to the next bound —
    /// so it covers them. Decoding them produced relocations, extraction
    /// dependencies and short-branch veneers out of a string constant.
    ///
    /// `libcrypto.so.3` has one at 0x20db00: an FDE covers 0x20db00..0x20db63,
    /// the next starts at 0x20dbb0, and the 0x4d bytes in between are the
    /// `"X25519 primitives for x86_64, CRYPTOGAMS by <appro@openssl.org>"`
    /// banner. Decoded as instructions it yielded seven rel8 branches needing
    /// veneers and a `xor dh, [rip+0x20393135]` pointing 0x20 MiB outside the
    /// library. The bytes still have to be copied — the unit is the merged
    /// binary's only copy of them — but nothing in them is a reference.
    #[test]
    fn constants_embedded_in_text_are_copied_but_not_decoded() {
        const FUNC: u64 = 0x20db00;
        const FUNC_END: u64 = 0x20db63;

        let lib = test_lib("libcrypto.so.3");
        let mut state = test_state();
        let bytes = std::fs::read(&lib).expect("read library");
        let elf = parse_lib(&bytes);
        let lib_id = state.lib_id(&lib);
        let index = state.lib_index(lib_id, &elf);
        assert_eq!(
            index.fdes.containing(FUNC),
            Some((FUNC, FUNC_END)),
            "fixture moved: no FDE for the X25519 primitive"
        );

        let key = UnitKey {
            lib: lib_id,
            sym: anon_unit_name(FUNC),
        };
        reserve_and_extract(&key, &mut state).expect("extract the X25519 primitive");
        let unit = state.units.last().expect("the extracted unit");

        let code_len = (FUNC_END - FUNC) as usize;
        assert!(
            unit.bytes.len() > code_len,
            "fixture moved: the unit stops at the function's last instruction"
        );
        for reloc in &unit.relocations {
            assert!(
                reloc.offset_within_unit < code_len as u64,
                "relocation at {:#x} was decoded out of the banner string",
                reloc.offset_within_unit
            );
        }
    }
}
