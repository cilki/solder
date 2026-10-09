use std::path::PathBuf;

/// A constructor/destructor function pointer from a library's init/fini array.
#[derive(Debug, Clone)]
pub struct InitFiniEntry {
    /// Path to the library this entry came from.
    pub source_lib: PathBuf,
    /// Name of the extracted unit holding the constructor/destructor function.
    pub unit_name: String,
}

/// Extracted init/fini arrays from merged libraries.
#[derive(Debug, Clone, Default)]
pub struct InitFiniArrays {
    pub init_entries: Vec<InitFiniEntry>,
    pub fini_entries: Vec<InitFiniEntry>,
}

/// Plan for running merged library constructors/destructors.
///
/// Constructor timing is subtle: glibc runs shared library constructors in
/// `_dl_init`, then `__libc_start_main` registers `_dl_fini` with
/// `__cxa_atexit`, and only then runs the executable's own init_array. C++
/// static destructors are registered via `__cxa_atexit` *by the constructors*,
/// so their position relative to `_dl_fini` in the exit-handler LIFO depends
/// on which phase the constructor ran in. Merged library constructors
/// therefore go into DT_PREINIT_ARRAY — which `_dl_init` processes before
/// `_dl_fini` is registered — reproducing the dynamic-linking destructor
/// order exactly. The executable's own init_array is left untouched.
///
/// Merged destructors are appended in front of the executable's fini_array
/// entries (ld.so runs DT_FINI_ARRAY backward, so the executable's entries
/// still run first, then each merged library's, dependents before
/// dependencies).
#[derive(Debug, Clone)]
pub struct InitFiniPlan {
    /// The preinit array. Entries: the exe's existing preinit entries first,
    /// then merged library constructors in dependency order. Empty when no
    /// library constructors are merged.
    pub preinit: MergedArray,
    /// The combined fini_array. Entries: merged library destructors in
    /// dependency order (original array order within each library), then the
    /// exe's original entries. Empty when no library destructors are merged.
    pub fini: MergedArray,
}

impl InitFiniPlan {
    /// Both arrays, each tagged with which one it is. Laying an array out,
    /// writing its pointers into the merged segment and repointing `.dynamic`
    /// at it is the same work either way, so each of those is done once over
    /// this list instead of once per array.
    pub fn arrays(&self) -> [(InitFiniKind, &MergedArray); 2] {
        [
            (InitFiniKind::Preinit, &self.preinit),
            (InitFiniKind::Fini, &self.fini),
        ]
    }
}

/// Which of an [`InitFiniPlan`]'s two arrays a [`MergedArray`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitFiniKind {
    Preinit,
    Fini,
}

impl InitFiniKind {
    /// The `DT_*` pair giving the array's address and its size in bytes. The
    /// same pair is read out of the executable (for the entries the merge has
    /// to keep running) and written back (pointing at the rebuilt array), so
    /// it is spelled out once here.
    pub fn dynamic_tags(self) -> (u64, u64) {
        use goblin::elf::dynamic::{
            DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ,
        };
        match self {
            Self::Preinit => (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ),
            Self::Fini => (DT_FINI_ARRAY, DT_FINI_ARRAYSZ),
        }
    }

    /// How the array is named in diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::Preinit => "preinit array",
            Self::Fini => "fini array",
        }
    }
}

/// A function-pointer array laid out in the merged segment.
#[derive(Debug, Clone)]
pub struct MergedArray {
    /// VA of the array in the merged segment.
    pub vaddr: u64,
    /// The function pointers, in the order the loader will read them.
    pub entries: Vec<u64>,
}

impl MergedArray {
    /// Size in bytes, for the matching `DT_*_ARRAYSZ`.
    pub fn size(&self) -> u64 {
        (self.entries.len() * 8) as u64
    }
}

/// A runtime relocation (R_X86_64_RELATIVE) to be added to .rela.dyn for PIE executables.
/// At runtime, ld.so computes: `*(vaddr + load_base) = load_base + addend`
#[derive(Debug, Clone)]
pub struct RelativeReloc {
    /// Virtual address (offset from load base) of the 8-byte slot to fix up.
    pub vaddr: u64,
    /// The addend value (the offset-based address already stored at the location).
    pub addend: i64,
}

/// A newly-injected external symbol — one that the merged libraries reference
/// but the original executable did not. Solder appends a new entry to a copy
/// of `.dynsym`/`.dynstr`/`.gnu.version` placed in the merged segment, adds a
/// `GLOB_DAT` relocation pointing at a fresh GOT slot (also in the merged
/// segment), and routes the trampoline for `name` through that slot.
#[derive(Debug, Clone)]
pub struct NewExternalSym {
    pub name: String,
    /// VA of the 8-byte GOT slot in the merged segment.
    pub got_vaddr: u64,
}

/// Stable identifier for an extracted unit across pipeline stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnitId(pub u32);

/// A GOT slot copied into the merged segment (inside a data blob) whose value
/// must be resolved by the dynamic loader at startup, exactly as it was for
/// the original library: the resolved symbol address, or 0 for an unresolved
/// weak symbol. Trampoline addresses are NOT a substitute — code null-checks
/// these slots (e.g. `register_tm_clones` testing `_ITM_registerTMCloneTable`).
///
/// Recorded during extraction as (unit, offset); layout converts it to a
/// `GotSlotImport` once the blob has an assigned VA.
#[derive(Debug, Clone)]
pub struct GotSlotFixup {
    pub unit: UnitId,
    pub offset: u64,
    pub name: String,
    /// Whether the symbol is weak in the source library. Preserved on the
    /// injected .dynsym entry so ld.so tolerates it staying unresolved.
    pub weak: bool,
}

/// A resolved `GotSlotFixup`: the writer emits an R_X86_64_GLOB_DAT at
/// `got_vaddr` against `name` (reusing the executable's .dynsym entry when one
/// exists, otherwise injecting one).
#[derive(Debug, Clone)]
pub struct GotSlotImport {
    pub got_vaddr: u64,
    pub name: String,
    pub weak: bool,
}

/// How a symbol is imported into the executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// Via PLT stub — R_X86_64_JUMP_SLOT relocation
    JumpSlot,
    /// Direct GOT reference — R_X86_64_GLOB_DAT relocation
    GlobDat,
}

/// A symbol that the executable imports from a shared library.
#[derive(Debug, Clone)]
pub struct ImportedSymbol {
    pub name: String,
    /// Resolved path to the library that defines this symbol.
    pub source_library: PathBuf,
    /// File offset of the 8-byte GOT slot for this symbol.
    pub got_file_offset: u64,
    pub kind: ImportKind,
}

/// Which kind of section a unit came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Text,
    ReadOnlyData,
    Data,
}

/// Target of a relocation within an extracted unit.
#[derive(Debug, Clone)]
pub enum RelocTarget {
    /// Another unit that is being merged into the executable.
    /// The UnitId is initially a placeholder (u32::MAX) during extraction,
    /// resolved in a second pass.
    MergedUnit(UnitId),
    /// A symbol that stays external (e.g. a glibc function).
    /// At runtime, calls go through a trampoline stub in the merged segment.
    External(String),
    /// A raw virtual address within a data blob (used for RIP-relative data references).
    /// The tuple is (blob_id, offset_within_blob).
    DataBlobOffset(UnitId, u64),
}

/// A relocation entry within an extracted unit's byte range.
#[derive(Debug, Clone)]
pub struct ExtractedReloc {
    /// Byte offset within `ExtractedUnit::bytes` where the patch is applied.
    pub offset_within_unit: u64,
    pub kind: object::RelocationKind,
    pub encoding: object::RelocationEncoding,
    /// Width of the value to write, in bits (typically 32 or 64).
    pub size: u8,
    pub addend: i64,
    pub target: RelocTarget,
}

impl ExtractedReloc {
    /// Whether this is a 64-bit absolute patch site. The value written there is
    /// a VA inside the output image, so under PIE the dynamic loader has to
    /// rebase it at startup — which both adds an `R_X86_64_RELATIVE` entry and
    /// requires the containing page to be writable while it does so.
    ///
    /// (`Unknown` covers the GLOB_DAT/RELATIVE entries lifted from a library's
    /// own `.rela.dyn`, which the relocator treats as absolute.)
    pub fn is_absolute64(&self) -> bool {
        self.size == 64
            && matches!(
                self.kind,
                object::RelocationKind::Absolute | object::RelocationKind::Unknown
            )
    }
}

/// A chunk of code or data extracted from a shared library.
#[derive(Debug, Clone)]
pub struct ExtractedUnit {
    pub id: UnitId,
    pub name: String,
    pub source_lib: PathBuf,
    /// The unit's contents; `bytes.len()` is the space it occupies in the
    /// merged segment.
    pub bytes: Vec<u8>,
    pub section_kind: SectionKind,
    /// Required alignment in bytes.
    pub alignment: u64,
    pub relocations: Vec<ExtractedReloc>,
}

/// An extracted unit with its assigned virtual address in the merged segment.
#[derive(Debug)]
pub struct AssignedUnit {
    pub unit: ExtractedUnit,
    /// Virtual address in the output executable where this unit will live.
    pub assigned_vaddr: u64,
}

/// A 14-byte trampoline stub: `jmp [rip+0]` followed by an 8-byte absolute address.
/// Used so that merged library code can call external (e.g. glibc) symbols via
/// the executable's existing GOT entries.
#[derive(Debug, Clone)]
pub struct TrampolineStub {
    pub symbol_name: String,
    /// VA of this stub in the merged segment.
    pub vaddr: u64,
    /// VA of the target GOT slot in the (unchanged) executable GOT.
    pub target_got_vaddr: u64,
}

/// A patch to apply to the executable's GOT.
#[derive(Debug, Clone)]
pub struct GotPatch {
    /// File offset of the 8-byte GOT slot.
    pub got_file_offset: u64,
    /// Virtual address of the GOT slot (for PIE relative reloc generation).
    pub got_vaddr: u64,
    /// The value to write (the resolved virtual address of the merged symbol).
    pub value: u64,
}

/// The complete merge plan produced after layout, ready for relocation application and output.
#[derive(Debug)]
pub struct MergePlan {
    /// Whether the executable is PIE (ET_DYN).
    pub is_pie: bool,
    /// Base virtual address of the new PT_LOAD segments.
    pub load_address: u64,
    /// Size of the leading executable run of the merged segment — the code
    /// units followed by the trampoline stubs — padded up to a page boundary.
    /// Nothing at or past this offset is mapped executable, and nothing before
    /// it is mapped writable, so no page of the merged region is ever both.
    pub exec_size: u64,
    /// Offset at which the read-only run of merged constants ends, padded up to
    /// a page boundary. It starts at `exec_size` and holds the extracted
    /// read-only data nothing writes to at runtime (string literals, jump
    /// tables, lookup tables), which the library itself had mapped read-only.
    /// Equal to `exec_size` when there is no such data.
    pub rodata_end: u64,
    /// Offset at which the writable run of the merged segment ends, padded up
    /// to a page boundary. It starts at `rodata_end` and covers the data units,
    /// the read-only data the dynamic loader still has to rebase, the GOT slots
    /// it fills in, and the init/fini arrays. The writer appends the rebuilt
    /// `.dynstr`/`.dynsym`/`.gnu.version`/`.rela.dyn` and the new program
    /// header table after it, in a read-only mapping.
    pub writable_end: u64,
    /// Every extracted unit with the address it was assigned, in layout order:
    /// the code units, then the merged constants, then everything the dynamic
    /// loader writes to.
    ///
    /// Which run a unit ended up in is a fact about its address — compare it
    /// against `exec_size`, `rodata_end` and `writable_end` — and a unit's
    /// origin is `AssignedUnit::unit`'s own `section_kind`. Neither is a
    /// reason to hold the units in more than one list.
    pub units: Vec<AssignedUnit>,
    /// One stub per unique External symbol referenced by merged code.
    pub trampoline_stubs: Vec<TrampolineStub>,
    /// GOT entries in the executable to patch with merged symbol addresses.
    pub got_patches: Vec<GotPatch>,
    /// JUMP_SLOT relocation file offsets to zero out (r_info + r_addend fields).
    pub jump_slot_reloc_offsets: Vec<u64>,
    /// R_X86_64_COPY relocation file offsets to zero out. Copy relocations for
    /// data symbols provided by a fully-merged library (e.g. ncurses' UP/PC/BC)
    /// must be neutralized, or ld.so fails to resolve the now-absent symbol.
    pub copy_reloc_offsets: Vec<u64>,
    /// DT_NEEDED string values to remove from the dynamic section.
    pub remove_needed: Vec<String>,
    /// Sonames to add to DT_NEEDED: dependencies of the merged-away libraries
    /// that still provide symbols the extracted code references. See
    /// `symbol_analysis::inherited_needed`.
    pub add_needed: Vec<String>,
    /// R_X86_64_RELATIVE relocations to add for PIE executables.
    pub relative_relocs: Vec<RelativeReloc>,
    /// Symbols the merged libraries reference but the executable doesn't import.
    /// Each gets a new `.dynsym` entry, a fresh GOT slot in the merged segment,
    /// and a `GLOB_DAT` relocation so the dynamic loader resolves it at startup.
    pub new_externals: Vec<NewExternalSym>,
    /// Copied GOT slots that must be re-resolved by ld.so at startup.
    pub got_imports: Vec<GotSlotImport>,
    /// Plan for extending init/fini arrays with merged library constructors/destructors.
    pub init_fini: Option<InitFiniPlan>,
}

impl MergePlan {
    /// Total size in bytes of the merged segment as laid out: every unit,
    /// trampoline, injected GOT slot and init/fini array, plus the page
    /// padding that separates the executable, read-only and writable runs.
    pub fn segment_size(&self) -> usize {
        self.writable_end as usize
    }
}
