use std::path::PathBuf;

/// A constructor/destructor function pointer from a library's init/fini array.
#[derive(Debug, Clone)]
pub struct InitFiniEntry {
    /// Path to the library this entry came from.
    pub _source_lib: PathBuf,
    /// Original virtual address of the function in the library.
    pub _func_vaddr: u64,
}

/// Extracted init/fini arrays from merged libraries.
#[derive(Debug, Clone, Default)]
pub struct InitFiniArrays {
    pub init_entries: Vec<InitFiniEntry>,
    pub fini_entries: Vec<InitFiniEntry>,
}

/// Info about the executable's existing init/fini arrays.
#[derive(Debug, Clone, Default)]
pub struct ExeInitFiniInfo {
    pub init_array_vaddr: Option<u64>,
    pub init_array_size: u64,
    pub fini_array_vaddr: Option<u64>,
    pub fini_array_size: u64,
}

/// Plan for init/fini array extension.
#[derive(Debug, Clone)]
pub struct InitFiniPlan {
    /// VA of the new combined init_array in the merged segment.
    pub combined_init_vaddr: u64,
    /// Function VAs to write (exe entries first, then merged entries in dependency order).
    pub combined_init_entries: Vec<u64>,
    /// VA of the new combined fini_array in the merged segment.
    pub combined_fini_vaddr: u64,
    /// Function VAs (merged entries in reverse dependency order, then exe entries).
    pub combined_fini_entries: Vec<u64>,
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

/// A chunk of code or data extracted from a shared library.
#[derive(Debug, Clone)]
pub struct ExtractedUnit {
    pub id: UnitId,
    pub name: String,
    pub source_lib: PathBuf,
    pub size: usize,
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
    /// Base virtual address of the new PT_LOAD segment.
    pub load_address: u64,
    pub text_units: Vec<AssignedUnit>,
    pub rodata_units: Vec<AssignedUnit>,
    pub data_units: Vec<AssignedUnit>,
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
    /// R_X86_64_RELATIVE relocations to add for PIE executables.
    pub relative_relocs: Vec<RelativeReloc>,
    /// Symbols the merged libraries reference but the executable doesn't import.
    /// Each gets a new `.dynsym` entry, a fresh GOT slot in the merged segment,
    /// and a `GLOB_DAT` relocation so the dynamic loader resolves it at startup.
    pub new_externals: Vec<NewExternalSym>,
    /// Plan for extending init/fini arrays with merged library constructors/destructors.
    pub init_fini: Option<InitFiniPlan>,
}

impl MergePlan {
    /// Total size in bytes of the merged segment (all units + trampolines + init/fini arrays).
    pub fn segment_size(&self) -> usize {
        let mut sz = 0usize;
        for u in self
            .text_units
            .iter()
            .chain(&self.rodata_units)
            .chain(&self.data_units)
        {
            let end = (u.assigned_vaddr - self.load_address) as usize + u.unit.size;
            if end > sz {
                sz = end;
            }
        }
        // Trampolines come after, each 14 bytes
        for t in &self.trampoline_stubs {
            let end = (t.vaddr - self.load_address) as usize + 14;
            if end > sz {
                sz = end;
            }
        }
        // Init/fini arrays come after trampolines, each entry is 8 bytes
        if let Some(ref init_fini) = self.init_fini {
            if !init_fini.combined_init_entries.is_empty() {
                let end = (init_fini.combined_init_vaddr - self.load_address) as usize
                    + init_fini.combined_init_entries.len() * 8;
                if end > sz {
                    sz = end;
                }
            }
            if !init_fini.combined_fini_entries.is_empty() {
                let end = (init_fini.combined_fini_vaddr - self.load_address) as usize
                    + init_fini.combined_fini_entries.len() * 8;
                if end > sz {
                    sz = end;
                }
            }
        }
        // New GOT slots for injected external symbols, 8 bytes each.
        for ext in &self.new_externals {
            let end = (ext.got_vaddr - self.load_address) as usize + 8;
            if end > sz {
                sz = end;
            }
        }
        sz
    }

    /// Iterate all assigned units across all section kinds.
    pub fn all_units(&self) -> impl Iterator<Item = &AssignedUnit> {
        self.text_units
            .iter()
            .chain(&self.rodata_units)
            .chain(&self.data_units)
    }

    /// Iterate all assigned units mutably.
    pub fn all_units_mut(&mut self) -> impl Iterator<Item = &mut AssignedUnit> {
        self.text_units
            .iter_mut()
            .chain(&mut self.rodata_units)
            .chain(&mut self.data_units)
    }
}
