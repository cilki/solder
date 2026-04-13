use std::path::PathBuf;

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
    /// The value to write (the resolved virtual address of the merged symbol).
    pub value: u64,
}

/// The complete merge plan produced after layout, ready for relocation application and output.
#[derive(Debug)]
pub struct MergePlan {
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
    /// DT_NEEDED string values to remove from the dynamic section.
    pub remove_needed: Vec<String>,
}

impl MergePlan {
    /// Total size in bytes of the merged segment (all units + trampolines).
    pub fn segment_size(&self) -> usize {
        let mut sz = 0usize;
        for u in self.text_units.iter().chain(&self.rodata_units).chain(&self.data_units) {
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
        sz
    }

    /// Iterate all assigned units across all section kinds.
    pub fn all_units(&self) -> impl Iterator<Item = &AssignedUnit> {
        self.text_units.iter().chain(&self.rodata_units).chain(&self.data_units)
    }

    /// Iterate all assigned units mutably.
    pub fn all_units_mut(&mut self) -> impl Iterator<Item = &mut AssignedUnit> {
        self.text_units.iter_mut().chain(&mut self.rodata_units).chain(&mut self.data_units)
    }

}
