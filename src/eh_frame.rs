//! Function boundaries recovered from `.eh_frame`.
//!
//! Extraction needs to know where the function that owns a given address
//! starts and ends. The symbol tables answer that only for symbols that have a
//! size, which in a stripped (or merely `-fvisibility=hidden`) library covers a
//! fraction of the code: everything else had to be bounded by "the next symbol
//! in the section", which over-extends a unit across dozens of unrelated
//! functions.
//!
//! Every function compiled with unwind information has an FDE in `.eh_frame`
//! giving its exact `[start, start + length)`, regardless of whether a symbol
//! survived. This module parses that table once per library.
//!
//! Only the two FDE header fields are decoded; the CFI instructions that make
//! up the rest of an entry are skipped. The format is the one described by the
//! LSB core spec (`.eh_frame` is a variant of DWARF's `.debug_frame`).

use std::collections::HashMap;

/// `DW_EH_PE_omit`: the pointer is not present.
const DW_EH_PE_OMIT: u8 = 0xff;
/// `DW_EH_PE_absptr`: native-width absolute pointer. Also the encoding to
/// assume when a CIE carries no `R` augmentation.
const DW_EH_PE_ABSPTR: u8 = 0x00;

/// The function address ranges of one library, sorted by start address and
/// guaranteed not to overlap.
#[derive(Debug, Default)]
pub struct FdeTable {
    ranges: Vec<(u64, u64)>,
}

impl FdeTable {
    /// Parse the `.eh_frame` section `data` loaded at `section_vaddr`.
    ///
    /// Unwind tables are self-describing but also easy to get wrong, and a
    /// library with an unparsable (or absent) one must still be mergeable: a
    /// malformed entry is skipped and a malformed *length* ends the walk, so
    /// the worst case is an empty or partial table and a fall back to
    /// symbol-table bounds.
    pub fn parse(data: &[u8], section_vaddr: u64) -> FdeTable {
        // CIE start offset → the `R` (FDE pointer) encoding it declares.
        let mut cie_encodings: HashMap<usize, u8> = HashMap::new();
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut pos = 0usize;

        while pos + 4 <= data.len() {
            let entry_start = pos;
            let mut r = Reader::at(data, pos);
            // A 32-bit length of 0xffffffff introduces the 64-bit format, in
            // which the real length and the CIE id/pointer are both 8 bytes.
            let Some(len32) = r.u32() else { break };
            let (len, id_width) = if len32 == 0xffff_ffff {
                match r.u64() {
                    Some(len) => (len, 8usize),
                    None => break,
                }
            } else {
                (u64::from(len32), 4usize)
            };
            if len == 0 {
                break; // terminator
            }
            let body_start = r.pos;
            let Some(body_end) = body_start
                .checked_add(len as usize)
                .filter(|&end| end <= data.len())
            else {
                break;
            };
            pos = body_end;

            let Some(id) = (if id_width == 4 {
                r.u32().map(u64::from)
            } else {
                r.u64()
            }) else {
                continue;
            };

            if id == 0 {
                // A CIE. Its `R` encoding governs every FDE that points back
                // to it, so it has to be decoded before those FDEs are read —
                // which is always the case, as a CIE precedes its FDEs.
                if let Some(enc) = parse_cie_fde_encoding(&mut r) {
                    cie_encodings.insert(entry_start, enc);
                }
                continue;
            }

            // An FDE. `id` is the distance from the CIE pointer field back to
            // the start of the CIE that describes it.
            let Some(cie_start) = body_start.checked_sub(id as usize) else {
                continue;
            };
            let enc = cie_encodings
                .get(&cie_start)
                .copied()
                .unwrap_or(DW_EH_PE_ABSPTR);

            let pc = section_vaddr + r.pos as u64;
            let Some(start) = read_encoded(&mut r, enc, pc) else {
                continue;
            };
            // `address_range` is a length, not an address: it uses the value
            // format of the FDE encoding but is never relative to anything.
            let Some(length) = read_encoded(&mut r, enc & 0x0f, 0) else {
                continue;
            };
            if let Some(end) = start.checked_add(length)
                && length > 0
            {
                ranges.push((start, end));
            }
        }

        // Sorting by (start, end) puts the tightest range for a given start
        // first, which is the conservative one to keep.
        ranges.sort_unstable();
        ranges.dedup_by_key(|&mut (start, _)| start);
        // Clamp any range that runs into its successor. Correct unwind tables
        // never overlap, but the lookups below assume it, so it is enforced
        // rather than trusted.
        for i in 1..ranges.len() {
            let next_start = ranges[i].0;
            if ranges[i - 1].1 > next_start {
                ranges[i - 1].1 = next_start;
            }
        }

        FdeTable { ranges }
    }

    /// The function range containing `addr`, as `(start, end)`.
    pub fn containing(&self, addr: u64) -> Option<(u64, u64)> {
        let idx = self.ranges.partition_point(|&(start, _)| start <= addr);
        let &(start, end) = self.ranges.get(idx.checked_sub(1)?)?;
        (addr >= start && addr < end).then_some((start, end))
    }

    /// The start of the first function range that begins after `addr`.
    ///
    /// An address with no FDE of its own (hand-written assembly, CRT glue) is
    /// still bounded by the next function that does have one.
    pub fn next_start_after(&self, addr: u64) -> Option<u64> {
        let idx = self.ranges.partition_point(|&(start, _)| start <= addr);
        self.ranges.get(idx).map(|&(start, _)| start)
    }

    pub fn fde_count(&self) -> usize {
        self.ranges.len()
    }
}

/// Parse a CIE far enough to recover the `R` augmentation, i.e. the encoding
/// its FDEs use for `initial_location` and `address_range`. Returns `None` for
/// a CIE that is malformed or that uses an augmentation we cannot walk past,
/// which leaves its FDEs out of the table rather than misreading them.
fn parse_cie_fde_encoding(r: &mut Reader<'_>) -> Option<u8> {
    let version = r.u8()?;
    let augmentation = r.cstr()?;
    if version >= 4 {
        r.u8()?; // address_size
        r.u8()?; // segment_selector_size
    }
    r.uleb()?; // code_alignment_factor
    r.sleb()?; // data_alignment_factor
    if version == 1 {
        r.u8()?; // return_address_register
    } else {
        r.uleb()?;
    }

    // Only a `z` augmentation has a length-prefixed data block, and only such a
    // CIE can carry an `R` entry at all.
    if augmentation.first() != Some(&b'z') {
        return Some(DW_EH_PE_ABSPTR);
    }
    r.uleb()?; // augmentation_data length
    let mut encoding = DW_EH_PE_ABSPTR;
    for c in &augmentation[1..] {
        match c {
            b'R' => encoding = r.u8()?,
            b'L' => {
                r.u8()?; // LSDA encoding
            }
            b'P' => {
                let enc = r.u8()?;
                read_encoded(r, enc, 0)?; // personality routine
            }
            // Flags with no augmentation data of their own.
            b'S' | b'B' | b'G' => {}
            // Something undocumented: the rest of the block can no longer be
            // walked, so the encoding cannot be trusted.
            _ => return None,
        }
    }
    Some(encoding)
}

/// Decode one pointer in the `DW_EH_PE_*` scheme. `pc` is the virtual address
/// of the field itself, which `pcrel` encodings are relative to.
fn read_encoded(r: &mut Reader<'_>, encoding: u8, pc: u64) -> Option<u64> {
    if encoding == DW_EH_PE_OMIT {
        return None;
    }
    // DW_EH_PE_indirect: the value is the address of the pointer, which means
    // reading memory that only exists at runtime.
    if encoding & 0x80 != 0 {
        return None;
    }
    let value: i128 = match encoding & 0x0f {
        // absptr is the native word size, i.e. 8 bytes on x86-64.
        0x00 | 0x04 => i128::from(r.u64()?),
        0x01 => i128::from(r.uleb()?),
        0x02 => i128::from(r.u16()?),
        0x03 => i128::from(r.u32()?),
        0x09 => i128::from(r.sleb()?),
        0x0a => i128::from(r.u16()? as i16),
        0x0b => i128::from(r.u32()? as i32),
        0x0c => i128::from(r.u64()? as i64),
        _ => return None,
    };
    let base: i128 = match encoding & 0x70 {
        0x00 => 0,              // absolute
        0x10 => i128::from(pc), // pcrel
        // textrel/datarel/funcrel/aligned need a base this parser does not
        // track; they do not appear in the `R` encoding of a linked object.
        _ => return None,
    };
    Some((base + value) as u64)
}

/// Bounds-checked sequential reader. Every accessor yields `None` at the end of
/// the buffer instead of panicking, so a truncated table degrades to a partial
/// one.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn at(data: &'a [u8], pos: usize) -> Self {
        Reader { data, pos }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= u64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                return Some(result);
            }
            if shift > 70 {
                return None; // runaway encoding
            }
        }
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= i64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift; // sign-extend
                }
                return Some(result);
            }
            if shift > 70 {
                return None;
            }
        }
    }

    /// A NUL-terminated string, returned without its terminator.
    fn cstr(&mut self) -> Option<&'a [u8]> {
        let rest = self.data.get(self.pos..)?;
        let nul = rest.iter().position(|&b| b == 0)?;
        self.pos += nul + 1;
        Some(&rest[..nul])
    }
}

#[cfg(test)]
mod tests {
    use super::FdeTable;

    const SECTION_VADDR: u64 = 0x10000;

    /// Build a `.eh_frame` with one `zR`/pcrel|sdata4 CIE — what gcc and clang
    /// emit for a shared library — followed by one FDE per `(start, length)`.
    fn eh_frame(fdes: &[(u64, u64)]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        // CIE: version 1, augmentation "zR", 1 byte of augmentation data
        // holding DW_EH_PE_pcrel | DW_EH_PE_sdata4.
        let mut cie = Vec::new();
        cie.extend_from_slice(&0u32.to_le_bytes()); // CIE id
        cie.push(1); // version
        cie.extend_from_slice(b"zR\0");
        cie.push(1); // code_alignment_factor (uleb)
        cie.push(0x78); // data_alignment_factor (sleb, -8)
        cie.push(16); // return_address_register
        cie.push(1); // augmentation_data length
        cie.push(0x1b); // pcrel | sdata4
        cie.resize(cie.len().next_multiple_of(4), 0); // CFI padding
        out.extend_from_slice(&(cie.len() as u32).to_le_bytes());
        out.extend_from_slice(&cie);

        for &(start, length) in fdes {
            let cie_pointer = out.len() as u32 + 4; // distance back to the CIE
            let mut fde = Vec::new();
            fde.extend_from_slice(&cie_pointer.to_le_bytes());
            // initial_location, pcrel from the field's own address.
            let field_vaddr = SECTION_VADDR + out.len() as u64 + 4 + 4;
            let rel = start as i64 - field_vaddr as i64;
            fde.extend_from_slice(&(rel as i32).to_le_bytes());
            fde.extend_from_slice(&(length as u32).to_le_bytes());
            fde.resize(fde.len().next_multiple_of(4), 0);
            out.extend_from_slice(&(fde.len() as u32).to_le_bytes());
            out.extend_from_slice(&fde);
        }

        out.extend_from_slice(&0u32.to_le_bytes()); // terminator
        out
    }

    #[test]
    fn recovers_pcrel_function_bounds() {
        let data = eh_frame(&[(0x3280, 0x40), (0x3400, 0x120)]);
        let table = FdeTable::parse(&data, SECTION_VADDR);
        assert_eq!(table.fde_count(), 2);
        assert_eq!(table.containing(0x3280), Some((0x3280, 0x32c0)));
        // The whole point: an address in the middle of a function resolves to
        // the function that owns it, not to a unit of its own.
        assert_eq!(table.containing(0x32bf), Some((0x3280, 0x32c0)));
        assert_eq!(table.containing(0x3410), Some((0x3400, 0x3520)));
    }

    #[test]
    fn addresses_outside_any_fde_are_unknown() {
        let data = eh_frame(&[(0x3280, 0x40)]);
        let table = FdeTable::parse(&data, SECTION_VADDR);
        assert_eq!(table.containing(0x327f), None);
        assert_eq!(table.containing(0x32c0), None); // one past the end
        assert_eq!(table.containing(0), None);
    }

    #[test]
    fn overlapping_fdes_are_clamped() {
        // A bogus table whose first FDE swallows the second.
        let data = eh_frame(&[(0x1000, 0x800), (0x1100, 0x100)]);
        let table = FdeTable::parse(&data, SECTION_VADDR);
        assert_eq!(table.containing(0x1050), Some((0x1000, 0x1100)));
        assert_eq!(table.containing(0x1150), Some((0x1100, 0x1200)));
    }

    #[test]
    fn a_truncated_table_keeps_the_entries_it_could_read() {
        let data = eh_frame(&[(0x3280, 0x40), (0x3400, 0x120)]);
        let table = FdeTable::parse(&data[..data.len() - 12], SECTION_VADDR);
        assert_eq!(table.containing(0x3290), Some((0x3280, 0x32c0)));
    }

    /// The committed `test/libs` libraries are the ones extraction is actually
    /// run against, so the parser is checked against their real unwind tables.
    /// Every exported function with a size in `.dynsym` must have an FDE
    /// starting at exactly its entry, and the next FDE must begin at or after
    /// the end of that function — the property extraction relies on when it
    /// bounds a symbol-less unit by the next FDE.
    #[test]
    fn agrees_with_the_symbol_tables_of_the_real_test_libraries() {
        use object::{Object, ObjectSection, ObjectSymbol};

        for lib in ["libpcre2-8.so.0", "libcrypto.so.3", "libtinfo.so.6"] {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test/libs/").to_string() + lib;
            let bytes = std::fs::read(&path).expect("test library");
            let elf = object::File::parse(&*bytes).expect("parse");
            let section = elf.section_by_name(".eh_frame").expect(".eh_frame");
            let table = FdeTable::parse(section.data().unwrap(), section.address());
            assert!(table.fde_count() > 100, "{lib}: {}", table.fde_count());

            let mut checked = 0;
            for sym in elf.dynamic_symbols() {
                if sym.kind() != object::SymbolKind::Text || sym.size() == 0 || sym.is_undefined() {
                    continue;
                }
                let name = sym.name().unwrap_or("?");
                let (start, end) = table
                    .containing(sym.address())
                    .unwrap_or_else(|| panic!("{lib}: no FDE for {name}"));
                assert_eq!(start, sym.address(), "{lib}: FDE for {name} starts late");
                let sym_end = sym.address() + sym.size();
                assert!(end <= sym_end, "{lib}: FDE for {name} runs past the symbol");
                // An address inside the covered range resolves to the same
                // function, which is what keeps extraction to one unit per
                // function instead of one per referenced address.
                assert_eq!(table.containing(end - 1), Some((start, end)));
                // Bounding a unit at this address by the next FDE can never
                // truncate the function.
                if let Some(next) = table.next_start_after(sym.address()) {
                    assert!(
                        next >= sym_end,
                        "{lib}: FDE after {name} starts inside it ({next:#x} < {sym_end:#x})"
                    );
                }
                checked += 1;
            }
            assert!(checked > 50, "{lib}: only checked {checked} symbols");
        }
    }

    #[test]
    fn no_eh_frame_yields_an_empty_table() {
        assert_eq!(FdeTable::parse(&[], SECTION_VADDR).fde_count(), 0);
        assert_eq!(FdeTable::default().containing(0x1000), None);
        // Garbage must not panic or loop.
        assert_eq!(FdeTable::parse(&[0xff; 64], SECTION_VADDR).fde_count(), 0);
    }
}
