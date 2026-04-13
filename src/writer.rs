use anyhow::{bail, Context, Result};

use crate::layout::align_up;
use crate::types::MergePlan;

/// Build the merged segment bytes (all units + trampoline stubs) in one flat buffer.
///
/// Each unit is placed at its `assigned_vaddr - plan.load_address` offset.
/// Gaps between units are zero-filled.
pub fn build_merged_segment(plan: &MergePlan) -> Result<Vec<u8>> {
    let size = plan.segment_size();
    let mut seg = vec![0u8; size];

    for au in plan.all_units() {
        let off = (au.assigned_vaddr - plan.load_address) as usize;
        let end = off + au.unit.bytes.len();
        if end > seg.len() {
            bail!(
                "unit '{}' at offset 0x{:x} + {} overflows segment of size {}",
                au.unit.name,
                off,
                au.unit.bytes.len(),
                seg.len()
            );
        }
        seg[off..end].copy_from_slice(&au.unit.bytes);
    }

    for stub in &plan.trampoline_stubs {
        let off = (stub.vaddr - plan.load_address) as usize;
        // Write: FF 25 00 00 00 00  (jmp [rip+0])
        //        <8 bytes: target GOT VA>
        // At runtime: [rip+0] = the 8 bytes immediately after this instruction.
        // The RIP after the instruction = stub.vaddr + 6, so:
        //   [rip + 0] = *(stub.vaddr + 6) = target_got_vaddr
        // But this is an *indirect* jump — it reads a 64-bit address from
        // stub.vaddr+6 and jumps to that address.  We store the target GOT *VA*
        // directly (the GOT slot holds the resolved function pointer at runtime).
        //
        // Actually: FF 25 imm32 means jmp QWORD PTR [rip + imm32].
        // The imm32 encodes the offset from (rip after this 6-byte instruction)
        // to the 8-byte target slot.  We place the target slot immediately after
        // the instruction, so imm32 = 0.
        if off + 14 > seg.len() {
            bail!("trampoline for '{}' overflows segment", stub.symbol_name);
        }
        seg[off] = 0xFF;
        seg[off + 1] = 0x25;
        seg[off + 2..off + 6].copy_from_slice(&0u32.to_le_bytes()); // RIP+0
        seg[off + 6..off + 14].copy_from_slice(&stub.target_got_vaddr.to_le_bytes());
    }

    Ok(seg)
}

/// Write the final output ELF file.
///
/// Structure:
///   [patched original ELF bytes]
///   [merged segment bytes]
///   [new program header table (old PHT + new PT_LOAD entry)]
///
/// The ELF header is updated in-place to point e_phoff at the new PHT location.
pub fn write_output(
    patched_exe: &[u8],
    plan: &MergePlan,
    merged_seg: &[u8],
    output_path: &std::path::Path,
) -> Result<()> {
    use object::elf::{PF_R, PF_W, PF_X, PT_LOAD, PT_PHDR};
    use object::read::elf::{ElfFile64, ProgramHeader};

    let exe = ElfFile64::<object::Endianness>::parse(patched_exe)
        .context("parsing patched executable for output")?;
    let endian = exe.endian();

    // Collect existing program headers.
    let old_phdrs: Vec<object::elf::ProgramHeader64<object::Endianness>> =
        exe.elf_program_headers().to_vec();
    let phdr_entry_size = std::mem::size_of::<object::elf::ProgramHeader64<object::Endianness>>();

    // File offset where the merged segment will start.
    let seg_file_offset = patched_exe.len() as u64;
    // Page-align the offset (required by the kernel for PT_LOAD).
    let seg_file_offset = align_up(seg_file_offset, 0x1000);

    // File offset where the new PHT will start (after the merged segment, page-aligned).
    let pht_file_offset = align_up(seg_file_offset + merged_seg.len() as u64, 8);
    let new_phnum = old_phdrs.len() + 1;
    let pht_size = (new_phnum * phdr_entry_size) as u64;

    // Build the output buffer.
    let total_size = pht_file_offset + pht_size;
    let mut out = vec![0u8; total_size as usize];

    // Copy patched exe bytes.
    out[..patched_exe.len()].copy_from_slice(patched_exe);
    // Copy merged segment.
    let seg_start = seg_file_offset as usize;
    let seg_end = seg_start + merged_seg.len();
    out[seg_start..seg_end].copy_from_slice(merged_seg);

    // Build the new PHT.
    let pht_start = pht_file_offset as usize;

    // Copy old entries, updating PT_PHDR if present.
    let mut written = 0usize;
    for phdr in &old_phdrs {
        let p_type = phdr.p_type(endian);
        let entry_bytes: &[u8] = as_bytes(phdr);
        let dst = pht_start + written;
        out[dst..dst + phdr_entry_size].copy_from_slice(entry_bytes);

        // If this is PT_PHDR, update p_offset and p_vaddr to new location.
        if p_type == PT_PHDR {
            // p_offset is at offset 8 in Phdr64 (after p_type + p_flags)
            // Actually layout: p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8) p_filesz(8) p_memsz(8) p_align(8)
            write_u64_le(&mut out, dst + 8, pht_file_offset);
            // p_vaddr: we can't know the mapping VA for the PHT without knowing the
            // load bias. For ET_EXEC, set p_vaddr = p_paddr = 0 (PHT is not mapped
            // as its own segment in typical executables; PT_PHDR is informational).
            // Leave p_vaddr unchanged (it was likely wrong anyway in the original
            // for our purposes).
        }

        written += phdr_entry_size;
    }

    // Write the new PT_LOAD entry for the merged segment.
    // Layout of Elf64_Phdr:
    //   p_type   u32  offset 0
    //   p_flags  u32  offset 4
    //   p_offset u64  offset 8
    //   p_vaddr  u64  offset 16
    //   p_paddr  u64  offset 24
    //   p_filesz u64  offset 32
    //   p_memsz  u64  offset 40
    //   p_align  u64  offset 48
    let dst = pht_start + written;
    write_u32_le(&mut out, dst, PT_LOAD);
    write_u32_le(&mut out, dst + 4, PF_R | PF_W | PF_X); // rwx — MVP
    write_u64_le(&mut out, dst + 8, seg_file_offset);
    write_u64_le(&mut out, dst + 16, plan.load_address);
    write_u64_le(&mut out, dst + 24, plan.load_address); // p_paddr = p_vaddr
    write_u64_le(&mut out, dst + 32, merged_seg.len() as u64);
    write_u64_le(&mut out, dst + 40, merged_seg.len() as u64);
    write_u64_le(&mut out, dst + 48, 0x1000); // p_align = 4 KiB

    // Update ELF header: e_phoff (offset 32 in Elf64 header) and e_phnum (offset 56).
    write_u64_le(&mut out, 32, pht_file_offset);
    write_u16_le(&mut out, 56, new_phnum as u16);

    // Write output file.
    std::fs::write(output_path, &out)
        .with_context(|| format!("writing output {}", output_path.display()))?;

    // Make executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(output_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(output_path, perms)?;
    }

    Ok(())
}

// Helper: view a value as bytes.
fn as_bytes<T: Sized>(val: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>())
    }
}

fn write_u64_le(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn write_u32_le(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u16_le(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}
