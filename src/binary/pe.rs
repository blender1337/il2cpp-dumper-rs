use anyhow::Result;
use goblin::pe::header::{COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use goblin::pe::section_table::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ};
use goblin::pe::PE;

use super::{BinaryImage, SectionRange};

pub fn extract_meta(pe: &PE) -> Result<(bool, String, u64, Vec<SectionRange>)> {
    let image_base = pe.image_base as u64;
    let arch = match pe.header.coff_header.machine {
        COFF_MACHINE_X86_64 => "x86_64".to_string(),
        COFF_MACHINE_X86 => "x86".to_string(),
        COFF_MACHINE_ARM64 => "arm64".to_string(),
        other => format!("pe_machine_{:#x}", other),
    };

    let mut sections = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let name = s.name().unwrap_or("").to_string();
        let va_start = image_base + s.virtual_address as u64;
        let vsize = (s.virtual_size.max(s.size_of_raw_data)) as u64;
        let va_end = va_start + vsize;
        let is_exec = (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_data = !is_exec
            && (s.characteristics & IMAGE_SCN_MEM_READ) != 0
            && (s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
        sections.push(SectionRange {
            name,
            va_start,
            va_end,
            file_offset: s.pointer_to_raw_data as usize,
            file_size: s.size_of_raw_data as usize,
            is_exec,
            is_data,
        });
    }

    Ok((pe.is_64, arch, image_base, sections))
}

fn is_valid_data_va(bin: &BinaryImage, va: u64) -> bool {
    bin.sections
        .iter()
        .any(|s| s.is_data && va >= s.va_start && va < s.va_end)
}

fn is_valid_exec_va(bin: &BinaryImage, va: u64) -> bool {
    bin.sections
        .iter()
        .any(|s| s.is_exec && va >= s.va_start && va < s.va_end)
}

/// Inspect x86_64 `.CRT$XCU` / `.rdata` initializer functions for `LEA RCX` (`code_reg`) + `LEA RDX` (`meta_reg`).
pub fn trace_pe_registration(bin: &BinaryImage) -> Option<(u64, u64)> {
    if !bin.is_64bit || bin.arch != "x86_64" {
        return None;
    }
    let ptr_sz = 8usize;

    // Prioritize .CRT* / .rdata sections first
    let mut ordered_secs: Vec<&SectionRange> = bin
        .sections
        .iter()
        .filter(|s| s.is_data && (s.name.starts_with(".CRT") || s.name == ".rdata"))
        .collect();
    for s in &bin.sections {
        if s.is_data && !ordered_secs.iter().any(|o| o.va_start == s.va_start) {
            ordered_secs.push(s);
        }
    }

    for s in ordered_secs {
        let start = s.file_offset;
        let end = (s.file_offset + s.file_size).min(bin.bytes.len());
        let mut off = start;
        while off + ptr_sz <= end {
            let fn_va = u64::from_le_bytes(bin.bytes[off..off + 8].try_into().ok()?);
            if is_valid_exec_va(bin, fn_va) {
                if let Some(code) = bin.read_bytes(fn_va, 96) {
                    let mut rcx_target = None;
                    let mut rdx_target = None;
                    let mut i = 0usize;
                    while i + 7 <= code.len() {
                        if code[i] == 0xC3 {
                            break;
                        }
                        if code[i] == 0x48 && code[i + 1] == 0x8D {
                            let modrm = code[i + 2];
                            let disp = i32::from_le_bytes([
                                code[i + 3],
                                code[i + 4],
                                code[i + 5],
                                code[i + 6],
                            ]);
                            let next_ip = fn_va + (i + 7) as u64;
                            let target = (next_ip as i64).wrapping_add(disp as i64) as u64;
                            if modrm == 0x0D {
                                rcx_target = Some(target);
                            } else if modrm == 0x15 {
                                rdx_target = Some(target);
                            }
                            i += 7;
                            continue;
                        }
                        i += 1;
                    }
                    if let (Some(cr), Some(mr)) = (rcx_target, rdx_target) {
                        if is_valid_data_va(bin, cr) && is_valid_data_va(bin, mr) {
                            let pl = bin.read_ptr(cr).unwrap_or(u64::MAX);
                            if pl < 500_000 {
                                return Some((cr, mr));
                            }
                        }
                    }
                }
            }
            off += ptr_sz;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::BinaryFormat;

    #[test]
    fn test_trace_pe_registration_x64_crt() {
        // Virtual PE layout: image_base = 0x1_8000_0000
        // .text  @ VA 0x1_8000_1000 (file_off 0x000, size 0x100)
        // .CRT   @ VA 0x1_8000_2000 (file_off 0x100, size 0x100)
        // .rdata @ VA 0x1_8000_3000 (file_off 0x200, size 0x100)
        let base = 0x1_8000_0000u64;
        let mut mem = vec![0u8; 0x300];

        // Function @ VA 0x1_8000_1000:
        //   +0..+7: LEA RCX, [rip + disp] -> cr = 0x1_8000_3000 (next_ip = 0x1_8000_1007 => disp = 0x1FF9)
        //   +7..+14: LEA RDX, [rip + disp] -> mr = 0x1_8000_3080 (next_ip = 0x1_8000_100E => disp = 0x2072)
        //   +14: C3 (RET)
        mem[0..3].copy_from_slice(&[0x48, 0x8D, 0x0D]);
        mem[3..7].copy_from_slice(&(0x1FF9i32).to_le_bytes());
        mem[7..10].copy_from_slice(&[0x48, 0x8D, 0x15]);
        mem[10..14].copy_from_slice(&(0x2072i32).to_le_bytes());
        mem[14] = 0xC3;

        // Pointer in .CRT$XCU @ offset 0x108 -> fn_va = 0x1_8000_1000
        mem[0x108..0x110].copy_from_slice(&(base + 0x1000).to_le_bytes());
        // code_reg @ 0x1_8000_3000: plausible count = 123
        mem[0x200..0x208].copy_from_slice(&123u64.to_le_bytes());

        let bin = BinaryImage {
            bytes: mem,
            format: BinaryFormat::Pe,
            is_64bit: true,
            arch: "x86_64".into(),
            image_base: base,
            sections: vec![
                SectionRange {
                    name: ".text".into(),
                    va_start: base + 0x1000,
                    va_end: base + 0x1100,
                    file_offset: 0x000,
                    file_size: 0x100,
                    is_exec: true,
                    is_data: false,
                },
                SectionRange {
                    name: ".CRT$XCU".into(),
                    va_start: base + 0x2000,
                    va_end: base + 0x2100,
                    file_offset: 0x100,
                    file_size: 0x100,
                    is_exec: false,
                    is_data: true,
                },
                SectionRange {
                    name: ".rdata".into(),
                    va_start: base + 0x3000,
                    va_end: base + 0x3100,
                    file_offset: 0x200,
                    file_size: 0x100,
                    is_exec: false,
                    is_data: true,
                },
            ],
            relocs: Vec::new(),
            is_memory_dump: false,
            fairplay_encrypted: false,
        };

        assert_eq!(
            trace_pe_registration(&bin),
            Some((base + 0x3000, base + 0x3080))
        );
    }
}
