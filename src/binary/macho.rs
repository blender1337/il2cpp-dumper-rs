use anyhow::{bail, Result};
use goblin::mach::constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::{Mach, MachO};

use super::{BinaryFormat, SectionRange};

pub type MachOMeta = (
    BinaryFormat,
    bool,
    String,
    u64,
    Vec<SectionRange>,
    Option<(usize, usize)>,
);

/// Extra fixup and encryption metadata parsed from Mach-O load commands.
#[derive(Debug, Default)]
pub struct MachOExtras {
    pub relocs: Vec<(u64, u64)>,
    pub patches: Vec<(usize, u64)>,
    pub fairplay_encrypted: bool,
}

fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let s = bytes.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let s = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let s = bytes.get(off..off + 8)?;
    Some(u64::from_le_bytes(s.try_into().ok()?))
}

/// Decode a `dyld_chained_ptr` entry into `(resolved_rebase_va, next_byte_stride)`.
/// Bind entries return `None` for the VA while preserving the chain walk stride.
pub fn decode_chained_pointer(raw: u64, pointer_format: u16, image_base: u64) -> (Option<u64>, u64) {
    match pointer_format {
        // DYLD_CHAINED_PTR_ARM64E
        1 => {
            let next = ((raw >> 51) & 0x7FF) * 8;
            let bind = (raw >> 62) & 1;
            let auth = (raw >> 63) & 1;
            if bind != 0 {
                return (None, next);
            }
            let va = if auth != 0 {
                image_base.wrapping_add(raw & 0xFFFF_FFFF)
            } else {
                raw & 0x07FF_FFFF_FFFF
            };
            (Some(va), next)
        }
        // DYLD_CHAINED_PTR_64
        2 => {
            let next = ((raw >> 51) & 0xFFF) * 4;
            let bind = (raw >> 63) & 1;
            if bind != 0 {
                return (None, next);
            }
            (Some(raw & 0x000F_FFFF_FFFF), next)
        }
        // DYLD_CHAINED_PTR_64_OFFSET
        6 => {
            let next = ((raw >> 51) & 0xFFF) * 4;
            let bind = (raw >> 63) & 1;
            if bind != 0 {
                return (None, next);
            }
            (Some(image_base.wrapping_add(raw & 0x000F_FFFF_FFFF)), next)
        }
        // DYLD_CHAINED_PTR_ARM64E_USERLAND / DYLD_CHAINED_PTR_ARM64E_USERLAND24
        9 | 12 => {
            let next = ((raw >> 51) & 0x7FF) * 8;
            let bind = (raw >> 62) & 1;
            let auth = (raw >> 63) & 1;
            if bind != 0 {
                return (None, next);
            }
            let va = if auth != 0 {
                image_base.wrapping_add(raw & 0xFFFF_FFFF)
            } else {
                image_base.wrapping_add(raw & 0x0003_FFFF_FFFF)
            };
            (Some(va), next)
        }
        _ => (None, 0),
    }
}

/// Walk `LC_DYLD_CHAINED_FIXUPS` chains and inspect FairPlay encryption status.
pub fn collect_macho_extras(slice: &[u8], macho: &MachO, image_base: u64) -> MachOExtras {
    let mut extras = MachOExtras::default();
    let mut fixups_range: Option<(usize, usize)> = None;

    for lc in &macho.load_commands {
        match &lc.command {
            CommandVariant::EncryptionInfo64(cmd) if cmd.cryptid != 0 => {
                extras.fairplay_encrypted = true;
            }
            CommandVariant::EncryptionInfo32(cmd) if cmd.cryptid != 0 => {
                extras.fairplay_encrypted = true;
            }
            CommandVariant::DyldChainedFixups(cmd) => {
                fixups_range = Some((cmd.dataoff as usize, cmd.datasize as usize));
            }
            _ => {}
        }
    }

    let Some((dataoff, datasize)) = fixups_range else {
        return extras;
    };
    if datasize < 28 || dataoff.saturating_add(datasize) > slice.len() {
        return extras;
    }

    let Some(starts_offset) = read_u32_le(slice, dataoff + 4) else {
        return extras;
    };
    let starts_off = dataoff.saturating_add(starts_offset as usize);
    let Some(seg_count) = read_u32_le(slice, starts_off) else {
        return extras;
    };

    for seg_idx in 0..seg_count as usize {
        let Some(seg_info_rel) = read_u32_le(slice, starts_off + 4 + seg_idx * 4) else {
            break;
        };
        if seg_info_rel == 0 {
            continue;
        }
        let seg_info_off = starts_off.saturating_add(seg_info_rel as usize);
        let Some(page_size) = read_u16_le(slice, seg_info_off + 4) else {
            continue;
        };
        let Some(pointer_format) = read_u16_le(slice, seg_info_off + 6) else {
            continue;
        };
        let Some(page_count) = read_u16_le(slice, seg_info_off + 20) else {
            continue;
        };
        let Some(seg) = macho.segments.get(seg_idx) else {
            continue;
        };
        if page_size < 8 {
            continue;
        }

        let max_steps = (page_size as usize) / 4;
        for p in 0..page_count as usize {
            let Some(page_start) = read_u16_le(slice, seg_info_off + 22 + p * 2) else {
                break;
            };
            if page_start == 0xFFFF || (page_start & 0x8000) != 0 {
                continue;
            }
            let page_file_off = (seg.fileoff as usize).saturating_add(p * page_size as usize);
            let page_va = seg.vmaddr.wrapping_add((p as u64) * (page_size as u64));
            let mut in_page_off = page_start as usize;

            for _ in 0..max_steps {
                if in_page_off + 8 > page_size as usize {
                    break;
                }
                let foff = page_file_off.saturating_add(in_page_off);
                let Some(raw) = read_u64_le(slice, foff) else {
                    break;
                };
                let (resolved, next) = decode_chained_pointer(raw, pointer_format, image_base);
                if let Some(val) = resolved {
                    let va = page_va.wrapping_add(in_page_off as u64);
                    extras.relocs.push((va, val));
                    extras.patches.push((foff, val));
                }
                if next == 0 {
                    break;
                }
                in_page_off = in_page_off.saturating_add(next as usize);
            }
        }
    }

    extras.relocs.sort_unstable_by_key(|&(va, _)| va);
    extras.relocs.dedup_by_key(|r| r.0);
    extras
}

pub fn extract_meta(bytes: &[u8], mach: Mach) -> Result<(MachOMeta, MachOExtras)> {
    match mach {
        Mach::Binary(m) => {
            let (is_64, arch, base, sects) = build_from_single(&m)?;
            let extras = collect_macho_extras(bytes, &m, base);
            Ok(((BinaryFormat::MachO, is_64, arch, base, sects, None), extras))
        }
        Mach::Fat(fat) => {
            let arches = fat.arches()?;
            let picked = arches
                .iter()
                .find(|a| a.cputype() == CPU_TYPE_ARM64 || a.cputype() == CPU_TYPE_X86_64)
                .or_else(|| arches.first());
            let Some(arch_info) = picked else {
                bail!("Empty Mach-O fat binary");
            };
            let offset = arch_info.offset as usize;
            let size = arch_info.size as usize;
            let slice = &bytes[offset..offset + size];
            let sub = MachO::parse(slice, 0)?;
            let (is_64, arch, base, sects) = build_from_single(&sub)?;
            let extras = collect_macho_extras(slice, &sub, base);
            Ok((
                (BinaryFormat::MachO, is_64, arch, base, sects, Some((offset, size))),
                extras,
            ))
        }
    }
}

fn build_from_single(macho: &MachO) -> Result<(bool, String, u64, Vec<SectionRange>)> {
    let arch = match macho.header.cputype() {
        CPU_TYPE_ARM64 => "arm64".to_string(),
        CPU_TYPE_X86_64 => "x86_64".to_string(),
        other => format!("macho_cpu_{:#x}", other),
    };

    let mut image_base = u64::MAX;
    let mut sections = Vec::new();
    for seg in &macho.segments {
        if let Ok(seg_name) = seg.name() {
            if seg_name == "__TEXT" {
                image_base = image_base.min(seg.vmaddr);
            }
        }
        if let Ok(sects) = seg.sections() {
            for (sect, _) in sects {
                let sect_name = sect.name().unwrap_or("").to_string();
                let seg_name = sect.segname().unwrap_or("");
                let full_name = format!("{},{}", seg_name, sect_name);
                let is_exec = seg_name == "__TEXT" && sect_name == "__text";
                let is_data = seg_name.starts_with("__DATA") || sect_name == "__const";
                if sect.size > 0 && sect.offset > 0 {
                    sections.push(SectionRange {
                        name: full_name,
                        va_start: sect.addr,
                        va_end: sect.addr + sect.size,
                        file_offset: sect.offset as usize,
                        file_size: sect.size as usize,
                        is_exec,
                        is_data,
                    });
                }
            }
        }
    }
    if image_base == u64::MAX {
        image_base = 0;
    }

    Ok((macho.is_64, arch, image_base, sections))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_chained_pointer_formats() {
        let base = 0x1_0000_0000u64;
        // Format 6 (DYLD_CHAINED_PTR_64_OFFSET): next=2 (*4=8), bind=0, target=0x123456
        let raw6 = (2u64 << 51) | 0x12_3456u64;
        assert_eq!(decode_chained_pointer(raw6, 6, base), (Some(base + 0x12_3456), 8));
        // Format 6 bind entry (bit 63 = 1)
        let raw6_bind = (1u64 << 63) | (3u64 << 51) | 5;
        assert_eq!(decode_chained_pointer(raw6_bind, 6, base), (None, 12));

        // Format 2 (DYLD_CHAINED_PTR_64): next=1 (*4=4), bind=0, vmaddr=0x100234000
        let raw2 = (1u64 << 51) | 0x1_0023_4000u64;
        assert_eq!(decode_chained_pointer(raw2, 2, base), (Some(0x1_0023_4000), 4));

        // Format 12 (DYLD_CHAINED_PTR_ARM64E_USERLAND24): next=2 (*8=16), non-auth rebase
        let raw12_unauth = (2u64 << 51) | 0x45_6000u64;
        assert_eq!(
            decode_chained_pointer(raw12_unauth, 12, base),
            (Some(base + 0x45_6000), 16)
        );
        // Format 12 auth rebase (bit 63 = 1, bind=0, 32-bit target offset)
        let raw12_auth = (1u64 << 63) | (1u64 << 51) | 0x78_9000u64;
        assert_eq!(
            decode_chained_pointer(raw12_auth, 12, base),
            (Some(base + 0x78_9000), 8)
        );
        // Format 9 bind entry (bit 62 = 1)
        let raw9_bind = (1u64 << 62) | (4u64 << 51) | 7;
        assert_eq!(decode_chained_pointer(raw9_bind, 9, base), (None, 32));

        // Format 1 (DYLD_CHAINED_PTR_ARM64E): unauth vmaddr vs auth offset
        let raw1_unauth = (1u64 << 51) | 0x1_0010_0000u64;
        assert_eq!(
            decode_chained_pointer(raw1_unauth, 1, base),
            (Some(0x1_0010_0000), 8)
        );
    }
}
