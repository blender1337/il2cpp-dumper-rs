use anyhow::Result;
use goblin::elf::dynamic::{
    DT_GNU_HASH, DT_HASH, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL, DT_PLTRELSZ, DT_STRSZ,
    DT_STRTAB, DT_SYMTAB,
};
use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_X86_64};
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHT_NOBITS};
use goblin::elf::Elf;

use super::SectionRange;

pub const DT_RELRSZ: u64 = 35;
pub const DT_RELR: u64 = 36;
#[allow(dead_code)]
pub const DT_RELRENT: u64 = 37;

/// Dynamic table metadata extracted from `PT_DYNAMIC` for sectionless (`sstrip`) ELFs.
#[derive(Debug, Clone, Default)]
pub struct ElfDynamicInfo {
    pub init_array_va: Option<u64>,
    pub init_array_sz: u64,
    pub symtab_va: Option<u64>,
    pub strtab_va: Option<u64>,
    pub strsz: u64,
    pub jmprel_va: Option<u64>,
    pub pltrelsz: u64,
    pub hash_va: Option<u64>,
    pub gnu_hash_va: Option<u64>,
    pub relr_va: Option<u64>,
    pub relr_sz: u64,
}

/// Parse `PT_DYNAMIC` entries from an ELF image.
pub fn extract_dynamic_info(elf: &Elf) -> ElfDynamicInfo {
    let mut info = ElfDynamicInfo::default();
    let Some(dyn_sec) = elf.dynamic.as_ref() else {
        return info;
    };
    for d in &dyn_sec.dyns {
        match d.d_tag {
            DT_INIT_ARRAY => info.init_array_va = Some(d.d_val),
            DT_INIT_ARRAYSZ => info.init_array_sz = d.d_val,
            DT_SYMTAB => info.symtab_va = Some(d.d_val),
            DT_STRTAB => info.strtab_va = Some(d.d_val),
            DT_STRSZ => info.strsz = d.d_val,
            DT_JMPREL => info.jmprel_va = Some(d.d_val),
            DT_PLTRELSZ => info.pltrelsz = d.d_val,
            DT_HASH => info.hash_va = Some(d.d_val),
            DT_GNU_HASH => info.gnu_hash_va = Some(d.d_val),
            DT_RELR => info.relr_va = Some(d.d_val),
            DT_RELRSZ => info.relr_sz = d.d_val,
            _ => {}
        }
    }
    info
}

fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let s = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Estimate `.dynsym` entry count from `DT_HASH` or `DT_GNU_HASH` when section headers are absent.
pub fn estimate_dynsym_count(
    dyn_info: &ElfDynamicInfo,
    va_to_off: impl Fn(u64) -> Option<usize>,
    bytes: &[u8],
    is_64: bool,
) -> Option<usize> {
    if let Some(hash_va) = dyn_info.hash_va {
        if let Some(off) = va_to_off(hash_va) {
            if let Some(nchain) = read_u32_le(bytes, off + 4) {
                return Some(nchain as usize);
            }
        }
    }

    let gnu_va = dyn_info.gnu_hash_va?;
    let off = va_to_off(gnu_va)?;
    let nbuckets = read_u32_le(bytes, off)?;
    let symoffset = read_u32_le(bytes, off + 4)?;
    let bloom_size = read_u32_le(bytes, off + 8)?;
    let bloom_word = if is_64 { 8usize } else { 4usize };
    let buckets_off = off.checked_add(16)?.checked_add((bloom_size as usize).checked_mul(bloom_word)?)?;

    let mut max_sym = 0u32;
    for i in 0..nbuckets as usize {
        let b = read_u32_le(bytes, buckets_off.checked_add(i * 4)?)?;
        if b > max_sym {
            max_sym = b;
        }
    }
    if max_sym < symoffset {
        return Some(symoffset as usize);
    }

    let chains_off = buckets_off.checked_add((nbuckets as usize).checked_mul(4)?)?;
    for cur_sym in (max_sym..).take(2_000_000) {
        let chain_idx = (cur_sym - symoffset) as usize;
        let val = read_u32_le(bytes, chains_off.checked_add(chain_idx * 4)?)?;
        if (val & 1) != 0 {
            return Some(cur_sym as usize + 1);
        }
    }
    None
}

pub fn extract_meta(elf: &Elf) -> Result<(bool, String, u64, Vec<SectionRange>)> {
    let arch = match elf.header.e_machine {
        EM_AARCH64 => "arm64".to_string(),
        EM_ARM => "armv7".to_string(),
        EM_X86_64 => "x86_64".to_string(),
        EM_386 => "x86".to_string(),
        other => format!("elf_machine_{}", other),
    };

    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        if (sh.sh_flags & SHF_ALLOC as u64) == 0 || sh.sh_type == SHT_NOBITS || sh.sh_size == 0 {
            continue;
        }
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let is_exec = (sh.sh_flags & SHF_EXECINSTR as u64) != 0;
        let is_data = !is_exec && sh.sh_addr != 0;
        sections.push(SectionRange {
            name,
            va_start: sh.sh_addr,
            va_end: sh.sh_addr + sh.sh_size,
            file_offset: sh.sh_offset as usize,
            file_size: sh.sh_size as usize,
            is_exec,
            is_data,
        });
    }

    // Fallback to PT_LOAD segments if section headers were stripped
    if sections.is_empty() {
        for (idx, ph) in elf.program_headers.iter().enumerate() {
            if ph.p_type == PT_LOAD && ph.p_filesz > 0 {
                let is_exec = (ph.p_flags & 1) != 0;
                sections.push(SectionRange {
                    name: format!("PT_LOAD_{}", idx),
                    va_start: ph.p_vaddr,
                    va_end: ph.p_vaddr + ph.p_memsz.max(ph.p_filesz),
                    file_offset: ph.p_offset as usize,
                    file_size: ph.p_filesz as usize,
                    is_exec,
                    is_data: !is_exec,
                });
            }
        }
    }

    Ok((elf.is_64, arch, 0, sections))
}

pub type ElfRelocData = (Vec<(u64, u64)>, Vec<(usize, u64)>);

pub fn decode_relr_entries(entries: &[u64], ptr_sz: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let bits_per_word = ptr_sz * 8 - 1;
    let mut base_va: u64 = 0;

    for &entry in entries {
        if (entry & 1) == 0 {
            out.push(entry);
            base_va = entry.wrapping_add(ptr_sz);
        } else {
            let mut bitmap = entry >> 1;
            let mut i = 0u64;
            while bitmap != 0 {
                if (bitmap & 1) != 0 {
                    out.push(base_va.wrapping_add(i * ptr_sz));
                }
                bitmap >>= 1;
                i += 1;
            }
            base_va = base_va.wrapping_add(bits_per_word * ptr_sz);
        }
    }
    out
}

fn read_ptr_slice(bytes: &[u8], off: usize, is_64: bool) -> Option<u64> {
    if is_64 {
        let s = bytes.get(off..off + 8)?;
        Some(u64::from_le_bytes(s.try_into().ok()?))
    } else {
        let s = bytes.get(off..off + 4)?;
        Some(u32::from_le_bytes(s.try_into().ok()?) as u64)
    }
}

fn append_relr_slice(
    bytes: &[u8],
    start: usize,
    end: usize,
    ptr_sz: usize,
    is_64: bool,
    va_to_off: impl Fn(u64) -> Option<usize>,
    relocs: &mut Vec<(u64, u64)>,
) {
    if end <= start {
        return;
    }
    let mut entries = Vec::with_capacity((end - start) / ptr_sz);
    let mut off = start;
    while off + ptr_sz <= end {
        if let Some(e) = read_ptr_slice(bytes, off, is_64) {
            entries.push(e);
        }
        off += ptr_sz;
    }
    for va in decode_relr_entries(&entries, ptr_sz as u64) {
        if let Some(foff) = va_to_off(va) {
            if let Some(val) = read_ptr_slice(bytes, foff, is_64) {
                if val != 0 {
                    relocs.push((va, val));
                }
            }
        }
    }
}

pub fn collect_relocations(elf: &Elf, sections: &[SectionRange], bytes: &[u8]) -> ElfRelocData {
    const R_X86_64_RELATIVE: u32 = 8;
    const R_386_RELATIVE: u32 = 8;
    const R_ARM_RELATIVE: u32 = 23;
    const R_AARCH64_RELATIVE: u32 = 0x403;
    const SHT_RELR: u32 = 19;

    let va_to_off = |va: u64| -> Option<usize> {
        for s in sections {
            if va >= s.va_start && va < s.va_end {
                let rel = (va - s.va_start) as usize;
                if rel < s.file_size {
                    return Some(s.file_offset + rel);
                }
            }
        }
        None
    };

    let mut relocs = Vec::new();
    let mut patches = Vec::new();

    // 1. .rela.dyn
    for r in elf.dynrelas.iter() {
        if r.r_type == R_AARCH64_RELATIVE || r.r_type == R_X86_64_RELATIVE {
            let val = r.r_addend.unwrap_or(0) as u64;
            if val != 0 {
                relocs.push((r.r_offset, val));
                if let Some(off) = va_to_off(r.r_offset) {
                    patches.push((off, val));
                }
            }
        }
    }

    // 2. .rel.dyn (32-bit REL without explicit addend)
    for r in elf.dynrels.iter() {
        if r.r_type == R_ARM_RELATIVE
            || r.r_type == R_386_RELATIVE
            || r.r_type == R_AARCH64_RELATIVE
            || r.r_type == R_X86_64_RELATIVE
        {
            if let Some(off) = va_to_off(r.r_offset) {
                if let Some(val) = read_ptr_slice(bytes, off, elf.is_64) {
                    if val != 0 {
                        relocs.push((r.r_offset, val));
                    }
                }
            }
        }
    }

    // 3. SHT_RELR (.relr.dyn) packed relative relocations (Android NDK r23+)
    let ptr_sz = if elf.is_64 { 8usize } else { 4usize };
    let mut saw_relr_section = false;
    for sh in &elf.section_headers {
        let is_relr = sh.sh_type == SHT_RELR
            || elf.shdr_strtab.get_at(sh.sh_name) == Some(".relr.dyn");
        if !is_relr || sh.sh_size == 0 {
            continue;
        }
        saw_relr_section = true;
        let start = sh.sh_offset as usize;
        let end = start.saturating_add(sh.sh_size as usize).min(bytes.len());
        append_relr_slice(bytes, start, end, ptr_sz, elf.is_64, va_to_off, &mut relocs);
    }

    // Fallback to PT_DYNAMIC DT_RELR / DT_RELRSZ for sectionless (sstrip) ELFs
    if !saw_relr_section {
        let dyn_info = extract_dynamic_info(elf);
        if let Some(relr_va) = dyn_info.relr_va {
            if dyn_info.relr_sz > 0 {
                if let Some(start) = va_to_off(relr_va) {
                    let end = start.saturating_add(dyn_info.relr_sz as usize).min(bytes.len());
                    append_relr_slice(bytes, start, end, ptr_sz, elf.is_64, va_to_off, &mut relocs);
                }
            }
        }
    }

    relocs.sort_unstable_by_key(|&(va, _)| va);
    relocs.dedup_by_key(|r| r.0);
    (relocs, patches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relr_bitmap_decoding() {
        // Even address 0x1000 -> patches 0x1000, sets base_va = 0x1008.
        // Odd bitmap (0b1011 << 1) | 1 = 0x17 -> bit 0 (0x1008), bit 1 (0x1010), bit 3 (0x1020).
        let entries = [0x1000u64, 0x17u64];
        let vas = decode_relr_entries(&entries, 8);
        assert_eq!(vas, vec![0x1000, 0x1008, 0x1010, 0x1020]);
    }

    #[test]
    fn test_estimate_dynsym_count_hash_and_gnu_hash() {
        let mut mem = vec![0u8; 0x200];
        // SysV DT_HASH at offset 0x10: nbuckets=2, nchain=42
        mem[0x10..0x14].copy_from_slice(&2u32.to_le_bytes());
        mem[0x14..0x18].copy_from_slice(&42u32.to_le_bytes());
        let sysv_info = ElfDynamicInfo {
            hash_va: Some(0x10),
            ..Default::default()
        };
        assert_eq!(
            estimate_dynsym_count(&sysv_info, |va| Some(va as usize), &mem, true),
            Some(42)
        );

        // GNU_HASH at offset 0x40: nbuckets=2, symoffset=10, bloom_size=1, bloom_shift=6
        mem[0x40..0x44].copy_from_slice(&2u32.to_le_bytes());
        mem[0x44..0x48].copy_from_slice(&10u32.to_le_bytes());
        mem[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes());
        mem[0x4C..0x50].copy_from_slice(&6u32.to_le_bytes());
        // bloom[0] @ 0x50 (8 bytes), buckets @ 0x58: bucket[0]=0, bucket[1]=11
        mem[0x58..0x5C].copy_from_slice(&0u32.to_le_bytes());
        mem[0x5C..0x60].copy_from_slice(&11u32.to_le_bytes());
        // chains @ 0x60: sym 10 (0), sym 11 (2 - continues), sym 12 (3 - odd/end bit)
        mem[0x60..0x64].copy_from_slice(&0u32.to_le_bytes());
        mem[0x64..0x68].copy_from_slice(&2u32.to_le_bytes());
        mem[0x68..0x6C].copy_from_slice(&3u32.to_le_bytes());
        let gnu_info = ElfDynamicInfo {
            gnu_hash_va: Some(0x40),
            ..Default::default()
        };
        assert_eq!(
            estimate_dynsym_count(&gnu_info, |va| Some(va as usize), &mem, true),
            Some(13)
        );
    }
}
