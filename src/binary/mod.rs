pub mod custom_elf;
pub mod elf;
pub mod il2cpp;
pub mod macho;
pub mod nso;
pub mod pe;
pub mod wasm;

use anyhow::{bail, Result};
use goblin::Object;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    Nso,
    Wasm,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SectionRange {
    pub name: String,
    pub va_start: u64,
    pub va_end: u64,
    pub file_offset: usize,
    pub file_size: usize,
    pub is_exec: bool,
    pub is_data: bool,
}

#[derive(Debug)]
pub struct BinaryImage {
    pub bytes: Vec<u8>,
    pub format: BinaryFormat,
    pub is_64bit: bool,
    pub arch: String,
    pub image_base: u64,
    pub sections: Vec<SectionRange>,
    pub relocs: Vec<(u64, u64)>,
    pub is_memory_dump: bool,
    pub fairplay_encrypted: bool,
}

impl BinaryImage {
    pub fn parse(mut bytes: Vec<u8>) -> Result<Self> {
        if bytes.starts_with(b"NSO0") {
            return nso::parse_nso(&bytes);
        }
        if bytes.starts_with(b"\0asm") {
            return wasm::parse_wasm(&bytes);
        }
        let mut relocs = Vec::new();
        let mut patches = Vec::new();
        let mut is_memory_dump = false;
        let mut fairplay_encrypted = false;
        let (format, is_64bit, arch, image_base, sections, fat_slice) = {
            match Object::parse(&bytes) {
                Ok(Object::PE(p)) => {
                    let m = pe::extract_meta(&p)?;
                    (BinaryFormat::Pe, m.0, m.1, m.2, m.3, None)
                }
                Ok(Object::Elf(e)) => {
                    let m = elf::extract_meta(&e)?;
                    let (r, p) = elf::collect_relocations(&e, &m.3, &bytes);
                    relocs = r;
                    patches = p;
                    (BinaryFormat::Elf, m.0, m.1, m.2, m.3, None)
                }
                Ok(Object::Mach(m)) => {
                    let (meta, extras) = macho::extract_meta(&bytes, m)?;
                    relocs = extras.relocs;
                    patches = extras.patches;
                    fairplay_encrypted = extras.fairplay_encrypted;
                    meta
                }
                Ok(_) => bail!("Unsupported binary format (expected PE, ELF, Mach-O, NSO, or WASM)"),
                Err(e) => {
                    if let Some(raw_meta) = Self::fallback_raw_memory_dump(&bytes) {
                        is_memory_dump = true;
                        raw_meta
                    } else {
                        return Err(e.into());
                    }
                }
            }
        };
        if let Some((off, len)) = fat_slice {
            bytes = bytes[off..off + len].to_vec();
        }
        for (off, val) in patches {
            if is_64bit {
                if off + 8 <= bytes.len() {
                    bytes[off..off + 8].copy_from_slice(&val.to_le_bytes());
                }
            } else if off + 4 <= bytes.len() {
                bytes[off..off + 4].copy_from_slice(&(val as u32).to_le_bytes());
            }
        }
        Ok(BinaryImage {
            bytes,
            format,
            is_64bit,
            arch,
            image_base,
            sections,
            relocs,
            is_memory_dump,
            fairplay_encrypted,
        })
    }

    pub fn configure_memory_dump(&mut self, dump_base: Option<u64>) {
        self.is_memory_dump = true;
        if let Some(base) = dump_base {
            let len = self.bytes.len();
            self.image_base = base;
            self.relocs.clear();
            self.sections = vec![SectionRange {
                name: "MEM_DUMP_REBASED".to_string(),
                va_start: base,
                va_end: base.saturating_add(len as u64),
                file_offset: 0,
                file_size: len,
                is_exec: true,
                is_data: true,
            }];
        }
    }

    fn fallback_raw_memory_dump(bytes: &[u8]) -> Option<macho::MachOMeta> {
        if bytes.starts_with(b"\x7FELF") && bytes.len() >= 64 {
            let is_64 = bytes[4] == 2;
            let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
            let arch = match machine {
                183 => "arm64",
                40 => "armv7",
                62 => "x86_64",
                3 => "x86",
                _ => "unknown",
            }
            .to_string();
            let sec = SectionRange {
                name: "RAW_MEM_DUMP".to_string(),
                va_start: 0,
                va_end: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len(),
                is_exec: true,
                is_data: true,
            };
            return Some((BinaryFormat::Elf, is_64, arch, 0, vec![sec], None));
        }
        if bytes.starts_with(b"MZ") && bytes.len() >= 0x100 {
            let e_lfanew = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
            let is_64 = bytes
                .get(e_lfanew + 24..e_lfanew + 26)
                .map(|b| u16::from_le_bytes([b[0], b[1]]) == 0x20B)
                .unwrap_or(true);
            let sec = SectionRange {
                name: "RAW_MEM_DUMP".to_string(),
                va_start: 0,
                va_end: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len(),
                is_exec: true,
                is_data: true,
            };
            return Some((
                BinaryFormat::Pe,
                is_64,
                if is_64 { "x86_64" } else { "x86" }.to_string(),
                0,
                vec![sec],
                None,
            ));
        }
        None
    }

    pub fn ptr_size(&self) -> usize {
        if self.is_64bit { 8 } else { 4 }
    }

    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        if va == 0 {
            return None;
        }
        if self.is_memory_dump {
            let rel = va.checked_sub(self.image_base)? as usize;
            return (rel < self.bytes.len()).then_some(rel);
        }
        for s in &self.sections {
            if va >= s.va_start && va < s.va_end {
                let rel = (va - s.va_start) as usize;
                if rel < s.file_size {
                    let off = s.file_offset + rel;
                    if off < self.bytes.len() {
                        return Some(off);
                    }
                }
            }
        }
        None
    }

    pub fn offset_to_va(&self, off: usize) -> Option<u64> {
        if self.is_memory_dump {
            return (off < self.bytes.len()).then(|| self.image_base.saturating_add(off as u64));
        }
        for s in &self.sections {
            if off >= s.file_offset && off < s.file_offset + s.file_size {
                return Some(s.va_start + (off - s.file_offset) as u64);
            }
        }
        None
    }

    pub fn is_valid_va(&self, va: u64) -> bool {
        self.va_to_offset(va).is_some()
    }

    pub fn read_bytes(&self, va: u64, len: usize) -> Option<&[u8]> {
        let off = self.va_to_offset(va)?;
        let end = off.checked_add(len)?;
        if end > self.bytes.len() {
            return None;
        }
        Some(&self.bytes[off..end])
    }

    pub fn read_u8(&self, va: u64) -> Option<u8> {
        self.read_bytes(va, 1).map(|b| b[0])
    }

    pub fn read_u32(&self, va: u64) -> Option<u32> {
        let b = self.read_bytes(va, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_i32(&self, va: u64) -> Option<i32> {
        self.read_u32(va).map(|v| v as i32)
    }

    pub fn read_u64(&self, va: u64) -> Option<u64> {
        let b = self.read_bytes(va, 8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_ptr(&self, va: u64) -> Option<u64> {
        if let Ok(idx) = self.relocs.binary_search_by_key(&va, |&(a, _)| a) {
            return Some(self.relocs[idx].1);
        }
        if self.is_64bit {
            self.read_u64(va)
        } else {
            self.read_u32(va).map(|v| v as u64)
        }
    }

    pub fn read_cstr(&self, va: u64) -> Option<String> {
        let off = self.va_to_offset(va)?;
        let tail = &self.bytes[off..self.bytes.len().min(off + 512)];
        let nul = tail.iter().position(|&b| b == 0)?;
        let s = std::str::from_utf8(&tail[..nul]).ok()?;
        Some(s.to_string())
    }

    pub fn find_cstr_vas(&self, needle: &str) -> Vec<u64> {
        let mut pat = needle.as_bytes().to_vec();
        pat.push(0);
        let mut results = Vec::new();
        for s in &self.sections {
            let start = s.file_offset;
            let end = (s.file_offset + s.file_size).min(self.bytes.len());
            if end <= start + pat.len() {
                continue;
            }
            let hay = &self.bytes[start..end];
            let mut pos = 0;
            while let Some(found) = hay[pos..].windows(pat.len()).position(|w| w == pat.as_slice()) {
                let abs_off = start + pos + found;
                if let Some(va) = self.offset_to_va(abs_off) {
                    results.push(va);
                }
                pos += found + 1;
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_dump_rebase_va_translation() {
        let mut mem = vec![0u8; 0x100];
        let base = 0x7A_1000_0000u64;
        mem[0x20..0x28].copy_from_slice(&(base + 0x40).to_le_bytes());
        mem[0x40..0x44].copy_from_slice(b"OK!\0");

        let mut bin = BinaryImage {
            bytes: mem,
            format: BinaryFormat::Elf,
            is_64bit: true,
            arch: "arm64".into(),
            image_base: 0,
            sections: vec![SectionRange {
                name: ".data".into(),
                va_start: 0,
                va_end: 0x100,
                file_offset: 0,
                file_size: 0x100,
                is_exec: false,
                is_data: true,
            }],
            relocs: vec![(0x20, 0x9999)],
            is_memory_dump: false,
            fairplay_encrypted: false,
        };

        bin.configure_memory_dump(Some(base));
        assert!(bin.is_memory_dump);
        assert_eq!(bin.image_base, base);
        assert_eq!(bin.va_to_offset(base + 0x20), Some(0x20));
        assert_eq!(bin.offset_to_va(0x40), Some(base + 0x40));
        assert_eq!(bin.read_ptr(base + 0x20), Some(base + 0x40));
        assert_eq!(bin.read_cstr(base + 0x40).as_deref(), Some("OK!"));
    }
}
