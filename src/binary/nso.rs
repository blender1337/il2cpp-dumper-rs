use anyhow::{bail, Result};

use super::{BinaryFormat, BinaryImage, SectionRange};

const NSO_HEADER_SIZE: usize = 0x100;

fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32> {
    let s = bytes
        .get(off..off + 4)
        .ok_or_else(|| anyhow::anyhow!("NSO truncated at offset 0x{:x}", off))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Decompress a raw LZ4 block into a buffer of `expected_len` bytes.
pub fn decompress_lz4_block(src: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    let mut dst = Vec::with_capacity(expected_len);
    let mut ip = 0usize;

    while ip < src.len() {
        let token = src[ip];
        ip += 1;

        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                let &b = src
                    .get(ip)
                    .ok_or_else(|| anyhow::anyhow!("Truncated LZ4 literal length"))?;
                ip += 1;
                lit_len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }

        let lit_end = ip
            .checked_add(lit_len)
            .ok_or_else(|| anyhow::anyhow!("LZ4 literal overflow"))?;
        let lit_slice = src
            .get(ip..lit_end)
            .ok_or_else(|| anyhow::anyhow!("Truncated LZ4 literal payload"))?;
        dst.extend_from_slice(lit_slice);
        ip = lit_end;

        if ip >= src.len() {
            break;
        }

        let off_bytes = src
            .get(ip..ip + 2)
            .ok_or_else(|| anyhow::anyhow!("Truncated LZ4 match offset"))?;
        ip += 2;
        let offset = u16::from_le_bytes([off_bytes[0], off_bytes[1]]) as usize;
        if offset == 0 || offset > dst.len() {
            bail!("Invalid LZ4 match offset {} (dst len {})", offset, dst.len());
        }

        let mut match_len = (token & 0x0F) as usize;
        if match_len == 15 {
            loop {
                let &b = src
                    .get(ip)
                    .ok_or_else(|| anyhow::anyhow!("Truncated LZ4 match length"))?;
                ip += 1;
                match_len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        match_len += 4;

        for _ in 0..match_len {
            let b = dst[dst.len() - offset];
            dst.push(b);
        }
    }

    if expected_len > 0 && dst.len() != expected_len {
        bail!(
            "NSO LZ4 decompressed length mismatch: got {}, expected {}",
            dst.len(),
            expected_len
        );
    }
    Ok(dst)
}

fn extract_segment(
    bytes: &[u8],
    file_off: usize,
    file_sz: usize,
    mem_sz: usize,
    compressed: bool,
    name: &str,
) -> Result<Vec<u8>> {
    if mem_sz == 0 {
        return Ok(Vec::new());
    }
    let raw_len = if compressed { file_sz } else { mem_sz.max(file_sz) };
    let end = file_off
        .checked_add(raw_len)
        .filter(|&e| e <= bytes.len())
        .ok_or_else(|| anyhow::anyhow!("NSO {} segment out of bounds", name))?;
    let slice = &bytes[file_off..end];
    if compressed {
        decompress_lz4_block(slice, mem_sz)
    } else {
        Ok(slice[..mem_sz.min(slice.len())].to_vec())
    }
}

/// Parse a Nintendo Switch `NSO0` executable (`main`), decompressing LZ4 segments.
pub fn parse_nso(bytes: &[u8]) -> Result<BinaryImage> {
    if bytes.len() < NSO_HEADER_SIZE || !bytes.starts_with(b"NSO0") {
        bail!("Not a valid NSO0 binary");
    }

    let flags = read_u32_le(bytes, 0x0C)?;
    let text_file_off = read_u32_le(bytes, 0x10)? as usize;
    let text_mem_off = read_u32_le(bytes, 0x14)? as u64;
    let text_size = read_u32_le(bytes, 0x18)? as usize;
    let text_file_sz = read_u32_le(bytes, 0x60)? as usize;

    let ro_file_off = read_u32_le(bytes, 0x20)? as usize;
    let ro_mem_off = read_u32_le(bytes, 0x24)? as u64;
    let ro_size = read_u32_le(bytes, 0x28)? as usize;
    let ro_file_sz = read_u32_le(bytes, 0x64)? as usize;

    let data_file_off = read_u32_le(bytes, 0x30)? as usize;
    let data_mem_off = read_u32_le(bytes, 0x34)? as u64;
    let data_size = read_u32_le(bytes, 0x38)? as usize;
    let data_file_sz = read_u32_le(bytes, 0x68)? as usize;

    let text_buf = extract_segment(bytes, text_file_off, text_file_sz, text_size, (flags & 1) != 0, ".text")?;
    let ro_buf = extract_segment(bytes, ro_file_off, ro_file_sz, ro_size, (flags & 2) != 0, ".rodata")?;
    let data_buf = extract_segment(bytes, data_file_off, data_file_sz, data_size, (flags & 4) != 0, ".data")?;

    let mut flat = Vec::with_capacity(text_buf.len() + ro_buf.len() + data_buf.len());
    let mut sections = Vec::with_capacity(3);

    for (name, buf, va, is_exec, is_data) in [
        (".text", text_buf, text_mem_off, true, false),
        (".rodata", ro_buf, ro_mem_off, false, true),
        (".data", data_buf, data_mem_off, false, true),
    ] {
        if buf.is_empty() {
            continue;
        }
        let off = flat.len();
        let len = buf.len();
        flat.extend_from_slice(&buf);
        sections.push(SectionRange {
            name: name.to_string(),
            va_start: va,
            va_end: va + len as u64,
            file_offset: off,
            file_size: len,
            is_exec,
            is_data,
        });
    }

    Ok(BinaryImage {
        bytes: flat,
        format: BinaryFormat::Nso,
        is_64bit: true,
        arch: "arm64".to_string(),
        image_base: 0,
        sections,
        relocs: Vec::new(),
        is_memory_dump: false,
        fairplay_encrypted: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress_lz4_block_literals_and_match() {
        // Token 0x51 => 5 literals ("Hello"), offset=5 (at "Hello"), matchlen = 1 + 4 = 5 ("Hello")
        let compressed = [0x51, b'H', b'e', b'l', b'l', b'o', 0x05, 0x00, 0x10, b'!'];
        let out = decompress_lz4_block(&compressed, 11).unwrap();
        assert_eq!(&out, b"HelloHello!");
    }

    #[test]
    fn test_parse_nso_compressed_and_uncompressed() {
        let mut nso = vec![0u8; 0x140];
        nso[0..4].copy_from_slice(b"NSO0");
        // flags: bit 1 set (.rodata compressed)
        nso[0x0C..0x10].copy_from_slice(&2u32.to_le_bytes());

        // .text uncompressed at 0x100, mem=0x0, size=8
        nso[0x10..0x14].copy_from_slice(&0x100u32.to_le_bytes());
        nso[0x14..0x18].copy_from_slice(&0x0u32.to_le_bytes());
        nso[0x18..0x1C].copy_from_slice(&8u32.to_le_bytes());
        nso[0x60..0x64].copy_from_slice(&8u32.to_le_bytes());
        nso[0x100..0x108].copy_from_slice(&[0xC0, 0x03, 0x5F, 0xD6, 0x1F, 0x20, 0x03, 0xD5]);

        // .rodata LZ4 compressed at 0x108, mem=0x1000, decomp=11 ("HelloHello!")
        let ro_lz4 = [0x51u8, b'H', b'e', b'l', b'l', b'o', 0x05, 0x00, 0x10, b'!'];
        nso[0x20..0x24].copy_from_slice(&0x108u32.to_le_bytes());
        nso[0x24..0x28].copy_from_slice(&0x1000u32.to_le_bytes());
        nso[0x28..0x2C].copy_from_slice(&11u32.to_le_bytes());
        nso[0x64..0x68].copy_from_slice(&(ro_lz4.len() as u32).to_le_bytes());
        nso[0x108..0x108 + ro_lz4.len()].copy_from_slice(&ro_lz4);

        // .data uncompressed at 0x120, mem=0x2000, size=8
        nso[0x30..0x34].copy_from_slice(&0x120u32.to_le_bytes());
        nso[0x34..0x38].copy_from_slice(&0x2000u32.to_le_bytes());
        nso[0x38..0x3C].copy_from_slice(&8u32.to_le_bytes());
        nso[0x68..0x6C].copy_from_slice(&8u32.to_le_bytes());
        nso[0x120..0x128].copy_from_slice(&0x1000u64.to_le_bytes());

        let img = parse_nso(&nso).unwrap();
        assert_eq!(img.format, BinaryFormat::Nso);
        assert_eq!(img.read_cstr(0x1000).as_deref(), Some("HelloHello!"));
        assert_eq!(img.read_ptr(0x2000), Some(0x1000));
    }
}
