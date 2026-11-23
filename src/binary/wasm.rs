use anyhow::{bail, Result};

use super::{BinaryFormat, BinaryImage, SectionRange};

const MAX_WASM_MEMORY: usize = 512 * 1024 * 1024;

fn read_leb128_u32(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        let &b = bytes
            .get(*pos)
            .ok_or_else(|| anyhow::anyhow!("Unexpected EOF reading u32 LEB128"))?;
        *pos += 1;
        result |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 35 {
            bail!("LEB128 u32 overflow");
        }
    }
}

fn read_leb128_i32(bytes: &[u8], pos: &mut usize) -> Result<i32> {
    let mut result = 0i32;
    let mut shift = 0u32;
    loop {
        let &b = bytes
            .get(*pos)
            .ok_or_else(|| anyhow::anyhow!("Unexpected EOF reading i32 LEB128"))?;
        *pos += 1;
        result |= ((b & 0x7F) as i32) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            if shift < 32 && (b & 0x40) != 0 {
                result |= !0i32 << shift;
            }
            return Ok(result);
        }
        if shift >= 35 {
            bail!("LEB128 i32 overflow");
        }
    }
}

fn skip_init_expr(bytes: &[u8], pos: &mut usize) -> Result<()> {
    while let Some(&op) = bytes.get(*pos) {
        *pos += 1;
        match op {
            0x0B => return Ok(()),
            0x41 => {
                let _ = read_leb128_i32(bytes, pos)?;
            }
            0x23 => {
                let _ = read_leb128_u32(bytes, pos)?;
            }
            other => bail!("Unsupported WASM init_expr opcode 0x{:02x}", other),
        }
    }
    bail!("Unterminated WASM init_expr")
}

/// Parse a WebAssembly (`.wasm`) binary's Data section (id `11`) into linear 32-bit memory.
pub fn parse_wasm(bytes: &[u8]) -> Result<BinaryImage> {
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        bail!("Not a valid WASM binary");
    }

    let mut pos = 8usize;
    let mut mem = Vec::<u8>::new();

    while pos < bytes.len() {
        let sec_id = bytes[pos];
        pos += 1;
        let sec_size = read_leb128_u32(bytes, &mut pos)? as usize;
        let sec_end = pos
            .checked_add(sec_size)
            .filter(|&e| e <= bytes.len())
            .ok_or_else(|| anyhow::anyhow!("WASM section {} out of bounds", sec_id))?;

        if sec_id == 11 {
            let mut sp = pos;
            let seg_count = read_leb128_u32(bytes, &mut sp)?;
            for _ in 0..seg_count {
                if sp >= sec_end {
                    break;
                }
                let flags = read_leb128_u32(bytes, &mut sp)?;
                match flags {
                    0 => {
                        let &op = bytes
                            .get(sp)
                            .ok_or_else(|| anyhow::anyhow!("WASM data segment EOF"))?;
                        sp += 1;
                        if op != 0x41 {
                            bail!("Expected i32.const (0x41) in WASM active data segment, got 0x{:02x}", op);
                        }
                        let offset = read_leb128_i32(bytes, &mut sp)? as u32 as usize;
                        if bytes.get(sp).copied() != Some(0x0B) {
                            bail!("Expected end opcode (0x0B) in WASM data init_expr");
                        }
                        sp += 1;
                        let data_len = read_leb128_u32(bytes, &mut sp)? as usize;
                        let data_end = sp
                            .checked_add(data_len)
                            .filter(|&e| e <= sec_end)
                            .ok_or_else(|| anyhow::anyhow!("WASM data payload out of bounds"))?;
                        let mem_end = offset
                            .checked_add(data_len)
                            .filter(|&e| e <= MAX_WASM_MEMORY)
                            .ok_or_else(|| anyhow::anyhow!("WASM linear memory exceeds 512 MiB limit"))?;
                        if mem_end > mem.len() {
                            mem.resize(mem_end, 0);
                        }
                        mem[offset..mem_end].copy_from_slice(&bytes[sp..data_end]);
                        sp = data_end;
                    }
                    1 => {
                        let data_len = read_leb128_u32(bytes, &mut sp)? as usize;
                        sp = sp
                            .checked_add(data_len)
                            .filter(|&e| e <= sec_end)
                            .ok_or_else(|| anyhow::anyhow!("WASM passive data out of bounds"))?;
                    }
                    2 => {
                        let _mem_idx = read_leb128_u32(bytes, &mut sp)?;
                        skip_init_expr(bytes, &mut sp)?;
                        let data_len = read_leb128_u32(bytes, &mut sp)? as usize;
                        sp = sp
                            .checked_add(data_len)
                            .filter(|&e| e <= sec_end)
                            .ok_or_else(|| anyhow::anyhow!("WASM data out of bounds"))?;
                    }
                    other => bail!("Unsupported WASM data segment flags {}", other),
                }
            }
        }
        pos = sec_end;
    }

    let len = mem.len();
    Ok(BinaryImage {
        bytes: mem,
        format: BinaryFormat::Wasm,
        is_64bit: false,
        arch: "wasm32".to_string(),
        image_base: 0,
        sections: vec![SectionRange {
            name: "WASM_MEMORY".to_string(),
            va_start: 0,
            va_end: len as u64,
            file_offset: 0,
            file_size: len,
            is_exec: false,
            is_data: true,
        }],
        relocs: Vec::new(),
        is_memory_dump: false,
        fairplay_encrypted: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wasm_data_section() {
        // Construct WASM with Data section (id 11), 1 active segment at i32.const 0x400 containing "mscorlib.dll\0"
        let payload = b"mscorlib.dll\0";
        let mut seg = vec![
            1,    // seg_count = 1
            0,    // flags = 0 (active)
            0x41, // i32.const
            0x80, // SLEB128(0x400 = 1024)
            0x08,
            0x0B, // end
            payload.len() as u8,
        ];
        seg.extend_from_slice(payload);

        let mut wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        wasm.push(11); // section id 11
        wasm.push(seg.len() as u8);
        wasm.extend_from_slice(&seg);

        let img = parse_wasm(&wasm).unwrap();
        assert_eq!(img.format, BinaryFormat::Wasm);
        assert!(!img.is_64bit);
        assert_eq!(img.read_cstr(0x400).as_deref(), Some("mscorlib.dll"));
    }
}
