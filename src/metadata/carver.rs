use anyhow::{bail, Result};

use super::adaptive::{parse_chain_tables, AdaptiveMetadata};
use super::header::{MetadataHeader, METADATA_MAGIC};

/// Carve an intact or magic-wiped `global-metadata.dat` out of a raw RAM dump.
pub fn carve_metadata_from_blob(blob: &[u8]) -> Result<Vec<u8>> {
    let magic_bytes = METADATA_MAGIC.to_le_bytes();

    // 1. Scan for intact 0xFAB11BAF magic at 4-byte aligned offsets
    let mut pos = 0usize;
    while pos + 256 <= blob.len() {
        if blob[pos..pos + 4] == magic_bytes {
            if let Some(carved) = try_carve_at(&blob[pos..]) {
                return Ok(carved);
            }
        }
        pos += 4;
    }

    // 2. Fallback for magic-wiped metadata in RAM: look for known anchor strings and probe nearby headers
    for anchor in [b"mscorlib.dll\0".as_slice(), b"Assembly-CSharp.dll\0".as_slice()] {
        if let Some(str_off) = find_subslice(blob, anchor) {
            let search_start = str_off.saturating_sub(32 * 1024 * 1024) & !3;
            let mut probe = search_start;
            while probe + 256 <= str_off {
                let ver = i32::from_le_bytes([
                    blob[probe + 4],
                    blob[probe + 5],
                    blob[probe + 6],
                    blob[probe + 7],
                ]);
                if (24..=39).contains(&ver) || (104..=120).contains(&ver) || ver == 1024 {
                    let tail_len = (blob.len() - probe).min(64 * 1024 * 1024);
                    let mut buf = blob[probe..probe + tail_len].to_vec();
                    buf[0..4].copy_from_slice(&magic_bytes);
                    if let Some(carved) = try_carve_at(&buf) {
                        if find_subslice(&carved, anchor).is_some() {
                            return Ok(carved);
                        }
                    }
                }
                probe += 4;
            }
        }
    }

    bail!("No valid IL2CPP metadata found in RAM blob ({} bytes)", blob.len())
}

fn try_carve_at(slice: &[u8]) -> Option<Vec<u8>> {
    if let Ok(hdr) = MetadataHeader::parse(slice) {
        let max_end = hdr
            .sections_summary()
            .iter()
            .map(|(_, s)| (s.offset as usize).saturating_add(s.size as usize))
            .max()
            .unwrap_or(0);
        if max_end > 256 && max_end <= slice.len() && hdr.string.slice(&slice[..max_end]).is_ok() {
            return Some(slice[..max_end].to_vec());
        }
    }

    if let Some(tabs) = parse_chain_tables(slice) {
        if tabs.len() >= 16 {
            let last_end = tabs.last().map(|t| t.start + t.size).unwrap_or(0);
            if last_end > 256
                && last_end <= slice.len()
                && AdaptiveMetadata::parse(&slice[..last_end]).is_ok()
            {
                return Some(slice[..last_end].to_vec());
            }
        }
    }

    None
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_v29_metadata(with_magic: bool) -> Vec<u8> {
        // v29 header has 31 section pairs = 248 bytes + 8 byte magic/version = 256 bytes
        let mut buf = vec![0u8; 320];
        if with_magic {
            buf[0..4].copy_from_slice(&METADATA_MAGIC.to_le_bytes());
        }
        buf[4..8].copy_from_slice(&29i32.to_le_bytes());
        // string section is pair index 2 -> offset = 8 + 2*8 = 24
        let str_off = 256u32;
        let anchor = b"mscorlib.dll\0";
        buf[24..28].copy_from_slice(&str_off.to_le_bytes());
        buf[28..32].copy_from_slice(&(anchor.len() as u32).to_le_bytes());
        buf[str_off as usize..str_off as usize + anchor.len()].copy_from_slice(anchor);
        let total = str_off as usize + anchor.len();
        buf.truncate(total);
        buf
    }

    #[test]
    fn test_carve_metadata_from_blob_magic_and_erased() {
        let meta = build_minimal_v29_metadata(true);
        let mut ram = vec![0xCCu8; 128];
        ram.extend_from_slice(&meta);
        ram.extend_from_slice(&[0xDDu8; 64]);

        let carved = carve_metadata_from_blob(&ram).unwrap();
        assert_eq!(carved, meta);

        // Now zero out magic in RAM
        ram[128..132].copy_from_slice(&0u32.to_le_bytes());
        let carved_wiped = carve_metadata_from_blob(&ram).unwrap();
        assert_eq!(carved_wiped, meta);
    }
}
