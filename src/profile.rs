use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DumpProfile {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub header_offset: usize,
    #[serde(default)]
    pub xor_key_hex: Option<String>,
    #[serde(default)]
    pub xor_range: Option<(usize, usize)>,
    #[serde(default)]
    pub expected_magic: Option<u32>,
    #[serde(default)]
    pub override_version: Option<i32>,
    #[serde(default)]
    pub header_mode: Option<String>,
    #[serde(default)]
    pub register_symbol: Option<String>,
}

impl DumpProfile {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read profile: {}", path.display()))?;
        let prof: Self = serde_json::from_str(&text)
            .with_context(|| format!("Invalid profile JSON: {}", path.display()))?;
        Ok(prof)
    }
}

pub fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        bail!("xor_key_hex length must be even");
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .with_context(|| format!("Invalid hex byte at {}: {}", i, &clean[i..i + 2]))?;
        out.push(byte);
    }
    Ok(out)
}

pub fn apply_profile(raw: &[u8], profile: &DumpProfile) -> Result<Vec<u8>> {
    if profile.header_offset > raw.len() {
        bail!(
            "profile header_offset ({}) exceeds metadata size ({})",
            profile.header_offset,
            raw.len()
        );
    }
    let mut data = raw[profile.header_offset..].to_vec();

    if let Some(ref key_hex) = profile.xor_key_hex {
        let key = decode_hex(key_hex)?;
        if key.is_empty() {
            bail!("xor_key_hex must not be empty");
        }
        let (start, end) = match profile.xor_range {
            Some((s, e)) => (s.min(data.len()), e.min(data.len())),
            None => (0, data.len()),
        };
        for (idx, b) in data[start..end].iter_mut().enumerate() {
            *b ^= key[idx % key.len()];
        }
    }

    if let Some(expected) = profile.expected_magic {
        if data.len() >= 4 {
            let current = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if current == expected {
                data[0..4].copy_from_slice(&0xFAB11BAFu32.to_le_bytes());
            }
        }
    }

    if let Some(ver) = profile.override_version {
        if data.len() >= 8 {
            data[4..8].copy_from_slice(&ver.to_le_bytes());
        }
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_slice_xor_and_magic_fixup() {
        let mut raw = vec![0xAAu8; 4]; // 4-byte prefix padding
        let mut payload = vec![0u8; 16];
        payload[0..4].copy_from_slice(&0x12345678u32.to_le_bytes());
        payload[4..8].copy_from_slice(&29i32.to_le_bytes());
        let key = [0x5Au8, 0xA5u8];
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i % key.len()];
        }
        raw.extend_from_slice(&payload);

        let prof = DumpProfile {
            name: "test".into(),
            header_offset: 4,
            xor_key_hex: Some("5AA5".into()),
            xor_range: None,
            expected_magic: Some(0x12345678),
            override_version: Some(39),
            ..Default::default()
        };
        let out = apply_profile(&raw, &prof).unwrap();
        assert_eq!(out.len(), 16);
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 0xFAB11BAF);
        assert_eq!(i32::from_le_bytes(out[4..8].try_into().unwrap()), 39);
    }
}
