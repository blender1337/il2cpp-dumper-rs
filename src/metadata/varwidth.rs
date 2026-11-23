use anyhow::{bail, Result};
use std::io::{Cursor, Read};

use super::header::MetadataHeader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Widths {
    pub type_def: u8,
    pub generic_container: u8,
    pub il2cpp_type: u8,
    pub parameter: u8,
    pub interface: u8,
    pub event: u8,
    pub property: u8,
    pub nested_type: u8,
    pub method: u8,
}

pub fn width_for_count(count: usize) -> u8 {
    if count <= 0xFE {
        1
    } else if count <= 0xFFFE {
        2
    } else {
        4
    }
}

impl Widths {
    pub fn fixed_32() -> Self {
        Self {
            type_def: 4,
            generic_container: 4,
            il2cpp_type: 4,
            parameter: 4,
            interface: 4,
            event: 4,
            property: 4,
            nested_type: 4,
            method: 4,
        }
    }

    pub fn for_version(version: i32, header: &MetadataHeader, num_types: Option<usize>) -> Self {
        if version < 38 {
            return Self::fixed_32();
        }

        let td_cnt = header.type_definitions.effective_count(if version >= 38 { 0 } else { 88 });
        let gc_cnt = header.generic_containers.effective_count(16);
        let param_cnt = header.parameters.effective_count(12);

        let inferred_type_w = Self::infer_type_width_from_fields(header).unwrap_or(4);
        let type_w = num_types.map(width_for_count).unwrap_or(inferred_type_w);

        let mut w = Self {
            type_def: width_for_count(td_cnt),
            generic_container: width_for_count(gc_cnt),
            il2cpp_type: type_w,
            parameter: if version >= 39 { width_for_count(param_cnt) } else { 4 },
            interface: 4,
            event: 4,
            property: 4,
            nested_type: 4,
            method: 4,
        };

        if version >= 104 {
            w.interface = width_for_count(header.interfaces.count as usize);
            w.event = width_for_count(header.events.count as usize);
            w.property = width_for_count(header.properties.count as usize);
            w.nested_type = width_for_count(header.nested_types.count as usize);
        }
        if version >= 105 {
            w.method = width_for_count(header.methods.count as usize);
        }

        w
    }

    /// Infer Il2CppType index width directly from the `fields` section stride:
    /// `nameIndex(4) + typeIndex(W) + token(4)` => 9, 10, or 12 bytes.
    pub fn infer_type_width_from_fields(header: &MetadataHeader) -> Option<u8> {
        let cnt = header.fields.count as usize;
        let sz = header.fields.size as usize;
        if cnt == 0 || !sz.is_multiple_of(cnt) {
            return None;
        }
        match sz / cnt {
            9 => Some(1),
            10 => Some(2),
            12 => Some(4),
            _ => None,
        }
    }
}

pub fn read_var_index(cursor: &mut Cursor<&[u8]>, width: u8) -> Result<i32> {
    let mut buf = [0u8; 4];
    match width {
        1 => {
            cursor.read_exact(&mut buf[..1])?;
            let v = buf[0];
            Ok(if v == u8::MAX { -1 } else { v as i32 })
        }
        2 => {
            cursor.read_exact(&mut buf[..2])?;
            let v = u16::from_le_bytes([buf[0], buf[1]]);
            Ok(if v == u16::MAX { -1 } else { v as i32 })
        }
        4 => {
            cursor.read_exact(&mut buf[..4])?;
            Ok(i32::from_le_bytes(buf))
        }
        other => bail!("Invalid variable-width index width: {}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_width_for_count_boundaries() {
        assert_eq!(width_for_count(0), 1);
        assert_eq!(width_for_count(254), 1);
        assert_eq!(width_for_count(255), 2);
        assert_eq!(width_for_count(65534), 2);
        assert_eq!(width_for_count(65535), 4);
        assert_eq!(width_for_count(265_000), 4);
    }

    #[test]
    fn test_read_var_index_null_sentinels() {
        let raw = [0xFFu8, 0x05, 0xFF, 0xFF, 0x2A, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x10, 0x00, 0x00, 0x00];
        let mut cur = Cursor::new(&raw[..]);
        assert_eq!(read_var_index(&mut cur, 1).unwrap(), -1);
        assert_eq!(read_var_index(&mut cur, 1).unwrap(), 5);
        assert_eq!(read_var_index(&mut cur, 2).unwrap(), -1);
        assert_eq!(read_var_index(&mut cur, 2).unwrap(), 42);
        assert_eq!(read_var_index(&mut cur, 4).unwrap(), -1);
        assert_eq!(read_var_index(&mut cur, 4).unwrap(), 16);
    }
}
