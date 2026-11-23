pub mod dump_cs;
pub mod il2cpp_h;
pub mod script_json;

pub fn sanitize_c_ident(s: &str) -> String {
    let mut res: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if res.is_empty() {
        return "_".to_string();
    }
    if res.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        res.insert(0, '_');
    }
    if is_cpp_keyword(&res) {
        res.push('_');
    }
    res
}

fn is_cpp_keyword(s: &str) -> bool {
    matches!(
        s,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "class"
            | "namespace"
            | "template"
            | "typename"
            | "operator"
            | "private"
            | "protected"
            | "public"
            | "virtual"
            | "friend"
            | "delete"
            | "new"
            | "this"
            | "throw"
            | "try"
            | "catch"
            | "bool"
            | "true"
            | "false"
            | "alignas"
            | "alignof"
            | "constexpr"
            | "decltype"
            | "noexcept"
            | "nullptr"
            | "static_assert"
            | "thread_local"
            | "explicit"
            | "export"
            | "mutable"
            | "using"
            | "wchar_t"
            | "char8_t"
            | "char16_t"
            | "char32_t"
            | "co_await"
            | "co_return"
            | "co_yield"
            | "concept"
            | "consteval"
            | "constinit"
            | "requires"
            | "and"
            | "or"
            | "not"
            | "xor"
            | "bitand"
            | "bitor"
            | "compl"
    )
}

pub fn read_compressed_uint32(blob: &[u8]) -> Option<(u32, usize)> {
    let b0 = *blob.first()?;
    if (b0 & 0x80) == 0 {
        Some((b0 as u32, 1))
    } else if (b0 & 0xC0) == 0x80 {
        let b1 = *blob.get(1)?;
        Some((((b0 & 0x3F) as u32) << 8 | (b1 as u32), 2))
    } else if (b0 & 0xE0) == 0xC0 {
        if blob.len() < 4 {
            return None;
        }
        let val = (((b0 & 0x1F) as u32) << 24)
            | ((blob[1] as u32) << 16)
            | ((blob[2] as u32) << 8)
            | (blob[3] as u32);
        Some((val, 4))
    } else if b0 == 0xF0 {
        if blob.len() < 5 {
            return None;
        }
        let val = u32::from_le_bytes([blob[1], blob[2], blob[3], blob[4]]);
        Some((val, 5))
    } else if b0 == 0xFE {
        Some((u32::MAX - 1, 1))
    } else if b0 == 0xFF {
        Some((u32::MAX, 1))
    } else {
        None
    }
}

pub fn read_compressed_int32(blob: &[u8]) -> Option<(i32, usize)> {
    let (encoded, consumed) = read_compressed_uint32(blob)?;
    if encoded == u32::MAX {
        return Some((i32::MIN, consumed));
    }
    let val = ((encoded >> 1) as i32) ^ (-((encoded & 1) as i32));
    Some((val, consumed))
}

pub fn decode_default_value(version: i32, type_enum: u8, blob: &[u8]) -> Option<String> {
    match type_enum {
        0x02 => blob
            .first()
            .map(|&b| if b != 0 { "true".into() } else { "false".into() }),
        0x03 => (blob.len() >= 2).then(|| {
            let v = u16::from_le_bytes([blob[0], blob[1]]);
            format!("'\\u{:04X}'", v)
        }),
        0x04 => blob.first().map(|&b| format!("{}", b as i8)),
        0x05 => blob.first().map(|&b| format!("{}", b)),
        0x06 => (blob.len() >= 2).then(|| format!("{}", i16::from_le_bytes([blob[0], blob[1]]))),
        0x07 => (blob.len() >= 2).then(|| format!("{}", u16::from_le_bytes([blob[0], blob[1]]))),
        0x08 => {
            if version >= 29 {
                read_compressed_int32(blob).map(|(v, _)| format!("{}", v))
            } else {
                (blob.len() >= 4)
                    .then(|| format!("{}", i32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]])))
            }
        }
        0x09 => {
            if version >= 29 {
                read_compressed_uint32(blob).map(|(v, _)| format!("{}", v))
            } else {
                (blob.len() >= 4)
                    .then(|| format!("{}", u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]])))
            }
        }
        0x0a => blob
            .get(..8)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map(|arr| format!("{}", i64::from_le_bytes(arr))),
        0x0b => blob
            .get(..8)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map(|arr| format!("{}", u64::from_le_bytes(arr))),
        0x0c => (blob.len() >= 4).then(|| {
            let v = f32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
            format!("{}f", v)
        }),
        0x0d => blob
            .get(..8)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map(|arr| format!("{}", f64::from_le_bytes(arr))),
        0x0e => {
            let (len, hdr_sz) = if version >= 29 {
                let (l, sz) = read_compressed_int32(blob)?;
                if l < 0 {
                    return Some("null".to_string());
                }
                (l as usize, sz)
            } else {
                if blob.len() < 4 {
                    return None;
                }
                let l = i32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
                if l < 0 {
                    return Some("null".to_string());
                }
                (l as usize, 4)
            };
            let end = hdr_sz.checked_add(len)?.min(blob.len());
            let s = String::from_utf8_lossy(&blob[hdr_sz..end]).replace('\\', "\\\\").replace('"', "\\\"");
            Some(format!("\"{}\"", s))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v29_compressed_default_values() {
        assert_eq!(decode_default_value(39, 0x08, &[0x00]).as_deref(), Some("0"));
        assert_eq!(decode_default_value(39, 0x08, &[0x02]).as_deref(), Some("1"));
        assert_eq!(decode_default_value(39, 0x08, &[0x04]).as_deref(), Some("2"));
        assert_eq!(decode_default_value(39, 0x08, &[0x01]).as_deref(), Some("-1"));
        assert_eq!(
            decode_default_value(39, 0x0E, &[0x04, b'o', b'k']).as_deref(),
            Some("\"ok\"")
        );
        assert_eq!(
            decode_default_value(39, 0x0A, &[0xFF, 0xFF, 0xFF, 0x1F, 0, 0, 0, 0]).as_deref(),
            Some("536870911")
        );
    }

    #[test]
    fn test_sanitize_c_ident_keywords_and_digits() {
        assert_eq!(sanitize_c_ident("return"), "return_");
        assert_eq!(sanitize_c_ident("template"), "template_");
        assert_eq!(sanitize_c_ident("enum"), "enum_");
        assert_eq!(sanitize_c_ident("123abc"), "_123abc");
        assert_eq!(sanitize_c_ident(""), "_");
        assert_eq!(sanitize_c_ident("<>c"), "__c");
    }
}
