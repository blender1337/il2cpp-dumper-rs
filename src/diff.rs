use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::Path;

use crate::codegen::sanitize_c_ident;

#[derive(Debug, Clone)]
pub struct ParsedField {
    pub name: String,
    pub field_type: String,
    pub offset: Option<u64>,
    pub is_static: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedMethod {
    pub name: String,
    pub signature: String,
    pub rva: Option<u64>,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ParsedClass {
    pub namespace: String,
    pub name: String,
    pub fields: Vec<ParsedField>,
    pub methods: Vec<ParsedMethod>,
}

pub type ClassKey = (String, String);

pub fn parse_dump_cs(text: &str) -> BTreeMap<ClassKey, ParsedClass> {
    let mut classes: BTreeMap<ClassKey, ParsedClass> = BTreeMap::new();
    let mut dup_counter = 0usize;
    let mut current_ns = String::new();
    let mut current_key: Option<ClassKey> = None;
    let mut pending_rva: Option<u64> = None;
    let mut in_fields = false;
    let mut in_methods = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if let Some(ns) = line.strip_prefix("// Namespace:") {
            let clean_ns = ns.split(';').next().unwrap_or(ns).trim().to_string();
            current_ns = clean_ns;
            current_key = None;
            pending_rva = None;
            in_fields = false;
            in_methods = false;
            continue;
        }

        if line.contains("// TypeDefIndex:")
            || (!in_fields && !in_methods && (line.starts_with("class ") || line.starts_with("public class ") || line.starts_with("internal class ") || line.starts_with("public static class ") || line.starts_with("public struct ") || line.starts_with("public enum ")))
        {
            if let Some(cls_name) = extract_class_name(line) {
                let mut map_name = cls_name.clone();
                if classes.contains_key(&(current_ns.clone(), map_name.clone())) {
                    if let Some((_, td_part)) = line.split_once("TypeDefIndex:") {
                        let td_tok = td_part.split_whitespace().next().unwrap_or("");
                        if !td_tok.is_empty() {
                            map_name = format!("{}#{}", cls_name, td_tok);
                        }
                    }
                    while classes.contains_key(&(current_ns.clone(), map_name.clone())) {
                        dup_counter += 1;
                        map_name = format!("{}#{}", cls_name, dup_counter);
                    }
                }
                let key = (current_ns.clone(), map_name);
                classes.insert(
                    key.clone(),
                    ParsedClass {
                        namespace: current_ns.clone(),
                        name: cls_name,
                        fields: Vec::new(),
                        methods: Vec::new(),
                    },
                );
                current_key = Some(key);
                pending_rva = None;
                in_fields = false;
                in_methods = false;
            }
            continue;
        }

        let Some(ref key) = current_key else {
            continue;
        };

        if line == "// Fields" {
            in_fields = true;
            in_methods = false;
            pending_rva = None;
            continue;
        }
        if line == "// Properties" {
            in_fields = false;
            in_methods = false;
            pending_rva = None;
            continue;
        }
        if line == "// Methods" {
            in_fields = false;
            in_methods = true;
            pending_rva = None;
            continue;
        }
        if line == "}" {
            current_key = None;
            in_fields = false;
            in_methods = false;
            pending_rva = None;
            continue;
        }

        if let Some(rest) = line.strip_prefix("// RVA:") {
            if let Some(hex_tok) = rest.split_whitespace().next() {
                let clean = hex_tok.trim_start_matches("0x").trim_start_matches("0X");
                pending_rva = u64::from_str_radix(clean, 16).ok();
            }
            continue;
        }

        if (in_fields || !in_methods) && (line.contains("// 0x") || line.contains("offset: 0x")) && !line.contains('(') {
            if let Some(field) = parse_field_line(line) {
                if let Some(cls) = classes.get_mut(key) {
                    cls.fields.push(field);
                }
            }
            continue;
        }

        if in_fields && (line.ends_with(';') || line.contains("; // 0x")) {
            if let Some(field) = parse_field_line(line) {
                if let Some(cls) = classes.get_mut(key) {
                    cls.fields.push(field);
                }
            }
            continue;
        }

        if !line.starts_with("//") && !line.starts_with('[') && line.contains('(') && (line.ends_with("{ }") || line.ends_with(';')) {
            if let Some(m) = parse_method_line(line, pending_rva.take()) {
                if let Some(cls) = classes.get_mut(key) {
                    cls.methods.push(m);
                }
            }
        }
    }

    classes
}

fn extract_class_name(line: &str) -> Option<String> {
    let head = line.split("//").next()?.trim();
    let tokens: Vec<&str> = head.split_whitespace().collect();
    for (i, &tok) in tokens.iter().enumerate() {
        if matches!(tok, "class" | "struct" | "enum" | "interface") {
            let name_tok = tokens.get(i + 1)?;
            return Some(name_tok.trim_end_matches('{').to_string());
        }
    }
    None
}

fn parse_field_line(line: &str) -> Option<ParsedField> {
    let mut parts = line.split("//");
    let decl_raw = parts.next()?.trim();
    let comment = parts.next().map(|s| s.trim());

    let offset = comment.and_then(|c| {
        for tok in c.split(&[' ', ';', ','][..]) {
            if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
                if !hex.is_empty() && !c.trim_start().starts_with("token:") {
                    return u64::from_str_radix(hex, 16).ok();
                }
            }
        }
        None
    });

    let decl = decl_raw.split('=').next()?.trim().trim_end_matches(';').trim();
    let is_static = decl.split_whitespace().any(|w| w == "static" || w == "const");
    let tokens: Vec<&str> = decl.split_whitespace().collect();
    let mut start = 0usize;
    while start < tokens.len()
        && matches!(
            tokens[start],
            "public"
                | "private"
                | "protected"
                | "internal"
                | "static"
                | "const"
                | "readonly"
                | "volatile"
                | "new"
                | "unsafe"
                | "fixed"
        )
    {
        start += 1;
    }
    let rest = &tokens[start..];
    if rest.len() < 2 {
        return None;
    }
    let name = rest.last()?.to_string();
    let field_type = rest[..rest.len() - 1].join(" ");
    Some(ParsedField {
        name,
        field_type,
        offset,
        is_static,
    })
}

fn parse_method_line(line: &str, rva: Option<u64>) -> Option<ParsedMethod> {
    let decl = line.trim_end_matches("{ }").trim_end_matches(';').trim();
    let paren = decl.find('(')?;
    let before = decl[..paren].trim();
    let name = before.split_whitespace().last()?.to_string();
    Some(ParsedMethod {
        name,
        signature: decl.to_string(),
        rva,
    })
}

pub fn compute_diff_report(
    old_path: &Path,
    new_path: &Path,
    filter: Option<&str>,
    emit_cpp: bool,
    only_changed: bool,
) -> Result<(String, usize, usize, usize)> {
    let old_text = std::fs::read_to_string(old_path)
        .with_context(|| format!("Failed to read old dump: {}", old_path.display()))?;
    let new_text = std::fs::read_to_string(new_path)
        .with_context(|| format!("Failed to read new dump: {}", new_path.display()))?;

    let old_classes = parse_dump_cs(&old_text);
    let new_classes = parse_dump_cs(&new_text);

    let filter_lower = filter.map(|s| s.to_lowercase());
    let mut total_shifted = 0usize;
    let mut total_added = 0usize;
    let mut total_removed = 0usize;
    let mut out = String::new();

    for (key, new_cls) in &new_classes {
        if let Some(ref f) = filter_lower {
            let full = format!("{}.{}", key.0, key.1).to_lowercase();
            if !full.contains(f) {
                continue;
            }
        }
        let Some(old_cls) = old_classes.get(key) else {
            continue;
        };

        let old_fields: HashMap<&str, &ParsedField> =
            old_cls.fields.iter().map(|f| (f.name.as_str(), f)).collect();
        let new_fields: HashMap<&str, &ParsedField> =
            new_cls.fields.iter().map(|f| (f.name.as_str(), f)).collect();

        let mut class_lines = Vec::new();

        for nf in &new_cls.fields {
            if nf.is_static {
                continue;
            }
            match old_fields.get(nf.name.as_str()) {
                Some(of) => match (of.offset, nf.offset) {
                    (Some(oo), Some(no)) if oo != no => {
                        total_shifted += 1;
                        let delta = no as i64 - oo as i64;
                        if emit_cpp {
                            class_lines.push(format!(
                                "#define {}_{} 0x{:X} // shifted from 0x{:X} ({:+#x})",
                                sanitize_c_ident(&key.1),
                                sanitize_c_ident(&nf.name),
                                no,
                                oo,
                                delta
                            ));
                        } else {
                            class_lines.push(format!(
                                "  [~] {} {}: 0x{:X} -> 0x{:X} ({:+#x})",
                                nf.field_type, nf.name, oo, no, delta
                            ));
                        }
                    }
                    (Some(oo), Some(no)) if !only_changed => {
                        if emit_cpp {
                            class_lines.push(format!(
                                "#define {}_{} 0x{:X} // unchanged",
                                sanitize_c_ident(&key.1),
                                sanitize_c_ident(&nf.name),
                                no
                            ));
                        } else {
                            class_lines.push(format!(
                                "  [=] {} {}: 0x{:X} (unchanged)",
                                nf.field_type, nf.name, oo
                            ));
                        }
                    }
                    _ => {}
                },
                None => {
                    total_added += 1;
                    if let Some(no) = nf.offset {
                        if emit_cpp {
                            class_lines.push(format!(
                                "#define {}_{} 0x{:X} // NEW {}",
                                sanitize_c_ident(&key.1),
                                sanitize_c_ident(&nf.name),
                                no,
                                nf.field_type
                            ));
                        } else {
                            class_lines.push(format!(
                                "  [+] {} {}: 0x{:X}",
                                nf.field_type, nf.name, no
                            ));
                        }
                    }
                }
            }
        }

        for of in &old_cls.fields {
            if !of.is_static && !new_fields.contains_key(of.name.as_str()) {
                total_removed += 1;
                if !emit_cpp {
                    class_lines.push(format!("  [-] {} {}", of.field_type, of.name));
                }
            }
        }

        let old_methods: HashMap<&str, Option<u64>> = old_cls
            .methods
            .iter()
            .map(|m| (m.signature.as_str(), m.rva))
            .collect();
        for nm in &new_cls.methods {
            if let Some(Some(orva)) = old_methods.get(nm.signature.as_str()) {
                if let Some(nrva) = nm.rva {
                    if *orva != nrva {
                        total_shifted += 1;
                        if emit_cpp {
                            class_lines.push(format!(
                                "#define RVA_{}_{} 0x{:X} // from 0x{:X}",
                                sanitize_c_ident(&key.1),
                                sanitize_c_ident(&nm.name),
                                nrva,
                                orva
                            ));
                        } else {
                            class_lines.push(format!(
                                "  [~] RVA {}(): 0x{:X} -> 0x{:X}",
                                nm.name, orva, nrva
                            ));
                        }
                    }
                }
            }
        }

        if !class_lines.is_empty() {
            let _ = writeln!(out, "// {}.{}", key.0, key.1);
            for l in class_lines {
                let _ = writeln!(out, "{}", l);
            }
        }
    }

    Ok((out, total_shifted, total_added, total_removed))
}

pub fn run_diff(
    old_path: &Path,
    new_path: &Path,
    filter: Option<&str>,
    emit_cpp: bool,
    only_changed: bool,
) -> Result<()> {
    let (report, total_shifted, total_added, total_removed) =
        compute_diff_report(old_path, new_path, filter, emit_cpp, only_changed)?;
    if !report.is_empty() {
        print!("{}", report);
    }
    eprintln!(
        "Diff summary: {} shifted, {} added, {} removed",
        total_shifted, total_added, total_removed
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_detects_shifted_field_and_rva() {
        let old_cs = r#"
// Namespace: Battle
public class ShowEntity : ShowActor // TypeDefIndex: 10
{
    // Fields
    public int m_Hp; // 0x1A4
    // Methods
    // RVA: 0x1000 Offset: 0x1000 VA: 0x180001000
    public void Update() { }
}
"#;
        let new_cs = r#"
// Namespace: Battle
public class ShowEntity : ShowActor // TypeDefIndex: 10
{
    // Fields
    public int m_Hp; // 0x1AC
    // Methods
    // RVA: 0x2000 Offset: 0x2000 VA: 0x180002000
    public void Update() { }
}
"#;
        let old_m = parse_dump_cs(old_cs);
        let new_m = parse_dump_cs(new_cs);
        let key = ("Battle".to_string(), "ShowEntity".to_string());
        assert_eq!(old_m[&key].fields[0].offset, Some(0x1A4));
        assert_eq!(new_m[&key].fields[0].offset, Some(0x1AC));
        assert_eq!(old_m[&key].methods[0].rva, Some(0x1000));
        assert_eq!(new_m[&key].methods[0].rva, Some(0x2000));
    }

    #[test]
    fn test_parse_dump_cs_generic_field_type_and_duplicate_classes() {
        let sample = r#"
// Namespace: 
internal sealed class <>c // TypeDefIndex: 10
{
    // Fields
    public Dictionary<int, string> mapA; // 0x10
}
// Namespace: 
internal sealed class <>c // TypeDefIndex: 20
{
    // Fields
    public Dictionary<int, List<float>> mapB; // 0x18
}
"#;
        let parsed = parse_dump_cs(sample);
        assert_eq!(parsed.len(), 2);
        let values: Vec<&ParsedClass> = parsed.values().collect();
        assert_eq!(values[0].fields.len(), 1);
        assert_eq!(values[0].fields[0].field_type, "Dictionary<int, string>");
        assert_eq!(values[0].fields[0].name, "mapA");
        assert_eq!(values[1].fields.len(), 1);
        assert_eq!(values[1].fields[0].field_type, "Dictionary<int, List<float>>");
        assert_eq!(values[1].fields[0].name, "mapB");
    }
}
