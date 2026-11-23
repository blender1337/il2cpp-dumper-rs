use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;

use super::il2cpp_h::map_c_type;
use super::sanitize_c_ident;
use crate::binary::il2cpp::{RegistrationResult, TypeResolver};
use crate::binary::BinaryImage;
use crate::metadata::adaptive::AdaptiveMetadata;
use crate::metadata::Metadata;

#[derive(Serialize)]
struct ScriptMethod {
    #[serde(rename = "Address")]
    address: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Signature")]
    signature: String,
}

#[derive(Serialize)]
struct ScriptStringEntry {
    #[serde(rename = "Index")]
    index: usize,
    #[serde(rename = "Value")]
    value: String,
    #[serde(rename = "Address")]
    address: u64,
}

#[derive(Serialize)]
struct ScriptMetadataEntry {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Token")]
    token: u32,
    #[serde(rename = "Fields")]
    fields: u16,
    #[serde(rename = "Methods")]
    methods: u16,
}

#[derive(Serialize)]
struct ScriptOutput {
    #[serde(rename = "ScriptMethod")]
    script_method: Vec<ScriptMethod>,
    #[serde(rename = "ScriptString")]
    script_string: Vec<ScriptStringEntry>,
    #[serde(rename = "ScriptMetadata")]
    script_metadata: Vec<ScriptMetadataEntry>,
    #[serde(rename = "Addresses")]
    addresses: Vec<u64>,
}

fn read_u32_slice(slice: &[u8], off: usize) -> Option<u32> {
    let bytes = slice.get(off..off + 4)?;
    let arr: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

fn is_clean_script_string(s: &str) -> bool {
    !s.is_empty()
        && !s
            .chars()
            .any(|c| (c as u32) < 0x20 && !matches!(c, '\r' | '\n' | '\t'))
}

fn extract_script_strings(meta: &Metadata) -> Vec<ScriptStringEntry> {
    let Ok(lit_tbl) = meta.header.string_literal.slice(&meta.raw) else {
        return Vec::new();
    };
    let Ok(lit_data) = meta.header.string_literal_data.slice(&meta.raw) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    if meta.header.version >= 35 {
        let count = lit_tbl.len() / 4;
        for idx in 0..count {
            let Some(start) = read_u32_slice(lit_tbl, idx * 4).map(|v| v as usize) else {
                break;
            };
            let end = if idx + 1 < count {
                read_u32_slice(lit_tbl, (idx + 1) * 4)
                    .map(|v| v as usize)
                    .unwrap_or(lit_data.len())
            } else {
                lit_data.len()
            };
            if start < end && end <= lit_data.len() {
                let capped = &lit_data[start..end.min(start + 256)];
                if let Ok(s) = std::str::from_utf8(capped) {
                    if is_clean_script_string(s) {
                        out.push(ScriptStringEntry {
                            index: idx,
                            value: s.to_string(),
                            address: 0,
                        });
                    }
                }
            }
        }
    } else {
        let count = lit_tbl.len() / 8;
        for idx in 0..count {
            let Some(len) = read_u32_slice(lit_tbl, idx * 8).map(|v| v as usize) else {
                break;
            };
            let Some(off) = read_u32_slice(lit_tbl, idx * 8 + 4).map(|v| v as usize) else {
                break;
            };
            if len > 0 && off < lit_data.len() {
                let take = len.min(256).min(lit_data.len() - off);
                if let Ok(s) = std::str::from_utf8(&lit_data[off..off + take]) {
                    if is_clean_script_string(s) {
                        out.push(ScriptStringEntry {
                            index: idx,
                            value: s.to_string(),
                            address: 0,
                        });
                    }
                }
            }
        }
    }
    out
}

pub fn write_script_json<W: Write>(
    writer: W,
    bin: &BinaryImage,
    meta: &Metadata,
    reg: &RegistrationResult,
    method_vas: &HashMap<usize, u64>,
) -> Result<()> {
    let mut script_methods = Vec::with_capacity(method_vas.len());
    let mut addresses = Vec::with_capacity(method_vas.len());
    let mut script_metadata = Vec::with_capacity(meta.type_defs.len());
    let mut seen_sigs: HashMap<String, usize> = HashMap::with_capacity(method_vas.len());
    let mut resolver = TypeResolver::new(bin, meta, reg);
    let ptr_sz = bin.ptr_size();

    for (td_idx, td) in meta.type_defs.iter().enumerate() {
        let (root_ns, nested_full) = resolver.resolve_full_typedef_name(td_idx);
        let full_cls = if root_ns.is_empty() {
            nested_full
        } else {
            format!("{}.{}", root_ns, nested_full)
        };
        script_metadata.push(ScriptMetadataEntry {
            name: full_cls.clone(),
            token: td.token,
            fields: td.field_count,
            methods: td.method_count,
        });

        if td.method_count == 0 || td.first_method_idx < 0 {
            continue;
        }
        let ms = td.first_method_idx as usize;
        let me = (ms + td.method_count as usize).min(meta.methods.len());
        for (local_i, m) in meta.methods[ms..me].iter().enumerate() {
            let global_m = ms + local_i;
            if let Some(&va) = method_vas.get(&global_m) {
                if va != 0 {
                    let rva = va.saturating_sub(bin.image_base);
                    let mname = meta.get_string(m.name_index);
                    let full_name = format!("{}$${}", full_cls, mname);
                    let base_sig_name = sanitize_c_ident(&full_name);
                    let cnt = seen_sigs.entry(base_sig_name.clone()).or_insert(0);
                    *cnt += 1;
                    let unique_sig_name = if *cnt == 1 {
                        base_sig_name
                    } else {
                        format!("{}_{}", base_sig_name, *cnt)
                    };

                    let mut params_c = Vec::new();
                    if (m.flags & 0x10) == 0 {
                        params_c.push("void* __this".to_string());
                    }
                    if m.parameter_count > 0 && m.parameter_start >= 0 {
                        let ps = m.parameter_start as usize;
                        let pe = (ps + m.parameter_count as usize).min(meta.parameters.len());
                        for (pi, p) in meta.parameters[ps..pe].iter().enumerate() {
                            let pt_name = resolver.format_type_name(p.type_index, 0);
                            let (c_t, _) = map_c_type(&pt_name, ptr_sz);
                            let mut pname = sanitize_c_ident(meta.get_string(p.name_index));
                            if pname.is_empty() {
                                pname = format!("arg{}", pi);
                            }
                            params_c.push(format!("{} {}", c_t, pname));
                        }
                    }
                    params_c.push("void* method".to_string());
                    let ret_name = resolver.format_type_name(m.return_type_idx, 0);
                    let ret_c = if ret_name == "void" {
                        "void"
                    } else {
                        map_c_type(&ret_name, ptr_sz).0
                    };

                    script_methods.push(ScriptMethod {
                        address: rva,
                        name: full_name,
                        signature: format!(
                            "{} {}({});",
                            ret_c,
                            unique_sig_name,
                            params_c.join(", ")
                        ),
                    });
                    addresses.push(rva);
                }
            }
        }
    }

    let doc = ScriptOutput {
        script_method: script_methods,
        script_string: extract_script_strings(meta),
        script_metadata,
        addresses,
    };
    serde_json::to_writer_pretty(writer, &doc)?;
    Ok(())
}

pub fn write_adaptive_script_json<W: Write>(
    writer: W,
    bin: &BinaryImage,
    meta: &AdaptiveMetadata,
    method_rvas: &[u64],
) -> Result<()> {
    let mut script_methods = Vec::with_capacity(method_rvas.len().min(meta.methods.len()));
    let mut addresses = Vec::with_capacity(method_rvas.len().min(meta.methods.len()));
    let mut script_metadata = Vec::with_capacity(meta.types.len());
    let mut seen_sigs: HashMap<String, usize> = HashMap::with_capacity(meta.methods.len());

    for td in &meta.types {
        let full_cls = if td.fullname.is_empty() {
            td.name.as_str()
        } else {
            td.fullname.as_str()
        };
        script_metadata.push(ScriptMetadataEntry {
            name: full_cls.to_string(),
            token: td.token,
            fields: td.field_count,
            methods: td.method_count,
        });

        if td.method_count == 0 {
            continue;
        }
        let ms = td.method_start;
        let me = (ms + td.method_count as usize).min(meta.methods.len());
        for (local_i, m) in meta.methods[ms..me].iter().enumerate() {
            let global_m = ms + local_i;
            if let Some(&va) = method_rvas.get(global_m) {
                if va != 0 {
                    let rva = va.saturating_sub(bin.image_base);
                    let full_name = format!("{}$${}", full_cls, m.name);
                    let base_sig_name = sanitize_c_ident(&full_name);
                    let cnt = seen_sigs.entry(base_sig_name.clone()).or_insert(0);
                    *cnt += 1;
                    let unique_sig_name = if *cnt == 1 {
                        base_sig_name
                    } else {
                        format!("{}_{}", base_sig_name, *cnt)
                    };
                    script_methods.push(ScriptMethod {
                        address: rva,
                        name: full_name,
                        signature: format!(
                            "void* {}(void* __this, void* method);",
                            unique_sig_name
                        ),
                    });
                    addresses.push(rva);
                }
            }
        }
    }

    let doc = ScriptOutput {
        script_method: script_methods,
        script_string: Vec::new(),
        script_metadata,
        addresses,
    };
    serde_json::to_writer_pretty(writer, &doc)?;
    Ok(())
}

/// Return a standalone IDA Python script that imports methods and signatures from `script.json`.
pub fn generate_ida_import_py() -> &'static str {
    r#"# Auto-generated by il2cpp-dumper-rs
import json
import os
import idaapi
import idc
import ida_name
import ida_funcs

def main():
    base = idaapi.get_imagebase()
    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script.json")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    methods = data.get("ScriptMethod", [])
    named = 0
    typed = 0
    flags = ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE
    for entry in methods:
        addr = base + int(entry["Address"])
        name = entry["Name"]
        sig = entry.get("Signature", "")
        if ida_funcs.get_func(addr) is None:
            ida_funcs.add_func(addr)
        if ida_name.set_name(addr, name, flags):
            named += 1
        if sig and idc.SetType(addr, sig):
            typed += 1

    print("[il2cpp-dumper-rs] Applied %d/%d names, %d signatures." % (named, len(methods), typed))

if __name__ == "__main__":
    main()
"#
}

/// Return a standalone Ghidra Python script that imports methods and comments from `script.json`.
pub fn generate_ghidra_import_py() -> &'static str {
    r#"# Auto-generated by il2cpp-dumper-rs (run in Ghidra Script Manager)
import json
import os
from ghidra.program.model.symbol import SourceType

def run():
    base = currentProgram.getImageBase().getOffset()
    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script.json")
    with open(json_path, "r") as f:
        data = json.load(f)

    af = currentProgram.getAddressFactory().getDefaultAddressSpace()
    methods = data.get("ScriptMethod", [])
    count = 0
    for entry in methods:
        addr = af.getAddress(base + int(entry["Address"]))
        func = getFunctionAt(addr)
        if func is None:
            func = createFunction(addr, entry["Name"])
        else:
            func.setName(entry["Name"], SourceType.USER_DEFINED)
        sig = entry.get("Signature", "")
        if sig and func is not None:
            func.setComment(sig)
        count += 1

    println("[il2cpp-dumper-rs] Imported %d methods into Ghidra." % count)

run()
"#
}
