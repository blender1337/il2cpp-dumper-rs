use anyhow::Result;
use std::collections::HashMap;
use std::fmt::Write as _;

use crate::binary::custom_elf::{infer_field_type_by_name, AdaptiveTypeResolver};
use crate::binary::il2cpp::{read_type_field_offset, RegistrationResult, TypeResolver};
use crate::binary::BinaryImage;
use crate::metadata::adaptive::AdaptiveMetadata;
use crate::metadata::Metadata;

use super::decode_default_value;

pub fn generate_dump_cs(
    bin: &BinaryImage,
    meta: &Metadata,
    reg: &RegistrationResult,
    method_vas: &HashMap<usize, u64>,
) -> Result<String> {
    let mut out = String::with_capacity(8 * 1024 * 1024);
    let mut resolver = TypeResolver::new(bin, meta, reg);

    for (img_idx, img) in meta.images.iter().enumerate() {
        let _ = writeln!(
            out,
            "// Image {}: {} - {}",
            img_idx,
            meta.get_string(img.name_index),
            img.first_type_index
        );
    }
    out.push('\n');

    for (td_idx, td) in meta.type_defs.iter().enumerate() {
        let (ns, nested_full) = resolver.resolve_full_typedef_name(td_idx);
        let (outer_prefix, leaf_raw) = match nested_full.rsplit_once('.') {
            Some((outer, leaf)) => (Some(outer), leaf),
            None => (None, nested_full.as_str()),
        };
        let leaf_clean = leaf_raw.split('`').next().unwrap_or(leaf_raw);
        let name = match outer_prefix {
            Some(outer) => format!("{}.{}", outer, leaf_clean),
            None => leaf_clean.to_string(),
        };
        let gen_suffix = format_generic_params(meta, td.generic_container_index);

        let _ = writeln!(out, "// Namespace: {}", ns);

        let vis = match td.flags & 0x07 {
            1 => "public ",
            2 => "public ",
            3 => "private ",
            4 => "protected ",
            5..=7 => "internal ",
            _ => "internal ",
        };

        let is_interface = (td.flags & 0x20) != 0;
        let is_abstract = (td.flags & 0x80) != 0;
        let is_sealed = (td.flags & 0x100) != 0;
        let is_enum = td.is_enum();
        let is_struct = td.is_valuetype() && !is_enum;

        let kind = if is_enum {
            "enum"
        } else if is_interface {
            "interface"
        } else if is_struct {
            "struct"
        } else {
            "class"
        };

        let mut mods = String::new();
        if !is_enum && !is_struct && !is_interface {
            if is_abstract && is_sealed {
                mods.push_str("static ");
            } else if is_abstract {
                mods.push_str("abstract ");
            } else if is_sealed {
                mods.push_str("sealed ");
            }
        }

        let mut parents = Vec::new();
        if is_enum && td.field_count > 0 && td.first_field_idx >= 0 {
            let fs = td.first_field_idx as usize;
            let fe = (fs + td.field_count as usize).min(meta.fields.len());
            for f in &meta.fields[fs..fe] {
                if meta.get_string(f.name_index) == "value__" {
                    let ut = resolver.format_type_name(f.type_index, 0);
                    if !ut.is_empty() && ut != "int" && ut != "object" {
                        parents.push(ut);
                    }
                    break;
                }
            }
        } else if td.parent_index >= 0 && !is_enum && !is_struct {
            let p_name = resolver.format_type_name(td.parent_index, 0);
            if p_name != "object" {
                parents.push(p_name);
            }
        }
        if td.interfaces_count > 0 && td.interfaces_start >= 0 {
            let s = td.interfaces_start as usize;
            let e = (s + td.interfaces_count as usize).min(meta.interfaces.len());
            for &iface_type_idx in &meta.interfaces[s..e] {
                parents.push(resolver.format_type_name(iface_type_idx, 0));
            }
        }
        let inherit = if parents.is_empty() {
            String::new()
        } else {
            format!(" : {}", parents.join(", "))
        };

        let _ = writeln!(
            out,
            "{}{}{} {}{}{} // TypeDefIndex: {}",
            vis, mods, kind, name, gen_suffix, inherit, td_idx
        );
        out.push_str("{\n");

        // Fields
        if td.field_count > 0 && td.first_field_idx >= 0 {
            out.push_str("\t// Fields\n");
            let fs = td.first_field_idx as usize;
            let fe = (fs + td.field_count as usize).min(meta.fields.len());
            for (local_i, f) in meta.fields[fs..fe].iter().enumerate() {
                let global_f_idx = fs + local_i;
                let fname = meta.get_string(f.name_index);
                let raw_t = resolver.read_type_by_index(f.type_index);
                let ftype = raw_t
                    .as_ref()
                    .map(|t| resolver.format_il2cpp_type(t, 0))
                    .unwrap_or_else(|| "object".to_string());
                let attrs = raw_t.as_ref().map(|t| t.attrs).unwrap_or(0);
                let fvis = match attrs & 0x07 {
                    6 => "public ",
                    4 => "protected ",
                    3 | 5 => "internal ",
                    1 => "private ",
                    _ => "private ",
                };
                let is_literal = (attrs & 0x40) != 0;
                let is_static = (attrs & 0x10) != 0;
                let is_readonly = (attrs & 0x20) != 0;

                let mut fmod = String::new();
                if is_literal {
                    fmod.push_str("const ");
                } else {
                    if is_static {
                        fmod.push_str("static ");
                    }
                    if is_readonly {
                        fmod.push_str("readonly ");
                    }
                }

                let mut default_str = String::new();
                if let Some(dv) = meta.field_default_values.get(&(global_f_idx as i32)) {
                    if let Some(blob) = meta.read_default_value_blob(dv.data_index) {
                        if let Some(dt) = resolver.read_type_by_index(dv.type_index) {
                            if let Some(val_s) = decode_default_value(meta.header.version, dt.type_enum, blob) {
                                default_str = format!(" = {}", val_s);
                            }
                        }
                    }
                }

                let offset_comment = match read_type_field_offset(
                    bin,
                    reg.field_offsets_table_va,
                    td_idx,
                    local_i,
                ) {
                    Some(off) if off >= 0 && !is_literal => {
                        let box_hdr = (bin.ptr_size() * 2) as i32;
                        let adj = if (is_struct || is_enum) && !is_static && off >= box_hdr {
                            off - box_hdr
                        } else {
                            off
                        };
                        format!(" // 0x{:X}", adj)
                    }
                    _ => String::new(),
                };

                let _ = writeln!(
                    out,
                    "\t{}{}{} {}{};{}",
                    fvis, fmod, ftype, fname, default_str, offset_comment
                );
            }
            out.push('\n');
        }

        // Properties
        if td.property_count > 0 && td.first_property_id >= 0 {
            out.push_str("\t// Properties\n");
            let ps = td.first_property_id as usize;
            let pe = (ps + td.property_count as usize).min(meta.properties.len());
            for p in &meta.properties[ps..pe] {
                let pname = meta.get_string(p.name_index);
                let mut ptype = "object".to_string();
                let mut p_is_static = false;
                let mut acc = Vec::new();
                if p.get >= 0 && td.first_method_idx >= 0 {
                    let gm_idx = td.first_method_idx as usize + p.get as usize;
                    if let Some(gm) = meta.methods.get(gm_idx) {
                        ptype = resolver.format_type_name(gm.return_type_idx, 0);
                        p_is_static |= (gm.flags & 0x10) != 0;
                    }
                    acc.push("get;");
                }
                if p.set >= 0 && td.first_method_idx >= 0 {
                    if let Some(sm) = meta.methods.get(td.first_method_idx as usize + p.set as usize) {
                        p_is_static |= (sm.flags & 0x10) != 0;
                        if ptype == "object" && sm.parameter_start >= 0 && sm.parameter_count > 0 {
                            if let Some(prm) = meta.parameters.get(sm.parameter_start as usize) {
                                ptype = resolver.format_type_name(prm.type_index, 0);
                            }
                        }
                    }
                    acc.push("set;");
                }
                let static_kw = if p_is_static { "static " } else { "" };
                let _ = writeln!(out, "\tpublic {}{} {} {{ {} }}", static_kw, ptype, pname, acc.join(" "));
            }
            out.push('\n');
        }

        // Methods
        if td.method_count > 0 && td.first_method_idx >= 0 {
            out.push_str("\t// Methods\n");
            let ms = td.first_method_idx as usize;
            let me = (ms + td.method_count as usize).min(meta.methods.len());
            for (local_m, m) in meta.methods[ms..me].iter().enumerate() {
                let global_m = ms + local_m;
                let va = method_vas.get(&global_m).copied().unwrap_or(0);
                if va != 0 {
                    let rva = va.saturating_sub(bin.image_base);
                    let foff = bin.va_to_offset(va).unwrap_or(0);
                    if m.slot != u16::MAX {
                        let _ = writeln!(
                            out,
                            "\t// RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X} Slot: {}",
                            rva, foff, va, m.slot
                        );
                    } else {
                        let _ = writeln!(
                            out,
                            "\t// RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}",
                            rva, foff, va
                        );
                    }
                } else {
                    let _ = writeln!(out, "\t// RVA: -1 Offset: -1");
                }

                let mvis = match m.flags & 0x07 {
                    6 => "public ",
                    4 => "protected ",
                    3 | 5 => "internal ",
                    1 => "private ",
                    _ => "private ",
                };
                let mut mmod = String::new();
                if (m.flags & 0x10) != 0 {
                    mmod.push_str("static ");
                } else if (m.flags & 0x400) != 0 {
                    mmod.push_str("abstract ");
                } else if (m.flags & 0x40) != 0 {
                    mmod.push_str("virtual ");
                }

                let ret = resolver.format_type_name(m.return_type_idx, 0);
                let mname = meta.get_string(m.name_index);
                let mgen = format_generic_params(meta, m.generic_container_index);

                let mut params = Vec::new();
                if m.parameter_count > 0 && m.parameter_start >= 0 {
                    let ps = m.parameter_start as usize;
                    let pe = (ps + m.parameter_count as usize).min(meta.parameters.len());
                    for p in &meta.parameters[ps..pe] {
                        let pt = resolver.format_type_name(p.type_index, 0);
                        let pn = meta.get_string(p.name_index);
                        if pn.is_empty() {
                            params.push(pt);
                        } else {
                            params.push(format!("{} {}", pt, pn));
                        }
                    }
                }

                let _ = writeln!(
                    out,
                    "\t{}{}{} {}{}({}) {{ }}",
                    mvis,
                    mmod,
                    ret,
                    mname,
                    mgen,
                    params.join(", ")
                );
            }
        }

        out.push_str("}\n\n");
    }

    Ok(out)
}

fn format_generic_params(meta: &Metadata, gc_idx: i32) -> String {
    if gc_idx < 0 {
        return String::new();
    }
    let Some(gc) = meta.generic_containers.get(gc_idx as usize) else {
        return String::new();
    };
    if gc.type_argc <= 0 || gc.generic_parameter_start < 0 {
        return String::new();
    }
    let s = gc.generic_parameter_start as usize;
    let e = (s + gc.type_argc as usize).min(meta.generic_parameters.len());
    let mut names = Vec::with_capacity(e.saturating_sub(s));
    for gp in &meta.generic_parameters[s..e] {
        let gn = meta.get_string(gp.name_index);
        if gn.is_empty() {
            names.push(format!("T{}", gp.num));
        } else {
            names.push(gn.to_string());
        }
    }
    if names.is_empty() {
        String::new()
    } else {
        format!("<{}>", names.join(", "))
    }
}

pub fn generate_adaptive_dump_cs(
    bin: &BinaryImage,
    meta: &AdaptiveMetadata,
    resolver: &AdaptiveTypeResolver,
    field_offsets: &HashMap<usize, Vec<u32>>,
    method_rvas: &[u64],
) -> Result<String> {
    let mut out = String::with_capacity(8 * 1024 * 1024);

    for (img_idx, img) in meta.images.iter().enumerate() {
        let _ = writeln!(
            out,
            "// Image {}: {} - {}",
            img_idx, img.name, img.type_start
        );
    }
    out.push('\n');

    let box_hdr = (bin.ptr_size() * 2) as u32;

    for td in &meta.types {
        let _ = writeln!(out, "// Namespace: {}", td.ns);

        let vis = match td.flags & 0x07 {
            1 | 2 => "public ",
            3 => "private ",
            4 => "protected ",
            _ => "internal ",
        };

        let is_interface = (td.flags & 0x20) != 0;
        let is_abstract = (td.flags & 0x80) != 0;
        let is_sealed = (td.flags & 0x100) != 0;
        let is_enum = td.is_enum();
        let is_struct = td.is_valuetype() && !is_enum;

        let kind = if is_enum {
            "enum"
        } else if is_interface {
            "interface"
        } else if is_struct {
            "struct"
        } else {
            "class"
        };

        let mut mods = String::new();
        if !is_enum && !is_struct && !is_interface {
            if is_abstract && is_sealed {
                mods.push_str("static ");
            } else if is_abstract {
                mods.push_str("abstract ");
            } else if is_sealed {
                mods.push_str("sealed ");
            }
        }

        let name = td.name.split('`').next().unwrap_or(&td.name);
        let _ = writeln!(
            out,
            "{}{}{} {} // TypeDefIndex: {}",
            vis, mods, kind, name, td.index
        );
        out.push_str("{\n");

        if td.field_count > 0 {
            out.push_str("\t// Fields\n");
            let fs = td.field_start;
            let fe = (fs + td.field_count as usize).min(meta.fields.len());
            let td_offsets = field_offsets.get(&td.index);
            for (local_i, f) in meta.fields[fs..fe].iter().enumerate() {
                let info = resolver.resolve_field_type(f.type_idx_raw);
                let display_type = if info.resolved {
                    info.type_name.as_str()
                } else {
                    infer_field_type_by_name(&f.name)
                };
                let fvis = match info.attrs & 0x07 {
                    6 => "public ",
                    4 => "protected ",
                    3..=5 => "internal ",
                    _ => "private ",
                };
                let is_literal = (info.attrs & 0x40) != 0;
                let is_static = info.is_static || (info.attrs & 0x10) != 0;
                let is_readonly = (info.attrs & 0x20) != 0;

                let mut fmod = String::new();
                if is_literal {
                    fmod.push_str("const ");
                } else {
                    if is_static {
                        fmod.push_str("static ");
                    }
                    if is_readonly {
                        fmod.push_str("readonly ");
                    }
                }

                let offset_comment = match td_offsets.and_then(|v| v.get(local_i)).copied() {
                    Some(off) if !is_literal && off != u32::MAX => {
                        let adj = if (is_struct || is_enum) && !is_static && off >= box_hdr {
                            off - box_hdr
                        } else {
                            off
                        };
                        format!(" // 0x{:X}", adj)
                    }
                    _ => String::new(),
                };

                let _ = writeln!(
                    out,
                    "\t{}{}{} {};{}",
                    fvis, fmod, display_type, f.name, offset_comment
                );
            }
            out.push('\n');
        }

        if td.method_count > 0 {
            out.push_str("\t// Methods\n");
            let ms = td.method_start;
            let me = (ms + td.method_count as usize).min(meta.methods.len());
            for (local_m, m) in meta.methods[ms..me].iter().enumerate() {
                let global_m = ms + local_m;
                let va = method_rvas.get(global_m).copied().unwrap_or(0);
                if va != 0 {
                    let rva = va.saturating_sub(bin.image_base);
                    let foff = bin.va_to_offset(va).unwrap_or(0);
                    if m.slot != u16::MAX {
                        let _ = writeln!(
                            out,
                            "\t// RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X} Slot: {}",
                            rva, foff, va, m.slot
                        );
                    } else {
                        let _ = writeln!(
                            out,
                            "\t// RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}",
                            rva, foff, va
                        );
                    }
                } else {
                    let _ = writeln!(out, "\t// RVA: -1 Offset: -1");
                }

                let mvis = match m.flags & 0x07 {
                    6 => "public ",
                    4 => "protected ",
                    3 | 5 => "internal ",
                    _ => "private ",
                };
                let mut mmod = String::new();
                if (m.flags & 0x10) != 0 {
                    mmod.push_str("static ");
                } else if (m.flags & 0x400) != 0 {
                    mmod.push_str("abstract ");
                } else if (m.flags & 0x40) != 0 {
                    mmod.push_str("virtual ");
                }

                let ret = resolver.resolve_type_name(m.return_type_raw);
                let mut params = Vec::new();
                if m.param_count > 0 {
                    let ps = m.param_start;
                    let pe = (ps + m.param_count as usize).min(meta.params.len());
                    for p in &meta.params[ps..pe] {
                        let pt = resolver.resolve_type_name(p.type_idx_raw);
                        if p.name.is_empty() {
                            params.push(pt);
                        } else {
                            params.push(format!("{} {}", pt, p.name));
                        }
                    }
                }

                let _ = writeln!(
                    out,
                    "\t{}{}{} {}({}) {{ }}",
                    mvis,
                    mmod,
                    ret,
                    m.name,
                    params.join(", ")
                );
            }
        }

        out.push_str("}\n\n");
    }

    Ok(out)
}
