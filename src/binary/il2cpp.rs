use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::metadata::Metadata;
use super::BinaryImage;

#[derive(Debug, Clone)]
pub struct Il2CppType {
    pub data: u64,
    pub attrs: u16,
    pub type_enum: u8,
    pub byref: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CodeGenModuleInfo {
    pub va: u64,
    pub name: String,
    pub method_pointer_count: usize,
    pub method_pointers_va: u64,
}

#[derive(Debug)]
pub struct RegistrationResult {
    pub code_registration_va: Option<u64>,
    pub metadata_registration_va: u64,
    pub num_types: usize,
    pub types_table_va: u64,
    pub field_offsets_table_va: u64,
    pub code_gen_modules: Vec<CodeGenModuleInfo>,
    pub legacy_method_pointers_va: Option<u64>,
    pub legacy_method_pointers_count: usize,
}

pub fn scan_pointer_hits(bin: &BinaryImage, target_va: u64) -> Vec<u64> {
    let ptr_sz = bin.ptr_size();
    let mut hits = Vec::new();
    for s in &bin.sections {
        if !s.is_data {
            continue;
        }
        let start = s.file_offset;
        let end = (s.file_offset + s.file_size).min(bin.bytes.len());
        if end <= start + ptr_sz {
            continue;
        }
        let mut off = start;
        while off + ptr_sz <= end {
            let val = if ptr_sz == 8 {
                let Ok(arr) = <[u8; 8]>::try_from(&bin.bytes[off..off + 8]) else {
                    break;
                };
                u64::from_le_bytes(arr)
            } else {
                let Ok(arr) = <[u8; 4]>::try_from(&bin.bytes[off..off + 4]) else {
                    break;
                };
                u32::from_le_bytes(arr) as u64
            };
            if val == target_va {
                hits.push(s.va_start + (off - start) as u64);
            }
            off += ptr_sz;
        }
    }
    hits
}

fn looks_like_field_offsets_table(bin: &BinaryImage, table_va: u64, type_def_count: usize) -> bool {
    if !bin.is_valid_va(table_va) || type_def_count == 0 {
        return false;
    }
    let ptr_sz = bin.ptr_size() as u64;
    let sample = type_def_count.min(200);
    let mut valid_hits = 0usize;
    for k in 0..sample {
        if let Some(arr_va) = bin.read_ptr(table_va + k as u64 * ptr_sz) {
            if arr_va != 0 && bin.is_valid_va(arr_va) {
                valid_hits += 1;
                if valid_hits >= 5 {
                    return true;
                }
            }
        }
    }
    false
}

fn probe_types_pair_near(
    bin: &BinaryImage,
    base: u64,
    preferred_off: u64,
    target: u64,
) -> Option<(usize, u64)> {
    let ptr_sz = bin.ptr_size() as u64;
    let try_at = |off: u64| -> Option<(usize, u64)> {
        let num_types = bin.read_ptr(base + off).unwrap_or(0);
        let types_ptr = bin.read_ptr(base + off + ptr_sz).unwrap_or(0);
        if num_types >= target && num_types < 10_000_000 && bin.is_valid_va(types_ptr) {
            let first_type_va = bin.read_ptr(types_ptr).unwrap_or(0);
            if bin.is_valid_va(first_type_va) {
                return Some((num_types as usize, types_ptr));
            }
        }
        None
    };

    if let Some(res) = try_at(preferred_off) {
        return Some(res);
    }
    for off in (0..=14 * ptr_sz).step_by(ptr_sz as usize) {
        if let Some(res) = try_at(off) {
            return Some(res);
        }
    }
    None
}

fn probe_mr_at(
    bin: &BinaryImage,
    mr: u64,
    target: u64,
    version: i32,
    num_types_idx: u64,
) -> Option<(u64, usize, u64, u64)> {
    if let Ok(res) = load_metadata_registration_at(bin, mr, version) {
        return Some(res);
    }
    let ptr_sz = bin.ptr_size() as u64;
    let type_def_count = target as usize;
    for off in (0..=20 * ptr_sz).step_by(ptr_sz as usize) {
        let cnt = bin.read_ptr(mr + off).unwrap_or(0);
        if cnt == target {
            let fo_tbl = bin.read_ptr(mr + off + ptr_sz).unwrap_or(0);
            if looks_like_field_offsets_table(bin, fo_tbl, type_def_count) {
                if let Some((num_types, types_ptr)) =
                    probe_types_pair_near(bin, mr, num_types_idx, target)
                {
                    return Some((mr, num_types, types_ptr, fo_tbl));
                }
            }
        }
    }
    None
}
pub fn locate_metadata_registration(bin: &BinaryImage, type_def_count: usize, version: i32) -> Result<(u64, usize, u64, u64)> {
    let ptr_sz = bin.ptr_size() as u64;
    let target = type_def_count as u64;
    let field_offsets_rel: u64 = if version >= 108 { 6 * ptr_sz } else { 10 * ptr_sz };
    let num_types_idx = if version >= 108 { 4 * ptr_sz } else { 6 * ptr_sz };

    // Pass 1: strict adjacent (fieldOffsetsCount, fieldOffsets, typeDefinitionsSizesCount, typeDefinitionsSizes)
    for s in &bin.sections {
        if !s.is_data {
            continue;
        }
        let start = s.file_offset;
        let end = (s.file_offset + s.file_size).min(bin.bytes.len());
        if end <= start + (6 * ptr_sz as usize) {
            continue;
        }
        let mut off = start;
        while off + (4 * ptr_sz as usize) <= end {
            let va = s.va_start + (off - start) as u64;
            let c1 = bin.read_ptr(va).unwrap_or(0);
            if c1 == target {
                let p1 = bin.read_ptr(va + ptr_sz).unwrap_or(0);
                let c2 = bin.read_ptr(va + 2 * ptr_sz).unwrap_or(0);
                let p2 = bin.read_ptr(va + 3 * ptr_sz).unwrap_or(0);
                if c2 == target
                    && bin.is_valid_va(p1)
                    && bin.is_valid_va(p2)
                    && va >= field_offsets_rel
                {
                    let base = va - field_offsets_rel;
                    if let Some((num_types, types_ptr)) =
                        probe_types_pair_near(bin, base, num_types_idx, target)
                    {
                        return Ok((base, num_types, types_ptr, p1));
                    }
                }
            }
            off += ptr_sz as usize;
        }
    }

    // Pass 2: relaxed single (fieldOffsetsCount == target, fieldOffsets) with table content validation
    for s in &bin.sections {
        if !s.is_data {
            continue;
        }
        let start = s.file_offset;
        let end = (s.file_offset + s.file_size).min(bin.bytes.len());
        if end <= start + (2 * ptr_sz as usize) {
            continue;
        }
        let mut off = start;
        while off + (2 * ptr_sz as usize) <= end {
            let va = s.va_start + (off - start) as u64;
            let c1 = bin.read_ptr(va).unwrap_or(0);
            if c1 == target && va >= field_offsets_rel {
                let p1 = bin.read_ptr(va + ptr_sz).unwrap_or(0);
                if looks_like_field_offsets_table(bin, p1, type_def_count) {
                    let base = va - field_offsets_rel;
                    if let Some((num_types, types_ptr)) =
                        probe_types_pair_near(bin, base, num_types_idx, target)
                    {
                        return Ok((base, num_types, types_ptr, p1));
                    }
                }
            }
            off += ptr_sz as usize;
        }
    }

    // Pass 3: ELF .dynsym/.init_array or PE .CRT$XCU registration tracing fallback
    if bin.format == super::BinaryFormat::Pe {
        if let Some((_cr, mr)) = super::pe::trace_pe_registration(bin) {
            if let Some(res) = probe_mr_at(bin, mr, target, version, num_types_idx) {
                return Ok(res);
            }
        }
    } else {
        let ctx = super::custom_elf::find_registration_context(bin, None);
        if let Some(mr) = ctx.meta_reg_va {
            if let Some(res) = probe_mr_at(bin, mr, target, version, num_types_idx) {
                return Ok(res);
            }
        }
    }

    bail!(
        "Failed to auto-locate Il2CppMetadataRegistration (type_defs={}). Try passing --meta-reg 0x...",
        type_def_count
    )
}

pub fn load_metadata_registration_at(bin: &BinaryImage, base: u64, version: i32) -> Result<(u64, usize, u64, u64)> {
    let ptr_sz = bin.ptr_size() as u64;
    let num_types_idx = if version >= 108 { 4 * ptr_sz } else { 6 * ptr_sz };
    let field_offsets_idx = if version >= 108 { 6 * ptr_sz } else { 10 * ptr_sz };
    let num_types = bin.read_ptr(base + num_types_idx).unwrap_or(0);
    let types_ptr = bin.read_ptr(base + num_types_idx + ptr_sz).unwrap_or(0);
    let field_offsets_ptr = bin.read_ptr(base + field_offsets_idx + ptr_sz).unwrap_or(0);
    if num_types == 0 || !bin.is_valid_va(types_ptr) || !bin.is_valid_va(field_offsets_ptr) {
        bail!("Invalid manual MetadataRegistration VA 0x{:x}", base);
    }
    Ok((base, num_types as usize, types_ptr, field_offsets_ptr))
}

pub fn locate_code_gen_modules(
    bin: &BinaryImage,
    image_names: &[String],
) -> Result<(Option<u64>, Vec<CodeGenModuleInfo>)> {
    let ptr_sz = bin.ptr_size() as u64;
    let image_count = image_names.len();
    if image_count == 0 {
        return Ok((None, Vec::new()));
    }

    // Search using the anchor image name ("mscorlib.dll" if present, else first image)
    let anchor = image_names
        .iter()
        .find(|n| *n == "mscorlib.dll")
        .unwrap_or(&image_names[0]);

    let str_vas = bin.find_cstr_vas(anchor);
    for str_va in str_vas {
        let mod_candidates = scan_pointer_hits(bin, str_va);
        for mod_va in mod_candidates {
            let mcnt = bin.read_ptr(mod_va + ptr_sz).unwrap_or(u64::MAX);
            if mcnt > 500_000 {
                continue;
            }
            let ptr_hits = scan_pointer_hits(bin, mod_va);
            for hit_va in ptr_hits {
                // Probe backwards up to image_count entries to locate the start of codeGenModules[]
                for back in 0..image_count {
                    let table_start = match hit_va.checked_sub(back as u64 * ptr_sz) {
                        Some(v) => v,
                        None => continue,
                    };
                    if let Some(mods) = try_read_codegen_table(bin, table_start, image_count) {
                        // Look for CodeRegistration tail pair: (image_count, table_start)
                        let cr_tail_hits = scan_pointer_hits(bin, table_start);
                        let mut cr_va = None;
                        for th in cr_tail_hits {
                            if th >= ptr_sz && bin.read_ptr(th - ptr_sz) == Some(image_count as u64) {
                                cr_va = Some(th - ptr_sz);
                                break;
                            }
                        }
                        return Ok((cr_va, mods));
                    }
                }
            }
        }
    }

    bail!("Failed to locate CodeGenModules table (images={})", image_count)
}

fn try_read_codegen_table(bin: &BinaryImage, table_va: u64, count: usize) -> Option<Vec<CodeGenModuleInfo>> {
    let ptr_sz = bin.ptr_size() as u64;
    // Quick pre-check endpoints and first 3 entries
    let check_indices = [0, 1.min(count - 1), count - 1];
    for &idx in &check_indices {
        let mod_va = bin.read_ptr(table_va + idx as u64 * ptr_sz)?;
        if !bin.is_valid_va(mod_va) {
            return None;
        }
        let name_va = bin.read_ptr(mod_va)?;
        let name = bin.read_cstr(name_va)?;
        if !name.ends_with(".dll") && name != "__Generated" {
            return None;
        }
    }

    let mut modules = Vec::with_capacity(count);
    let mut valid_mptrs = 0usize;
    for i in 0..count {
        let mod_va = bin.read_ptr(table_va + i as u64 * ptr_sz)?;
        let name_va = bin.read_ptr(mod_va)?;
        let name = bin.read_cstr(name_va)?;
        let mcnt = bin.read_ptr(mod_va + ptr_sz)? as usize;
        let mptrs = bin.read_ptr(mod_va + 2 * ptr_sz)?;
        if mcnt > 500_000 {
            return None;
        }
        if mcnt > 0 && mptrs == 0 {
            return None;
        }
        if mcnt == 0 || bin.is_valid_va(mptrs) {
            valid_mptrs += 1;
        }
        modules.push(CodeGenModuleInfo {
            va: mod_va,
            name,
            method_pointer_count: mcnt,
            method_pointers_va: mptrs,
        });
    }
    if valid_mptrs == 0 {
        return None;
    }
    Some(modules)
}

/// Locate legacy `Il2CppCodeRegistration` (`v16..=v24.1`) flat `(methodPointersCount, methodPointers)`.
pub fn locate_legacy_code_registration(
    bin: &BinaryImage,
    expected_methods: usize,
) -> Option<(u64, usize, u64)> {
    let ptr_sz = bin.ptr_size() as u64;
    let min_cnt = expected_methods.saturating_div(2).max(1) as u64;
    let max_cnt = expected_methods.saturating_mul(8).max(10_000) as u64;

    let is_exec_ptr = |va: u64| -> bool {
        bin.sections
            .iter()
            .any(|sec| sec.is_exec && va >= sec.va_start && va < sec.va_end)
    };

    for s in &bin.sections {
        if !s.is_data || s.file_size < (2 * ptr_sz as usize) {
            continue;
        }
        let start = s.file_offset;
        let end = (s.file_offset + s.file_size).min(bin.bytes.len());
        let mut off = start;
        while off + (2 * ptr_sz as usize) <= end {
            let va = s.va_start + (off - start) as u64;
            let cnt = bin.read_ptr(va).unwrap_or(0);
            if (min_cnt..=max_cnt).contains(&cnt) {
                let tbl = bin.read_ptr(va + ptr_sz).unwrap_or(0);
                if bin.is_valid_va(tbl) {
                    let sample = (cnt as usize).min(64);
                    let mut exec_hits = 0usize;
                    let mut bad = false;
                    for k in 0..sample {
                        let p = bin.read_ptr(tbl + k as u64 * ptr_sz).unwrap_or(0);
                        if p != 0 {
                            if !bin.is_valid_va(p) {
                                if k < 16 {
                                    bad = true;
                                }
                                break;
                            }
                            if is_exec_ptr(p) {
                                exec_hits += 1;
                            }
                        }
                    }
                    if !bad && exec_hits >= 5 {
                        return Some((va, cnt as usize, tbl));
                    }
                }
            }
            off += ptr_sz as usize;
        }
    }
    None
}

pub fn run_registration_scan(
    bin: &BinaryImage,
    meta_prelim_type_defs: usize,
    meta_version: i32,
    image_names: &[String],
    legacy_method_count: usize,
    manual_meta_reg: Option<u64>,
) -> Result<RegistrationResult> {
    let (meta_reg_va, num_types, types_table_va, field_offsets_table_va) = match manual_meta_reg {
        Some(va) => load_metadata_registration_at(bin, va, meta_version)?,
        None => locate_metadata_registration(bin, meta_prelim_type_defs, meta_version)?,
    };

    match locate_code_gen_modules(bin, image_names) {
        Ok((code_reg_va, code_gen_modules)) => Ok(RegistrationResult {
            code_registration_va: code_reg_va,
            metadata_registration_va: meta_reg_va,
            num_types,
            types_table_va,
            field_offsets_table_va,
            code_gen_modules,
            legacy_method_pointers_va: None,
            legacy_method_pointers_count: 0,
        }),
        Err(err) => {
            if meta_version <= 24 {
                if let Some((cr_va, cnt, tbl)) =
                    locate_legacy_code_registration(bin, legacy_method_count)
                {
                    return Ok(RegistrationResult {
                        code_registration_va: Some(cr_va),
                        metadata_registration_va: meta_reg_va,
                        num_types,
                        types_table_va,
                        field_offsets_table_va,
                        code_gen_modules: Vec::new(),
                        legacy_method_pointers_va: Some(tbl),
                        legacy_method_pointers_count: cnt,
                    });
                }
            }
            Err(err)
        }
    }
}

pub struct TypeResolver<'a> {
    pub bin: &'a BinaryImage,
    pub meta: &'a Metadata,
    pub types_table_va: u64,
    pub num_types: usize,
    pub version: i32,
    type_cache: HashMap<u64, Il2CppType>,
}

impl<'a> TypeResolver<'a> {
    pub fn new(bin: &'a BinaryImage, meta: &'a Metadata, reg: &RegistrationResult) -> Self {
        Self {
            bin,
            meta,
            types_table_va: reg.types_table_va,
            num_types: reg.num_types,
            version: meta.header.version,
            type_cache: HashMap::new(),
        }
    }

    pub fn read_type_by_index(&mut self, index: i32) -> Option<Il2CppType> {
        if index < 0 || (index as usize) >= self.num_types {
            return None;
        }
        let ptr_sz = self.bin.ptr_size() as u64;
        let va = self.bin.read_ptr(self.types_table_va + (index as u64) * ptr_sz)?;
        self.read_type_at_va(va)
    }

    pub fn read_type_at_va(&mut self, va: u64) -> Option<Il2CppType> {
        if let Some(t) = self.type_cache.get(&va) {
            return Some(t.clone());
        }
        let ptr_sz = self.bin.ptr_size() as u64;
        let data = self.bin.read_ptr(va)?;
        let bits = self.bin.read_u32(va + ptr_sz)?;
        let attrs = (bits & 0xFFFF) as u16;
        let type_enum = ((bits >> 16) & 0xFF) as u8;
        let byref = if self.version >= 27 {
            ((bits >> 29) & 1) != 0
        } else {
            ((bits >> 30) & 1) != 0
        };
        let t = Il2CppType {
            data,
            attrs,
            type_enum,
            byref,
        };
        self.type_cache.insert(va, t.clone());
        Some(t)
    }

    pub fn format_type_name(&mut self, index: i32, depth: usize) -> String {
        let Some(t) = self.read_type_by_index(index) else {
            return "object".to_string();
        };
        self.format_il2cpp_type(&t, depth)
    }

    pub fn format_il2cpp_type(&mut self, t: &Il2CppType, depth: usize) -> String {
        if depth > 8 {
            return "...".to_string();
        }
        let base = match t.type_enum {
            0x01 => "void".to_string(),
            0x02 => "bool".to_string(),
            0x03 => "char".to_string(),
            0x04 => "sbyte".to_string(),
            0x05 => "byte".to_string(),
            0x06 => "short".to_string(),
            0x07 => "ushort".to_string(),
            0x08 => "int".to_string(),
            0x09 => "uint".to_string(),
            0x0a => "long".to_string(),
            0x0b => "ulong".to_string(),
            0x0c => "float".to_string(),
            0x0d => "double".to_string(),
            0x0e => "string".to_string(),
            0x18 => "IntPtr".to_string(),
            0x19 => "UIntPtr".to_string(),
            0x1c => "object".to_string(),
            0x0f => {
                // IL2CPP_TYPE_PTR
                if let Some(sub) = self.read_type_at_va(t.data) {
                    format!("{}*", self.format_il2cpp_type(&sub, depth + 1))
                } else {
                    "void*".to_string()
                }
            }
            0x10 => {
                // IL2CPP_TYPE_BYREF
                if let Some(sub) = self.read_type_at_va(t.data) {
                    format!("ref {}", self.format_il2cpp_type(&sub, depth + 1))
                } else {
                    "ref object".to_string()
                }
            }
            0x1d => {
                // IL2CPP_TYPE_SZARRAY
                if let Some(sub) = self.read_type_at_va(t.data) {
                    format!("{}[]", self.format_il2cpp_type(&sub, depth + 1))
                } else {
                    "object[]".to_string()
                }
            }
            0x14 => {
                // IL2CPP_TYPE_ARRAY -> Il2CppArrayType { Il2CppType* etype; uint8_t rank; ... }
                let rank = self.bin.read_u8(t.data + self.bin.ptr_size() as u64).unwrap_or(2);
                let etype_va = self.bin.read_ptr(t.data).unwrap_or(0);
                let elem = if let Some(sub) = self.read_type_at_va(etype_va) {
                    self.format_il2cpp_type(&sub, depth + 1)
                } else {
                    "object".to_string()
                };
                let commas = ",".repeat(rank.saturating_sub(1) as usize);
                format!("{}[{}]", elem, commas)
            }
            0x11 | 0x12 => {
                // VALUETYPE | CLASS -> TypeDefinitionIndex in data
                let td_idx = t.data as usize;
                if let Some(td) = self.meta.type_defs.get(td_idx) {
                    self.format_typedef_short_name(td)
                } else {
                    format!("TypeDef_{}", td_idx)
                }
            }
            0x15 => {
                // IL2CPP_TYPE_GENERICINST -> Il2CppGenericClass
                self.format_generic_inst(t.data, depth + 1)
            }
            0x13 | 0x1e => {
                // VAR | MVAR -> GenericParameterIndex in data
                let gp_idx = t.data as usize;
                if let Some(gp) = self.meta.generic_parameters.get(gp_idx) {
                    let s = self.meta.get_string(gp.name_index);
                    if s.is_empty() {
                        format!("T{}", gp.num)
                    } else {
                        s.to_string()
                    }
                } else {
                    format!("T{}", gp_idx)
                }
            }
            other => format!("Type_0x{:02x}", other),
        };

        if t.byref && t.type_enum != 0x10 {
            format!("ref {}", base)
        } else {
            base
        }
    }

    pub fn format_typedef_short_name(&self, td: &crate::metadata::structs::Il2CppTypeDefinition) -> String {
        let raw = self.meta.get_string(td.name_index);
        match raw.split('`').next() {
            Some(clean) if !clean.is_empty() => clean.to_string(),
            _ => raw.to_string(),
        }
    }

    /// Resolve `(root_namespace, Outer.Inner.Leaf)` by walking `declaring_type_index`.
    pub fn resolve_full_typedef_name(&mut self, td_idx: usize) -> (String, String) {
        let mut chain = Vec::new();
        let mut cur_idx = td_idx;
        let mut root_ns = String::new();

        for _ in 0..16 {
            let Some(td) = self.meta.type_defs.get(cur_idx) else {
                break;
            };
            let name = self.meta.get_string(td.name_index).to_string();
            let ns = self.meta.get_string(td.namespace_index);
            if !ns.is_empty() && root_ns.is_empty() {
                root_ns = ns.to_string();
            }
            chain.push(name);

            if td.declaring_type_index < 0 {
                break;
            }
            let Some(decl_t) = self.read_type_by_index(td.declaring_type_index) else {
                break;
            };
            if !matches!(decl_t.type_enum, 0x11 | 0x12) {
                break;
            }
            let next_idx = decl_t.data as usize;
            if next_idx == cur_idx || next_idx >= self.meta.type_defs.len() {
                break;
            }
            cur_idx = next_idx;
        }

        chain.reverse();
        (root_ns, chain.join("."))
    }

    fn format_generic_inst(&mut self, gc_va: u64, depth: usize) -> String {
        let ptr_sz = self.bin.ptr_size() as u64;
        let first_word = self.bin.read_ptr(gc_va).unwrap_or(0);
        let base_name = if self.version >= 27 {
            if let Some(base_t) = self.read_type_at_va(first_word) {
                if let Some(td) = self.meta.type_defs.get(base_t.data as usize) {
                    self.format_typedef_short_name(td)
                } else {
                    "Generic".to_string()
                }
            } else {
                "Generic".to_string()
            }
        } else if let Some(td) = self.meta.type_defs.get(first_word as usize) {
            self.format_typedef_short_name(td)
        } else {
            "Generic".to_string()
        };

        // Il2CppGenericContext starts immediately after first_word:
        // { const Il2CppGenericInst* class_inst; const Il2CppGenericInst* method_inst; }
        let class_inst_va = self.bin.read_ptr(gc_va + ptr_sz).unwrap_or(0);
        if class_inst_va == 0 {
            return base_name;
        }
        let argc = self.bin.read_ptr(class_inst_va).unwrap_or(0) as usize;
        let argv_va = self.bin.read_ptr(class_inst_va + ptr_sz).unwrap_or(0);
        if argc == 0 || argc > 32 || !self.bin.is_valid_va(argv_va) {
            return base_name;
        }
        let mut args = Vec::with_capacity(argc);
        for i in 0..argc {
            let arg_t_va = self.bin.read_ptr(argv_va + i as u64 * ptr_sz).unwrap_or(0);
            if let Some(arg_t) = self.read_type_at_va(arg_t_va) {
                args.push(self.format_il2cpp_type(&arg_t, depth + 1));
            } else {
                args.push("?".to_string());
            }
        }
        format!("{}<{}>", base_name, args.join(", "))
    }
}

pub fn read_type_field_offset(
    bin: &BinaryImage,
    field_offsets_table_va: u64,
    type_idx: usize,
    local_field_idx: usize,
) -> Option<i32> {
    let ptr_sz = bin.ptr_size() as u64;
    let arr_va = bin.read_ptr(field_offsets_table_va + type_idx as u64 * ptr_sz)?;
    if !bin.is_valid_va(arr_va) {
        return None;
    }
    bin.read_i32(arr_va + (local_field_idx as u64) * 4)
}

pub fn build_method_pointer_map(
    bin: &BinaryImage,
    meta: &Metadata,
    reg: &RegistrationResult,
) -> HashMap<usize, u64> {
    let ptr_sz = bin.ptr_size() as u64;
    if reg.code_gen_modules.is_empty() {
        let mut method_vas = HashMap::new();
        if let Some(tbl) = reg.legacy_method_pointers_va {
            for (global_m_idx, m) in meta.methods.iter().enumerate() {
                let leg = m.method_index_legacy;
                if leg >= 0 && (leg as usize) < reg.legacy_method_pointers_count {
                    if let Some(va) = bin.read_ptr(tbl + (leg as u64) * ptr_sz) {
                        if va != 0 {
                            method_vas.insert(global_m_idx, va);
                        }
                    }
                }
            }
        }
        return method_vas;
    }

    let modules = &reg.code_gen_modules;
    let mut mod_by_name: HashMap<&str, &CodeGenModuleInfo> = HashMap::with_capacity(modules.len());
    for m in modules {
        mod_by_name.insert(m.name.as_str(), m);
    }

    let mut method_vas = HashMap::new();
    for img in &meta.images {
        let img_name = meta.get_string(img.name_index);
        let Some(cgm) = mod_by_name.get(img_name) else {
            continue;
        };
        if cgm.method_pointer_count == 0 || cgm.method_pointers_va == 0 {
            continue;
        }
        let start_td = img.first_type_index.max(0) as usize;
        let end_td = (start_td + img.type_count as usize).min(meta.type_defs.len());
        for td in &meta.type_defs[start_td..end_td] {
            if td.first_method_idx < 0 || td.method_count == 0 {
                continue;
            }
            let ms = td.first_method_idx as usize;
            let me = (ms + td.method_count as usize).min(meta.methods.len());
            for (m_idx, m) in meta.methods[ms..me].iter().enumerate() {
                let global_m_idx = ms + m_idx;
                let rid = (m.token & 0x00FF_FFFF) as usize;
                if rid >= 1 && rid <= cgm.method_pointer_count {
                    if let Some(va) = bin.read_ptr(cgm.method_pointers_va + ((rid - 1) as u64) * ptr_sz) {
                        if va != 0 {
                            method_vas.insert(global_m_idx, va);
                        }
                    }
                }
            }
        }
    }
    method_vas
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{BinaryFormat, SectionRange};

    #[test]
    fn test_locate_metadata_registration_single_field_offsets_fallback() {
        // Synthetic 64-bit ELF data section at VA 0x1000..0x1400
        let mut mem = vec![0u8; 0x400];
        let base_va = 0x1000u64;
        let meta_reg_off = 0x40usize; // base = 0x1040
        // At +48 (6 * 8): numTypes = 20, types_ptr = 0x1140
        mem[meta_reg_off + 48..meta_reg_off + 56].copy_from_slice(&20u64.to_le_bytes());
        mem[meta_reg_off + 56..meta_reg_off + 64].copy_from_slice(&(base_va + 0x140).to_le_bytes());
        // At +80 (10 * 8): fieldOffsetsCount = 10, fieldOffsets = 0x1180 (NO c2 == 10 after it!)
        mem[meta_reg_off + 80..meta_reg_off + 88].copy_from_slice(&10u64.to_le_bytes());
        mem[meta_reg_off + 88..meta_reg_off + 96].copy_from_slice(&(base_va + 0x180).to_le_bytes());
        // types[0] @ 0x1140 -> 0x1200
        mem[0x140..0x148].copy_from_slice(&(base_va + 0x200).to_le_bytes());
        // fieldOffsets[0..6] @ 0x1180 -> valid VAs
        for k in 0..6usize {
            mem[0x180 + k * 8..0x188 + k * 8].copy_from_slice(&(base_va + 0x240).to_le_bytes());
        }

        let bin = BinaryImage {
            bytes: mem,
            format: BinaryFormat::Elf,
            is_64bit: true,
            arch: "arm64".into(),
            image_base: 0,
            sections: vec![SectionRange {
                name: ".data.rel.ro".into(),
                va_start: base_va,
                va_end: base_va + 0x400,
                file_offset: 0,
                file_size: 0x400,
                is_exec: false,
                is_data: true,
            }],
            relocs: Vec::new(),
            is_memory_dump: false,
            fairplay_encrypted: false,
        };

        let (mr_va, num_types, types_ptr, fo_ptr) = locate_metadata_registration(&bin, 10, 31).unwrap();
        assert_eq!(mr_va, base_va + meta_reg_off as u64);
        assert_eq!(num_types, 20);
        assert_eq!(types_ptr, base_va + 0x140);
        assert_eq!(fo_ptr, base_va + 0x180);
    }
}
