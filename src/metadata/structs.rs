#![allow(dead_code)]

use anyhow::Result;
use std::collections::HashMap;
use std::io::{Cursor, Read};

use super::header::MetadataHeader;
use super::varwidth::{read_var_index, Widths};

#[derive(Debug, Clone)]
pub struct Il2CppImageDefinition {
    pub name_index: i32,
    pub assembly_index: i32,
    pub first_type_index: i32,
    pub type_count: u32,
    pub exported_type_start: i32,
    pub exported_type_count: u32,
    pub entry_point_index: i32,
    pub token: u32,
}

#[derive(Debug, Clone)]
pub struct Il2CppTypeDefinition {
    pub name_index: i32,
    pub namespace_index: i32,
    pub byval_type_index: i32,
    pub declaring_type_index: i32,
    pub parent_index: i32,
    pub generic_container_index: i32,
    pub flags: u32,
    pub first_field_idx: i32,
    pub first_method_idx: i32,
    pub first_event_id: i32,
    pub first_property_id: i32,
    pub nested_types_start: i32,
    pub interfaces_start: i32,
    pub vtable_start: i32,
    pub interface_offsets_start: i32,
    pub method_count: u16,
    pub property_count: u16,
    pub field_count: u16,
    pub event_count: u16,
    pub nested_type_count: u16,
    pub vtable_count: u16,
    pub interfaces_count: u16,
    pub interface_offsets_count: u16,
    pub bitfield: u32,
    pub token: u32,
}

impl Il2CppTypeDefinition {
    pub fn is_valuetype(&self) -> bool {
        (self.bitfield & 1) != 0
    }
    pub fn is_enum(&self) -> bool {
        (self.bitfield & 2) != 0
    }
}

#[derive(Debug, Clone)]
pub struct Il2CppFieldDefinition {
    pub name_index: i32,
    pub type_index: i32,
    pub token: u32,
}

#[derive(Debug, Clone)]
pub struct Il2CppMethodDefinition {
    pub name_index: i32,
    pub declaring_type_idx: i32,
    pub return_type_idx: i32,
    pub return_parameter_token: u32,
    pub parameter_start: i32,
    pub generic_container_index: i32,
    pub method_index_legacy: i32,
    pub token: u32,
    pub flags: u16,
    pub iflags: u16,
    pub slot: u16,
    pub parameter_count: u16,
}

#[derive(Debug, Clone)]
pub struct Il2CppParameterDefinition {
    pub name_index: i32,
    pub token: u32,
    pub type_index: i32,
}

#[derive(Debug, Clone)]
pub struct Il2CppPropertyDefinition {
    pub name_index: i32,
    pub get: i32,
    pub set: i32,
    pub attrs: u32,
    pub token: u32,
}

#[derive(Debug, Clone)]
pub struct Il2CppGenericContainer {
    pub owner_index: i32,
    pub type_argc: i32,
    pub is_method: bool,
    pub generic_parameter_start: i32,
}

#[derive(Debug, Clone)]
pub struct Il2CppGenericParameter {
    pub owner_index: i32,
    pub name_index: i32,
    pub constraints_start: i16,
    pub constraints_count: i16,
    pub num: u16,
    pub flags: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct Il2CppFieldDefaultValue {
    pub field_index: i32,
    pub type_index: i32,
    pub data_index: i32,
}

fn r_i32(c: &mut Cursor<&[u8]>) -> Result<i32> {
    let mut b = [0u8; 4];
    c.read_exact(&mut b)?;
    Ok(i32::from_le_bytes(b))
}

fn r_u32(c: &mut Cursor<&[u8]>) -> Result<u32> {
    let mut b = [0u8; 4];
    c.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn r_i16(c: &mut Cursor<&[u8]>) -> Result<i16> {
    let mut b = [0u8; 2];
    c.read_exact(&mut b)?;
    Ok(i16::from_le_bytes(b))
}

fn r_u16(c: &mut Cursor<&[u8]>) -> Result<u16> {
    let mut b = [0u8; 2];
    c.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn r_u8(c: &mut Cursor<&[u8]>) -> Result<u8> {
    let mut b = [0u8; 1];
    c.read_exact(&mut b)?;
    Ok(b[0])
}

pub fn parse_images(raw: &[u8], header: &MetadataHeader, w: &Widths) -> Result<Vec<Il2CppImageDefinition>> {
    let slice = header.images.slice(raw)?;
    let ver = header.version;
    let has_v24_ca = if ver == 24 {
        if slice.len() >= 80 && slice.len().is_multiple_of(40) {
            let second_asm_40 = slice[44..48]
                .try_into()
                .ok()
                .map(i32::from_le_bytes)
                .unwrap_or(-1);
            let second_asm_32 = slice[36..40]
                .try_into()
                .ok()
                .map(i32::from_le_bytes)
                .unwrap_or(-1);
            second_asm_40 == 1 || (!slice.len().is_multiple_of(32) && second_asm_32 != 1)
        } else {
            slice.len().is_multiple_of(40) && !slice.len().is_multiple_of(32)
        }
    } else {
        ver > 24
    };

    let stride = if ver < 19 {
        16
    } else if ver < 24 {
        24
    } else {
        8 + w.type_def as usize
            + 4
            + w.type_def as usize
            + 4
            + w.method as usize
            + 4
            + if has_v24_ca { 8 } else { 0 }
            + if ver >= 108 { 12 + w.type_def as usize + 4 } else { 0 }
    };
    let count = header.images.effective_count(stride);
    let mut cur = Cursor::new(slice);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name_index = r_i32(&mut cur)?;
        let assembly_index = r_i32(&mut cur)?;
        let first_type_index = read_var_index(&mut cur, w.type_def)?;
        let type_count = r_u32(&mut cur)?;
        let (exported_type_start, exported_type_count) = if ver >= 24 {
            (read_var_index(&mut cur, w.type_def)?, r_u32(&mut cur)?)
        } else {
            (-1, 0)
        };
        let entry_point_index = if ver >= 19 { read_var_index(&mut cur, w.method)? } else { -1 };
        let token = if ver >= 19 { r_u32(&mut cur)? } else { 0 };
        if has_v24_ca {
            let _ca_start = r_i32(&mut cur)?;
            let _ca_count = r_u32(&mut cur)?;
        }
        if ver >= 108 {
            let _invoker = r_i32(&mut cur)?;
            let _rgctx_start = r_i32(&mut cur)?;
            let _rgctx_cnt = r_u32(&mut cur)?;
            let _cctor_start = read_var_index(&mut cur, w.type_def)?;
            let _cctor_cnt = r_u32(&mut cur)?;
        }
        out.push(Il2CppImageDefinition {
            name_index,
            assembly_index,
            first_type_index,
            type_count,
            exported_type_start,
            exported_type_count,
            entry_point_index,
            token,
        });
    }
    Ok(out)
}

pub fn parse_type_definitions(
    raw: &[u8],
    header: &MetadataHeader,
    w: &Widths,
) -> Result<Vec<Il2CppTypeDefinition>> {
    let slice = header.type_definitions.slice(raw)?;
    let ver = header.version;
    let stride = 8
        + if ver <= 24 { 4 } else { 0 }
        + w.il2cpp_type as usize
        + if ver < 27 { 4 } else { 0 }
        + 2 * w.il2cpp_type as usize
        + if ver < 35 { 4 } else { 0 }
        + if ver <= 24 { 8 } else { 0 }
        + w.generic_container as usize
        + 8
        + w.method as usize
        + w.event as usize
        + w.property as usize
        + w.nested_type as usize
        + w.interface as usize
        + 4
        + w.interface as usize
        + 16
        + 4
        + if ver >= 19 { 4 } else { 0 };
    let count = header.type_definitions.effective_count(stride);
    let mut cur = Cursor::new(slice);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name_index = r_i32(&mut cur)?;
        let namespace_index = r_i32(&mut cur)?;
        if ver <= 24 {
            let _ca = r_i32(&mut cur)?;
        }
        let byval_type_index = read_var_index(&mut cur, w.il2cpp_type)?;
        if ver < 27 {
            let _byref = r_i32(&mut cur)?;
        }
        let declaring_type_index = read_var_index(&mut cur, w.il2cpp_type)?;
        let parent_index = read_var_index(&mut cur, w.il2cpp_type)?;
        if ver < 35 {
            let _elem = r_i32(&mut cur)?;
        }
        if ver <= 24 {
            let _rgctx_start = r_i32(&mut cur)?;
            let _rgctx_cnt = r_i32(&mut cur)?;
        }
        let generic_container_index = read_var_index(&mut cur, w.generic_container)?;
        let flags = r_u32(&mut cur)?;
        let first_field_idx = r_i32(&mut cur)?;
        let first_method_idx = read_var_index(&mut cur, w.method)?;
        let first_event_id = read_var_index(&mut cur, w.event)?;
        let first_property_id = read_var_index(&mut cur, w.property)?;
        let nested_types_start = read_var_index(&mut cur, w.nested_type)?;
        let interfaces_start = read_var_index(&mut cur, w.interface)?;
        let vtable_start = r_i32(&mut cur)?;
        let interface_offsets_start = read_var_index(&mut cur, w.interface)?;
        let method_count = r_u16(&mut cur)?;
        let property_count = r_u16(&mut cur)?;
        let field_count = r_u16(&mut cur)?;
        let event_count = r_u16(&mut cur)?;
        let nested_type_count = r_u16(&mut cur)?;
        let vtable_count = r_u16(&mut cur)?;
        let interfaces_count = r_u16(&mut cur)?;
        let interface_offsets_count = r_u16(&mut cur)?;
        let bitfield = r_u32(&mut cur)?;
        let token = if ver >= 19 { r_u32(&mut cur)? } else { 0 };

        out.push(Il2CppTypeDefinition {
            name_index,
            namespace_index,
            byval_type_index,
            declaring_type_index,
            parent_index,
            generic_container_index,
            flags,
            first_field_idx,
            first_method_idx,
            first_event_id,
            first_property_id,
            nested_types_start,
            interfaces_start,
            vtable_start,
            interface_offsets_start,
            method_count,
            property_count,
            field_count,
            event_count,
            nested_type_count,
            vtable_count,
            interfaces_count,
            interface_offsets_count,
            bitfield,
            token,
        });
    }
    Ok(out)
}

pub fn parse_fields(
    raw: &[u8],
    header: &MetadataHeader,
    w: &Widths,
) -> Result<Vec<Il2CppFieldDefinition>> {
    let slice = header.fields.slice(raw)?;
    let ver = header.version;
    let stride = 4
        + w.il2cpp_type as usize
        + if ver <= 24 { 4 } else { 0 }
        + if ver >= 19 { 4 } else { 0 };
    let count = header.fields.effective_count(stride);
    let mut cur = Cursor::new(slice);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name_index = r_i32(&mut cur)?;
        let type_index = read_var_index(&mut cur, w.il2cpp_type)?;
        if ver <= 24 {
            let _ca = r_i32(&mut cur)?;
        }
        let token = if ver >= 19 { r_u32(&mut cur)? } else { 0 };
        out.push(Il2CppFieldDefinition {
            name_index,
            type_index,
            token,
        });
    }
    Ok(out)
}

pub fn parse_methods(
    raw: &[u8],
    header: &MetadataHeader,
    w: &Widths,
) -> Result<Vec<Il2CppMethodDefinition>> {
    let slice = header.methods.slice(raw)?;
    let ver = header.version;
    let stride = 4
        + w.type_def as usize
        + w.il2cpp_type as usize
        + if ver >= 31 { 4 } else { 0 }
        + w.parameter as usize
        + if ver <= 24 { 4 } else { 0 }
        + w.generic_container as usize
        + if ver <= 24 { 20 } else { 0 }
        + if ver >= 19 { 4 } else { 0 }
        + 8;
    let count = header.methods.effective_count(stride);
    let mut cur = Cursor::new(slice);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name_index = r_i32(&mut cur)?;
        let declaring_type_idx = read_var_index(&mut cur, w.type_def)?;
        let return_type_idx = read_var_index(&mut cur, w.il2cpp_type)?;
        let return_parameter_token = if ver >= 31 { r_u32(&mut cur)? } else { 0 };
        let parameter_start = read_var_index(&mut cur, w.parameter)?;
        if ver <= 24 {
            let _ca = r_i32(&mut cur)?;
        }
        let generic_container_index = read_var_index(&mut cur, w.generic_container)?;
        let method_index_legacy = if ver <= 24 {
            let m = r_i32(&mut cur)?;
            let _inv = r_i32(&mut cur)?;
            let _del = r_i32(&mut cur)?;
            let _rs = r_i32(&mut cur)?;
            let _rc = r_i32(&mut cur)?;
            m
        } else {
            -1
        };
        let token = if ver >= 19 { r_u32(&mut cur)? } else { 0 };
        let flags = r_u16(&mut cur)?;
        let iflags = r_u16(&mut cur)?;
        let slot = r_u16(&mut cur)?;
        let parameter_count = r_u16(&mut cur)?;

        out.push(Il2CppMethodDefinition {
            name_index,
            declaring_type_idx,
            return_type_idx,
            return_parameter_token,
            parameter_start,
            generic_container_index,
            method_index_legacy,
            token,
            flags,
            iflags,
            slot,
            parameter_count,
        });
    }
    Ok(out)
}

pub fn parse_parameters(
    raw: &[u8],
    header: &MetadataHeader,
    w: &Widths,
) -> Result<Vec<Il2CppParameterDefinition>> {
    let slice = header.parameters.slice(raw)?;
    let ver = header.version;
    let stride = 4
        + if ver >= 19 { 4 } else { 0 }
        + if ver <= 24 { 4 } else { 0 }
        + w.il2cpp_type as usize;
    let count = header.parameters.effective_count(stride);
    let mut cur = Cursor::new(slice);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name_index = r_i32(&mut cur)?;
        let token = if ver >= 19 { r_u32(&mut cur)? } else { 0 };
        if ver <= 24 {
            let _ca = r_i32(&mut cur)?;
        }
        let type_index = read_var_index(&mut cur, w.il2cpp_type)?;
        out.push(Il2CppParameterDefinition {
            name_index,
            token,
            type_index,
        });
    }
    Ok(out)
}

pub fn parse_properties(
    raw: &[u8],
    header: &MetadataHeader,
    w: &Widths,
) -> Result<Vec<Il2CppPropertyDefinition>> {
    let slice = header.properties.slice(raw)?;
    let ver = header.version;
    let stride = 8
        + 2 * w.method as usize
        + if ver <= 24 { 4 } else { 0 }
        + if ver >= 19 { 4 } else { 0 };
    let count = header.properties.effective_count(stride);
    let mut cur = Cursor::new(slice);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name_index = r_i32(&mut cur)?;
        let get = read_var_index(&mut cur, w.method)?;
        let set = read_var_index(&mut cur, w.method)?;
        let attrs = r_u32(&mut cur)?;
        if ver <= 24 {
            let _ca = r_i32(&mut cur)?;
        }
        let token = if ver >= 19 { r_u32(&mut cur)? } else { 0 };
        out.push(Il2CppPropertyDefinition {
            name_index,
            get,
            set,
            attrs,
            token,
        });
    }
    Ok(out)
}

pub fn parse_generic_containers(
    raw: &[u8],
    header: &MetadataHeader,
    w: &Widths,
) -> Result<Vec<Il2CppGenericContainer>> {
    let slice = header.generic_containers.slice(raw)?;
    let ver = header.version;
    let stride = if ver >= 106 { 11 } else { 16 };
    let count = header.generic_containers.effective_count(stride);
    let mut cur = Cursor::new(slice);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_index = r_i32(&mut cur)?;
        let (type_argc, is_method) = if ver >= 106 {
            let argc = r_u16(&mut cur)? as i32;
            let is_m = r_u8(&mut cur)? != 0;
            (argc, is_m)
        } else {
            let argc = r_i32(&mut cur)?;
            let is_m = r_i32(&mut cur)? != 0;
            (argc, is_m)
        };
        let generic_parameter_start = read_var_index(&mut cur, 4)?;
        let _ = w;
        out.push(Il2CppGenericContainer {
            owner_index,
            type_argc,
            is_method,
            generic_parameter_start,
        });
    }
    Ok(out)
}

pub fn parse_generic_parameters(
    raw: &[u8],
    header: &MetadataHeader,
    w: &Widths,
) -> Result<Vec<Il2CppGenericParameter>> {
    let slice = header.generic_parameters.slice(raw)?;
    let stride = w.generic_container as usize + 12;
    let count = header.generic_parameters.effective_count(stride);
    let mut cur = Cursor::new(slice);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_index = read_var_index(&mut cur, w.generic_container)?;
        let name_index = r_i32(&mut cur)?;
        let constraints_start = r_i16(&mut cur)?;
        let constraints_count = r_i16(&mut cur)?;
        let num = r_u16(&mut cur)?;
        let flags = r_u16(&mut cur)?;
        out.push(Il2CppGenericParameter {
            owner_index,
            name_index,
            constraints_start,
            constraints_count,
            num,
            flags,
        });
    }
    Ok(out)
}

pub fn parse_var_index_array(
    raw: &[u8],
    sec: &super::header::SectionHeader,
    width: u8,
) -> Result<Vec<i32>> {
    let slice = sec.slice(raw)?;
    let count = sec.effective_count(width as usize);
    let mut cur = Cursor::new(slice);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_var_index(&mut cur, width)?);
    }
    Ok(out)
}

pub fn parse_field_default_values(
    raw: &[u8],
    header: &MetadataHeader,
    w: &Widths,
) -> Result<HashMap<i32, Il2CppFieldDefaultValue>> {
    let slice = header.field_default_values.slice(raw)?;
    let stride = 8 + w.il2cpp_type as usize;
    let count = header.field_default_values.effective_count(stride);
    let mut cur = Cursor::new(slice);
    let mut out = HashMap::with_capacity(count);
    for _ in 0..count {
        let field_index = r_i32(&mut cur)?;
        let type_index = read_var_index(&mut cur, w.il2cpp_type)?;
        let data_index = r_i32(&mut cur)?;
        out.insert(
            field_index,
            Il2CppFieldDefaultValue {
                field_index,
                type_index,
                data_index,
            },
        );
    }
    Ok(out)
}
