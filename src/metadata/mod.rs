pub mod adaptive;
pub mod carver;
pub mod header;
pub mod structs;
pub mod varwidth;

use anyhow::Result;
use std::collections::HashMap;

use header::MetadataHeader;
use structs::*;
use varwidth::Widths;

#[derive(Debug)]
pub struct Metadata {
    pub raw: Vec<u8>,
    pub header: MetadataHeader,
    pub widths: Widths,
    pub images: Vec<Il2CppImageDefinition>,
    pub type_defs: Vec<Il2CppTypeDefinition>,
    pub fields: Vec<Il2CppFieldDefinition>,
    pub methods: Vec<Il2CppMethodDefinition>,
    pub parameters: Vec<Il2CppParameterDefinition>,
    pub properties: Vec<Il2CppPropertyDefinition>,
    pub generic_containers: Vec<Il2CppGenericContainer>,
    pub generic_parameters: Vec<Il2CppGenericParameter>,
    pub interfaces: Vec<i32>,
    pub field_default_values: HashMap<i32, Il2CppFieldDefaultValue>,
}

impl Metadata {
    pub fn parse(raw: Vec<u8>, num_types_hint: Option<usize>) -> Result<Self> {
        let header = MetadataHeader::parse(&raw)?;
        let widths = Widths::for_version(header.version, &header, num_types_hint);
        Self::parse_with_widths(raw, header, widths)
    }

    pub fn parse_with_widths(
        raw: Vec<u8>,
        header: MetadataHeader,
        widths: Widths,
    ) -> Result<Self> {
        let images = parse_images(&raw, &header, &widths)?;
        let type_defs = parse_type_definitions(&raw, &header, &widths)?;
        let fields = parse_fields(&raw, &header, &widths)?;
        let methods = parse_methods(&raw, &header, &widths)?;
        let parameters = parse_parameters(&raw, &header, &widths)?;
        let properties = parse_properties(&raw, &header, &widths)?;
        let generic_containers = parse_generic_containers(&raw, &header, &widths)?;
        let generic_parameters = parse_generic_parameters(&raw, &header, &widths)?;
        let interfaces = parse_var_index_array(&raw, &header.interfaces, widths.il2cpp_type)?;
        let field_default_values = parse_field_default_values(&raw, &header, &widths)?;

        Ok(Self {
            raw,
            header,
            widths,
            images,
            type_defs,
            fields,
            methods,
            parameters,
            properties,
            generic_containers,
            generic_parameters,
            interfaces,
            field_default_values,
        })
    }

    pub fn get_string(&self, index: i32) -> &str {
        if index < 0 {
            return "";
        }
        let base = self.header.string.offset as usize + index as usize;
        if base >= self.raw.len() {
            return "";
        }
        let end = (self.header.string.offset as usize + self.header.string.size as usize)
            .min(self.raw.len());
        if base >= end {
            return "";
        }
        let slice = &self.raw[base..end];
        let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..nul]).unwrap_or("")
    }

    pub fn read_default_value_blob(&self, data_index: i32) -> Option<&[u8]> {
        if data_index < 0 {
            return None;
        }
        let base = self.header.field_and_parameter_default_value_data.offset as usize
            + data_index as usize;
        let end = (self.header.field_and_parameter_default_value_data.offset as usize
            + self.header.field_and_parameter_default_value_data.size as usize)
            .min(self.raw.len());
        if base >= end {
            return None;
        }
        Some(&self.raw[base..end])
    }
}
