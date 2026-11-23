use anyhow::{bail, Result};
use std::io::{Cursor, Read};

pub const METADATA_MAGIC: u32 = 0xFAB11BAF;

#[derive(Debug, Clone, Copy, Default)]
pub struct SectionHeader {
    pub offset: u32,
    pub size: u32,
    pub count: u32,
}

impl SectionHeader {
    pub fn read(cur: &mut Cursor<&[u8]>, version: i32) -> Result<Self> {
        let mut buf = [0u8; 4];
        cur.read_exact(&mut buf)?;
        let offset = u32::from_le_bytes(buf);
        cur.read_exact(&mut buf)?;
        let size = u32::from_le_bytes(buf);
        let count = if version >= 38 {
            cur.read_exact(&mut buf)?;
            u32::from_le_bytes(buf)
        } else {
            0
        };
        Ok(Self { offset, size, count })
    }

    pub fn effective_count(&self, fallback_stride: usize) -> usize {
        if self.count > 0 {
            self.count as usize
        } else {
            (self.size as usize).checked_div(fallback_stride).unwrap_or(0)
        }
    }

    pub fn slice<'a>(&self, data: &'a [u8]) -> Result<&'a [u8]> {
        let start = self.offset as usize;
        let end = start
            .checked_add(self.size as usize)
            .ok_or_else(|| anyhow::anyhow!("Section offset overflow"))?;
        if end > data.len() {
            bail!(
                "Section out of bounds: offset=0x{:x}, size=0x{:x}, file_len=0x{:x}",
                self.offset,
                self.size,
                data.len()
            );
        }
        Ok(&data[start..end])
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MetadataHeader {
    pub magic: u32,
    pub version: i32,
    pub string_literal: SectionHeader,
    pub string_literal_data: SectionHeader,
    pub string: SectionHeader,
    pub events: SectionHeader,
    pub properties: SectionHeader,
    pub methods: SectionHeader,
    pub parameter_default_values: SectionHeader,
    pub field_default_values: SectionHeader,
    pub field_and_parameter_default_value_data: SectionHeader,
    pub field_marshaled_sizes: SectionHeader,
    pub parameters: SectionHeader,
    pub fields: SectionHeader,
    pub generic_parameters: SectionHeader,
    pub generic_parameter_constraints: SectionHeader,
    pub generic_containers: SectionHeader,
    pub nested_types: SectionHeader,
    pub interfaces: SectionHeader,
    pub vtable_methods: SectionHeader,
    pub interface_offsets: SectionHeader,
    pub type_definitions: SectionHeader,
    pub type_inline_arrays: SectionHeader,
    pub rgctx_entries: SectionHeader,
    pub images: SectionHeader,
    pub assemblies: SectionHeader,
    pub metadata_usage_lists: SectionHeader,
    pub metadata_usage_pairs: SectionHeader,
    pub field_refs: SectionHeader,
    pub referenced_assemblies: SectionHeader,
    pub attributes_info: SectionHeader,
    pub attribute_types: SectionHeader,
    pub attribute_data: SectionHeader,
    pub attribute_data_range: SectionHeader,
    pub unresolved_virtual_call_parameter_types: SectionHeader,
    pub unresolved_virtual_call_parameter_ranges: SectionHeader,
    pub windows_runtime_type_names: SectionHeader,
    pub windows_runtime_strings: SectionHeader,
    pub exported_type_definitions: SectionHeader,
    pub method_specs_on_generic_type: SectionHeader,
    pub generic_method_specs_on_type: SectionHeader,
    pub method_specs: SectionHeader,
    pub generic_method_functions_definitions: SectionHeader,
    pub generic_method_functions_definitions_with_adjustor: SectionHeader,
    pub invoker_indices: SectionHeader,
    pub rgctx_ranges: SectionHeader,
    pub rgctx_values: SectionHeader,
    pub static_constructor_type_indices: SectionHeader,
}

impl MetadataHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            bail!("Metadata file too small ({} bytes)", data.len());
        }
        let mut cur = Cursor::new(data);
        let mut buf = [0u8; 4];
        cur.read_exact(&mut buf)?;
        let magic = u32::from_le_bytes(buf);
        if magic != METADATA_MAGIC {
            bail!(
                "Invalid metadata magic 0x{:08X} (expected 0x{:08X}). File may be encrypted or shifted; supply a --profile JSON.",
                magic,
                METADATA_MAGIC
            );
        }
        cur.read_exact(&mut buf)?;
        let version = i32::from_le_bytes(buf);
        if version < 16 {
            bail!("Unsupported legacy metadata version {} (supported: >= 16)", version);
        }

        let r = |c: &mut Cursor<&[u8]>| SectionHeader::read(c, version);

        let string_literal = r(&mut cur)?;
        let string_literal_data = r(&mut cur)?;
        let string = r(&mut cur)?;
        let events = r(&mut cur)?;
        let properties = r(&mut cur)?;
        let methods = r(&mut cur)?;
        let parameter_default_values = r(&mut cur)?;
        let field_default_values = r(&mut cur)?;
        let field_and_parameter_default_value_data = r(&mut cur)?;
        let field_marshaled_sizes = r(&mut cur)?;
        let parameters = r(&mut cur)?;
        let fields = r(&mut cur)?;
        let generic_parameters = r(&mut cur)?;
        let generic_parameter_constraints = r(&mut cur)?;
        let generic_containers = r(&mut cur)?;
        let nested_types = r(&mut cur)?;
        let interfaces = r(&mut cur)?;
        let vtable_methods = r(&mut cur)?;
        let interface_offsets = r(&mut cur)?;
        let type_definitions = r(&mut cur)?;

        let type_inline_arrays = if version >= 104 { r(&mut cur)? } else { SectionHeader::default() };
        let rgctx_entries = if version <= 24 { r(&mut cur)? } else { SectionHeader::default() };

        let images = r(&mut cur)?;
        let assemblies = r(&mut cur)?;

        let (metadata_usage_lists, metadata_usage_pairs) = if (19..27).contains(&version) {
            (r(&mut cur)?, r(&mut cur)?)
        } else {
            (SectionHeader::default(), SectionHeader::default())
        };

        let field_refs = if version >= 19 { r(&mut cur)? } else { SectionHeader::default() };
        let referenced_assemblies = if version >= 20 { r(&mut cur)? } else { SectionHeader::default() };

        let (attributes_info, attribute_types, attribute_data, attribute_data_range) =
            if (21..29).contains(&version) {
                (
                    r(&mut cur)?,
                    r(&mut cur)?,
                    SectionHeader::default(),
                    SectionHeader::default(),
                )
            } else if version >= 29 {
                (
                    SectionHeader::default(),
                    SectionHeader::default(),
                    r(&mut cur)?,
                    r(&mut cur)?,
                )
            } else {
                Default::default()
            };

        let (unresolved_virtual_call_parameter_types, unresolved_virtual_call_parameter_ranges) =
            if version >= 22 {
                (r(&mut cur)?, r(&mut cur)?)
            } else {
                (SectionHeader::default(), SectionHeader::default())
            };
        let windows_runtime_type_names = if version >= 23 { r(&mut cur)? } else { SectionHeader::default() };
        let windows_runtime_strings = if version >= 27 { r(&mut cur)? } else { SectionHeader::default() };
        let exported_type_definitions = if version >= 24 { r(&mut cur)? } else { SectionHeader::default() };

        let (
            method_specs_on_generic_type,
            generic_method_specs_on_type,
            method_specs,
            generic_method_functions_definitions,
            generic_method_functions_definitions_with_adjustor,
            invoker_indices,
            rgctx_ranges,
            rgctx_values,
            static_constructor_type_indices,
        ) = if version >= 108 {
            (
                r(&mut cur)?,
                r(&mut cur)?,
                r(&mut cur)?,
                r(&mut cur)?,
                r(&mut cur)?,
                r(&mut cur)?,
                r(&mut cur)?,
                r(&mut cur)?,
                r(&mut cur)?,
            )
        } else {
            Default::default()
        };

        Ok(Self {
            magic,
            version,
            string_literal,
            string_literal_data,
            string,
            events,
            properties,
            methods,
            parameter_default_values,
            field_default_values,
            field_and_parameter_default_value_data,
            field_marshaled_sizes,
            parameters,
            fields,
            generic_parameters,
            generic_parameter_constraints,
            generic_containers,
            nested_types,
            interfaces,
            vtable_methods,
            interface_offsets,
            type_definitions,
            type_inline_arrays,
            rgctx_entries,
            images,
            assemblies,
            metadata_usage_lists,
            metadata_usage_pairs,
            field_refs,
            referenced_assemblies,
            attributes_info,
            attribute_types,
            attribute_data,
            attribute_data_range,
            unresolved_virtual_call_parameter_types,
            unresolved_virtual_call_parameter_ranges,
            windows_runtime_type_names,
            windows_runtime_strings,
            exported_type_definitions,
            method_specs_on_generic_type,
            generic_method_specs_on_type,
            method_specs,
            generic_method_functions_definitions,
            generic_method_functions_definitions_with_adjustor,
            invoker_indices,
            rgctx_ranges,
            rgctx_values,
            static_constructor_type_indices,
        })
    }

    pub fn sections_summary(&self) -> Vec<(&'static str, SectionHeader)> {
        vec![
            ("stringLiteral", self.string_literal),
            ("stringLiteralData", self.string_literal_data),
            ("string", self.string),
            ("events", self.events),
            ("properties", self.properties),
            ("methods", self.methods),
            ("parameterDefaultValues", self.parameter_default_values),
            ("fieldDefaultValues", self.field_default_values),
            ("defaultValueData", self.field_and_parameter_default_value_data),
            ("fieldMarshaledSizes", self.field_marshaled_sizes),
            ("parameters", self.parameters),
            ("fields", self.fields),
            ("genericParameters", self.generic_parameters),
            ("genericParameterConstraints", self.generic_parameter_constraints),
            ("genericContainers", self.generic_containers),
            ("nestedTypes", self.nested_types),
            ("interfaces", self.interfaces),
            ("vtableMethods", self.vtable_methods),
            ("interfaceOffsets", self.interface_offsets),
            ("typeDefinitions", self.type_definitions),
            ("images", self.images),
            ("assemblies", self.assemblies),
            ("fieldRefs", self.field_refs),
            ("referencedAssemblies", self.referenced_assemblies),
            ("attributeData", self.attribute_data),
            ("attributeDataRange", self.attribute_data_range),
            ("exportedTypeDefinitions", self.exported_type_definitions),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v39_header_and_v29_header() {
        // Synthetic v39 header: 8 + 31 * 12 = 380 (0x17C) bytes
        let mut buf39 = vec![0u8; 0x17C];
        buf39[0..4].copy_from_slice(&METADATA_MAGIC.to_le_bytes());
        buf39[4..8].copy_from_slice(&39i32.to_le_bytes());
        // typeDefinitions is section index 19 -> byte 8 + 19*12 = 236
        buf39[236..240].copy_from_slice(&0x17Cu32.to_le_bytes());
        buf39[240..244].copy_from_slice(&82u32.to_le_bytes());
        buf39[244..248].copy_from_slice(&1u32.to_le_bytes());
        let h39 = MetadataHeader::parse(&buf39).unwrap();
        assert_eq!(h39.version, 39);
        assert_eq!(h39.type_definitions.offset, 0x17C);
        assert_eq!(h39.type_definitions.size, 82);
        assert_eq!(h39.type_definitions.count, 1);

        // Synthetic v29 header: 8 + 31 * 8 = 256 bytes
        let mut buf29 = vec![0u8; 256];
        buf29[0..4].copy_from_slice(&METADATA_MAGIC.to_le_bytes());
        buf29[4..8].copy_from_slice(&29i32.to_le_bytes());
        // typeDefinitions is index 19 -> 8 + 19*8 = 160
        buf29[160..164].copy_from_slice(&0x100u32.to_le_bytes());
        buf29[164..168].copy_from_slice(&880u32.to_le_bytes());
        let h29 = MetadataHeader::parse(&buf29).unwrap();
        assert_eq!(h29.version, 29);
        assert_eq!(h29.type_definitions.offset, 0x100);
        assert_eq!(h29.type_definitions.size, 880);
        assert_eq!(h29.type_definitions.count, 0);
    }

    #[test]
    fn test_parse_legacy_v20_header() {
        // v20 has 27 SectionHeaders * 8 bytes + 8 bytes prefix = 224 bytes
        let mut buf20 = vec![0u8; 224];
        buf20[0..4].copy_from_slice(&METADATA_MAGIC.to_le_bytes());
        buf20[4..8].copy_from_slice(&20i32.to_le_bytes());
        // typeDefinitions index 19 -> byte 8 + 19*8 = 160
        buf20[160..164].copy_from_slice(&0xE0u32.to_le_bytes());
        buf20[164..168].copy_from_slice(&100u32.to_le_bytes());
        // referencedAssemblies index 26 -> byte 8 + 26*8 = 216
        buf20[216..220].copy_from_slice(&0x200u32.to_le_bytes());
        buf20[220..224].copy_from_slice(&16u32.to_le_bytes());
        let h20 = MetadataHeader::parse(&buf20).unwrap();
        assert_eq!(h20.version, 20);
        assert_eq!(h20.type_definitions.offset, 0xE0);
        assert_eq!(h20.referenced_assemblies.offset, 0x200);
        assert_eq!(h20.exported_type_definitions.size, 0);
    }
}
