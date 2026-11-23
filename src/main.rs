mod binary;
mod codegen;
mod diff;
mod gui;
mod metadata;
mod package;
mod profile;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use binary::custom_elf::{
    extract_field_offsets, extract_method_rvas, find_registration_context, find_types_array,
    scan_metadata_registration, AdaptiveTypeResolver,
};
use binary::il2cpp::{build_method_pointer_map, run_registration_scan};
use binary::BinaryImage;
use codegen::dump_cs::{generate_adaptive_dump_cs, generate_dump_cs};
use codegen::il2cpp_h::{generate_adaptive_il2cpp_h, generate_il2cpp_h};
use codegen::script_json::{
    generate_ghidra_import_py, generate_ida_import_py, write_adaptive_script_json,
    write_script_json,
};
use metadata::adaptive::{is_chain_header, AdaptiveMetadata};
use metadata::carver::carve_metadata_from_blob;
use metadata::header::{MetadataHeader, METADATA_MAGIC};
use metadata::varwidth::Widths;
use metadata::Metadata;
use profile::{apply_profile, DumpProfile};

#[derive(Parser)]
#[command(
    name = "il2cpp-dumper-rs",
    version,
    about = "Fast cross-platform static IL2CPP metadata & binary dumper (Unity v16-v39 + adaptive custom layouts)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch the native Desktop GUI
    Gui,
    /// Inspect global-metadata.dat (and optionally binary or .apk/.xapk/.ipa package) without writing outputs
    Inspect {
        #[arg(short, long)]
        metadata: Option<PathBuf>,
        #[arg(short, long)]
        binary: Option<PathBuf>,
        #[arg(long)]
        package: Option<PathBuf>,
        #[arg(long)]
        arch: Option<String>,
        #[arg(short, long)]
        profile: Option<PathBuf>,
        #[arg(long, value_parser = parse_hex_u64)]
        image_base: Option<u64>,
    },
    /// Dump IL2CPP types, fields, methods and RVAs to dump.cs, script.json and il2cpp.h
    Dump {
        #[arg(short, long)]
        binary: Option<PathBuf>,
        #[arg(short, long)]
        metadata: Option<PathBuf>,
        #[arg(long)]
        package: Option<PathBuf>,
        #[arg(long)]
        arch: Option<String>,
        #[arg(short, long, default_value = "dump_out")]
        out: PathBuf,
        #[arg(short, long)]
        profile: Option<PathBuf>,
        #[arg(long, value_parser = parse_hex_u64)]
        meta_reg: Option<u64>,
        #[arg(long, value_parser = parse_hex_u64)]
        code_reg: Option<u64>,
        #[arg(long)]
        memory_dump: bool,
        #[arg(long, value_parser = parse_hex_u64)]
        image_base: Option<u64>,
    },
    /// Carve decrypted global-metadata.dat out of a raw RAM dump
    Carve {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, default_value = "carved-metadata.dat")]
        out: PathBuf,
    },
    /// Compare two dump.cs files and report shifted offsets (optionally emit C++ #define)
    Diff {
        #[arg(long)]
        old: PathBuf,
        #[arg(long)]
        new: PathBuf,
        #[arg(short, long)]
        filter: Option<String>,
        #[arg(long)]
        cpp: bool,
        #[arg(long)]
        changed: bool,
    },
}

pub fn parse_hex_u64(s: &str) -> std::result::Result<u64, String> {
    let clean = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(clean, 16).map_err(|e| format!("Invalid hex address '{}': {}", s, e))
}

fn apply_profile_to_bytes(
    raw: Vec<u8>,
    profile_path: Option<&Path>,
) -> Result<(Vec<u8>, Option<DumpProfile>)> {
    if let Some(pp) = profile_path {
        let prof = DumpProfile::load(pp)?;
        let processed = apply_profile(&raw, &prof)?;
        Ok((processed, Some(prof)))
    } else {
        Ok((raw, None))
    }
}

fn load_metadata_bytes(
    path: &Path,
    profile_path: Option<&Path>,
) -> Result<(Vec<u8>, Option<DumpProfile>)> {
    let raw = std::fs::read(path)
        .with_context(|| format!("Failed to read metadata: {}", path.display()))?;
    apply_profile_to_bytes(raw, profile_path)
}

fn should_use_adaptive(meta_bytes: &[u8], profile: Option<&DumpProfile>) -> bool {
    if let Some(mode) = profile.and_then(|p| p.header_mode.as_deref()) {
        if mode.eq_ignore_ascii_case("adaptive") {
            return true;
        }
        if mode.eq_ignore_ascii_case("standard") {
            return false;
        }
    }
    if meta_bytes.len() >= 8 {
        let magic = u32::from_le_bytes([meta_bytes[0], meta_bytes[1], meta_bytes[2], meta_bytes[3]]);
        if magic == METADATA_MAGIC {
            let ver = i32::from_le_bytes([meta_bytes[4], meta_bytes[5], meta_bytes[6], meta_bytes[7]]);
            if ver >= 200 {
                return true;
            }
        }
    }
    is_chain_header(meta_bytes)
}

fn run_adaptive_inspect(
    meta_bytes: &[u8],
    bin_bytes: Option<Vec<u8>>,
    profile: Option<&DumpProfile>,
    image_base: Option<u64>,
) -> Result<String> {
    let mut out = String::new();
    let meta = AdaptiveMetadata::parse(meta_bytes)?;
    let _ = writeln!(out, "Engine:           Adaptive (chain/custom IL2CPP)");
    let _ = writeln!(out, "Metadata version: {}", meta.version);
    let _ = writeln!(out, "Module tag:       {}", meta.module_tag);
    let _ = writeln!(out, "Detected layout:  {}", meta.layout_summary);
    let _ = writeln!(
        out,
        "Parsed counts:    images={}, types={}, fields={}, methods={}, params={}",
        meta.images.len(),
        meta.types.len(),
        meta.fields.len(),
        meta.methods.len(),
        meta.params.len()
    );

    if let Some(bytes) = bin_bytes {
        let mut bin = BinaryImage::parse(bytes)?;
        if image_base.is_some() {
            bin.configure_memory_dump(image_base);
        }
        let _ = writeln!(
            out,
            "\nBinary format={:?}, arch={}, 64bit={}, image_base=0x{:X}, sections={}",
            bin.format,
            bin.arch,
            bin.is_64bit,
            bin.image_base,
            bin.sections.len()
        );
        if bin.fairplay_encrypted {
            let _ = writeln!(
                out,
                "[WARNING] Mach-O has FairPlay encryption (cryptid != 0): __TEXT code may be encrypted."
            );
        }
        let custom_sym = profile.and_then(|p| p.register_symbol.as_deref());
        let ctx = find_registration_context(&bin, custom_sym);
        let meta_reg_va = ctx
            .meta_reg_va
            .or_else(|| scan_metadata_registration(&bin, &meta.types));
        let _ = writeln!(
            out,
            "Register symbol:  {}",
            ctx.matched_symbol.as_deref().unwrap_or("none (fallback scan)")
        );
        let _ = writeln!(
            out,
            "CodeRegistration: {}",
            ctx.code_reg_va
                .map(|v| format!("0x{:X}", v))
                .unwrap_or_else(|| "not found".into())
        );
        let _ = writeln!(
            out,
            "MetaRegistration: {}",
            meta_reg_va
                .map(|v| format!("0x{:X}", v))
                .unwrap_or_else(|| "not found".into())
        );

        if let Some(cr) = ctx.code_reg_va {
            let rvas = extract_method_rvas(&bin, cr);
            let _ = writeln!(out, "Extracted RVAs:   {}", rvas.len());
        }
        if let Some(mr) = meta_reg_va {
            let offsets = extract_field_offsets(&bin, &meta.types, mr);
            let types_arr = find_types_array(&bin, mr, &meta.types);
            let _ = writeln!(out, "Types w/ offsets: {}", offsets.len());
            if let Some((cnt, arr_va, stride)) = types_arr {
                let _ = writeln!(
                    out,
                    "Types array:      va=0x{:X}, count={}, stride={}B",
                    arr_va, cnt, stride
                );
            } else {
                let _ = writeln!(out, "Types array:      not found");
            }
        }
    }
    Ok(out)
}

pub fn execute_inspect(
    metadata: &Path,
    binary: Option<&Path>,
    profile: Option<&Path>,
    image_base: Option<u64>,
) -> Result<String> {
    let (meta_bytes, prof) = load_metadata_bytes(metadata, profile)?;
    let bin_bytes = match binary {
        Some(p) => Some(
            std::fs::read(p).with_context(|| format!("Failed to read binary: {}", p.display()))?,
        ),
        None => None,
    };
    execute_inspect_bytes(meta_bytes, bin_bytes, prof.as_ref(), image_base)
}

pub fn execute_inspect_package(
    package_path: &Path,
    preferred_arch: Option<&str>,
    profile: Option<&Path>,
    image_base: Option<u64>,
) -> Result<String> {
    let pkg = package::extract_from_package(package_path, preferred_arch)?;
    let (meta_bytes, prof) = apply_profile_to_bytes(pkg.metadata_bytes, profile)?;
    let report =
        execute_inspect_bytes(meta_bytes, Some(pkg.binary_bytes), prof.as_ref(), image_base)?;
    Ok(format!("Package:          {}\n{}", pkg.summary, report))
}

fn execute_inspect_bytes(
    meta_bytes: Vec<u8>,
    bin_bytes: Option<Vec<u8>>,
    prof: Option<&DumpProfile>,
    image_base: Option<u64>,
) -> Result<String> {
    if should_use_adaptive(&meta_bytes, prof) {
        return run_adaptive_inspect(&meta_bytes, bin_bytes, prof, image_base);
    }

    let mut out = String::new();
    let header = MetadataHeader::parse(&meta_bytes)?;
    let widths = Widths::for_version(header.version, &header, None);
    let _ = writeln!(out, "Metadata magic:   0x{:08X}", header.magic);
    let _ = writeln!(out, "Metadata version: {}", header.version);
    let _ = writeln!(
        out,
        "Inferred widths:  type_def={}B, gc={}B, type={}B, param={}B, iface={}B, method={}B",
        widths.type_def,
        widths.generic_container,
        widths.il2cpp_type,
        widths.parameter,
        widths.interface,
        widths.method
    );
    let _ = writeln!(out, "\nSections:");
    for (name, sec) in header.sections_summary() {
        let _ = writeln!(
            out,
            "  {:32} off=0x{:08x} size=0x{:08x} count={}",
            name, sec.offset, sec.size, sec.count
        );
    }

    if let Some(bytes) = bin_bytes {
        let mut bin = BinaryImage::parse(bytes)?;
        if image_base.is_some() {
            bin.configure_memory_dump(image_base);
        }
        let _ = writeln!(
            out,
            "\nBinary format={:?}, arch={}, 64bit={}, image_base=0x{:X}, sections={}",
            bin.format,
            bin.arch,
            bin.is_64bit,
            bin.image_base,
            bin.sections.len()
        );
        if bin.fairplay_encrypted {
            let _ = writeln!(
                out,
                "[WARNING] Mach-O has FairPlay encryption (cryptid != 0): __TEXT code may be encrypted."
            );
        }
        let meta = Metadata::parse_with_widths(meta_bytes, header, widths)?;
        let img_names: Vec<String> = meta
            .images
            .iter()
            .map(|i| meta.get_string(i.name_index).to_string())
            .collect();
        let reg = run_registration_scan(
            &bin,
            meta.type_defs.len(),
            meta.header.version,
            &img_names,
            meta.methods.len(),
            None,
        )?;
        let _ = writeln!(
            out,
            "MetadataRegistration VA: 0x{:X} (numTypes={})",
            reg.metadata_registration_va, reg.num_types
        );
        let _ = writeln!(
            out,
            "CodeRegistration VA:     {}",
            reg.code_registration_va
                .map(|v| format!("0x{:X}", v))
                .unwrap_or_else(|| "not found (modules found directly)".into())
        );
        let _ = writeln!(out, "CodeGenModules matched:  {}", reg.code_gen_modules.len());
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn run_adaptive_dump<F>(
    bin: &BinaryImage,
    meta_bytes: &[u8],
    out: &Path,
    profile: Option<&DumpProfile>,
    meta_reg_override: Option<u64>,
    code_reg_override: Option<u64>,
    log: &mut String,
    mut on_progress: F,
) -> Result<String>
where
    F: FnMut(f32, &str),
{
    let mut emit = |p: f32, msg: String| {
        on_progress(p, &msg);
        let _ = writeln!(log, "{}", msg);
    };

    emit(0.25, "[2/5] Parsing metadata tables (Adaptive Engine)...".into());
    let meta = AdaptiveMetadata::parse(meta_bytes)?;
    emit(
        0.38,
        format!(
            "      Layout: {} | images={}, types={}, fields={}, methods={}, params={}",
            meta.layout_summary,
            meta.images.len(),
            meta.types.len(),
            meta.fields.len(),
            meta.methods.len(),
            meta.params.len()
        ),
    );

    emit(0.45, "[3/5] Tracing Registration & Il2CppType layout in binary...".into());
    let custom_sym = profile.and_then(|p| p.register_symbol.as_deref());
    let ctx = find_registration_context(bin, custom_sym);
    let code_reg_va = code_reg_override.or(ctx.code_reg_va);
    let meta_reg_va = meta_reg_override
        .or(ctx.meta_reg_va)
        .or_else(|| scan_metadata_registration(bin, &meta.types));

    if let Some(ref sym) = ctx.matched_symbol {
        emit(0.50, format!("      Matched register symbol: {}", sym));
    }

    let method_rvas = if let Some(cr) = code_reg_va {
        emit(0.55, format!("      CodeRegistration=0x{:X}", cr));
        extract_method_rvas(bin, cr)
    } else {
        emit(0.55, "      Warning: CodeRegistration not found (method RVAs will be -1)".into());
        Vec::new()
    };

    let (field_offsets, count, array_va, stride) = if let Some(mr) = meta_reg_va {
        let offsets = extract_field_offsets(bin, &meta.types, mr);
        let (cnt, arr_va, st) = find_types_array(bin, mr, &meta.types).unwrap_or((0, 0, 0));
        emit(
            0.68,
            format!(
                "      MetadataRegistration=0x{:X} (typesWithOffsets={}, typesArray=0x{:X}, count={}, stride={}B)",
                mr,
                offsets.len(),
                arr_va,
                cnt,
                st
            ),
        );
        (offsets, cnt, arr_va, st)
    } else {
        emit(0.68, "      Warning: MetadataRegistration not found (offsets and field types degraded)".into());
        (HashMap::new(), 0, 0, 0)
    };

    emit(
        0.75,
        format!(
            "[4/5] Mapping {} method pointers & generating outputs...",
            method_rvas.len()
        ),
    );
    let resolver = AdaptiveTypeResolver {
        bin,
        types: &meta.types,
        array_va,
        count,
        stride,
        module_tag: meta.module_tag,
    };

    std::fs::create_dir_all(out)?;
    let dump_cs = generate_adaptive_dump_cs(bin, &meta, &resolver, &field_offsets, &method_rvas)?;
    std::fs::write(out.join("dump.cs"), &dump_cs)?;

    emit(0.90, "      Writing script.json, il2cpp.h & IDA/Ghidra scripts...".into());
    {
        let f = std::fs::File::create(out.join("script.json"))?;
        let mut bw = std::io::BufWriter::new(f);
        write_adaptive_script_json(&mut bw, bin, &meta, &method_rvas)?;
        bw.flush()?;
    }
    std::fs::write(out.join("ida_import.py"), generate_ida_import_py())?;
    std::fs::write(out.join("ghidra_import.py"), generate_ghidra_import_py())?;

    let il2cpp_h = generate_adaptive_il2cpp_h(&meta, &resolver, &field_offsets)?;
    std::fs::write(out.join("il2cpp.h"), il2cpp_h)?;

    emit(
        1.0,
        format!(
            "[5/5] Done! Wrote dump.cs, script.json, il2cpp.h, ida_import.py, ghidra_import.py to {}",
            out.display()
        ),
    );
    Ok(dump_cs)
}

#[allow(clippy::too_many_arguments)]
pub fn execute_dump<F>(
    binary: &Path,
    metadata: &Path,
    out: &Path,
    profile: Option<&Path>,
    meta_reg: Option<u64>,
    code_reg: Option<u64>,
    memory_dump: bool,
    image_base: Option<u64>,
    on_progress: F,
) -> Result<(String, String)>
where
    F: FnMut(f32, &str),
{
    let (meta_bytes, prof) = load_metadata_bytes(metadata, profile)?;
    let bin_bytes = std::fs::read(binary)
        .with_context(|| format!("Failed to read binary: {}", binary.display()))?;
    execute_dump_bytes(
        bin_bytes,
        meta_bytes,
        prof.as_ref(),
        None,
        out,
        meta_reg,
        code_reg,
        memory_dump,
        image_base,
        on_progress,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_dump_package<F>(
    package_path: &Path,
    preferred_arch: Option<&str>,
    out: &Path,
    profile: Option<&Path>,
    meta_reg: Option<u64>,
    code_reg: Option<u64>,
    memory_dump: bool,
    image_base: Option<u64>,
    mut on_progress: F,
) -> Result<(String, String)>
where
    F: FnMut(f32, &str),
{
    on_progress(0.05, "[0/5] Extracting package archive...");
    let pkg = package::extract_from_package(package_path, preferred_arch)?;
    let (meta_bytes, prof) = apply_profile_to_bytes(pkg.metadata_bytes, profile)?;
    execute_dump_bytes(
        pkg.binary_bytes,
        meta_bytes,
        prof.as_ref(),
        Some(&pkg.summary),
        out,
        meta_reg,
        code_reg,
        memory_dump,
        image_base,
        on_progress,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_dump_bytes<F>(
    bin_bytes: Vec<u8>,
    meta_bytes: Vec<u8>,
    prof: Option<&DumpProfile>,
    pkg_summary: Option<&str>,
    out: &Path,
    meta_reg: Option<u64>,
    code_reg: Option<u64>,
    memory_dump: bool,
    image_base: Option<u64>,
    mut on_progress: F,
) -> Result<(String, String)>
where
    F: FnMut(f32, &str),
{
    let mut log = String::new();
    let mut emit = |p: f32, msg: String| {
        on_progress(p, &msg);
        let _ = writeln!(log, "{}", msg);
    };

    if let Some(summary) = pkg_summary {
        emit(0.08, format!("      {}", summary));
    } else {
        emit(0.08, "[1/5] Loading metadata and binary...".into());
    }
    let mut bin = BinaryImage::parse(bin_bytes)?;
    if memory_dump || image_base.is_some() {
        bin.configure_memory_dump(image_base);
    }
    if bin.fairplay_encrypted {
        emit(
            0.12,
            "[WARNING] Mach-O has FairPlay encryption (cryptid != 0): __TEXT code may be encrypted.".into(),
        );
    }

    if should_use_adaptive(&meta_bytes, prof) {
        let ver = if meta_bytes.len() >= 8 {
            i32::from_le_bytes([meta_bytes[4], meta_bytes[5], meta_bytes[6], meta_bytes[7]])
        } else {
            0
        };
        emit(
            0.18,
            format!(
                "      Binary: {:?} ({}, 64bit={}, base=0x{:X}) | Metadata v{} (adaptive)",
                bin.format, bin.arch, bin.is_64bit, bin.image_base, ver
            ),
        );
        let dump_cs = run_adaptive_dump(
            &bin,
            &meta_bytes,
            out,
            prof,
            meta_reg,
            code_reg,
            &mut log,
            on_progress,
        )?;
        return Ok((log, dump_cs));
    }

    let header = MetadataHeader::parse(&meta_bytes)?;
    emit(
        0.18,
        format!(
            "      Binary: {:?} ({}, 64bit={}, base=0x{:X}) | Metadata v{}",
            bin.format, bin.arch, bin.is_64bit, bin.image_base, header.version
        ),
    );

    emit(0.30, "[2/5] Parsing metadata tables...".into());
    let prelim_meta = Metadata::parse(meta_bytes.clone(), None)?;

    emit(0.45, "[3/5] Scanning binary for Registration structures...".into());
    let img_names: Vec<String> = prelim_meta
        .images
        .iter()
        .map(|i| prelim_meta.get_string(i.name_index).to_string())
        .collect();
    let reg = run_registration_scan(
        &bin,
        prelim_meta.type_defs.len(),
        header.version,
        &img_names,
        prelim_meta.methods.len(),
        meta_reg,
    )?;

    let exact_widths = Widths::for_version(header.version, &header, Some(reg.num_types));
    let meta = if exact_widths != prelim_meta.widths {
        Metadata::parse_with_widths(meta_bytes, header, exact_widths)?
    } else {
        prelim_meta
    };
    emit(
        0.65,
        format!(
            "      MetadataRegistration=0x{:X} (numTypes={}, typesWidth={}B), CodeGenModules={}",
            reg.metadata_registration_va,
            reg.num_types,
            meta.widths.il2cpp_type,
            reg.code_gen_modules.len()
        ),
    );

    emit(0.75, "[4/5] Mapping method pointers & generating outputs...".into());
    let method_vas = build_method_pointer_map(&bin, &meta, &reg);
    emit(0.82, format!("      Mapped {} method RVAs", method_vas.len()));

    std::fs::create_dir_all(out)?;
    let dump_cs = generate_dump_cs(&bin, &meta, &reg, &method_vas)?;
    std::fs::write(out.join("dump.cs"), &dump_cs)?;

    emit(0.92, "      Writing script.json, il2cpp.h & IDA/Ghidra scripts...".into());
    {
        let f = std::fs::File::create(out.join("script.json"))?;
        let mut bw = std::io::BufWriter::new(f);
        write_script_json(&mut bw, &bin, &meta, &reg, &method_vas)?;
        bw.flush()?;
    }
    std::fs::write(out.join("ida_import.py"), generate_ida_import_py())?;
    std::fs::write(out.join("ghidra_import.py"), generate_ghidra_import_py())?;

    let il2cpp_h = generate_il2cpp_h(&bin, &meta, &reg)?;
    std::fs::write(out.join("il2cpp.h"), il2cpp_h)?;

    emit(
        1.0,
        format!(
            "[5/5] Done! Wrote dump.cs, script.json, il2cpp.h, ida_import.py, ghidra_import.py to {}",
            out.display()
        ),
    );
    Ok((log, dump_cs))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None | Some(Commands::Gui) => {
            gui::run_gui()?;
        }
        Some(Commands::Inspect {
            metadata,
            binary,
            package: pkg,
            arch,
            profile,
            image_base,
        }) => {
            let report = if let Some(pkg_path) = pkg {
                execute_inspect_package(&pkg_path, arch.as_deref(), profile.as_deref(), image_base)?
            } else if let Some(meta_path) = metadata {
                execute_inspect(&meta_path, binary.as_deref(), profile.as_deref(), image_base)?
            } else {
                bail!("Inspect requires either --package <file> or --metadata <file>");
            };
            print!("{}", report);
        }
        Some(Commands::Dump {
            binary,
            metadata,
            package: pkg,
            arch,
            out,
            profile,
            meta_reg,
            code_reg,
            memory_dump,
            image_base,
        }) => {
            if let Some(pkg_path) = pkg {
                let _ = execute_dump_package(
                    &pkg_path,
                    arch.as_deref(),
                    &out,
                    profile.as_deref(),
                    meta_reg,
                    code_reg,
                    memory_dump,
                    image_base,
                    |_, msg| println!("{}", msg),
                )?;
            } else if let (Some(bin_path), Some(meta_path)) = (binary, metadata) {
                let _ = execute_dump(
                    &bin_path,
                    &meta_path,
                    &out,
                    profile.as_deref(),
                    meta_reg,
                    code_reg,
                    memory_dump,
                    image_base,
                    |_, msg| println!("{}", msg),
                )?;
            } else {
                bail!("Dump requires either --package <file> or both --binary <file> and --metadata <file>");
            }
        }
        Some(Commands::Carve { input, out }) => {
            let blob = std::fs::read(&input)
                .with_context(|| format!("Failed to read RAM dump: {}", input.display()))?;
            let carved = carve_metadata_from_blob(&blob)?;
            std::fs::write(&out, &carved)?;
            let ver = if carved.len() >= 8 {
                i32::from_le_bytes([carved[4], carved[5], carved[6], carved[7]])
            } else {
                0
            };
            println!(
                "Carved metadata v{} ({} bytes) -> {}",
                ver,
                carved.len(),
                out.display()
            );
        }
        Some(Commands::Diff {
            old,
            new,
            filter,
            cpp,
            changed,
        }) => {
            diff::run_diff(&old, &new, filter.as_deref(), cpp, changed)?;
        }
    }

    Ok(())
}
