use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use zip::ZipArchive;

const MAX_NESTED_APK_BYTES: u64 = 1024 * 1024 * 1024;

/// Binary and metadata payloads extracted in memory from an `.apk`, `.xapk`, `.apks`, or `.ipa`.
#[allow(dead_code)]
pub struct ExtractedPackage {
    pub binary_bytes: Vec<u8>,
    pub binary_name: String,
    pub metadata_bytes: Vec<u8>,
    pub metadata_name: String,
    pub summary: String,
}

struct ArchiveScanResult {
    best_bin: Option<(usize, String, Vec<u8>)>,
    metadata: Option<(String, Vec<u8>)>,
    nested_apks: Vec<String>,
}

/// Return `true` when `path` has a supported mobile package extension.
pub fn is_package_path(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .as_deref(),
        Some("apk" | "xapk" | "apks" | "ipa")
    )
}

fn is_macho_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    matches!(
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        0xFEED_FACF | 0xCF_FA_ED_FE | 0xCAFE_BABE | 0xBEBA_FECA
    )
}

fn abi_rank(entry_name: &str, preferred_arch: Option<&str>) -> Option<usize> {
    let lower = entry_name.to_ascii_lowercase();
    if !lower.ends_with(".so") || !lower.contains("libil2cpp") {
        return None;
    }
    if let Some(pref) = preferred_arch {
        let p = pref.trim().to_ascii_lowercase();
        if !p.is_empty() && p != "auto" {
            return lower.contains(&format!("/{}/", p)).then_some(0);
        }
    }
    if lower.contains("/arm64-v8a/") {
        Some(0)
    } else if lower.contains("/armeabi-v7a/") {
        Some(1)
    } else if lower.contains("/x86_64/") {
        Some(2)
    } else if lower.contains("/x86/") {
        Some(3)
    } else {
        Some(4)
    }
}

fn read_zip_entry<R: Read + Seek>(archive: &mut ZipArchive<R>, index: usize) -> Result<Vec<u8>> {
    let mut entry = archive.by_index(index)?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

fn scan_archive<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    prefix: &str,
    preferred_arch: Option<&str>,
    is_ipa_hint: bool,
) -> Result<ArchiveScanResult> {
    let mut best_apk_bin: Option<(usize, String, Vec<u8>)> = None;
    let mut best_ipa_bin: Option<(usize, String, Vec<u8>)> = None;
    let mut metadata_found: Option<(String, Vec<u8>)> = None;
    let mut nested_apks = Vec::new();

    for i in 0..archive.len() {
        let (name, size) = {
            let f = archive.by_index(i)?;
            (f.name().to_string(), f.size())
        };
        let lower = name.to_ascii_lowercase();

        if lower.ends_with(".apk") && !lower.contains('/') {
            if size <= MAX_NESTED_APK_BYTES {
                nested_apks.push(name);
            }
            continue;
        }
        if lower.ends_with(".apk") && lower.contains('/') && size <= MAX_NESTED_APK_BYTES {
            nested_apks.push(name);
            continue;
        }

        if metadata_found.is_none() && lower.ends_with("global-metadata.dat") {
            let bytes = read_zip_entry(archive, i)?;
            metadata_found = Some((format!("{}{}", prefix, name), bytes));
            continue;
        }

        if let Some(rank) = abi_rank(&name, preferred_arch) {
            let replace = best_apk_bin
                .as_ref()
                .map(|(best_rank, _, _)| rank < *best_rank)
                .unwrap_or(true);
            if replace {
                let bytes = read_zip_entry(archive, i)?;
                best_apk_bin = Some((rank, format!("{}{}", prefix, name), bytes));
            }
            continue;
        }

        if is_ipa_hint && lower.starts_with("payload/") {
            if lower.contains("/frameworks/unityframework.framework/unityframework")
                && !lower.ends_with(".plist")
            {
                let bytes = read_zip_entry(archive, i)?;
                best_ipa_bin = Some((0, format!("{}{}", prefix, name), bytes));
            } else if best_ipa_bin.as_ref().map(|(r, _, _)| *r > 0).unwrap_or(true)
                && size > 512 * 1024
            {
                // Check top-level Payload/<App>.app/<Executable> without extension
                let parts: Vec<&str> = name.split('/').collect();
                if parts.len() == 3 && parts[1].to_ascii_lowercase().ends_with(".app") && !parts[2].contains('.') {
                    let bytes = read_zip_entry(archive, i)?;
                    if is_macho_bytes(&bytes) {
                        let score = usize::MAX - bytes.len();
                        let replace = best_ipa_bin
                            .as_ref()
                            .map(|(best_s, _, _)| score < *best_s)
                            .unwrap_or(true);
                        if replace {
                            best_ipa_bin = Some((score.max(1), format!("{}{}", prefix, name), bytes));
                        }
                    }
                }
            }
        }
    }

    let picked_bin = best_apk_bin.or(best_ipa_bin);
    Ok(ArchiveScanResult {
        best_bin: picked_bin,
        metadata: metadata_found,
        nested_apks,
    })
}

/// Extract `libil2cpp.so` / Mach-O binary and `global-metadata.dat` from `.apk`/`.xapk`/`.apks`/`.ipa`.
pub fn extract_from_package(path: &Path, preferred_arch: Option<&str>) -> Result<ExtractedPackage> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    let is_ipa = ext == "ipa";

    let file = File::open(path)
        .with_context(|| format!("Failed to open package: {}", path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("Invalid ZIP/package archive: {}", path.display()))?;

    let scan = scan_archive(&mut archive, "", preferred_arch, is_ipa)?;
    let mut best_bin = scan.best_bin;
    let mut metadata_found = scan.metadata;
    let nested_apks = scan.nested_apks;

    if (best_bin.is_none() || metadata_found.is_none()) && !nested_apks.is_empty() {
        for apk_name in nested_apks {
            let apk_bytes = {
                let mut entry = archive.by_name(&apk_name)?;
                let mut buf = Vec::with_capacity(entry.size() as usize);
                entry.read_to_end(&mut buf)?;
                buf
            };
            let mut sub = ZipArchive::new(Cursor::new(apk_bytes))
                .with_context(|| format!("Failed to open nested APK {}", apk_name))?;
            let prefix = format!("{}!", apk_name);
            let sub_scan = scan_archive(&mut sub, &prefix, preferred_arch, false)?;
            if let Some((rank, bname, bbytes)) = sub_scan.best_bin {
                let replace = best_bin
                    .as_ref()
                    .map(|(r, _, _)| rank < *r)
                    .unwrap_or(true);
                if replace {
                    best_bin = Some((rank, bname, bbytes));
                }
            }
            if metadata_found.is_none() {
                metadata_found = sub_scan.metadata;
            }
            if best_bin.is_some() && metadata_found.is_some() {
                if let Some(pref) = preferred_arch {
                    if !pref.is_empty() && pref != "auto" {
                        break;
                    }
                } else if best_bin.as_ref().map(|(r, _, _)| *r == 0).unwrap_or(false) {
                    break;
                }
            }
        }
    }

    let Some((_, binary_name, binary_bytes)) = best_bin else {
        bail!(
            "Could not find IL2CPP binary inside package {} (arch={})",
            path.display(),
            preferred_arch.unwrap_or("auto")
        );
    };
    let Some((metadata_name, metadata_bytes)) = metadata_found else {
        bail!("Could not find global-metadata.dat inside package {}", path.display());
    };

    let summary = format!(
        "Extracted {} ({} bytes) & {} ({} bytes)",
        binary_name,
        binary_bytes.len(),
        metadata_name,
        metadata_bytes.len()
    );
    Ok(ExtractedPackage {
        binary_bytes,
        binary_name,
        metadata_bytes,
        metadata_name,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn build_zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zw = ZipWriter::new(&mut cursor);
            let opts = SimpleFileOptions::default();
            for (name, data) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn test_extract_apk_prefers_arm64_and_respects_arch() {
        let tmp = std::env::temp_dir().join("il2cpp_rs_test_pkg.apk");
        let bytes = build_zip_bytes(&[
            ("lib/armeabi-v7a/libil2cpp.so", b"ARMV7_SO"),
            ("lib/arm64-v8a/libil2cpp.so", b"ARM64_SO"),
            ("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"META31"),
        ]);
        std::fs::write(&tmp, bytes).unwrap();

        let auto_pkg = extract_from_package(&tmp, None).unwrap();
        assert_eq!(auto_pkg.binary_name, "lib/arm64-v8a/libil2cpp.so");
        assert_eq!(auto_pkg.binary_bytes, b"ARM64_SO");
        assert_eq!(auto_pkg.metadata_bytes, b"META31");

        let v7_pkg = extract_from_package(&tmp, Some("armeabi-v7a")).unwrap();
        assert_eq!(v7_pkg.binary_name, "lib/armeabi-v7a/libil2cpp.so");
        assert_eq!(v7_pkg.binary_bytes, b"ARMV7_SO");

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_extract_xapk_nested_splits() {
        let tmp = std::env::temp_dir().join("il2cpp_rs_test_pkg.xapk");
        let base_apk = build_zip_bytes(&[(
            "assets/bin/Data/Managed/Metadata/global-metadata.dat",
            b"SPLIT_META",
        )]);
        let arm64_apk = build_zip_bytes(&[("lib/arm64-v8a/libil2cpp.so", b"SPLIT_ARM64")]);
        let xapk_bytes = build_zip_bytes(&[
            ("base.apk", &base_apk),
            ("config.arm64_v8a.apk", &arm64_apk),
        ]);
        std::fs::write(&tmp, xapk_bytes).unwrap();

        let pkg = extract_from_package(&tmp, None).unwrap();
        assert_eq!(pkg.binary_name, "config.arm64_v8a.apk!lib/arm64-v8a/libil2cpp.so");
        assert_eq!(pkg.binary_bytes, b"SPLIT_ARM64");
        assert_eq!(pkg.metadata_bytes, b"SPLIT_META");

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_extract_ipa_unity_framework() {
        let tmp = std::env::temp_dir().join("il2cpp_rs_test_pkg.ipa");
        let bytes = build_zip_bytes(&[
            (
                "Payload/Game.app/Frameworks/UnityFramework.framework/UnityFramework",
                b"MACHO_UF",
            ),
            (
                "Payload/Game.app/Data/Managed/Metadata/global-metadata.dat",
                b"IPA_META",
            ),
        ]);
        std::fs::write(&tmp, bytes).unwrap();

        let pkg = extract_from_package(&tmp, None).unwrap();
        assert!(pkg.binary_name.ends_with("UnityFramework"));
        assert_eq!(pkg.binary_bytes, b"MACHO_UF");
        assert_eq!(pkg.metadata_bytes, b"IPA_META");

        let _ = std::fs::remove_file(&tmp);
    }
}
