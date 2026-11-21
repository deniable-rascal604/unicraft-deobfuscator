use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use anyhow::{bail, Context, Result};

// A 16-byte crafted ASAR can claim a 4GB header; cap before allocating to avoid OOM.
const MAX_HEADER_SIZE: u32 = 64 * 1024 * 1024;

// 2GB quota to stop archive bombs from filling the analyst's disk.
const MAX_EXTRACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct AsarStats {
    pub total_files: usize,
    pub total_dirs: usize,
    pub total_bytes: u64,
}

// Windows chokes on CON/PRN/NUL even inside subfolders.
fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("");
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn validate_entry_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.contains(':')
        || is_windows_reserved(name)
    {
        bail!(
            "Guvenlik ihlali: ASAR icinde gecersiz veya tehlikeli dosya adi: {:?}",
            name
        );
    }
    Ok(())
}

pub fn extract_asar(asar_path: &Path, output_dir: &Path) -> Result<AsarStats> {
    let mut file = File::open(asar_path)
        .with_context(|| format!("ASAR dosyasi acilamadi: {:?}", asar_path))?;

    let file_len = file
        .metadata()
        .with_context(|| format!("ASAR dosya boyutu alinamadi: {:?}", asar_path))?
        .len();

    if file_len < 16 {
        bail!(
            "Gecersiz ASAR: Dosya boyutu 16 bayttan kucuk ({} bayt)",
            file_len
        );
    }

    let mut header_bytes = [0u8; 16];
    file.read_exact(&mut header_bytes)
        .context("ASAR 16-byte baslik okunamadi")?;

    let total_header_len = u32::from_le_bytes(header_bytes[4..8].try_into().unwrap());
    let json_len = u32::from_le_bytes(header_bytes[12..16].try_into().unwrap());

    if json_len == 0 || json_len > MAX_HEADER_SIZE || (json_len as u64) > file_len - 16 {
        bail!(
            "Gecersiz veya supheli ASAR baslik boyutu: {} bayt (Dosya: {} bayt)",
            json_len,
            file_len
        );
    }

    if total_header_len < json_len.saturating_add(8) {
        bail!("Gecersiz ASAR toplam baslik uzunlugu: {}", total_header_len);
    }

    let payload_base = 8u64
        .checked_add(total_header_len as u64)
        .context("ASAR baslik boyutu tasti")?;

    if payload_base > file_len {
        bail!(
            "Gecersiz ASAR: payload baslangici ({}) dosya boyutunu ({}) asiyor",
            payload_base,
            file_len
        );
    }

    let mut json_buf = vec![0u8; json_len as usize];
    file.read_exact(&mut json_buf)
        .context("ASAR JSON baslik verisi okunamadi")?;

    let json_str =
        String::from_utf8(json_buf).context("ASAR basligi gecerli UTF-8 icermiyor")?;

    let header: serde_json::Value =
        serde_json::from_str(&json_str).context("ASAR basligi JSON olarak ayristirilamadi")?;

    let unpacked_dir = {
        let parent = asar_path.parent().unwrap_or_else(|| Path::new(""));
        let file_name = asar_path.file_name().unwrap_or_default().to_string_lossy();
        let path = parent.join(format!("{}.unpacked", file_name));
        if path.exists() {
            Some(path)
        } else {
            None
        }
    };
    let canonical_unpacked_root = unpacked_dir
        .as_ref()
        .and_then(|p| p.canonicalize().ok());

    fs::create_dir_all(output_dir)
        .with_context(|| format!("Cikti dizini olusturulamadi: {:?}", output_dir))?;

    let canonical_out_dir = output_dir
        .canonicalize()
        .unwrap_or_else(|_| output_dir.to_path_buf());

    let mut stats = AsarStats::default();

    if let Some(files_map) = header.get("files") {
        extract_tree(
            &mut file,
            file_len,
            payload_base,
            files_map,
            &canonical_out_dir,
            &canonical_out_dir,
            unpacked_dir.as_deref(),
            canonical_unpacked_root.as_deref(),
            &mut stats,
        )?;
    }

    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn extract_tree(
    reader: &mut (impl Read + Seek),
    file_len: u64,
    payload_base: u64,
    node: &serde_json::Value,
    current_dir: &Path,
    root_output_dir: &Path,
    unpacked_dir: Option<&Path>,
    unpacked_root: Option<&Path>,
    stats: &mut AsarStats,
) -> Result<()> {
    let files = match node {
        serde_json::Value::Object(map) => map,
        _ => return Ok(()),
    };

    for (name, item) in files {
        validate_entry_name(name)?;

        let target_path = current_dir.join(name);
        if !target_path.starts_with(root_output_dir) {
            bail!("Path traversal engellendi: {:?}", target_path);
        }

        if item.get("link").is_some() {
            continue;
        }

        if let Some(sub_files) = item.get("files") {
            fs::create_dir_all(&target_path)?;
            stats.total_dirs += 1;
            let child_unpacked = unpacked_dir.map(|p| p.join(name));
            extract_tree(
                reader,
                file_len,
                payload_base,
                sub_files,
                &target_path,
                root_output_dir,
                child_unpacked.as_deref(),
                unpacked_root,
                stats,
            )?;
            continue;
        }

        let is_unpacked = item
            .get("unpacked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if is_unpacked {
            if let Some(u_dir) = unpacked_dir {
                let source = u_dir.join(name);
                if let Ok(meta) = fs::symlink_metadata(&source) {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    if let Some(u_root) = unpacked_root {
                        if let Ok(canon) = source.canonicalize() {
                            if !canon.starts_with(u_root) {
                                bail!(
                                    "Unpacked path traversal engellendi: {:?}",
                                    source
                                );
                            }
                        }
                    }
                    if meta.is_file() {
                        if let Some(p) = target_path.parent() {
                            fs::create_dir_all(p)?;
                        }
                        let copied = fs::copy(&source, &target_path)?;
                        if stats.total_bytes.saturating_add(copied) > MAX_EXTRACT_BYTES {
                            bail!("ASAR toplam cikarma boyutu sinirini asti");
                        }
                        stats.total_files += 1;
                        stats.total_bytes += copied;
                    }
                }
            }
            continue;
        }

        let size = match item.get("size") {
            Some(v) => v
                .as_u64()
                .with_context(|| format!("ASAR dosya boyutu gecersiz: {:?}", name))?,
            None => 0,
        };

        let offset = match item.get("offset") {
            Some(serde_json::Value::String(s)) => s
                .parse::<u64>()
                .with_context(|| format!("ASAR dosya offseti gecersiz: {:?}", name))?,
            Some(serde_json::Value::Number(n)) => n
                .as_u64()
                .with_context(|| format!("ASAR dosya offseti gecersiz: {:?}", name))?,
            None if size == 0 => 0,
            _ => bail!("ASAR dosya offseti eksik veya gecersiz: {:?}", name),
        };

        let file_pos = payload_base
            .checked_add(offset)
            .with_context(|| format!("ASAR dosya offseti tasti: {:?}", name))?;
        let end_pos = file_pos
            .checked_add(size)
            .with_context(|| format!("ASAR dosya araligi tasti: {:?}", name))?;

        if end_pos > file_len {
            bail!(
                "ASAR dosya verisi dosya sonunu asiyor: {} (end={}, file_len={})",
                name,
                end_pos,
                file_len
            );
        }

        if stats.total_bytes.saturating_add(size) > MAX_EXTRACT_BYTES {
            bail!("ASAR toplam cikarma boyutu sinirini asti");
        }

        reader
            .seek(SeekFrom::Start(file_pos))
            .with_context(|| format!("Dosya konumuna atlanamadi: pos={}", file_pos))?;

        if let Some(p) = target_path.parent() {
            fs::create_dir_all(p)?;
        }

        let mut out_file = File::create(&target_path)
            .with_context(|| format!("Dosya olusturulamadi: {:?}", target_path))?;

        let mut take_reader = reader.by_ref().take(size);
        let copied = io::copy(&mut take_reader, &mut out_file)
            .with_context(|| format!("Dosya verisi yazilamadi: {:?}", target_path))?;

        stats.total_files += 1;
        stats.total_bytes += copied;
    }

    Ok(())
}
