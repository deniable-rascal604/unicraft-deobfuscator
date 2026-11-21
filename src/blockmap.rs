use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use anyhow::{bail, Context, Result};
use chrono::Local;
use flate2::read::GzDecoder;
use regex::Regex;

use crate::utils;

static VERSION_STRIP_RE: OnceLock<Regex> = OnceLock::new();

fn blockmap_family_key(filename: &str) -> String {
    let re = VERSION_STRIP_RE.get_or_init(|| Regex::new(r"\d+\.\d+\.\d+").unwrap());
    re.replace_all(filename, "").to_lowercase()
}

fn inner_ext_tag(filename: &str) -> String {
    let stripped = if filename.to_ascii_lowercase().ends_with(".blockmap") {
        &filename[..filename.len() - ".blockmap".len()]
    } else {
        filename
    };
    let ext = Path::new(stripped)
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    let clean: String = ext
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if clean.is_empty() {
        "blockmap".to_string()
    } else {
        clean
    }
}

fn read_blockmap_json(path: &Path) -> Result<serde_json::Value> {
    let file = File::open(path)
        .with_context(|| format!("Blockmap dosyasi acilamadi: {:?}", path))?;
    let mut decoder = GzDecoder::new(file);
    let mut json_content = String::new();
    decoder
        .read_to_string(&mut json_content)
        .with_context(|| format!("Gzip acma hatasi ({:?}): gecerli bir .blockmap olmayabilir", path))?;
    serde_json::from_str(&json_content)
        .with_context(|| format!("Blockmap JSON ayristirilamadi: {:?}", path))
}

fn collect_checksums(data: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(files) = data.get("files").and_then(|f| f.as_array()) {
        for f in files {
            if let Some(arr) = f
                .get("checksums")
                .or_else(|| f.get("blockHashes"))
                .and_then(|h| h.as_array())
            {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}

pub fn analyze_blockmap(
    current_path: &Path,
    previous_path: Option<&Path>,
    output_dir: &Path,
) -> Result<PathBuf> {
    let filename = current_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let ext_tag = inner_ext_tag(&filename);
    let version = utils::extract_version(&filename);
    let version_str = format!("{}.{}.{}", version.0, version.1, version.2);

    println!("    [*] Analyzing blockmap compression blocks (v{})...", version_str);

    let prev_file_to_compare: Option<PathBuf> = if let Some(explicit_prev) = previous_path {
        if !explicit_prev.exists() {
            bail!(
                "Specified previous blockmap file not found: {:?}",
                explicit_prev
            );
        }
        Some(explicit_prev.to_path_buf())
    } else if version > (0, 0, 0) {
        let search_dir = current_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let target_family = blockmap_family_key(&filename);

        fs::read_dir(search_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .filter_map(|p| {
                let name = p.file_name()?.to_string_lossy().into_owned();
                if !name.to_ascii_lowercase().ends_with(".blockmap") {
                    return None;
                }
                if blockmap_family_key(&name) != target_family {
                    return None;
                }
                let v = utils::extract_version(&name);
                if v > (0, 0, 0) && v < version {
                    Some((p, v))
                } else {
                    None
                }
            })
            .max_by_key(|(_, v)| *v)
            .map(|(p, _)| p)
    } else {
        None
    };

    let current_data = read_blockmap_json(current_path)?;
    let hashes = collect_checksums(&current_data);

    let mut report = format!("# Versiyon Degisiklik Raporu: v{}\n\n", version_str);
    report.push_str(&format!("- **Dosya:** `{}`\n", filename));
    report.push_str(&format!(
        "- **Tarih:** {}\n",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    ));

    let total_blocks = hashes.len();
    report.push_str(&format!("- **Toplam Blok Sayisi:** {}\n", total_blocks));

    if let Some(prev_path) = prev_file_to_compare {
        let prev_filename = prev_path.file_name().unwrap_or_default().to_string_lossy();
        let prev_version = utils::extract_version(&prev_filename);
        let prev_str = format!("{}.{}.{}", prev_version.0, prev_version.1, prev_version.2);
        report.push_str(&format!(
            "- **Karsilastirilan Onceki Surum:** v{} (`{}`)\n",
            prev_str, prev_filename
        ));

        match read_blockmap_json(&prev_path) {
            Ok(prev_data) => {
                let p_hashes = collect_checksums(&prev_data);
                let current_set: HashSet<&str> = hashes.iter().map(String::as_str).collect();
                let prev_set: HashSet<&str> = p_hashes.iter().map(String::as_str).collect();

                let new_or_changed = current_set.difference(&prev_set).count();
                let percent = if total_blocks > 0 {
                    (new_or_changed as f64 / total_blocks as f64) * 100.0
                } else {
                    0.0
                };

                report.push_str(&format!(
                    "- **Yeni veya Degisen Benzersiz Blok Sayisi:** {}\n",
                    new_or_changed
                ));
                report.push_str(&format!("- **Tahmini Degisim Orani:** %{:.2}\n", percent));

                if percent > 20.0 {
                    report.push_str("\n> [!WARNING]\n> Bu surumde onemli olcude yeni blok tespit edildi (%20+). Kod tabaninda buyuk degisiklikler veya yeni bilesenler eklenmis olabilir.\n");
                }
            }
            Err(e) => {
                report.push_str(&format!(
                    "- **Uyari:** Onceki blockmap okunamadi ({}).\n",
                    e
                ));
            }
        }
    } else {
        report.push_str("- **Not:** Karsilastirilacak uygun eski .blockmap dosyasi bulunamadi.\n");
    }

    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let report_file = output_dir.join(format!("blockmap_diff_{}_{}.md", version_str, ext_tag));
    fs::write(&report_file, report)?;
    println!("    [+] Blockmap diff report saved: {:?}", report_file);

    Ok(report_file)
}
