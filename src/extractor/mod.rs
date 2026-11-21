pub mod asar;
pub mod nsis;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::Result;
use walkdir::WalkDir;

pub fn extract_all(input_file: &Path, output_base: &Path, password: Option<&str>) -> Result<Vec<PathBuf>> {
    let mut extracted_targets = Vec::new();

    if input_file.is_dir() {
        println!(
            "    [*] Target input is already an extracted directory: {:?}",
            input_file
        );
        extracted_targets.push(input_file.to_path_buf());
        return Ok(extracted_targets);
    }

    let ext = input_file
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    if ext == "asar" {
        let asar_out = output_base.join("asar_extracted");
        println!("    [*] Unpacking standalone ASAR archive -> {:?}", asar_out);
        let stats = asar::extract_asar(input_file, &asar_out)?;
        println!(
            "    [+] ASAR extraction complete: {} files, {} directories ({:.2} MB)",
            stats.total_files,
            stats.total_dirs,
            (stats.total_bytes as f64) / 1024.0 / 1024.0
        );
        extracted_targets.push(asar_out);
        return Ok(extracted_targets);
    }

    let extracted_dir = output_base.join("extracted");
    println!("    [*] Unpacking outer container package -> {:?}", extracted_dir);
    nsis::extract_archive(input_file, &extracted_dir, password)?;

    let mut asar_files: Vec<PathBuf> = WalkDir::new(&extracted_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .ends_with(".asar")
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    asar_files.sort();

    if asar_files.is_empty() {
        println!("    [-] No ASAR archives found; using raw extracted container tree.");
        extracted_targets.push(extracted_dir);
    } else {
        println!("    [*] Discovered {} ASAR archive(s).", asar_files.len());
        let mut seen_names: HashMap<String, usize> = HashMap::new();

        for asar_path in asar_files {
            let file_stem = asar_path.file_stem().unwrap_or_default().to_string_lossy();
            let mut clean_name: String = file_stem
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if clean_name.is_empty() {
                clean_name = "archive".to_string();
            }

            let count = seen_names.entry(clean_name.clone()).or_insert(0);
            *count += 1;
            let suffix = if *count == 1 {
                clean_name
            } else {
                format!("{}_{}", clean_name, *count)
            };

            let target_out = output_base.join(format!("asar_extracted_{}", suffix));

            println!(
                "    [*] Native ASAR unpacker: {:?} -> {:?}",
                asar_path.file_name().unwrap_or_default(),
                target_out
            );
            let stats = asar::extract_asar(&asar_path, &target_out)?;
            println!(
                "    [+] Unpacked: {} files ({:.2} MB)",
                stats.total_files,
                (stats.total_bytes as f64) / 1024.0 / 1024.0
            );

            extracted_targets.push(target_out);
        }
    }

    Ok(extracted_targets)
}
