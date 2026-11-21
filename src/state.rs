use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

pub fn load_state(path: &Path) -> Result<HashMap<String, serde_json::Value>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("State dosyasi okunamadi: {:?}", path))?;

    match serde_json::from_str(&content) {
        Ok(state) => Ok(state),
        Err(e) => {
            eprintln!(
                "[!] Uyari: {:?} bozuk ({}), yedeklenip sifirlaniyor.",
                path, e
            );
            let backup = path.with_extension("json.corrupt");
            let _ = fs::copy(path, backup);
            Ok(HashMap::new())
        }
    }
}

pub fn save_state(path: &Path, state: &HashMap<String, serde_json::Value>) -> Result<()> {
    let content = serde_json::to_string_pretty(state)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let tmp_path = parent.join(format!("{}.{}.tmp", file_name, std::process::id()));

    if let Err(e) = fs::write(&tmp_path, content) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e).context("State gecici dosyaya yazilamadi");
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e).context("State dosyasi guncellenemedi");
    }

    Ok(())
}
