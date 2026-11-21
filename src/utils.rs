use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::OnceLock;
use anyhow::{Context, Result};
use md5::{Digest, Md5};
use regex::Regex;
use walkdir::WalkDir;

static VERSION_RE: OnceLock<Regex> = OnceLock::new();

pub fn get_file_hash(path: &Path) -> Result<String> {
    if path.is_dir() {
        let mut hasher = Md5::new();
        let mut entries: Vec<_> = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .collect();

        entries.sort_by(|a, b| a.path().cmp(b.path()));

        for entry in entries {
            let rel = entry.path().strip_prefix(path).unwrap_or(entry.path());
            let rel_str = rel.to_string_lossy();
            hasher.update((rel_str.len() as u64).to_le_bytes());
            hasher.update(rel_str.as_bytes());
            let len = entry.metadata()?.len();
            hasher.update(len.to_le_bytes());
            hash_stream(entry.path(), &mut hasher)?;
        }
        Ok(hex::encode(hasher.finalize()))
    } else {
        let mut hasher = Md5::new();
        hash_stream(path, &mut hasher)?;
        Ok(hex::encode(hasher.finalize()))
    }
}

fn hash_stream(file_path: &Path, hasher: &mut Md5) -> Result<()> {
    let file = File::open(file_path)
        .with_context(|| format!("Dosya okunamadi: {:?}", file_path))?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(())
}

pub fn extract_version(filename: &str) -> (u32, u32, u32) {
    let re = VERSION_RE.get_or_init(|| Regex::new(r"(\d+)\.(\d+)\.(\d+)").unwrap());
    if let Some(caps) = re.captures(filename) {
        let major = caps.get(1).map_or(0, |m| m.as_str().parse().unwrap_or(0));
        let minor = caps.get(2).map_or(0, |m| m.as_str().parse().unwrap_or(0));
        let patch = caps.get(3).map_or(0, |m| m.as_str().parse().unwrap_or(0));
        (major, minor, patch)
    } else {
        (0, 0, 0)
    }
}
