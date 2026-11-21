use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{bail, Context, Result};
use walkdir::WalkDir;

// Depth limit to avoid infinite loops on nested archive quines.
const MAX_NESTED_DEPTH: usize = 4;
const OVERLAY_SCAN_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NestedKind {
    Mandatory,
    SpeculativeExe,
}

struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn safe_archive_arg(path: &Path) -> PathBuf {
    if path.is_relative() && path.to_string_lossy().starts_with('-') {
        Path::new(".").join(path)
    } else {
        path.to_path_buf()
    }
}

// AppImage --appimage-extract executes the untrusted ELF directly.
// We scan for the squashfs superblock offset to extract without running host code.
fn detect_appimage_squashfs_offset(path: &Path) -> Result<Option<u64>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len < 64 {
        return Ok(None);
    }

    let mut hdr = [0u8; 64];
    file.read_exact(&mut hdr)?;
    if &hdr[0..4] != b"\x7fELF" || hdr[5] != 1 {
        return Ok(None);
    }

    let elf_end = match hdr[4] {
        2 => {
            let e_shoff = u64::from_le_bytes(hdr[40..48].try_into().unwrap());
            let e_shentsize = u16::from_le_bytes(hdr[58..60].try_into().unwrap()) as u64;
            let e_shnum = u16::from_le_bytes(hdr[60..62].try_into().unwrap()) as u64;
            e_shentsize
                .checked_mul(e_shnum)
                .and_then(|sz| e_shoff.checked_add(sz))
        }
        1 => {
            let e_shoff = u32::from_le_bytes(hdr[32..36].try_into().unwrap()) as u64;
            let e_shentsize = u16::from_le_bytes(hdr[46..48].try_into().unwrap()) as u64;
            let e_shnum = u16::from_le_bytes(hdr[48..50].try_into().unwrap()) as u64;
            e_shentsize
                .checked_mul(e_shnum)
                .and_then(|sz| e_shoff.checked_add(sz))
        }
        _ => None,
    };

    let Some(offset) = elf_end else {
        return Ok(None);
    };

    if offset.saturating_add(4) > len {
        return Ok(None);
    }

    file.seek(SeekFrom::Start(offset))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic == b"hsqs" {
        Ok(Some(offset))
    } else {
        Ok(None)
    }
}

// Portable electron builds place the runtime exe next to resources/. 7z unpacks .text/.rdata
// sections as files on raw PEs, dumping 150MB of garbage. Only unpack if there's an installer overlay
// signature past the last mapped PE section.
fn pe_overlay_offset(file: &mut File, file_len: u64) -> Option<u64> {
    if file_len < 64 {
        return None;
    }

    let mut dos = [0u8; 64];
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_exact(&mut dos).ok()?;
    if &dos[0..2] != b"MZ" {
        return None;
    }

    let e_lfanew = u32::from_le_bytes(dos[60..64].try_into().ok()?) as u64;
    if e_lfanew.checked_add(24)? > file_len {
        return None;
    }

    file.seek(SeekFrom::Start(e_lfanew)).ok()?;
    let mut pe_hdr = [0u8; 24];
    file.read_exact(&mut pe_hdr).ok()?;
    if &pe_hdr[0..4] != b"PE\0\0" {
        return None;
    }

    let num_sections = u16::from_le_bytes(pe_hdr[6..8].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(pe_hdr[20..22].try_into().ok()?) as u64;
    if num_sections == 0 || num_sections > 256 {
        return None;
    }

    let sec_table = e_lfanew.checked_add(24)?.checked_add(opt_size)?;
    let sec_bytes_len = (num_sections as u64).checked_mul(40)?;
    if sec_table.checked_add(sec_bytes_len)? > file_len {
        return None;
    }

    file.seek(SeekFrom::Start(sec_table)).ok()?;
    let mut max_end = sec_table + sec_bytes_len;
    let mut sec = [0u8; 40];
    for _ in 0..num_sections {
        file.read_exact(&mut sec).ok()?;
        let raw_size = u32::from_le_bytes(sec[16..20].try_into().ok()?) as u64;
        let raw_ptr = u32::from_le_bytes(sec[20..24].try_into().ok()?) as u64;
        if raw_ptr > 0 && raw_size > 0 {
            if let Some(end) = raw_ptr.checked_add(raw_size) {
                if end <= file_len && end > max_end {
                    max_end = end;
                }
            }
        }
    }

    if max_end < file_len {
        Some(max_end)
    } else {
        None
    }
}

fn has_installer_overlay_magic(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    let Some(overlay_off) = pe_overlay_offset(&mut file, meta.len()) else {
        return false;
    };
    if file.seek(SeekFrom::Start(overlay_off)).is_err() {
        return false;
    }

    let mut buf = Vec::new();
    if file.take(OVERLAY_SCAN_BYTES).read_to_end(&mut buf).is_err() {
        return false;
    }

    buf.windows(12).any(|w| w == b"NullsoftInst")
        || buf.windows(6).any(|w| w == b"7z\xBC\xAF\x27\x1C")
        || buf.windows(10).any(|w| w == b"Inno Setup")
        || buf.windows(4).any(|w| w == b"PK\x03\x04")
}

fn extract_appimage_statical(
    input_path: &Path,
    offset: u64,
    output_dir: &Path,
    password: Option<&str>,
) -> Result<()> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_sqfs = std::env::temp_dir().join(format!(
        "unicraft_sqfs_{}_{}.squashfs",
        std::process::id(),
        nanos
    ));
    let _guard = TempFileGuard(temp_sqfs.clone());

    let mut src = File::open(input_path)?;
    src.seek(SeekFrom::Start(offset))?;
    let mut dst = File::create(&temp_sqfs)?;
    io::copy(&mut src, &mut dst)?;
    drop(dst);

    if let Err(err_7z) = run_7z(&temp_sqfs, output_dir, password) {
        let unsquash = Command::new("unsquashfs")
            .arg("-no-xattrs")
            .arg("-f")
            .arg("-d")
            .arg(output_dir)
            .arg(&temp_sqfs)
            .stdin(Stdio::null())
            .output();

        match unsquash {
            Ok(out) if out.status.success() => return Ok(()),
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                bail!(
                    "AppImage SquashFS acilamadi (7z: {}; unsquashfs: {})",
                    err_7z,
                    stderr.trim()
                );
            }
            Err(_) => return Err(err_7z),
        }
    }

    Ok(())
}

fn extract_single_package(
    input_path: &Path,
    output_dir: &Path,
    password: Option<&str>,
) -> Result<()> {
    let is_appimage = input_path
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .eq_ignore_ascii_case("appimage");

    if is_appimage {
        if let Some(offset) = detect_appimage_squashfs_offset(input_path)? {
            println!("    [*] Statically extracting AppImage SquashFS partition (zero host execution)...");
            return extract_appimage_statical(input_path, offset, output_dir, password);
        }
    }

    run_7z(input_path, output_dir, password)
}

fn classify_nested_archive(path: &Path, root_dir: &Path) -> Option<NestedKind> {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();

    if (name.starts_with("app-") || name == "app.7z") && name.ends_with(".7z") {
        return Some(NestedKind::Mandatory);
    }

    if name.ends_with(".appimage") {
        return Some(NestedKind::Mandatory);
    }

    if name.ends_with(".exe") {
        if name.contains("uninstall") || name == "elevate.exe" {
            return None;
        }

        if let Some(parent) = path.parent() {
            if parent.join("resources").exists() {
                return None;
            }
        }

        let is_direct_child = path.parent().map(|p| p == root_dir).unwrap_or(false);
        let is_setup = name.contains("setup") || name.contains("installer");

        if is_setup || is_direct_child {
            if has_installer_overlay_magic(path) {
                return Some(NestedKind::Mandatory);
            }
            if is_setup {
                return Some(NestedKind::SpeculativeExe);
            }
        }
    }

    None
}

pub fn extract_archive(input_path: &Path, output_dir: &Path, password: Option<&str>) -> Result<()> {
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    println!("    [*] Unpacking primary installer package...");
    extract_single_package(input_path, output_dir, password)?;

    let mut used_stems: HashMap<String, usize> = HashMap::new();
    let mut processed_archives: HashSet<PathBuf> = HashSet::new();
    let mut depth = 0;

    loop {
        let mut new_archives: Vec<(PathBuf, NestedKind)> = Vec::new();

        for entry in WalkDir::new(output_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let path = entry.path().to_path_buf();
                if processed_archives.contains(&path) {
                    continue;
                }
                if let Some(kind) = classify_nested_archive(&path, output_dir) {
                    new_archives.push((path, kind));
                }
            }
        }

        if new_archives.is_empty() {
            break;
        }

        depth += 1;
        if depth > MAX_NESTED_DEPTH {
            println!(
                "    [*] Reached maximum recursion depth ({} levels), terminating unpack loop.",
                MAX_NESTED_DEPTH
            );
            break;
        }

        new_archives.sort_by(|a, b| a.0.cmp(&b.0));

        for (archive, kind) in new_archives {
            processed_archives.insert(archive.clone());
            let stem = archive.file_stem().unwrap_or_default().to_string_lossy();
            let clean_stem: String = stem
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            let base_tag = if clean_stem.is_empty() {
                "pkg".to_string()
            } else {
                clean_stem
            };
            let count = used_stems.entry(base_tag.clone()).or_insert(0);
            *count += 1;
            let folder_tag = if *count == 1 {
                base_tag
            } else {
                format!("{}_{}", base_tag, *count)
            };

            let nested_out = output_dir.join(format!("app_package_{}", folder_tag));
            println!(
                "    [+] Nested archive discovered: {:?} -> {:?}",
                archive.file_name().unwrap_or_default(),
                nested_out
            );
            fs::create_dir_all(&nested_out)?;

            if let Err(e) = extract_single_package(&archive, &nested_out, password) {
                let _ = fs::remove_dir_all(&nested_out);
                match kind {
                    NestedKind::Mandatory => return Err(e),
                    NestedKind::SpeculativeExe => {
                        eprintln!(
                            "    [-] Non-installer executable skipped ({:?}): {}",
                            archive.file_name().unwrap_or_default(),
                            e
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn run_7z(archive_path: &Path, output_dir: &Path, password: Option<&str>) -> Result<()> {
    let safe_path = safe_archive_arg(archive_path);
    let clean_pwd = password.filter(|p| !p.is_empty());

    // 7z hangs on stdin if password is omitted on an encrypted archive.
    // -p- fails fast so the 'infected' fallback retry can run.
    let pwd_arg = match clean_pwd {
        Some(p) => format!("-p{}", p),
        None => "-p-".to_string(),
    };

    let output = Command::new("7z")
        .arg("x")
        .arg(&safe_path)
        .arg(format!("-o{}", output_dir.display()))
        .arg("-y")
        .arg(&pwd_arg)
        .stdin(Stdio::null())
        .output()
        .context("Failed to execute 7z CLI. Is 7z installed and on system PATH?")?;

    if !output.status.success() {
        if clean_pwd.is_none() {
            let stderr_initial = String::from_utf8_lossy(&output.stderr);
            let lower = stderr_initial.to_ascii_lowercase();
            if lower.contains("password") || lower.contains("encrypted") {
                let retry = Command::new("7z")
                    .arg("x")
                    .arg(&safe_path)
                    .arg(format!("-o{}", output_dir.display()))
                    .arg("-y")
                    .arg("-pinfected")
                    .stdin(Stdio::null())
                    .output();

                if let Ok(retry_out) = retry {
                    if retry_out.status.success() {
                        println!("    [+] Archive unlocked using threat intelligence fallback password ('infected').");
                        return Ok(());
                    }
                }
            }
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "7z extraction failed (exit: {:?}): {}",
            output.status.code(),
            stderr.trim()
        );
    }

    Ok(())
}
