pub mod rules;

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use chrono::Local;
use walkdir::WalkDir;

pub use rules::Severity;

const MAX_SCAN_FILE_BYTES: u64 = 20 * 1024 * 1024;
const MAX_FINDINGS_PER_RULE_PER_FILE: usize = 25;

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub file_path: PathBuf,
    pub line_num: usize,
    pub line_content: String,
}

pub struct AuditReport {
    pub target_path: PathBuf,
    pub total_scanned_files: usize,
    pub findings: Vec<Finding>,
}

pub fn scan_path(target_path: &Path) -> Result<AuditReport> {
    if !target_path.exists() {
        bail!("Taranacak hedef bulunamadi: {:?}", target_path);
    }

    let rules = rules::get_rules();
    let mut findings = Vec::new();
    let mut scanned_count = 0;

    if target_path.is_file() {
        scanned_count = 1;
        scan_file(target_path, rules, &mut findings)?;
    } else {
        let walker = WalkDir::new(target_path).into_iter();
        for entry in walker
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                name != "node_modules" && name != ".git"
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let ext = path
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase();

            if matches!(
                ext.as_str(),
                "js" | "mjs" | "cjs" | "ts" | "json" | "yml" | "yaml"
            ) {
                scanned_count += 1;
                scan_file(path, rules, &mut findings)?;
            }
        }
    }

    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line_num.cmp(&b.line_num))
    });

    Ok(AuditReport {
        target_path: target_path.to_path_buf(),
        total_scanned_files: scanned_count,
        findings,
    })
}

// String slicing on raw bytes panics mid-UTF-8. Align to char boundaries.
fn step_back_char(s: &str, idx: usize) -> usize {
    if idx == 0 {
        return 0;
    }
    let mut pos = idx - 1;
    while pos > 0 && !s.is_char_boundary(pos) {
        pos -= 1;
    }
    pos
}

fn step_forward_char(s: &str, idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    let mut pos = idx + 1;
    while pos < s.len() && !s.is_char_boundary(pos) {
        pos += 1;
    }
    pos
}

fn extract_snippet(content: &str, match_start: usize, match_end: usize) -> String {
    let line_start = content[..match_start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = content[match_start..]
        .find('\n')
        .map_or(content.len(), |i| match_start + i);

    if match_end <= line_end {
        let line = content[line_start..line_end].trim();
        if line.chars().count() <= 220 {
            return line.replace(['\r', '\t'], " ");
        }
    }

    let mut start = match_start;
    for _ in 0..80 {
        if start == 0 {
            break;
        }
        start = step_back_char(content, start);
    }

    let mut end = match_end;
    for _ in 0..140 {
        if end >= content.len() {
            break;
        }
        end = step_forward_char(content, end);
    }

    let mut snippet = content[start..end]
        .trim()
        .replace(['\r', '\n', '\t'], " ");
    if snippet.chars().count() > 220 {
        snippet = snippet.chars().take(220).collect();
        snippet.push_str("...");
    } else {
        if start > line_start {
            snippet = format!("...{}", snippet);
        }
        if end < line_end {
            snippet.push_str("...");
        }
    }
    snippet
}

fn scan_file(
    file_path: &Path,
    rules: &[rules::AuditRule],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let meta = match fs::metadata(file_path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if meta.len() > MAX_SCAN_FILE_BYTES {
        return Ok(());
    }

    let bytes = match fs::read(file_path) {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };
    if bytes.contains(&0) {
        return Ok(());
    }

    let content = String::from_utf8_lossy(&bytes);
    let mut line_starts = vec![0usize];
    for (i, b) in content.bytes().enumerate() {
        if b == b'\n' {
            line_starts.push(i + 1);
        }
    }

    let mut seen_rule_lines: HashSet<(&'static str, usize)> = HashSet::new();
    let mut rule_counts: HashMap<&'static str, usize> = HashMap::new();

    for rule in rules {
        for m in rule.regex.find_iter(&content) {
            let count = rule_counts.entry(rule.id).or_insert(0);
            if *count >= MAX_FINDINGS_PER_RULE_PER_FILE {
                break;
            }

            let line_num = line_starts.partition_point(|&s| s <= m.start());
            if !seen_rule_lines.insert((rule.id, line_num)) {
                continue;
            }

            *count += 1;
            let snippet = extract_snippet(&content, m.start(), m.end());

            findings.push(Finding {
                rule_id: rule.id.to_string(),
                title: rule.title.to_string(),
                description: rule.description.to_string(),
                severity: rule.severity,
                file_path: file_path.to_path_buf(),
                line_num,
                line_content: snippet,
            });
        }
    }

    Ok(())
}

fn display_relative_path<'a>(target_path: &Path, file_path: &'a Path) -> String {
    let rel = file_path.strip_prefix(target_path).unwrap_or(file_path);
    if rel.as_os_str().is_empty() {
        file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    } else {
        rel.to_string_lossy().into_owned()
    }
}

pub fn generate_markdown_report(report: &AuditReport, output_file: &Path) -> Result<()> {
    let mut file = File::create(output_file)
        .with_context(|| format!("Rapor dosyasi olusturulamadi: {:?}", output_file))?;

    let now_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    writeln!(file, "# UniCraft Guvenlik ve Tehdit Analiz Raporu\n")?;
    writeln!(file, "- **Tarih:** {}", now_str)?;
    writeln!(file, "- **Taranan Konum:** `{}`", report.target_path.display())?;
    writeln!(
        file,
        "- **Taranan Dosya Sayisi:** {}",
        report.total_scanned_files
    )?;
    writeln!(
        file,
        "- **Toplam Tehdit Tespiti:** {}\n",
        report.findings.len()
    )?;

    let critical_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let info_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    writeln!(file, "### Tehdit Seviyesi Dagilimi\n")?;
    writeln!(file, "| Seviye | Tespit Sayisi |")?;
    writeln!(file, "|---|---|")?;
    writeln!(file, "| **CRITICAL** | {} |", critical_count)?;
    writeln!(file, "| **HIGH** | {} |", high_count)?;
    writeln!(file, "| **MEDIUM** | {} |", medium_count)?;
    writeln!(file, "| **INFO** | {} |\n", info_count)?;

    if report.findings.is_empty() {
        writeln!(
            file,
            "## [OK] Hicbir supheli model veya guvenlik acigi tespit edilmedi.\n"
        )?;
        return Ok(());
    }

    writeln!(file, "## Detayli Guvenlik Bulgulari\n")?;
    writeln!(
        file,
        "| ID | Seviye | Kural | Dosya | Satir | Kod Baglami |"
    )?;
    writeln!(file, "|---|---|---|---|---|---|")?;

    for f in &report.findings {
        let display_name = display_relative_path(&report.target_path, &f.file_path);
        let escaped_code = f.line_content.replace('|', "\\|").replace('`', "'");

        writeln!(
            file,
            "| `{}` | **{}** | {} | `{}` | {} | `{}` |",
            f.rule_id,
            f.severity.as_str(),
            f.title,
            display_name,
            f.line_num,
            escaped_code
        )?;
    }

    writeln!(file, "\n---\n")?;
    writeln!(file, "### Tehdit Aciklamalari\n")?;
    for f in &report.findings {
        let display_name = display_relative_path(&report.target_path, &f.file_path);
        writeln!(
            file,
            "#### [{}] {} (`{}`)",
            f.severity.as_str(),
            f.title,
            f.rule_id
        )?;
        writeln!(file, "- **Aciklama:** {}", f.description)?;
        writeln!(file, "- **Konum:** `{}:{}`\n", display_name, f.line_num)?;
    }

    Ok(())
}
