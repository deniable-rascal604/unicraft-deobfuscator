mod auditor;
mod blockmap;
mod cli;
mod extractor;
mod state;
mod utils;

use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;

use cli::{Cli, Commands};

struct Config {
    girdi_dir: PathBuf,
    cikti_dir: PathBuf,
    state_file: PathBuf,
}

fn output_folder_name(input: &Path) -> String {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    let ext = input.extension().unwrap_or_default().to_string_lossy();
    if stem.is_empty() {
        "unicraft_output".to_string()
    } else if ext.is_empty() {
        stem.into_owned()
    } else {
        format!("{} ({})", stem, ext)
    }
}

fn main() -> Result<()> {
    let args = Cli::parse();

    println!("=======================================================");
    println!("  UniCraft Threat Intelligence & Rust Auditor v1.0.0");
    println!("=======================================================");

    let mut project_root = std::env::current_dir().context("Calisma dizini alinamadi")?;
    if project_root.ends_with("program") {
        project_root.pop();
    }

    let config = Config {
        girdi_dir: project_root.join("girdi"),
        cikti_dir: project_root.join("cikti"),
        state_file: project_root.join("state.json"),
    };

    if let Some(cmd) = args.command {
        match cmd {
            Commands::Extract {
                input,
                output,
                password,
            } => {
                let out_dir =
                    output.unwrap_or_else(|| config.cikti_dir.join(output_folder_name(&input)));
                println!("[*] Extracting package: {:?} -> {:?}", input, out_dir);
                let targets = extractor::extract_all(&input, &out_dir, password.as_deref())?;
                println!("[+] Successfully extracted targets:");
                for t in targets {
                    println!("    - {:?}", t);
                }
            }
            Commands::Audit { target, output } => {
                println!("[*] Running security audit: {:?}", target);
                let report = auditor::scan_path(&target)?;
                print_audit_summary(&report);

                let base_dir = if target.is_file() {
                    target
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."))
                } else {
                    &target
                };

                let out_file = output.unwrap_or_else(|| {
                    let ts = Local::now().format("%Y%m%d_%H%M%S");
                    base_dir.join(format!("security_report_{}.md", ts))
                });
                if let Some(parent) = out_file.parent().filter(|p| !p.as_os_str().is_empty()) {
                    fs::create_dir_all(parent)?;
                }
                auditor::generate_markdown_report(&report, &out_file)?;
                println!("[+] Markdown audit report saved: {:?}", out_file);
            }
            Commands::Blockmap {
                current,
                previous,
                output,
            } => {
                let out_dir = output.unwrap_or_else(|| {
                    current
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."))
                        .to_path_buf()
                });

                let report = blockmap::analyze_blockmap(&current, previous.as_deref(), &out_dir)?;
                println!("[+] Blockmap comparison report generated: {:?}", report);
            }
            Commands::Pipeline {
                input,
                force,
                no_audit,
                no_degisiklikler,
                password,
            } => {
                run_pipeline(
                    &config,
                    input,
                    force,
                    !no_audit,
                    !no_degisiklikler,
                    password.as_deref(),
                )?;
            }
        }
        return Ok(());
    }

    run_pipeline(
        &config,
        args.input,
        args.force,
        args.audit,
        args.degisiklikler,
        args.password.as_deref(),
    )?;

    Ok(())
}

fn run_pipeline(
    config: &Config,
    single_input: Option<PathBuf>,
    force: bool,
    audit_enabled: bool,
    degisiklikler_enabled: bool,
    password: Option<&str>,
) -> Result<()> {
    let mut files_to_process: Vec<PathBuf> = if let Some(target) = single_input {
        if !target.exists() {
            eprintln!("[!] Specified target not found: {:?}", target);
            return Ok(());
        }
        vec![target]
    } else {
        if !config.girdi_dir.exists() {
            fs::create_dir_all(&config.girdi_dir)?;
            println!(
                "[*] Created {:?}. Place target installer packages here for batch inspection.",
                config.girdi_dir
            );
            return Ok(());
        }

        fs::read_dir(&config.girdi_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                !name.starts_with('.') && !name.to_ascii_lowercase().ends_with(".blockmap")
            })
            .collect()
    };

    files_to_process.sort();

    if files_to_process.is_empty() {
        println!("[!] No input packages found to process.");
        return Ok(());
    }

    let mut state = state::load_state(&config.state_file)?;
    let mut total_processed = 0;
    let mut total_success = 0;

    for input_file in &files_to_process {
        total_processed += 1;
        let filename = input_file.file_name().unwrap_or_default().to_string_lossy();
        let file_hash = utils::get_file_hash(input_file)?;
        let output_base = config.cikti_dir.join(output_folder_name(input_file));

        let state_key = format!(
            "{}_{}_{}",
            file_hash, audit_enabled as i32, degisiklikler_enabled as i32
        );

        if state.contains_key(&state_key) && output_base.exists() && !force {
            println!("\n[*] Skipping {} (Already processed and cached).", filename);
            total_success += 1;
            continue;
        }

        println!("\n[*] Processing: {} (MD5: {})", filename, &file_hash[..8]);
        fs::create_dir_all(&output_base)?;

        let extracted_targets = match extractor::extract_all(input_file, &output_base, password) {
            Ok(targets) => targets,
            Err(e) => {
                eprintln!("[X] Extraction error: {}", e);
                continue;
            }
        };

        if audit_enabled {
            println!("    [*] Running static heuristic pattern rules...");
            for target_source in &extracted_targets {
                let source_name = target_source
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                match auditor::scan_path(target_source) {
                    Ok(report) => {
                        println!(
                            "    -> {:?} scanned files: {}",
                            source_name, report.total_scanned_files
                        );
                        print_audit_summary(&report);

                        let report_name = format!("security_report_{}.md", source_name);
                        let report_file = output_base.join(report_name);
                        if let Err(e) = auditor::generate_markdown_report(&report, &report_file) {
                            eprintln!("    [!] Report export error: {}", e);
                        } else {
                            println!("    [+] Report written: {:?}", report_file);
                        }
                    }
                    Err(e) => {
                        eprintln!("    [!] Error during audit: {}", e);
                    }
                }
            }
        }

        if degisiklikler_enabled && input_file.is_file() {
            let mut bm_os = input_file.as_os_str().to_os_string();
            bm_os.push(".blockmap");
            let blockmap_path = PathBuf::from(bm_os);
            if blockmap_path.exists() {
                if let Err(e) = blockmap::analyze_blockmap(&blockmap_path, None, &output_base) {
                    eprintln!("    [!] Blockmap error: {}", e);
                }
            }
        }

        state.insert(
            state_key,
            serde_json::json!({
                "status": "SUCCESS",
                "date": Local::now().to_rfc3339(),
                "target": filename.to_string(),
            }),
        );
        if let Err(e) = state::save_state(&config.state_file, &state) {
            eprintln!("    [!] Failed to persist state: {}", e);
        }
        total_success += 1;
    }

    println!("\n=======================================================");
    println!(
        "  Pipeline Completed ({}/{} Success)",
        total_success, total_processed
    );
    println!("=======================================================");

    Ok(())
}

fn print_audit_summary(report: &auditor::AuditReport) {
    let critical = report
        .findings
        .iter()
        .filter(|f| f.severity == auditor::Severity::Critical)
        .count();
    let high = report
        .findings
        .iter()
        .filter(|f| f.severity == auditor::Severity::High)
        .count();
    let medium = report
        .findings
        .iter()
        .filter(|f| f.severity == auditor::Severity::Medium)
        .count();

    println!(
        "       Findings: {} Critical, {} High, {} Medium",
        critical, high, medium
    );
    for f in &report.findings {
        let rel = f
            .file_path
            .strip_prefix(&report.target_path)
            .unwrap_or(&f.file_path);
        let display_name = if rel.as_os_str().is_empty() {
            f.file_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        } else {
            rel.to_string_lossy()
        };
        println!(
            "       {} [{}] {}:{} -> {}",
            f.severity.badge(),
            f.rule_id,
            display_name,
            f.line_num,
            f.title
        );
    }
}
