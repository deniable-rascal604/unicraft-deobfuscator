# unicraft-deobfuscator

Static analysis and container extraction CLI written in Rust to inspect untrusted Electron desktop applications without executing host code.

## Security audit reports

The complete audit findings and reverse engineering evidence for UniCraft Launcher v2.5.6 are documented in:
- [REPORT.md](REPORT.md) covers the technical security analysis and vulnerability assessment in English.
- [RAPOR.md](RAPOR.md) contains the Turkish community audit and architectural review.

## Threat Model

Auditing suspicious Electron installers with standard tools introduces two security hazards:
- Running `AppImage --appimage-extract` executes the target ELF directly on the host machine. A malicious package can hook entrypoints or ignore flags to execute arbitrary code on the researcher workstation.
- Using npm or Node.js to unpack ASAR archives introduces supply-chain risks and executes JavaScript lifecycle hooks during dependency installation.

Archive bombs and malformed archives present additional risks. A 16-byte fake archive can declare a 4 GB header to trigger memory allocation panics, while portable Electron builds place runtime executables next to application assets. Extracting those executables naively dumps hundreds of megabytes of raw PE sections instead of useful source code.

This tool guarantees static inspection. It decodes container structures, extracts payloads, and scans for hostile patterns in memory without invoking Node.js or executing the target binaries.

## Design

### Native Chromium Pickle and ASAR parser
The ASAR unpacker decodes Pickle headers and directory trees in pure Rust. It verifies entry paths against directory traversal and rejects Windows reserved names like CON, PRN, AUX, and NUL to prevent arbitrary file overwrite. Headers larger than 64 MB and extractions exceeding 2 GB are rejected to prevent memory exhaustion.

### Static SquashFS extraction
Instead of calling the AppImage runtime, the tool parses ELF headers directly to locate the `hsqs` superblock offset. It then reads the embedded filesystem statically without running the target executable.

### PE overlay detection
Portable Electron builds place runtime executables alongside application resources. Naive 7-Zip runs unpack raw `.text` and `.rdata` sections, creating massive directory noise. The overlay engine parses the PE section table to find the end of the last mapped section. It only extracts executables that carry genuine installer signatures such as NSIS, 7z, Inno Setup, or ZIP past that boundary.

### Safe UTF-8 snippet slicing
Rust string slicing operates on raw byte offsets. Slicing across multi-byte UTF-8 characters causes runtime panics on localized source files. The reporting engine walks to character boundaries before generating code snippets.

### Password-protected archives
If an archive is encrypted, the unpacker passes `-p-` to disable interactive password prompts that would hang automated runs. It automatically falls back to the standard malware research password `infected` upon password errors.

## Supported Formats

| Format | Structure | Extraction Method |
|---|---|---|
| Windows installers | PE executables with appended overlays | PE section parser and 7z |
| Linux AppImage | ELF Type 2 bundles with embedded SquashFS | Static superblock offset search |
| Electron archives | ASAR application packages | Pure Rust Pickle parser |
| Compressed archives | 7z, zip, and nested app-64.7z packages | 7z with infected password fallback |
| Version blockmaps | Blockmap metadata files | Flate2 decompression and delta engine |

## Building

Prerequisites: Rust 2021 edition and 7z.

```bash
cargo build --release
```

The executable is generated at `target/release/unicraft`.

## Usage

Run the complete pipeline to extract, compare blockmaps, and run security audits:
```bash
./target/release/unicraft pipeline sample.exe
```

Run extraction only without auditing:
```bash
./target/release/unicraft pipeline sample.exe --no-audit --no-diff
```

Extract a specific package to an output folder:
```bash
./target/release/unicraft extract sample.exe -o cikti/sample
```

Extract an encrypted sample with a password:
```bash
./target/release/unicraft extract sample.zip -o cikti/sample -p infected
```

Run the security audit engine on an extracted directory:
```bash
./target/release/unicraft audit cikti/sample/asar_extracted -o report.md
```

Compare two version blockmaps to measure changed blocks:
```bash
./target/release/unicraft blockmap current.blockmap --previous baseline.blockmap -o diff_output/
```

## Detection Rules

The audit engine runs static regex rules against extracted JavaScript and JSON files to detect suspicious behaviors:
- Update signature bypasses, including setting verifySignature to null or leaving unicraftUpdatePublicKey empty.
- Surveillance mechanisms, including background tasklist polling and checks for developer tools such as Wireshark, Fiddler, Process Hacker, and Cheat Engine.
- Wiper routines, including recursive directory scans using fs.unlinkSync to delete unapproved mod files.
- Host permission tampering, including Windows icacls commands that deny write permissions on local directories.
- Credential exposure, including hardcoded symmetric encryption keys and plaintext Discord webhooks.

## Repository Layout

```
src/
├── main.rs          Entry point, pipeline orchestration, and state caching
├── cli.rs           Command-line argument specifications
├── extractor/
│   ├── mod.rs       Recursive extraction loop and container routing
│   ├── asar.rs      Pure Rust ASAR archive and Chromium Pickle parser
│   └── nsis.rs      PE section overlay parser and SquashFS offset detector
├── auditor/
│   ├── mod.rs       UTF-8 safe snippet slicing and Markdown report generator
│   └── rules.rs     Pattern definitions and severity classifications
├── blockmap.rs      Gzip blockmap decompression and block diff engine
├── state.rs         Local hash state cache
└── utils.rs         File hashing and version parsing utilities
```

## License

This tool is built strictly for defensive analysis, threat research, and authorized security auditing of Electron desktop clients.
