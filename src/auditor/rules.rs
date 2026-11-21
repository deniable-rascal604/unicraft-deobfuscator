use std::sync::OnceLock;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Info => "INFO",
        }
    }

    pub fn badge(&self) -> &'static str {
        match self {
            Severity::Critical => "[CRITICAL]",
            Severity::High => "[HIGH]",
            Severity::Medium => "[MEDIUM]",
            Severity::Info => "[INFO]",
        }
    }
}

pub struct AuditRule {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub regex: Regex,
}

static RULES: OnceLock<Vec<AuditRule>> = OnceLock::new();

pub fn get_rules() -> &'static [AuditRule] {
    RULES.get_or_init(|| {
        vec![
            AuditRule {
                id: "RCE-001",
                title: "Guncelleme Imza Dogrulama Baypasi",
                description: "autoUpdater.verifySignature veya verifyUpdateCodeSignature null dondurecek sekilde devre disi birakilmis. Yerlesik OS kod imza denetimi atlaniyor.",
                severity: Severity::Critical,
                regex: Regex::new(
                    r"(?i)(?:verifySignature|verifyUpdateCodeSignature)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*(?:null|Promise\.resolve\s*\(\s*null\s*\))"
                )
                .unwrap(),
            },
            AuditRule {
                id: "RCE-002",
                title: "Bos veya Null Imza Genel Anahtari (unicraftUpdatePublicKey)",
                description: "package.json icinde unicraftUpdatePublicKey bos veya null birakilmis; ozel imza dogrulamasi calismaz.",
                severity: Severity::Critical,
                regex: Regex::new(
                    r#"(?i)"unicraftUpdatePublicKey"\s*:\s*(?:""|null)(?:\s*[,}])"#
                )
                .unwrap(),
            },
            AuditRule {
                id: "RCE-003",
                title: "Eksik Anahtarda Imza Dogrulamasini Sessizce Atlama",
                description: "Acik anahtar bos geldiginde guncelleme imza dogrulamasi hata firlatmak yerine sessizce atlaniyor.",
                severity: Severity::High,
                regex: Regex::new(
                    r"(?is)if\s*\(\s*!\s*UPDATE_PUBLIC_KEY\s*\)\s*\{[^}]{0,200}\breturn\b"
                )
                .unwrap(),
            },
            AuditRule {
                id: "WIPE-001",
                title: "Yetkisiz Mod / Jar Silme Mekanizmasi (ModGuard)",
                description: "mods klasoru periyodik taranarak izin listesi disindaki .jar dosyalari otomatik siliniyor.",
                severity: Severity::Critical,
                regex: Regex::new(
                    r#"(?i)(?:function\s+startModGuard|"foreign_jar_detected"|unlink(?:Sync|WithRetry)?\s*\([^)]*(?:mods|jar))"#
                )
                .unwrap(),
            },
            AuditRule {
                id: "SPY-001",
                title: "Arka Planda Surec Listesi Okuma (tasklist)",
                description: "tasklist komutu ile kullanicinin calisan programlari periyodik olarak taraniyor.",
                severity: Severity::High,
                regex: Regex::new(r"(?i)\btasklist\b[^;\n]{0,80}/fo").unwrap(),
            },
            AuditRule {
                id: "SPY-002",
                title: "Ag Analiz ve Hata Ayiklayici Taramasi",
                description: "Wireshark, Fiddler, Charles, Process Hacker gibi analiz araclari hile listesinde izleniyor.",
                severity: Severity::High,
                regex: Regex::new(
                    r"(?i)\b(?:wireshark|fiddler|charlesproxy|charles\s+proxy|mitmproxy|cheatengine|cheat_engine|x64dbg|x32dbg|ollydbg|processhacker)\b"
                )
                .unwrap(),
            },
            AuditRule {
                id: "EXFIL-001",
                title: "Guvenlik Telemetri Bildirim Endpointi",
                description: "Surec ve yerel dosya ihlalleri uzak guvenlik API ucuna raporlaniyor.",
                severity: Severity::High,
                regex: Regex::new(r"(?i)/v1/security/report").unwrap(),
            },
            AuditRule {
                id: "HOST-001",
                title: "NTFS Izin Manipulasyonu (icacls /deny)",
                description: "Windows icacls komutu ile kullanicinin klasor yazma/ekleme yetkisi kaldiriliyor; cokme halinde kilitli kalabilir.",
                severity: Severity::High,
                regex: Regex::new(r"(?i)\bicacls\b[^;\n]{0,120}/deny").unwrap(),
            },
            AuditRule {
                id: "HOST-002",
                title: "PowerShell Uzerinden Donanim UUID Toplama",
                description: "PowerShell -ExecutionPolicy Bypass veya WMI/CIM uzerinden anakart/sistem UUID cekiliyor.",
                severity: Severity::High,
                regex: Regex::new(
                    r#"(?i)\bpowershell\b[^;\n]{0,180}(?:-executionpolicy["'\s,]+bypass|get-ciminstance|get-wmiobject|win32_computersystemproduct|win32_bios)"#
                )
                .unwrap(),
            },
            AuditRule {
                id: "HOST-003",
                title: "Guvenlik Yazilimi Uyarisi",
                description: "Kullaniciya antivirus veya guvenlik yaziliminin PowerShell/WMI erisimini engellememesi yonunde uyari yapiliyor.",
                severity: Severity::Medium,
                regex: Regex::new(
                    r"(?i)(?:antivir[uü]s|g[uü]venlik\s+yaz[ıi]l[ıi]m|defender)[^.\n]{0,120}(?:engelle|powershell|wmi|devre\s+d[ıi][şs][ıi])"
                )
                .unwrap(),
            },
            AuditRule {
                id: "CRYPTO-001",
                title: "Kod Icinde Sabit Sifreleme Anahtari",
                description: "Yerel ayar deposu icin kaynak kodda sabit encryptionKey degeri gomulu.",
                severity: Severity::Medium,
                regex: Regex::new(
                    r#"(?i)(?:encryptionKey\s*:\s*["'][^"']+["']|unicraft-2026-secure-key)"#
                )
                .unwrap(),
            },
            AuditRule {
                id: "HWID-001",
                title: "Dogrulanmadan Guvenilen Yerel HWID Onbellegi",
                description: "hwid-cache.json dosyasi yeniden donanim kontrolu yapilmadan dogrudan okunup guveniliyor.",
                severity: Severity::Medium,
                regex: Regex::new(r"(?is)\bHWID_CACHE_FILE\b.{0,220}readFileSync").unwrap(),
            },
            AuditRule {
                id: "AUTH-001",
                title: "Istemci Tarafinda Rol Kontrolu",
                description: "admin veya student_plus yetki kontrolu istemci kodunda yapiliyor (sunucu tarafinda da dogrulanmasi gerekir).",
                severity: Severity::Medium,
                regex: Regex::new(
                    r#"(?i)(?:\[[^\]]{0,100}["'](?:admin|student_plus)["'][^\]]{0,100}\]\.includes\([^)]*accountType|accountType\s*===\s*["'](?:admin|student_plus)["'])"#
                )
                .unwrap(),
            },
            AuditRule {
                id: "CFG-001",
                title: "Kullanici Ayarlarinin Zorla Ezilmesi (servers.dat / options.txt)",
                description: "Launcher kullanicinin mevcut sunucu listesini veya tam ekran tercihini zorla eziyor.",
                severity: Severity::Medium,
                regex: Regex::new(
                    r"(?is)(?:servers\.dat.{0,200}play\.unicraftmc\.com|fullscreen:false)"
                )
                .unwrap(),
            },
        ]
    })
}
