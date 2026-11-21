# Technical Security Audit: UniCraft Launcher v2.5.6 Architecture and Privacy Analysis

Date: November 21, 2026
Target artifact: `UniCraft Launcher Setup 2.5.6.exe`, SHA-256 digest `da19665407a2546fa3aa576949563ae4e84d4f3cfa3982a59924ee142b477ba1`.
Analyzed components: Distributed `app.asar` payload, `package.json`, `unicraftmc.com` web frontend, and backend API routes.
Dynamic sandbox detonation: `https://tria.ge/261121-arp23azs2k/behavioral1`, threat score 7/10.

## 1. Executive Summary

UniCraft markets its custom Electron-based desktop client to Turkish university students as a secure, anti-cheat protected Minecraft launcher. In public communications with users, the development team attributed high threat scores in dynamic sandboxes to behavioral detection heuristics common to commercial anti-cheat engines like BattlEye or EasyAntiCheat. They also claimed that application code signing was bypassed due to the high costs of commercial certificates.

This static analysis and reverse engineering audit evaluates the technical validity of those claims. The findings show that the client lacks an enterprise anti-cheat architecture. Instead, it incorporates destructive file deletion routines, tampers with operating system access control lists, conducts undocumented background process surveillance in violation of its public privacy policy, and disables fundamental cryptographic update verification mechanisms.

## 2. Distribution Architecture and Infrastructure History

The client distribution relies on inconsistent access control layers.

On the web frontend, the download button on `unicraftmc.com` issues a request to `POST https://api.unicraftmc.com/v1/launcher/download-ticket` for authenticated sessions to generate a single-use download token.

Conversely, the update CDN on `updates.unicraftmc.com` serves `latest.yml` and the 77.6 MB installer binary directly without requiring authentication or session tokens. This discrepancy highlights an incomplete access control boundary between the promotional frontend and the delivery infrastructure.

Infrastructure history embedded in the client source reveals that the `_normalizeModUrl` function originally targeted `updates.gogusler.de`. That domain and its related asset `unicraft.sbs` were suspended on April 19, 2026 by Hostinger Abuse following Terms of Service violations, documented under Ticket QTB-KSPPZ-122. The client URL rewrite was introduced to migrate traffic to `updates.unicraftmc.com`. Furthermore, Cloudflare Trust and Safety restricted access to URLs on `unicraftmc.com` following an abuse report on May 2, 2026, documented under Ticket d3778c262bc4d08d:

```javascript
// main.js (Line 1919)
function _normalizeModUrl(url) {
  if (typeof url !== "string") return url;
  return url.replace(/^https?:\/\/updates\.gogusler\.de\//i, "https://updates.unicraftmc.com/");
}
```

## 3. Technical Findings and Vulnerability Analysis

### 3.1. Disabled Update Signature Verification and the Certificate Cost Defense (CWE-347 / CWE-494)

The development team defended the absence of update verification with the following statement: *"Signature bypass: The launcher is not code-signed because certificates are expensive for a student volunteer project. Updates still arrive from our domain over HTTPS."*

This statement conflates two distinct security boundaries: Windows Authenticode certificate validation and application-level asymmetric package verification. Validating the integrity of an application update does not require paid certificates from commercial authorities. Using Node.js's native `crypto` module, an application can verify updates using an Ed25519 or RSA keypair at zero cost.

The developers implemented the structural skeleton for this custom verification, but left the public key field blank in `package.json`:

```json
"unicraftUpdatePublicKey": ""
```

In the main process, built-in verification functions are forced to return null, and `verifyDownloadedUpdate` exits early when it encounters the empty key:

```javascript
// main.js (Lines 376 - 386)
autoUpdater.verifySignature = async () => null;
autoUpdater.verifyUpdateCodeSignature = () => Promise.resolve(null);

// main.js (Lines 51 - 56)
async function verifyDownloadedUpdate(updateInfo) {
  if (!UPDATE_PUBLIC_KEY) {
    console.warn("[updater] unicraftUpdatePublicKey is not defined; signature verification skipped.");
    return;
  }
}
```

Relying solely on transport-layer HTTPS is insufficient. If the update host or Cloudflare account is compromised, a malicious payload pushed to the client will execute without integrity verification. This constitutes a severe supply-chain vulnerability categorized under CWE-347 and CWE-494.

### 3.2. Background Process Surveillance Contradicting Privacy Commitments (CWE-359)

The developers rationalized the 7/10 threat score on Tria.ge by asserting that sandboxes flag process scanning and hardware ID checks by default, comparing the behavior to BattlEye or EasyAntiCheat.

However, the primary issue is the direct contradiction with the published user agreement. The official privacy policy published at `https://unicraftmc.com/gizlilik-politikasi` explicitly guarantees:

> *"Anti-cheat: solely verifies that approved mods are installed. The contents of your mods or your in-game behavior are not read; only file hashes are compared."*
> *"The launcher does not collect: keyboard or mouse inputs, screenshots, entire filesystem data, personal documents, browser history, or other game data..."*

Despite promising that only mod file hashes are compared, `main.js` executes the Windows `tasklist` command every 60 seconds to inspect active processes:

```javascript
// main.js (Lines 2150 - 2165)
const targetProcesses = [
  "cheatengine", "cheat engine", "x64dbg", "x32dbg", "ollydbg",
  "windbg", "radare2", "processhacker", "artmoney",
  "wireshark", "fiddler", "charlesproxy", "charles proxy", "mitmproxy"
];

exec("tasklist /fo csv /nh", { timeout: 5000 }, (err, stdout) => {
  const running = stdout.toLowerCase();
  for (const proc of targetProcesses) {
    if (running.includes(proc)) {
      reportSecurityEvent("cheat_process_detected", { process: proc });
      break;
    }
  }
});
```

Legitimate network diagnostic and development tools including Wireshark, Fiddler, Charles Proxy, and Process Hacker are categorized as cheats. The launcher transmits the detected process name along with user credentials and timestamps to `/v1/security/report`. Collecting running process telemetry while publicly assuring users that no such inspection occurs constitutes an undisclosed surveillance mechanism (CWE-359).

### 3.3. Arbitrary File Deletion in User-Selected Game Directories

The client includes a watchdog routine intended to clean unapproved modifications:

```javascript
// main.js (Lines 1475 - 1506)
function startModGuard(modsDir, allowedList) {
  const allowed = new Set([...allowedList].map(x => x.toLowerCase()));
  function scan() {
    if (!active) return;
    try {
      const files = fs.readdirSync(modsDir);
      for (const file of files) {
        if (!file.toLowerCase().endsWith(".jar")) continue;
        if (!allowed.has(file.toLowerCase())) {
          fs.unlinkSync(path.join(modsDir, file));
          reportSecurityEvent("foreign_jar_detected", { file, action: "deleted" });
        }
      }
    } catch {}
    if (active) setTimeout(scan, 100);
  }
  scan();
}
```

Standard gaming clients isolate managed mods into dedicated profiles. UniCraft allows users to specify an arbitrary working directory. If a player points the client to their existing `.minecraft` folder, `startModGuard` deletes all `.jar` files not present on UniCraft's server whitelist without prompting for confirmation.

### 3.4. NTFS ACL Manipulation and Lockout Risks (CWE-732 / CWE-459)

To block runtime modifications, the launcher invokes Windows `icacls` to deny write permissions:

```javascript
// main.js (Lines 1436 - 1446)
execFile("icacls", [modsDir, "/deny", principal + ":(CI)(WD,AD)"], { shell: false });
```

This command restricts write and append operations. While cleanup is intended via `/remove:d` on client shutdown, abrupt crashes or process termination leave the access restriction intact. Users are then unable to modify their own local directory. This mechanism is absent on Linux and macOS, exposing Windows users to filesystem lockouts.

### 3.5. Student Identity Card Processing via General Feedback Channels (KVKK Law No. 6698 Art. 12)

The manual verification flow on `/dogrula-manuel` collects student full names, university identification numbers, institution names, and identity card photographs. The client converts images to Base64 strings.

Rather than isolating sensitive identity data into a cryptographically secured verification module, the client embeds card photos directly into generic feedback tickets:

```javascript
// dogrula-manuel (Lines 810 - 825)
const mainBody = {
  subject: subject,
  message: textMsg + "

PHOTO:
" + photoB64,
  category: "manual_verification",
  turnstileToken: turnstileToken,
};
const r = await fetch(API + "/v1/feedback", {
  method: "POST", headers, body: JSON.stringify(mainBody),
});
```

Analysis of the static administration panel hosted on Vercel at `/yonetim` shows that administrative users parse these strings using regular expressions to render student cards:

```javascript
// yonetim (Lines 3740 - 3755)
const photoMatch = raw.match(/
PHOTO:
?(data:image\/[^\s][\s\S]*)/);
if (photoMatch) {
  info.photoData = photoMatch[1].trim();
}
```

Storing student identification documents containing citizen registration numbers, university IDs, and photographs within an unencrypted general support ticket table lacks required data isolation and cryptographic controls, posing significant compliance and data security risks under Article 12 of Turkish Personal Data Protection Law No. 6698.

### 3.6. Client-Side Security Bypasses and Host Tampering

The client's enforcement mechanisms rely on easily subverted local logic:

Hardware ID spoofing:
The client reads hardware identifiers from a local file without querying system hardware:

```javascript
// main.js (Lines 905 - 915)
async function getOrReadHwid() {
  try {
    if (fs.existsSync(HWID_CACHE_FILE)) {
      const cached = JSON.parse(fs.readFileSync(HWID_CACHE_FILE, "utf8"));
      if (cached && typeof cached.hwid === "string" && cached.hwid.length >= 32) {
        return cached.hwid;
      }
    }
  } catch {}
```

The motherboard UUID is collected on initial execution and written to `hwid-cache.json`. On subsequent launches, the client returns this cached value. Modifying the string in a text editor fools the backend into treating the machine as a new device, bypassing hardware bans.

Unverified JVM binaries:
The runtime executable `javaw.exe` is not verified against a trusted server hash. The client relies entirely on local file size and modification timestamps (Lines 3270 - 3310).

Process sleep loops:
When instance lock contention occurs, the client invokes a shell ping command to block the Node.js event loop:

```javascript
// main.js (Lines 226 - 234)
if (err.code === "EPERM" || err.code === "EACCES" || err.code === "EBUSY") {
  try {
    require("child_process").execSync("ping -n 1 -w 80 127.0.0.1 >nul", {
      stdio: "ignore"
    });
  } catch {}
  continue;
}
```

Host server list overwrite:
If `servers.dat` does not already contain `play.unicraftmc.com`, the client overwrites the file with a single-entry configuration, erasing all existing Minecraft servers:

```javascript
// main.js (Lines 2702 - 2719)
async function ensureUniCraftServer(gameDir) {
  const fsExtra = require("fs-extra");
  const serversDatPath = path.join(gameDir, "servers.dat");
  const serverIp = "play.unicraftmc.com";
  if (await fsExtra.pathExists(serversDatPath)) {
    try {
      const buf = await fsExtra.readFile(serversDatPath);
      if (buf.includes(Buffer.from(serverIp, "utf8"))) return;
    } catch {}
  }
  await fsExtra.ensureDir(gameDir);
  await fsExtra.writeFile(serversDatPath, buildServersDat([{
    name: "ÜniCraft",
    ip: serverIp,
    acceptTextures: true
  }]));
}
```

Display setting overrides:
The client parses `options.txt` before launch and forcibly sets `fullscreen:false`:

```javascript
// main.js (Lines 2955 - 2969)
if (/^fullscreen:/m.test(options)) {
  options = options.replace(/^fullscreen:.*$/m, "fullscreen:false");
}
await fsExtra.writeFile(optionsTxtPath, options, "utf8");
```

## 4. Vulnerability Taxonomy Summary

| Category | Standard ID | Title | Observed System State |
|---|---|---|---|
| Software Integrity | CWE-347 | Improper Verification of Cryptographic Signature | verifySignature set to null to bypass update integrity checks |
| Supply Chain | CWE-494 | Download of Code Without Integrity Check | Public key left empty and unsigned update packages accepted |
| Privacy Violation | CWE-359 | Exposure of Private Personal Information | Undisclosed background process surveillance via tasklist |
| Local Permissions | CWE-732 / CWE-459 | Incorrect Permission Assignment / Incomplete Cleanup | icacls lockouts left active on unexpected client termination |
| Data Security | KVKK Law No. 6698 Art. 12 | Obligations Concerning Data Security | Student ID card photographs stored in generic feedback channels |

## 5. Assessment for the Community and Players

Technical evaluation of UniCraft Launcher v2.5.6 reveals that its security protections are fundamentally flawed:

1. Update signature checks are disabled, exposing client systems to unverified payload execution.
2. Background process inspection runs continuously despite explicit policy commitments stating that only mod file hashes are compared.
3. Unapproved mod deletion runs without user confirmation and damages files in custom user directories.
4. Hardware banning relies on a client-editable JSON cache that offers no protection against basic evasion.
5. User configuration files including Minecraft server bookmarks and display preferences are overwritten without consent.
6. Student identity cards are routed through unsegmented customer support channels.

These findings show that the client fails to provide the protections claimed by its operators, presenting measurable privacy and system integrity risks to users.
