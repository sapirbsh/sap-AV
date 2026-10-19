# sap-AV Roadmap

Status: **in progress.** Each completed step is committed as "<step>: …" (see `git log`).

Owners: `engine-dev` (SapAV.Engine), `detection-dev` (detection logic in SapAV.Core), `ui-designer` (SapAV.App).
Every build step goes through the standard workflow when done: **owner → tester → reviewer → fix**.
A step is done only when its tests pass (CLAUDE.md: "Every feature gets tests before it's considered done").

---

## Feature overview

| # | Feature | Phase | Primary owner | Also involved |
|---|---------|-------|---------------|---------------|
| 1 | Scan modes (Quick / Full / Custom) + results screen | 1 | engine-dev | ui-designer (screens, Explorer menu), detection-dev (judging persistence entries) |
| 2 | Local detection engine (blocklist, YARA, heuristics, Authenticode) | 1 | detection-dev | — |
| 3 | VirusTotal hash lookup (API v3) | 1 | detection-dev | engine-dev (wiring, pipe), ui-designer (settings, counter, upload button) |
| 4 | Mark-of-the-Web | 1 | detection-dev | engine-dev (queue priority), ui-designer (show source URL) |
| 5 | Real-time persistence monitoring | 1 | engine-dev | detection-dev (judge target exe), ui-designer (alert + "block & remove") |
| 11 | Cracked-software threat pack (infostealers, miners, Defender tampering, script persistence, browser hijack, PUP/HackTool, "Remove threat") | 1 | detection-dev (rules, categories) | engine-dev (collectors, monitors, remediation), ui-designer (category display, Remove threat, delete permanently) |
| 6 | Process monitoring + suspicious parent-child chains | 2 | engine-dev | detection-dev (chain rules), ui-designer |
| 7 | Ransomware canary files | 2 | engine-dev | ui-designer |
| 8 | USB auto-scan | 2 | engine-dev | ui-designer |
| 9 | Hosts file monitoring | 2 | engine-dev | detection-dev (judge changes) |
| 10 | Scheduled scans | 2 | engine-dev | ui-designer |
| X1 | MITRE ATT&CK mapping on every alert | cross-cutting | detection-dev | ui-designer (show technique) |
| X2 | Windows Event Log output (source "sap-AV") | cross-cutting | engine-dev | — |

---

## Phase 1 (MVP)

### Feature specs

#### 1. Scan modes
- **Quick Scan** — target: under 3 minutes.
  - Running processes and their executables.
  - All persistence locations: Registry Run/RunOnce (HKCU + HKLM, incl. WOW6432Node), Winlogon `Shell` / `Userinit`,
    Image File Execution Options (`Debugger`, `GlobalFlag`/SilentProcessExit), Services, Startup folders (per-user + all-users),
    Scheduled Tasks.
  - High-risk folders: Downloads, Desktop, Temp (user + `C:\Windows\Temp`), AppData.
  - Files created/modified in the last 7 days — scoped to user profiles and `ProgramData` (not whole drives) to keep the time budget.
- **Full Scan** — all fixed drives, all files, plus the full persistence/Registry check.
  - Progress bar with ETA, Pause / Resume / Cancel.
  - Low CPU/IO priority: scan threads use background mode (`THREAD_MODE_BACKGROUND_BEGIN`) — per thread, not per process,
    so real-time protection in the same service is not throttled.
  - Skip files unchanged since the last scan: cache keyed by path + size + last-write time, storing the hash and verdict.
    When the blocklist/rules change, cached hashes are re-checked against the blocklist cheaply instead of re-reading files.
  - Don't follow reparse points / junctions (avoids loops and double scanning).
- **Custom Scan** — a chosen file or folder, plus an Explorer right-click "Scan with sap-AV" entry.
  - Phase 1 uses the classic registry verb (`HKCU\Software\Classes\*\shell` and `Directory\shell`). On Windows 11 it appears under
    "Show more options"; a top-level entry needs a sparse MSIX package + `IExplorerCommand` (later, optional).
  - The App receives the path as a command-line argument and forwards it to the engine over the pipe.
- **Scan results screen** — each found item shows verdict, reason, MITRE technique, and actions: quarantine / ignore / restore.
  "Ignore" adds a path+hash exclusion; it never deletes anything.

#### 2. Local detection engine
Does most of the work in every scan. Order:
1. SHA-256 (streaming, skip files over the size limit) → local blocklist. A blocklist match is Malicious **even if signed**.
2. Authenticode signature check (`WinVerifyTrust`, including **catalog-signed** files, which covers most Windows system files).
   Revocation checks are off by default to keep it fast.
   - **Signed by Microsoft** (embedded or Windows catalog signature) → Clean, skip all remaining steps.
     "Microsoft" is decided by the chain ending in a Microsoft root certificate (checked by thumbprint), not by the
     publisher name text, which another CA could issue.
   - **Other valid trusted signature** → skip VirusTotal only; YARA and heuristics still run.
   - Unsigned or invalid signature → all steps run.
3. YARA rules (compiled once, reused; rules carry a `mitre` meta field).
4. Heuristics: entropy (packed/encrypted), double extension (`.pdf.exe`), executable in Temp/Downloads/AppData,
   Mark-of-the-Web origin (feature 4).
5. Verdict: Clean / Suspicious / Malicious + reason(s) + MITRE technique ID.

#### 3. VirusTotal hash lookup (API v3)
- **When:**
  - Real-time: new/downloaded **unsigned** files in watched folders, only with risky extensions:
    `.exe .dll .msi .ps1 .js .vbs .bat .cmd .zip .docm .xlsm`.
  - Scans: only files the local engine rated Suspicious **and** unsigned.
  - Any file with a valid trusted signature (Microsoft or not) is never sent to VirusTotal.
- **Privacy:** send only the SHA-256, never the file. Optional manual "Upload to VirusTotal" button only, with a confirmation
  dialog warning that uploaded files become visible to VirusTotal users.
- **Local SQLite cache** of results (with expiry, so old "unknown" results get re-asked).
- **Rate-limited queue:** max 4 requests/minute, 500/day (VT public API limits). Requests beyond the budget wait or are dropped
  with an "unchecked" status, never blocking local detection. Usage counter (today / 500) is shown in the UI.
- **API key** lives in local settings on the user's machine (`%ProgramData%\sap-AV\`, DPAPI-encrypted) — never in the repo.
  An environment variable override is allowed for development.
- **`%ProgramData%\sap-AV\` ACL:** created by the engine/installer with inheritance disabled and access limited to
  **SYSTEM and Administrators** (full control); no access for Users. The same folder holds settings, the VT cache and the scan cache.
  Because the GUI runs as a normal user, it never reads or writes this folder directly: it sends settings (including the key)
  to the engine over the pipe, and the engine never sends the key back (the UI only sees "key set / not set").
- Feature is off until the user enables it and enters a key.

#### 4. Mark-of-the-Web
- Read the `Zone.Identifier` alternate data stream: `ZoneId`, `HostUrl`, `ReferrerUrl`.
- Show the download source URL in results and alerts.
- Prioritize internet files (ZoneId 3/4): they jump ahead in the scan queue and count as a heuristic signal.

#### 5. Real-time persistence monitoring
- Alert on new Registry autorun entries, new services, new startup-folder items, new scheduled tasks.
  - Registry: `RegNotifyChangeKeyValue` on the persistence keys, diffed against a baseline snapshot.
  - Services: Service Control Manager notifications or System event 7045.
  - Startup folders: FileSystemWatcher.
  - Scheduled tasks: watch `C:\Windows\System32\Tasks` (the service runs as LocalSystem) and/or TaskScheduler/Operational event 106.
- For each new entry, resolve and scan the target executable with the local engine (+ VT if enabled).
- Offer **"Block & remove"** in the alert, which first backs up the entry (registry value, task XML, service config,
  startup item moved to quarantine) so it can be restored. Services are **disabled**, not deleted.
- **Never auto-remove.** The user always decides.

#### 11. Cracked-software threat pack
Targets what typically comes bundled with cracked games/software. The scan-time checks run in **both Quick Scan and Full Scan**;
the behaviour monitors run in real time.

**Detection**
- **Infostealers**
  - *Behaviour (real time):* a process that is not the owning app reads browser credential/cookie stores, Discord tokens or
    crypto wallet files:
    - Chrome/Edge `Login Data`, `Cookies`, `Local State`
    - Firefox `logins.json`, `key4.db`, `cookies.sqlite`
    - Discord `Local Storage\leveldb`
    - wallet folders (Exodus, Electrum, Atomic, and browser-extension wallets such as MetaMask)

    `FileSystemWatcher` does not report reads, so this needs ETW file I/O events (kernel file provider) in the SYSTEM service.
    Expected readers (the browser itself, signed by its vendor) are allowlisted by signer + path.
  - *Static (scans):* random-named executables in AppData (high name entropy, unsigned, no version info), plus public
    infostealer YARA rules.
  - **YARA-Forge rules only, never real samples.** Use a curated subset (infostealer, miner, hacktool/keygen) vendored under
    `data/rules/third-party/`, with each rule's license/attribution kept and an update script. Each file is compiled separately,
    so a rule our libyara version can't compile is skipped with a warning instead of breaking the whole set. A scan-time budget
    keeps a large rule set from slowing scans.
- **Cryptominers**
  - *Static (scans):* known miner names and command lines (`xmrig`, `stratum+tcp://`, `stratum+ssl://`, `--donate-level`,
    `-o pool…`, common pool ports such as 3333/4444/5555/7777/14444) in running processes, persistence entries and files.
  - *Behaviour (real time):* sustained high CPU (per process) or GPU (PDH `GPU Engine` counters) while the user is idle.
    The service runs in session 0 and can't see user input, so the App reports the idle state (`GetLastInputInfo`) over the pipe.
    Also flags processes that exit or stop using the CPU/GPU right after `taskmgr.exe` / Process Explorer / Resource Monitor start.
- **Defender tampering (scans)**
  - Read Microsoft Defender status and exclusions through WMI `root\Microsoft\Windows\Defender`: `MSFT_MpComputerStatus` and
    `MSFT_MpPreference` (`ExclusionPath` / `ExclusionExtension` / `ExclusionProcess`). This requires admin; the service runs as SYSTEM.
  - Flag broad or suspicious exclusions: drive roots, `%AppData%`, `%LocalAppData%`, `%Temp%`, user profile roots, game folders,
    executable extensions (`.exe`, `.dll`), and exclusions pointing at unsigned processes.
  - Flag disabled real-time protection, behaviour monitoring or tamper protection.
  - Developer exclusions can be legitimate, so these are findings for the user to judge, never auto-fixed.
- **Script-based persistence (scans + real time):** scheduled tasks and Run keys with encoded PowerShell (`-enc`, `-e`,
  `-EncodedCommand` and their abbreviations; the decoded command is shown to the user), `mshta`, or `rundll32` loading a DLL
  from user-writable folders. This extends C3's persistence judgement and D4's real-time alerts.
- **Browser hijack (scans)**
  - Changed proxy settings: per logged-on user, `HKU\<SID>\…\Internet Settings` `ProxyEnable` / `ProxyServer` / `AutoConfigURL`,
    plus the WinHTTP proxy.
  - Hosts file entries that block or redirect security sites (AV vendors, Windows Update, VirusTotal). The domain list lives in `data/`.
- **New category "PUP / HackTool"** (keygens, cracks, activators) is separate from Malicious:
  - never auto-quarantined;
  - shown with its own label so the user decides;
  - a file that is both (e.g. a trojanized keygen) gets the worse verdict, Malicious.
- Every finding has a MITRE ID (see X1).

**Removal (always user-confirmed, never automatic)**
- **"Remove threat"** button: shows the list of planned changes, then on confirmation:
  1. kills the process (and its child processes);
  2. removes its persistence (Registry / tasks / services, using D5);
  3. quarantines the file (B2);
  4. removes the flagged Defender exclusions.

  Every change is backed up in one **remediation record** and can be undone as a group. The exception is killing the process,
  which can't be undone and is shown as such.
- **"Delete permanently"** from the quarantine screen, with **double confirmation**. Only the user can trigger it.
- **Locked files:** schedule the action for the next reboot (`MoveFileEx` with `MOVEFILE_DELAY_UNTIL_REBOOT`, run by the SYSTEM
  service). It should be a reboot-time *move into quarantine* (reversible) when the file is on the same volume as the quarantine
  folder. A reboot-time *delete* is used only when the user chose "Delete permanently", or confirms it after being told the move
  isn't possible (see Decisions). Pending reboot actions are listed in the UI and can be cancelled before the reboot.

### Build steps (in order)

Each step is small enough for one agent session and one or a few commits.

**A. Detection engine (detection-dev)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| A1 | detection-dev | Core models: `ScanItem`, `Verdict`, `Detection` (verdict, reasons, MITRE ID, source), `ScanResult`. MITRE technique catalog (ID → name). | Model + catalog unit tests |
| A2 | detection-dev | Streaming SHA-256 hasher with size limit + blocklist loader/lookup | EICAR hash found in a test blocklist; oversize file skipped |
| A3 | detection-dev | Switch SapAV.Core, SapAV.Engine and both test projects to `net10.0-windows`. Authenticode checker (embedded + catalog signatures) returning Microsoft / OtherTrusted / Unsigned-or-invalid | `notepad.exe` (catalog-signed) → Microsoft; a temp unsigned file → Unsigned; Microsoft check uses root thumbprint, not name |
| | | **Carried over from the A1 review:** add an optional `SignatureStatus` (Microsoft / OtherTrusted / UnsignedOrInvalid) and signer name to `ScanResult`, so a Clean result records *why* it is clean and the X2 Event Log payload can include the signer. Added as an optional parameter, without breaking existing callers. | Results carry the signature status; JSON round-trip still passes |
| A4 | detection-dev | YARA wrapper: load/compile `data/rules/*.yar` once, scan file, read `mitre` meta. **Carried over from the A1 review:** when the lenient MITRE parser (`MitreTechniqueIdFormat.TryNormalize` / `SelectOrDefault`) changes or drops a rule's `mitre` value (e.g. `T1059,001` → `T1059`, an invalid token dropped, or a fallback to T1204.002), log a warning naming the rule and the raw value. Never change it silently. Normalization that keeps the meaning (trim, uppercase) needs no warning | EICAR YARA rule matches the generated EICAR file |
| A5 | detection-dev | Heuristics: entropy, double extension, risky-folder executable. **Carried over from the A2 review:** flag oversized executables padded to dodge the hash size limit (e.g. a PE file far over the limit, mostly zero-filled), reading only the headers and tail | Each heuristic has positive + negative cases |
| A6 | detection-dev | Mark-of-the-Web reader (ZoneId, HostUrl, ReferrerUrl) | Test writes a Zone.Identifier ADS on a temp file and reads it back |
| A7 | detection-dev | `FileScanner` orchestrator: A2 → A3 → A4 → A5/A6 → verdict + reasons + MITRE. **Carried over from the A2 review:** a hash that fails (`HashResult` not hashed) becomes `ScanResult.NotScanned` via `ToNotScannedResult`, never Clean. `SkippedTooLarge` and `SkippedOffline` are logged clearly | Blocklist beats signature; Microsoft-signed skips YARA + heuristics; other trusted signed still gets YARA + heuristics but no VT; EICAR → Malicious |

**B. Engine infrastructure (engine-dev)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| B1 | engine-dev | Alert model + Windows Event Log writer (source "sap-AV", structured data, event IDs per alert type). Source registered at service install. **Carried over from the A1 review:** cap `Detection.Reason` length (e.g. 1024 characters) and reject or strip control characters/newlines, so reasons can't break the Event Log payload or SIEM parsing (also relevant for B4 message size). | Writer formats the expected structured payload; registration is idempotent |
| B2 | engine-dev | Reversible quarantine: move + rename + strip execute, metadata JSON, restore | Quarantine → restore round-trip keeps content, path, timestamps |
| B3 | engine-dev | Scan job framework: bounded queue, background-priority worker threads, progress + ETA, pause/resume/cancel. **Carried over from the A2 review:** opening a file is synchronous and can't be cancelled (slow shares, held oplocks), so hashing runs on dedicated low-priority worker threads, not the shared thread pool. Benchmark sync vs `FileOptions.Asynchronous` reads on local disk and pick one | Pause stops progress; cancel ends cleanly; ETA computed from throughput |
| B4 | engine-dev | Named-pipe protocol v1 (JSON): start/pause/resume/cancel scan, progress events, results, item actions. Bad client messages are caught (`JsonException` **and** the `ArgumentException`s thrown by model validation) and must not kill the connection handler. **Carried over from the A1 review:** every path received over the pipe goes through `ScanPathPolicy` (see C1) before a scan is started. Don't register `JsonStringEnumConverter` (or any enum converter) in the pipe's `JsonSerializerOptions`: options-level converters override the models' `StrictEnumConverter<T>` attribute and would re-allow numbers and any letter case. If enum-keyed dictionaries are needed, add `ReadAsPropertyName`/`WriteAsPropertyName` to `StrictEnumConverter<T>` first. Set `AllowDuplicateProperties = false` in the pipe options, so `{"Status":"Locked", …, "Status":"Scanned"}` can't turn a skipped file into Clean | Round-trip serialization tests + in-process pipe test; malformed message → error reply, connection stays up |

**C. Scan modes (engine-dev, detection-dev for judgement)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| C1 | engine-dev | Custom Scan (file / folder) end to end through B3 + A7. **Carried over from the A1 review:** add `ScanPathPolicy` in Core. `ScanItem` only checks format, but the engine runs as SYSTEM and Custom Scan paths come from a normal user. The policy rejects device/namespace paths (`\\.\…`, `\\?\…` other than `\\?\X:\…`, `\\?\GLOBALROOT`), NUL characters, reserved device names (`CON`, `NUL`, …) and alternate data streams. It rejects UNC/network paths from the pipe, so SYSTEM never authenticates to a remote SMB server. It normalizes with `Path.GetFullPath`, so `..` can't bypass the "Ignore" exclusions or the C5 cache key. **Carried over from the A2 review:** (W-A) A path-string policy can't stop SMB authentication: a local file symlink to `\\server\share\x` makes SYSTEM authenticate to that server when the hasher opens it, with an NTLM relay risk on domain-joined machines. After opening, check `GetFileInformationByHandleEx(FileRemoteProtocolInfo)` and refuse remote files unless the caller asked for them. Document outbound-NTLM restriction / SMB signing for deployment. (W-B) `Sha256Hasher.IsFileSymlinkToDirectory` (the AccessDenied fallback) calls `Directory.Exists` on the link target, which opens it without the hashing flags. Replace it with a handle-based check through `OpenForHashing`, or drop the relabel. If the engine ever enables SeBackupPrivilege, on-demand scans from the pipe must check the requesting user's access first, so a user can't learn the hash, size or timestamps of files they can't read. | EICAR in a temp folder found; clean files Clean; policy tests for each rejected path form + normalization; symlink-to-UNC test refused | EICAR in a temp folder found; clean files Clean; policy tests for each rejected path form + normalization |
| C2 | engine-dev | Persistence collectors: Run/RunOnce, Winlogon, IFEO, Services, Startup folders, Scheduled Tasks → `PersistenceEntry` with resolved target path | Command-line → path resolution tests (quotes, args, env vars, `rundll32` targets); collectors run read-only |
| C3 | detection-dev | Persistence judgement: target scan + entry-specific rules (target in Temp, unsigned, IFEO debugger set, missing target), MITRE IDs | Rule unit tests on synthetic entries |
| C4 | engine-dev | Quick Scan: processes + C2/C3 + high-risk folders + last-7-days files. Built from pluggable "scan checks", so the threat pack (E) adds its checks to Quick and Full Scan without changing the scan framework | Integration test on a temp tree; timing logged against the 3-minute target |
| C5 | engine-dev | Scan cache (SQLite): path + size + last-write + hash + verdict; blocklist re-check on update. **Carried over from the A1 review:** `ScanItem` compares paths case-sensitively. Cache keys and "Ignore" exclusions must use the normalized path from `ScanPathPolicy` (C1), compared case-insensitively (`OrdinalIgnoreCase`), so `C:\X.bin` and `c:\x.bin` are the same file | Unchanged file skipped; changed file rescanned; blocklist update flags cached hash |
| C6 | engine-dev | Full Scan: all fixed drives, reparse points skipped, cache used, full persistence check. **Carried over from the A2 review:** pass the hasher `\\?\`-prefixed full paths built from enumeration results (D1 too). Otherwise Win32 path normalization hides files: `dir\NUL` resolves to the NUL device, and trailing dots/spaces are stripped, so `a.exe.` would read `a.exe`. Malware can use such names to dodge scanning | Integration test on a temp tree; cancel mid-scan |

**D. Real-time + online (engine-dev, detection-dev)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| D1 | engine-dev | Real-time file monitoring: FileSystemWatcher on watched folders → wait-until-unlocked → queue (MOTW files first). **Carried over from the A2 review:** the hasher shares ReadWrite, so it is *not* an "is the download finished" check. "Wait until unlocked" is its own probe: open with `FileShare.Read`, which fails while any writer is open, retried with backoff. A `HashFailureReason.BlockedByAntivirus` result (Defender got there first) is reported as such, not as an error. Like C6, use `\\?\` paths for watcher events, and apply the C1 remote-file check (W-A) | EICAR written to a watched temp folder is detected and quarantined. That test needs a Defender exclusion for the temp folder, or it is skipped when Defender blocks the write |
| D2 | detection-dev | VirusTotal v3 client (hash lookup only) + SQLite cache + rate limiter (4/min, 500/day) + key storage (DPAPI) | Limiter tests with a fake clock; client tests with a fake HTTP handler — no real API calls in tests |
| D3 | engine-dev | Wire VT: real-time for unsigned risky-extension files in watched folders, scans only for Suspicious + unsigned; usage counter over the pipe. Create `%ProgramData%\sap-AV\` with the SYSTEM + Administrators ACL (or fix it if it exists with a wider ACL). **Carried over from the A2 review:** the engine loads the blocklist (and later the rules) only from this protected folder. A user who could edit it could take their own malware off the list | Policy tests: signed files never queried. ACL test on a temp folder: inheritance off, only SYSTEM + Administrators |
| D4 | engine-dev | Real-time persistence monitoring (registry, services, startup, tasks) with baseline diff → alerts | New HKCU Run value in a test key triggers an alert |
| D5 | engine-dev | "Block & remove" with backup + restore for each persistence type | Remove → restore round-trip on HKCU test entries |

**E. Cracked-software threat pack (detection-dev, engine-dev)**

Detection rules and categories come first, then the scan-time collectors (wired into Quick + Full Scan), then the real-time
monitors, then removal. Tests never use real malware or miners. They use synthetic data, fake event feeds and temp files,
and **never change the real Defender configuration** (Defender access goes through an interface with a fake in tests).

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| E1 | detection-dev | PUP / HackTool category: add `Verdict.PotentiallyUnwanted` (order Clean < Suspicious < PotentiallyUnwanted < Malicious) and a `ThreatCategory` on `Detection` (Malware, Pup, HackTool, Infostealer, Miner, DefenderTampering, BrowserHijack). PotentiallyUnwanted is never auto-quarantined. Add the new MITRE IDs from X1 to the catalog | Ordering + worst-verdict tests; JSON round-trip with the new values; catalog tests |
| E2 | detection-dev | Third-party YARA rules: curated YARA-Forge subset (infostealer, miner, hacktool/keygen) in `data/rules/third-party/` with licenses/attribution + update script; per-file compile with skip-and-warn; scan-time budget | Every vendored file compiles or is reported; rule metadata gives MITRE IDs; timing test on a temp tree. No real samples: test strings only |
| E3 | detection-dev | Static infostealer/miner heuristics: random-named unsigned executables in AppData; miner names, command lines and pool ports | Positive + negative cases on synthetic names/command lines |
| E4 | detection-dev | Script-persistence rules (extends C3): encoded PowerShell (all `-enc` forms, decoded for display), `mshta`, `rundll32` with a user-folder DLL | Synthetic Run/task entries; decoding tests; no false positive on a normal `rundll32 shell32.dll,…` |
| E5 | engine-dev + detection-dev | Defender collector (engine-dev: WMI `MSFT_MpPreference` / `MSFT_MpComputerStatus` behind an interface) + exclusion/status rules (detection-dev: broad paths, risky extensions, disabled protection) | Rule tests on synthetic exclusion lists; collector tested against a fake. Real Defender read only in a skippable integration test, never written |
| E6 | engine-dev + detection-dev | Browser-hijack collector (per-user proxy via `HKU\<SID>`, WinHTTP proxy, hosts file) + rules (proxy/PAC set by a non-system source, hosts entries for security domains) | Synthetic proxy values and hosts files; per-SID enumeration tested with a test key |
| E7 | engine-dev | Add E2–E6 as scan checks in Quick Scan (C4) and Full Scan (C6), including running-process command lines (WMI `Win32_Process.CommandLine`) | Quick and Full Scan results include pack findings on a synthetic setup; Quick Scan still within its time budget |
| E8 | engine-dev | Process event source: process start/stop with command line and parent (ETW or WMI `Win32_ProcessStartTrace`). Pulled forward from Phase 2 #6, which then only adds the parent-child rules | Fake feed tests + one integration test that starts and stops a harmless child process |
| E9 | engine-dev + detection-dev | Miner behaviour monitor: sustained per-process CPU / GPU (PDH `GPU Engine`) while idle (idle state from the App over the pipe), and "stops when Task Manager opens" (correlated with E8) | Fake counter/event feeds with a fake clock: sustained-vs-spike, idle-vs-active, taskmgr correlation |
| E10 | engine-dev + detection-dev | Infostealer behaviour monitor: ETW file-read events on browser/Discord/wallet store paths by non-owning processes; allowlist by signer + path | Fake ETW feed tests; one integration test where a test process reads a **fake** store file in a temp folder that is registered as a watched pattern |
| E11 | engine-dev | "Remove threat" remediation: kill the process tree → remove persistence (D5) → quarantine the file (B2) → remove the flagged Defender exclusions. One remediation record with grouped undo (the kill is not undoable) | Dry-run plan test; remove → undo round-trip on HKCU test entries + temp files + a fake Defender; partial-failure test: a failed step is reported and the earlier steps stay undoable |
| E12 | engine-dev | Quarantine "Delete permanently" (engine requires an explicit confirmed request from the UI) + reboot-time actions for locked files (`MoveFileEx` delay; move into quarantine when possible, delete only for "Delete permanently"); list and cancel pending reboot actions | Delete only with confirmation; a pending reboot action is registered and can be cancelled (checked through `PendingFileRenameOperations`, then cleaned up) |

**F. UI (ui-designer)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| F1 | ui-designer | Pipe client + scan screen: mode picker, progress bar, ETA, pause/resume/cancel | View-model tests with a fake pipe |
| F2 | ui-designer | Scan results screen: verdict, reason, MITRE technique, MOTW source URL, quarantine / ignore / restore. Shows the PUP / HackTool category with its own label, separate from Malicious | View-model tests |
| F3 | ui-designer | Explorer "Scan with sap-AV" (registry verb, register/unregister in settings) + command-line handling | Argument parsing tests; register/unregister under HKCU |
| F4 | ui-designer | Settings: VirusTotal toggle + key entry (sent to the engine over the pipe, never stored by the App), usage counter, manual upload button with confirmation | View-model tests |
| F5 | ui-designer | Persistence alert notification with "Block & remove" / "Allow" | View-model tests |
| F6 | ui-designer | "Remove threat" flow: planned-changes list, confirmation, result, and undo from the remediation history. Defender-tampering and browser-hijack findings view | View-model tests with a fake pipe |
| F7 | ui-designer | Quarantine screen: restore, "Delete permanently" with double confirmation, and pending reboot actions (with cancel). Reports the user's idle state to the engine for E9 | View-model tests; the second confirmation can't be skipped |
| F8 | ui-designer | UI polish pass: dashboard, animations, empty/error states, consistent purple/graphite theme | Reviewer sign-off |

---

## Phase 2

| # | Feature | Owner | Notes |
|---|---------|-------|-------|
| 6 | Process monitoring + suspicious parent-child chains | detection-dev (chain rules), engine-dev | The process event source is built in Phase 1 (E8); this adds the chain rules. e.g. Word/Excel/Outlook → powershell/cmd/wscript/cscript/mshta. MITRE T1059.x / T1566.001 |
| 7 | Ransomware canary files | engine-dev | Hidden decoy files in user folders; any modification → high-severity alert. MITRE T1486 |
| 8 | USB auto-scan | engine-dev | Detect volume arrival, Custom Scan of the drive, autorun.inf check. MITRE T1091 |
| 9 | Hosts file monitoring | engine-dev, detection-dev | Scan-time hosts checks are in Phase 1 (E6); this adds real-time watching. Watch `drivers\etc\hosts`, diff, flag redirects of security/banking domains. MITRE T1565.001 |
| 10 | Scheduled scans | engine-dev, ui-designer | e.g. weekly Quick Scan; schedule stored in engine settings, editor in UI |

---

## Cross-cutting

### X1. MITRE ATT&CK mapping (detection-dev)
Every alert carries exactly one primary technique ID (more allowed as secondary). Starting map:

| Detection | Technique |
|-----------|-----------|
| Registry Run/RunOnce, Startup folder | T1547.001 |
| Winlogon Shell/Userinit | T1547.004 |
| Image File Execution Options | T1546.012 |
| New/modified service | T1543.003 |
| Scheduled task | T1053.005 |
| Double extension | T1036.007 |
| High entropy / packed | T1027.002 |
| Malicious file from blocklist / YARA / VT (no rule-specific ID) | T1204.002 |
| Office → script interpreter (Phase 2) | T1566.001 + T1059.x |
| Ransomware canary (Phase 2) | T1486 |
| USB (Phase 2) | T1091 |
| Hosts file (Phase 2) | T1565.001 |
| Threat pack: reading browser credential stores | T1555.003 |
| Threat pack: reading browser cookies | T1539 |
| Threat pack: Discord tokens / credential files | T1552.001 |
| Threat pack: crypto wallet files | T1005 |
| Threat pack: cryptominer (CPU/GPU, miner command line, stops on Task Manager) | T1496.001 (Compute Hijacking; T1496 got sub-techniques in ATT&CK v16) |
| Threat pack: Defender exclusions / disabled protection; hosts entries blocking security sites | T1562.001 |
| Threat pack: encoded PowerShell | T1059.001 + T1027.010 |
| Threat pack: `mshta` / `rundll32` from user folders | T1218.005 / T1218.011 |
| Threat pack: proxy / PAC hijack | T1557 (closest fit: Adversary-in-the-Middle) |
| Threat pack: random-named AppData executable, PUP / HackTool | T1204.002 |

YARA rules may override with their own `mitre` meta value.

### X2. Windows Event Log (engine-dev)
- Every alert is written to the Application log with source **"sap-AV"**, registered by the service installer (needs admin; the service runs as LocalSystem).
- Structured payload (JSON in the message, stable field names) for SIEM collection: timestamp, alert type, verdict, file path,
  SHA-256, signer, MITRE ID, reason(s), MOTW URL, action taken.
- Fixed event IDs per alert type (documented here once defined in B1).

---

## Decisions

Approved:
1. **Target framework:** SapAV.Core and SapAV.Engine (and their test projects) switch to `net10.0-windows` at step A3.
   Authenticode, Registry, ADS and Event Log are Windows-only APIs and the product is Windows-only.
2. **New dependency:** `Microsoft.Data.Sqlite` for the VT cache and the scan cache (added at C5 / D2, whichever comes first).
3. **Signature rule:** only Microsoft-signed files (incl. Windows catalog-signed) skip all checks; other trusted signed files
   skip VirusTotal only.
4. **`%ProgramData%\sap-AV\`** is restricted to SYSTEM and Administrators.

Open (decide before the step that needs it):
- **New dependencies for the threat pack (E):**
  - `Microsoft.Diagnostics.Tracing.TraceEvent`, for ETW process and file-read events (E8, E10);
  - `System.Management`, for WMI: Defender, process command lines (E5, E7);
  - `System.Diagnostics.PerformanceCounter`, for CPU/GPU counters (E9).
- **YARA-Forge licensing:** the repo is public. Vendored rules must keep their per-rule licenses, and any rule whose license
  doesn't allow redistribution is left out (or downloaded by the update script instead of committed). Decide at E2.
- **Locked files on another volume:** a reboot-time move can't cross volumes. The options are a per-volume quarantine folder,
  or a reboot-time delete after an extra confirmation. Decide at E12.

Deferred:
- **MalwareBazaar** is dropped from Phase 1 (VirusTotal only); can come back later as a second lookup source.
- **Windows 11 top-level context menu** (sparse MSIX + `IExplorerCommand`); Phase 1 uses "Show more options".
