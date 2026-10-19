# sap-AV Roadmap

Status: **planning only** — nothing below is implemented yet beyond the initial skeleton.

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

### Build steps (in order)

Each step is small enough for one agent session and one or a few commits.

**A. Detection engine (detection-dev)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| A1 | detection-dev | Core models: `ScanItem`, `Verdict`, `Detection` (verdict, reasons, MITRE ID, source), `ScanResult`. MITRE technique catalog (ID → name). | Model + catalog unit tests |
| A2 | detection-dev | Streaming SHA-256 hasher with size limit + blocklist loader/lookup | EICAR hash found in a test blocklist; oversize file skipped |
| A3 | detection-dev | Switch SapAV.Core, SapAV.Engine and both test projects to `net10.0-windows`. Authenticode checker (embedded + catalog signatures) returning Microsoft / OtherTrusted / Unsigned-or-invalid | `notepad.exe` (catalog-signed) → Microsoft; a temp unsigned file → Unsigned; Microsoft check uses root thumbprint, not name |
| A4 | detection-dev | YARA wrapper: load/compile `data/rules/*.yar` once, scan file, read `mitre` meta | EICAR YARA rule matches the generated EICAR file |
| A5 | detection-dev | Heuristics: entropy, double extension, risky-folder executable | Each heuristic has positive + negative cases |
| A6 | detection-dev | Mark-of-the-Web reader (ZoneId, HostUrl, ReferrerUrl) | Test writes a Zone.Identifier ADS on a temp file and reads it back |
| A7 | detection-dev | `FileScanner` orchestrator: A2 → A3 → A4 → A5/A6 → verdict + reasons + MITRE | Blocklist beats signature; Microsoft-signed skips YARA + heuristics; other trusted signed still gets YARA + heuristics but no VT; EICAR → Malicious |

**B. Engine infrastructure (engine-dev)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| B1 | engine-dev | Alert model + Windows Event Log writer (source "sap-AV", structured data, event IDs per alert type). Source registered at service install. | Writer formats the expected structured payload; registration is idempotent |
| B2 | engine-dev | Reversible quarantine: move + rename + strip execute, metadata JSON, restore | Quarantine → restore round-trip keeps content, path, timestamps |
| B3 | engine-dev | Scan job framework: bounded queue, background-priority worker threads, progress + ETA, pause/resume/cancel | Pause stops progress; cancel ends cleanly; ETA computed from throughput |
| B4 | engine-dev | Named-pipe protocol v1 (JSON): start/pause/resume/cancel scan, progress events, results, item actions | Round-trip serialization tests + in-process pipe test |

**C. Scan modes (engine-dev, detection-dev for judgement)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| C1 | engine-dev | Custom Scan (file / folder) end to end through B3 + A7 | EICAR in a temp folder found; clean files Clean |
| C2 | engine-dev | Persistence collectors: Run/RunOnce, Winlogon, IFEO, Services, Startup folders, Scheduled Tasks → `PersistenceEntry` with resolved target path | Command-line → path resolution tests (quotes, args, env vars, `rundll32` targets); collectors run read-only |
| C3 | detection-dev | Persistence judgement: target scan + entry-specific rules (target in Temp, unsigned, IFEO debugger set, missing target), MITRE IDs | Rule unit tests on synthetic entries |
| C4 | engine-dev | Quick Scan: processes + C2/C3 + high-risk folders + last-7-days files | Integration test on a temp tree; timing logged against the 3-minute target |
| C5 | engine-dev | Scan cache (SQLite): path + size + last-write + hash + verdict; blocklist re-check on update | Unchanged file skipped; changed file rescanned; blocklist update flags cached hash |
| C6 | engine-dev | Full Scan: all fixed drives, reparse points skipped, cache used, full persistence check | Integration test on a temp tree; cancel mid-scan |

**D. Real-time + online (engine-dev, detection-dev)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| D1 | engine-dev | Real-time file monitoring: FileSystemWatcher on watched folders → wait-until-unlocked → queue (MOTW files first) | EICAR written to a watched temp folder is detected and quarantined |
| D2 | detection-dev | VirusTotal v3 client (hash lookup only) + SQLite cache + rate limiter (4/min, 500/day) + key storage (DPAPI) | Limiter tests with a fake clock; client tests with a fake HTTP handler — no real API calls in tests |
| D3 | engine-dev | Wire VT: real-time for unsigned risky-extension files in watched folders, scans only for Suspicious + unsigned; usage counter over the pipe. Create `%ProgramData%\sap-AV\` with the SYSTEM + Administrators ACL (or fix it if it exists with a wider ACL) | Policy tests: signed files never queried. ACL test on a temp folder: inheritance off, only SYSTEM + Administrators |
| D4 | engine-dev | Real-time persistence monitoring (registry, services, startup, tasks) with baseline diff → alerts | New HKCU Run value in a test key triggers an alert |
| D5 | engine-dev | "Block & remove" with backup + restore for each persistence type | Remove → restore round-trip on HKCU test entries |

**E. UI (ui-designer)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| E1 | ui-designer | Pipe client + scan screen: mode picker, progress bar, ETA, pause/resume/cancel | View-model tests with a fake pipe |
| E2 | ui-designer | Scan results screen: verdict, reason, MITRE technique, MOTW source URL, quarantine / ignore / restore | View-model tests |
| E3 | ui-designer | Explorer "Scan with sap-AV" (registry verb, register/unregister in settings) + command-line handling | Argument parsing tests; register/unregister under HKCU |
| E4 | ui-designer | Settings: VirusTotal toggle + key entry (sent to the engine over the pipe, never stored by the App), usage counter, manual upload button with confirmation | View-model tests |
| E5 | ui-designer | Persistence alert notification with "Block & remove" / "Allow" | View-model tests |
| E6 | ui-designer | UI polish pass: dashboard, animations, empty/error states, consistent purple/graphite theme | Reviewer sign-off |

---

## Phase 2

| # | Feature | Owner | Notes |
|---|---------|-------|-------|
| 6 | Process monitoring + suspicious parent-child chains | engine-dev (process-start events via WMI `Win32_ProcessStartTrace` or ETW), detection-dev (chain rules) | e.g. Word/Excel/Outlook → powershell/cmd/wscript/cscript/mshta. MITRE T1059.x / T1566.001 |
| 7 | Ransomware canary files | engine-dev | Hidden decoy files in user folders; any modification → high-severity alert. MITRE T1486 |
| 8 | USB auto-scan | engine-dev | Detect volume arrival, Custom Scan of the drive, autorun.inf check. MITRE T1091 |
| 9 | Hosts file monitoring | engine-dev, detection-dev | Watch `drivers\etc\hosts`, diff, flag redirects of security/banking domains. MITRE T1565.001 |
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

Deferred:
- **MalwareBazaar** is dropped from Phase 1 (VirusTotal only); can come back later as a second lookup source.
- **Windows 11 top-level context menu** (sparse MSIX + `IExplorerCommand`); Phase 1 uses "Show more options".
