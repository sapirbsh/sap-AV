# sap-AV Roadmap

Status: **in progress.** Each completed step is committed as "<step>: …" (see `git log`).

Owners: `engine-dev` (SapAV.Engine), `detection-dev` (detection logic in SapAV.Core), `ui-designer` (SapAV.App).
### Workflow
- **Every step:** the owning agent writes and runs its own tests. The step is done, and committed as `<step>: …`, when its
  tests pass with 0 build warnings. There is no separate tester/reviewer pass per step.
- **End of each section (A, B, C, D, E, F, G):** one **tester** pass and one **reviewer** pass over the whole section, then fix
  until clean (committed as `<section>: section review fixes`).
- **Review fixes:** Critical and High findings are fixed. Medium/Low findings are recorded under the step they belong to
  (as "Carried over from the … review") instead of running extra review rounds.
- **Batches:** small related steps are built together by one agent, with one commit per step where practical:
  A4–A7 · B1+B3 · C2+C3 · C5+C6 · D1+D2 · E1–E4 · E5+E6 · F2–F5 · G3a+G3b · G4a+G4b. Steps with an immediate review are never batched past their review.
- **Exception — immediate review:** steps that run privileged code as SYSTEM, touch quarantine, write or remove Registry
  entries, delete files, or touch the pipe get their own **reviewer** pass right after the step, before the next step starts:
  - **B:** B1 (Event Log source registration), B2 (quarantine), B4 (pipe server), B5 (privilege separation: full review), B6 (dedicated event log + CustomSD)
  - **C:** C1 (pipe-supplied scan paths, `ScanPathPolicy`)
  - **D:** D3 (`%ProgramData%\sap-AV` ACL, API key), D5 (Block & remove: Registry/task/service changes)
  - **E:** E5 (Defender access as SYSTEM), E8/E10 (ETW sessions as SYSTEM), E11 (Remove threat: kill/Registry/Defender writes),
    E12 (Delete permanently, reboot-time actions)
  - **F:** F1 (pipe client), F3 (Explorer context-menu Registry writes)
  - **G:** G1b (honeytokens planted as SYSTEM, ACLs), G2a (process + network telemetry), G2b (incident store),
    G2c (story-wide Remove threat), G3c (Explorer verb Registry writes)
- Tests that depend on certificates, files or software that exist on the dev PC but not everywhere must **skip cleanly**
  (reported as Skipped, with a reason) so the suite also passes on a clean machine and on GitHub Actions `windows-latest`.
- Work continues from step to step without waiting for approval. It stops only for a **Critical** security finding or a
  decision the user has to make (e.g. a new package, a licensing question, or a deviation from an approved rule).

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
| G1 | Honeytokens (deception trap for infostealers) | 1 | detection-dev + engine-dev | — |
| G2 | Attack Story (EDR-style incident timeline) | 1 | engine-dev (telemetry, correlation) | ui-designer (timeline), detection-dev (chain rules) |
| G3 | Pre-Flight check ("check before you run") | 1 | detection-dev | ui-designer (drag-and-drop, Explorer verb) |
| G4 | Exposure Report ("what was stolen?") | 1 | detection-dev | ui-designer (report + recovery checklist) |
| 6 | Process monitoring + suspicious parent-child chains | **moved to Phase 1** (E8 + G2a) | engine-dev | detection-dev (chain rules), ui-designer |
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
     "Microsoft" is decided by certificate thumbprints, not by the publisher name text, which another CA could issue.
     Two checks must both pass: the chain ends in a Microsoft product root, **and** the issuing CA is one of Microsoft's own
     first-party code-signing CAs (e.g. Windows Production PCA 2011, Code Signing PCA 2010/2011).
   - The Microsoft roots also sign third-party content: WHQL/attestation-signed drivers (Third Party Component CA),
     Store/Marketplace apps, and Microsoft's Trusted/Artifact Signing service for any customer ("ID Verified" chain).
     These count as **OtherTrusted**, so YARA and heuristics still run on them.
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


**Section A review — required items (added after A7):**
- **YARA engine (decided):** switch from libyara 4.1.1 (2021, via dnYara.NativePack) to **YARA-X**, using the official prebuilt C API (`yara-x-capi`, latest release for `x86_64-pc-windows-msvc`). The A4 layer is rewritten on the YARA-X C API with the same interface for FileScanner. It keeps: scanning our own hardened handle / mapped view, per-file rule compilation, safe rule swapping, the scan timeout, and mitre warnings. The downloaded DLL is pinned by version and verified by SHA-256 (both recorded here once known). **Fallback:** if the YARA-X integration does not work within section A's fixes, keep libyara 4.1.1 with only allowlisted modules, record this as an open item, and continue to section B. **Done (A4, `697e3f4`):** YARA-X **v1.22.0**, asset `yara-x-capi-v1.22.0-x86_64-pc-windows-msvc.zip`, zip SHA-256 `40317f65781e3a17bffe31f9837143a51c1c28ce5061eac2b90695fbb30e1664` (matches the digest GitHub publishes), `yara_x_capi.dll` SHA-256 `bb5c112bf479d1b1706fbecf85275d3806321ee2912dea4f36750289d0294848`. Downloaded at build time by `native/yara-x/YaraX.targets` and hash-checked, never committed. The fallback was not needed.
- **YARA modules:** only the modules our rules need (e.g. `pe`, `math`, `hash`) may run. libyara only runs a module when a rule imports it, so `YaraRuleSet` enforces an `import` allowlist at load time: a rule file importing anything else (`cuckoo`, `magic`, `dotnet`, `elf`, `macho`, `dex`, `console`, …) is rejected and reported in `FileErrors`. If we build libyara ourselves, unused modules are also compiled out.

**Carried over from the section A review (Medium/Low, by target step).** The High findings H1–H3 are fixed in
section A: single-handle pipeline, crash-safe YARA content access, YARA import allowlist.
- **A5 (follow-up, before E3; still open after E3, see "Notes from E1/E3/E4"):**
  - (M2) PE detection is easy to dodge. More than 96 sections, `e_lfanew` > 4072, or a section table past the first 4 KiB → no PE
    → the unsigned/entropy/folder rules are skipped. Treat MZ or any executable extension as executable, read headers up to
    `SizeOfHeaders` (cap 64 KiB), raise the section cap to 65535, and count "malformed PE" as a signal.
  - (M3) Entropy read amplification: overlapping sections can make one file cost GBs of reads. Merge ranges and cap the
    sampled bytes.
  - (M7) `.7z.exe` / `.zip.exe` self-extractors score 60 on the double-extension rule even when trusted-signed. Archive
    decoys don't count for trusted-signed files.
  - (L1) Bidi masquerading also needs U+202B, U+202D and U+2066–2069, not just U+202E.
- **A7:** (L6) `HeuristicResult.ContentInspected == false` is ignored; add a note to the report.
- **B1 / X2:** (L2) MOTW URL sanitizing: strip U+2028/2029; treat `\` as the end of the authority (`https://evil\@good`);
  strip query strings (presigned tokens) before writing to the Event Log / SIEM.
- **B3:**
  - (M4) Exceptions escape `FileScanner.ScanAsync`: wrap each step, map to NotScanned(Error), and treat it as a cancel only
    when our own token is cancelled.
  - (M5) Zero loaded rules, or a non-empty `FileErrors`, still scans as Clean: the engine alerts/degrades. Rule files are
    opened by path, which is acceptable only from D3's protected folder.
  - (M6) Each file was opened 5–6 times and read 3–4 times; H1 fixes the opens. Compute section entropy in the same pass
    where possible.
  - (L5) Files that defeat rule atoms pin a worker for the full YARA timeout: add a per-job time budget.
- **B5:**
  - (H2 residual) Until B5 lands, a native crash inside YARA-X, or an in-page error on a mapped view, is a service crash.
  - (L7) Some signature handlers (MSI, scripts) may open `pcwszFilePath` themselves instead of `hFile`: test inside the
    worker. MOTW in the worker needs the stream handle from the broker (H1's handle-relative open).
- **C6:** (M6) Full Scan relies on H1's single-handle pipeline for I/O cost.
- **D1 (and A2):** (M1) Byte-range-lock evasion: a dropper keeping an exclusive lock on its payload makes hashing fail
  (Locked → NotScanned) while image loading ignores the lock. On `ERROR_LOCK_VIOLATION` (33), hash from a mapped view of
  the same handle.
- **D2:** (M4) Online-lookup failures and HttpClient timeouts become a note, never a scan failure or a fake cancel.
- **D3:** (M5) Rule and blocklist files load only from the ACL'd `%ProgramData%\sap-AV` folder.
- **E2:** (L5) Lint rule atom quality, since slow rules turn into timeouts.

**Carried over from the B1 review (Medium/Low).** H1 (the ILogger EventLog provider auto-registering a source),
H2 (a write re-creating a removed source) and M2/L1/L2/L3/L6/L7 are fixed in B1.
- **X2 — decided 2026-10-24 (M1): dedicated `sap-AV` event log.** Today anyone on the machine can write Application-log
  events with source `sap-AV` (fake 1001 alerts, or floods that push real ones out). Fix, built as **B6** (see below).
- **Service installer / D3 (M3):** the message DLL `System.Diagnostics.EventLog.Messages.dll` is registered from the
  engine folder. The installer must refuse unless that folder is admin-only (Program Files), or point
  `MessageResourceFile` at a protected path.
- **B3 (M4):** alert flooding and blocking writes. Aggregate/rate-limit per hash+path with one summary event; write
  through a bounded channel with a single writer, so a hung Event Log RPC can't block scan threads.
- **X2 (L4):** middle truncation of a crafted long path can hide the directory that matters (`\Startup\`). Add
  `FilePathLength` + `FilePathSha256`, or keep the last directory parts and the file name first.
- **F1 / UI (L5):** `FilePath` keeps bidi controls on purpose (evidence). The UI must show paths with FSI/PDI isolation or
  visible escapes, so an RLO can't spoof names.
- **B4 / F (L8):** `SafeText.SingleLine` keeps invisible format characters (U+200B, U+2060–2064, U+FEFF, U+FFF9–FFFB, tag
  characters). Map them to U+FFFD before display.
- **X2 (L9):** apply the "`\` ends the authority" URL rule only to http/https/ftp/file; other schemes keep their
  userinfo redaction as before.
- **A7 (L10):** heuristic findings are joined in insertion order, so the 1024-character reason cap can cut the strongest
  one. Join them by score.

**Carried over from the B2 review (Medium/Low).** C1 (quarantine not bound to the scanned file, so it could be
redirected into a SYSTEM file delete), H1 (PE heuristic tests could pass vacuously under a Defender block),
M1, L1, L6 and L7 are fixed in B2/A5.
- **B3 (M2):** `SafeDirectory` refuses every reparse point, so nothing under a OneDrive sync root (Desktop/Documents) can
  be quarantined or restored. Refuse only name-surrogate tags (`IsReparseTagNameSurrogate`); `OBJ_DONT_REPARSE` still
  blocks real redirects. Verify on a OneDrive machine.
- **D3 (M3):** a standard user can pre-create `%ProgramData%\sap-AV` (or `…\Quarantine`) so the store is UntrustedOwner
  and quarantine stays off. The installer creates the folders with a protected ACL, and startup raises an Event Log
  error/alert when the store is unavailable.
- **B3 (M4):** no store quota or free-space floor, so mass-dropped unique flagged files can fill the system drive. Add a
  quota plus a free-space check → `StoreFull` + alert.
- **B4/B5 (M5):** restore has no caller identity. B4 must authorise restore (admin, or the requester's token has
  FILE_ADD_FILE on the target folder), and quarantine requests from the pipe need DELETE on the file for the client token.
- **B2 follow-up (L2):** restoring an unprotected DACL may recompute inheritance by resolving the parent by name, which
  can follow reparse points. Merge the original explicit entries with the inherited ones the kernel set at create time,
  and set them with `NtSetSecurityObject`. Verify.
- **B5 (L3):** the original owner isn't restored (SeRestorePrivilege off), so a protected original DACL can lock the
  user out of their restored file.
- **D3 (L4):** TOCTOU in `FixWiderAcl` (empty check, then DACL replace). Set the DACL first, then enumerate.
- **D3 (L5):** for a configured `Root`, only the immediate parent is checked and pinned, and store I/O goes by path.
  Require all ancestors to be non-user-writable, or do store I/O relative to `RootHandle`.
- **Tests (L8):** add the missing cases as each item above lands: C1 swap, hard link after the check, untrusted-owner
  parent, recovery rollback.
- **From the B2 follow-up review (C1/H1 confirmed closed):**
  - **B4/B3/D3 (Medium):** who may request a quarantine.
    - B4: pipe requests require DELETE on the file for the client token.
    - B4: never deserialize a `FileScanReport`/`Identity` from the pipe.
    - B3/D3: exclude the engine's own data folders (e.g. `rules\*.yar`, which match themselves) from scanning and quarantine.
  - **B2 follow-up (Low):** if `SecurityDescriptor` is null, a moved-back file keeps the lockdown DACL. Set an empty
    unprotected DACL so it re-inherits from the folder.
  - **B2 follow-up (Low):** a tiny hard-link window remains between the re-check and the delete. After the delete, check
    `NumberOfLinks` again; if it isn't 0, report a partial result and raise an alert.
  - **B3 (Low):** `Path.GetFullPath` strips trailing dots/spaces and doesn't expand 8.3 names, so `x.exe.` can't be
    quarantined. Compare `\\?\`-normalised paths, or use the scan's final path as canonical.
  - **B3 (Low):** the handle overload can't verify the caller's handle denies writers, so B3 must open with Read|Delete sharing only.
  - **Phase 2 USB (Low):** FAT/exFAT may not report `FileIdInfo`, so quarantine refuses those files (fails closed). Verify.
  - Tests: add an explicit object-manager link test (junction to `\RPC Control` + symlink).

**Carried over from the B5 review (Medium/Low).** H1 (worker process/thread DACL, name-derived AppContainer SID),
M1 (worker keeping duplicated handles), M4 partially (no ACL grant as SYSTEM), L1 and L3 are fixed in B5.
- **X2 / B3 (M2):** worker free text (reasons, notes, YARA descriptions, signer) is sanitized but can still carry up to
  ~256 KiB of scanned file content. Since the Application log is user-readable, a compromised worker could leak content
  of files the engine read as SYSTEM. Build Event Log/alert text from engine-side templates + validated identifiers
  (rule id, MITRE id, enum kinds), and keep worker free text out of the Event Log or cap it hard. On-demand scans
  (C1) should use the requesting user's access.
- **B3 / D1 (M3):** a compromised worker can fake a Malicious verdict for files only SYSTEM/TrustedInstaller may change
  (System32, Program Files), and auto-quarantine would move them. Auto-quarantine refuses protected locations unless
  the user confirms, and rate-limits with burst alerts.
- **Installer / D3 (M4 rest, M5):** the worker folder and exe must be owned by an admin or TrustedInstaller with no
  non-admin write ACEs, or the SYSTEM engine refuses to launch it. The installer sets the AppContainer ACL. Optionally
  pin the worker exe hash or check its signature.
- **C2 / E (L2):** pipe handles are inheritable only during the worker CreateProcess under `LaunchLock`. Any other
  engine `CreateProcess` with inheritance must run under the same lock, or there must be none.
- **B5 follow-up (L4):** a compromised long-lived worker could crash on another file twice to get it flagged
  Suspicious (T1211). Count a failure only when the worker was freshly started for that file. Suspicious only, never
  quarantine.
- **B5 follow-up review (H1 confirmed closed, no Critical/High).** These are done as the first commit of B3:
  - (Medium, M-A) The M1 handle-copy check can be bypassed. A worker can keep the handle count flat by closing a dummy
    handle, the enumeration has a TOCTOU, and section views aren't seen. Fix: after `CloseInWorker`,
    `NtQueryObject(ObjectBasicInformation)` on the broker's own file/stream handles must report a system-wide HandleCount
    of exactly 1, else discard the worker. Add a test fault that duplicates the handle and closes a dummy.
  - (Low) Refuse `Sandbox:Mode=InProcess` whenever running as LocalSystem, not only under services.exe.
  - (Low) Also enforce `MaxWorkerLifetime` in `EnsureReadyAsync` (idle workers).
  - (Low) `WorkerObjectSecurity.IsLockedDown` fails open on non-CommonAce ACEs: return false for any other ACE type.
  - (Low) A failed handle enumeration discards the worker without counting it against the file.
  - (Low) Log the AppContainer profile name/SID at Debug, not Information.
  - (Low) Tests: `WorkerFolderAccessTests` disposes every container in `finally`. The fixture purges stale
    `sap-AV.ScanWorker.Test.*` profiles and their S-1-15-2-* ACEs (keeping S-1-15-2-1/-2). Use a named mutex for the
    DACL gate across concurrent test runs. Fix the misleading "non-admin account" test name.
  - (Low, docs) The per-install suffix is not secret: AppContainer SIDs are visible in the object namespace while a
    worker runs. Fix the comments in `AppContainerName`/`AppContainerProfile`: the protection is the explicit DACL plus
    the lowbox double access check, and the suffix only avoids collisions. Optional: set the worker token's
    TokenDefaultDacl to SYSTEM + Administrators before resume, and test the DACL of every worker thread.
- **D3 (Medium, M-B):** a standard user can pre-create `%ProgramData%\sap-AV\Sandbox`, so it is UntrustedOwner and the
  sandbox, and with it **all scanning**, is unavailable (worse than B2 M3). The installer creates the folder with the
  protected ACL, and startup raises an Event Log alert whenever the sandbox is unavailable.

**Carried over from the B3 review (Medium/Low).** H1 (trailing dot/space names bypassing exclusions and scanning),
M3, M4, L1 and L4 are fixed in B3.
- **C1 / C6 (M1):** walker TOCTOU. A folder's reparse tag is read by path at classify time, but the folder is listed by
  path later; a swap to a junction or directory symlink in between escapes the tree (with Developer Mode, even a
  symlink to `\\host\share`, giving machine-account NTLM). List folders relative to handles: open with
  BACKUP_SEMANTICS|OPEN_REPARSE_POINT, check the tag and FileRemoteProtocolInfo on the handle, list via
  `FileIdExtdDirectoryInfo`, and open children relative to the parent with OBJ_DONT_REPARSE.
- **C6 (M2):** any user can register a Cloud Files sync root; listing a placeholder folder as SYSTEM triggers the user's
  provider, which can return an endless tree or stall. Don't descend into unpopulated folders
  (RECALL_ON_OPEN / RECALL_ON_DATA_ACCESS; count them as offline). Add a max depth (e.g. 256) and max entries per job.
- **D3 (M5):** excluded folders are trusted even if a user controls them (pre-created `%ProgramData%\sap-AV`, or an engine
  running from a user-writable folder). Exclude a folder only if its owner is SYSTEM/Administrators/TrustedInstaller
  and no non-admin can write to it; otherwise scan it and raise a health alert.
- **D1 (L2):** 20 cheap detections can use up the auto-quarantine window, so the real payload only gets
  NeedsUserConfirmation. That's the rate-limit trade-off; document it, and consider prioritising by verdict source.
- **X2 / B6 / B4 (L3):** worker text still partly reaches outputs: alerts carry 4×200 characters of reasons + signer + URL,
  and `ScanJobFileResult.Detail` carries worker note text (up to 512 characters) to pipe clients.
- **B4 (L5):** Created-but-never-started jobs are never trimmed; B4 must cap them.
- **B2 follow-up (from the H1 fix):** names ending in a dot or space (e.g. a Malicious `evil.exe.`) are detected and
  alerted, but auto-quarantine refuses them as PathRedirected, because quarantine/restore (`SafeFile`, `SafeDirectory`)
  still normalise with `GetFullPath`. This fails safe (never confused with `evil.exe`), but the user must act. Make
  quarantine and restore use `ExactPath` (`\\?\` exact names).
- **B3 follow-up (M4 detail):** deny ACEs are ignored when judging "user-modifiable", so a file can look modifiable
  even if a deny ACE blocks the user (minor; it only makes such a file eligible).
- **D1 (L6):** a writer holding a writable mapped view gets around deny-writers sharing (a scan race on the attacker's
  own file, an evasion, not a quarantine abuse).

**Carried over from the B6 review (CLEAN, no Critical/High; Medium/Low).** The CustomSD bit values were checked against
the live Windows defaults for classic logs.
- **D3 (M1):** "clear once" doesn't revoke a write handle opened during the brief window between creating the log key and
  writing CustomSD, and a rerun after a partial failure skips the clear. Fix:
  - create the log key and its values in one KTM transaction (`RegCreateKeyTransacted`);
  - clear whenever the source wasn't already in our log before this run;
  - tell the user that a reboot (or Event Log service restart) closes handles opened before the CustomSD took effect.
- **B3 / X2 (M2):** the writer trusts the registration but never checks the log's actual SD. A GPO or
  `wevtutil sl sap-AV /ca:` could widen it silently. At startup and on each recheck, verify the CustomSD with
  `EventLogCustomSd.IsExpected`; on a mismatch, report "log integrity: degraded" (and recheck the message DLL path).
- **D3 (L1):** a mapped or SUBST drive letter passes the message DLL path check. Require DRIVE_FIXED, compare
  `GetFinalPathNameByHandle` with the input, and reject `:` after index 2.
- **D3 (L2):** uninstall + reinstall in the same boot clears the reused .evtx and wipes old evidence. Back it up first
  (`ClearLog(backupPath)` / `EvtExportLog`).
- **B6 follow-up / tester (L3):** the real test has no positive control. Show the same filtered token *can* write to a
  default-SD throwaway log, so ERROR_ACCESS_DENIED is proven to come from our CustomSD.
- **X2 (L4):** the guard test can be bypassed by aliasing (target-typed `new`, `using` aliases, concatenated registry
  paths, a second ReportEvent P/Invoke). Add those patterns; a Roslyn analyzer would be more robust.
- **B3 (L5):** one transient registry error skips alerts for the whole 5-minute recheck interval. Retry quickly with
  backoff after errors.
- **X2 (L6):** right after a same-boot migration, the service may briefly still map the source to Application. Read the
  first event back after migrating, or recheck after a few seconds.
- **X2 docs (L7):** users can still write Application events with look-alike sources (`sap-AV ` with a trailing space,
  homoglyphs). SIEM docs must say: filter on `Channel == "sap-AV"`, never on the provider name alone.

**Carried over from the C1 review (Medium/Low).** H1 (restore gave the file to the requester, including admins →
silent elevation path), M1 (Signer/SourceUrl as a worker → standard-user channel) and L1 (RestorePrivilege refusing an
already-impersonating thread) are fixed in C1.
- **Before F1 exposes it (M2):** the admin `AllowRemote` opt-in makes SYSTEM authenticate to the server with the machine
  account (NTLM relay risk on domain-joined machines), and the scan runs with the computer's rights on the share. Open
  remote paths while impersonating the admin client, or at least show the server name for explicit confirmation in the
  UI and document the risk.
- **C5 / C6 (L2):** a file root's size goes into BytesTotal before the access check. Run the access check first for
  standard-user jobs.
- **C6 (L3, acceptable):** remaining access-first side channels: NotFound is faster than "exists but denied"; the
  CheckRoot parent-list check is path-based; subfolder Unreadable details are visible in folders the user can list.
- **C6 (L4):** the RemoteFileProbe error mapping (87/1/50 = local) is verified only on NTFS. On ReFS/Dev Drive, FAT,
  exFAT or UDF an unexpected code would make every file look remote (fails closed, but a coverage gap). Log Unknown once per
  volume with the error code; add a VHD-based ReFS/FAT test under a RequiresFact.
- **F1 (L5):** an owner whose DACL denies them read can't see their own quarantined item, and dropping the parent-list
  check shows paths from folders the user can't list. Optionally also show the item to `RequestedBy == user`.
- **D1 (L6):** the requester quota check decrypts every metadata file per request (O(N); bounded by the rate limit, not
  for auto-quarantines in user jobs). The global 4 GiB quota is reachable by 8 users. Real-time quarantines of files a
  user drops use only the engine budget and the global quota.
- **D1 (L7):** a Malicious alert from a user's own job can be dropped when that user's half of the alert queue is full
  (counted, with hashes, in the summary). Document this next to "Malicious alerts are never dropped".
- **Tests:** add an end-to-end "local file symlink → `\\localhost\C$\…` is refused" test (RequiresFact DeveloperMode +
  AdminShare) that exercises the post-open remote check; visibility tests with a null DACL and inherited ACEs.

**Notes from C2 (persistence collectors, built `ee7e59b`…`b5846c9`).**
- **C3 / section C review (B5 rule):** the `.lnk` parser (`ShellLink`) and task XML parser (`TaskXml`) run inside the
  SYSTEM engine, and Startup `.lnk` files are user-writable. Both are managed and bounded, but CLAUDE.md says the SYSTEM
  engine never parses file contents. Move them into the sandboxed scan worker, or have the section C review accept them
  explicitly with reasons.
- **D4:** tasks that exist only in the registry TaskCache (no file under `System32\Tasks`) aren't seen. RunOnceEx,
  `Windows\Load`/`Run`, App Paths and `conhost --headless` aren't covered yet.
- **Unloaded user hives** are skipped (HiveNotLoaded issue), not loaded, because loading NTUSER.DAT as SYSTEM needs
  SeBackup/SeRestore, parses a user-writable hive and can break that user's next logon. Their Startup folder is still
  collected.
- **Real task files untested so far:** the test process isn't elevated, so the real `System32\Tasks` gave AccessDenied.
  The first elevated / SYSTEM / CI run is the real check.
- **From C3 (persistence judgement, built `f92aa33`, `f335c8e`):**
  - New alerts: 2001 MaliciousPersistence (Error), 2002 SuspiciousPersistence (Warning); `Alert.Autostart` carries
    the entry. New MITRE IDs: T1574.009, T1574.010, T1546.008, T1546.015, T1218.005, T1218.010, T1218.011.
  - C4: register `PersistenceScanner` in `EngineHost`, use Parallelism 1 (so opens stay on the job's low-priority
    thread), and plug the file verdict handler in as the target handler. F1: map findings to the pipe.
  - E4: add script-persistence rules through `PersistenceJudge.WithRules(...)`.
  - Known false positives: legitimate IFEO uses (Process Explorer replacing Task Manager, `vsjitdebugger`).
  - The ACL writability check ignores deny ACEs and integrity labels (it only over-reports), and doesn't tell another
    user's writable folder apart from the user's own.
- **From C4 (Quick Scan, built `0e57d9c`…`c8ecff3`):**
  - **Tuning needed:** on the dev PC the two folder phases were cut short by the 3-minute budget (about 100 files/s;
    AppData full of `.dll`/`.js`/`.py`). Tune the extension list, depth and cache skips. The scan cache (C5) should
    make repeat Quick Scans much faster. Timings were measured in-process and non-elevated, not with the AppContainer
    worker as SYSTEM.
  - Quick Scan through the pipe is admin-only (it reads every profile, process and machine autostart); its results are
    visible to admins only.
  - Phase 4 skips phase-3 folders, so recent files deeper than 10 levels inside AppData are missed. No USN journal
    (it would need a volume handle and by-ID opens outside the handle-bound walk).
  - Process images are judged by file only (command lines come with E7). Collection (≤ 30 s) can't be paused partway.
  - Section E adds checks by registering an `IScanCheck`; the factory inserts them after persistence.
  - **C4 review: CLEAN.** M1 (user-controlled folder roots), M2 (phase 4 skipping unfinished phase-3 roots), L4, L5, L6
    and L7 are fixed in the C5/C6 batch. Remaining:
    - **E7 / G2a (L1):** a running image can be renamed away and the old path refilled with a benign file. Compare the
      file's creation/change time with the process start time; if newer, report "image replaced after start" (T1036).
    - **E7 (L2):** processes running from a share or device path are only logged. Add a phase note and a low finding.
    - **C4 tuning (L3):** skip-folder patterns (`*` caches, `Explorer`) are user-writable, so a payload dropped there is
      never seen. In skipped folders, still list one level and queue executables.
    - **Section C tester (L8):** the 800 ms budget test with 50 ms broker delays is load-sensitive on CI. Drive it with
      a FakeTimeProvider or widen the margins.
- **Section C review (5 High: resolver stack overflow, TaskXml stack overflow + parsers moved to the worker, `attrib +O`
  evasion, false Clean on autostart entries, stale Clean without a change journal). M3, M4, M5, M7, M8 pulled forward;
  all fixed in the section C fix round. Remaining:**
  - **D1 (M1):** worker compromise can poison the cache: verdict, SHA-256 and the rules fingerprint are worker-supplied,
    and Clean outlives recycling. Compute the fingerprint in the engine from the RulePackage; record the worker generation
    and purge its rows on a protocol violation; re-scan about 1% of hits in a fresh worker and purge on a mismatch.
  - **D1 (M2):** USB-as-fixed and VHD volumes use the cache, and offline edits keep all stamp fields. Skip the cache for
    BusTypeUsb and file-backed virtual disks (`IOCTL_STORAGE_QUERY_PROPERTY`).
  - **D1 (M6):** root skip lists are by name only: `D:\pagefile.sys` on a data volume whose root users can modify is never
    opened and still runs. Skip a file only on a sharing violation; skip `System Volume Information` only if SYSTEM-owned
    with a SYSTEM-only DACL.
  - **E4 (M9):** LOLBin arguments are ignored (`msiexec /i https://…`, `explorer.exe C:\Users\u\evil.exe`, `forfiles`,
    `pcalua`, `conhost --headless`, `certutil`, `msbuild`). Extend E4 beyond PowerShell, mshta and rundll32.
  - **D4 / E4 (M10):** COM hijack through `GroupId` tasks is missed: the override check runs only for a `UserId` SID. For
    group or interactive principals, check every loaded `<SID>_Classes` hive.
  - **E7 (M11):** volumes mounted on a folder are never scanned (letters only). Use `FindFirstVolume` +
    `GetVolumePathNamesForVolumeName`.
  - **D1 (L1):** cache disk use is bounded by rows, not bytes (several GB worst case), with no VACUUM. Add
    `PRAGMA max_page_count` and a path-length limit; `quick_check` also blocks the first scan.
  - **D1 (L2):** the USN moved 2–3 s after a mapped write, so one stale hit is possible in that window.
  - **D4 (L3):** `AclPathWritability` checks only the file and its immediate folder. A writable grandparent allows
    rename-and-replace, and DELETE + FILE_DELETE_CHILD isn't counted. Check ancestors for machine-wide targets.
  - **D1 (L4):** the 25M entry cap is global and depth-first, so a user folder early on `C:\` can use it up. Use per-volume
    budgets and name the first few too-deep paths.
  - **E (L5):** named streams (ADS) aren't enumerated, so payloads in them aren't scanned.
  - **D2 (L6):** a cache hit skips the online lookup, and VT outcomes get stored. Bind rows to the VT result or its age.
  - **D1 (L7):** the journal ID isn't bound to rows (admin-only to exploit).
  - **D1 L6 is downgraded for NTFS:** a deny-writers open fails with error 32 while a writable view exists, so it falls
    back to the shared path and isn't cached.
- **Section C follow-up review (4 High: cmd switch parsing, false "missing" targets, unsupported shortcut ID lists,
  user-settable placeholder folders; fixed in the follow-up fix round, together with M3 Unverified classes and M6
  collection budget share). Remaining:**
  - **C2 follow-up (M1):** `System32\Tasks` is user-writable (`Authenticated Users:(CI)(W,Rc)`). Root files count as
    machine scope and come before `\Microsoft\…`, so 625 fake files × 32 actions reach MaxEntries 20,000 and blind every
    later task and user entry. Use TaskCache (admin-only) as the authoritative task list, bucket files with no TaskCache
    entry by file owner with their own cap, walk admin-owned subfolders first, and give each source its own entry share.
  - **C2 follow-up (M2 rest):** parse crashes push up the restart backoff on the shared scan slots (about 12 crashing
    files use up 60 s and stall other jobs). Add a per-collection failure limit and a dedicated parse slot.
  - **E4 (M4):** host-argument payloads behind Microsoft binaries come out Clean: `regsvr32 /i:C:\…\evil.sct scrobj.dll`,
    `regsvr32 /s evil.dll scrobj.dll` (only the last DLL is kept), `rundll32 url.dll,FileProtocolHandler <exe>`,
    `rundll32 shell32.dll,ShellExec_RunDLL <exe>`, `conhost --headless <exe>`, `forfiles /c`. Extract the argument
    payloads or mark them Unverified.
  - **D4 (M5):** tasks with `<GroupId>` or a name principal never check user `Classes\CLSID` overrides, and
    `ComClassNotRegistered` with an unloaded hive is treated as "nothing runs". Check every loaded `_Classes`; an unknown
    hive is Unverified.
  - **C5 (L2):** cached Microsoft-signed rows are tied to `EngineInfo.Version`, which carries the git SHA only when built
    from git. Add a trust-policy fingerprint (allowlist + trust store) to the cache context.
  - **C3 / B6 (L3):** Unverified entries write no Event Log record, so a SIEM never sees them. Consider an informational
    event.
  - **F (L4):** the alert `FilePath` and the pipe `TargetPath` show only the primary command, even when the detection came
    from an `Additional` command. Show the command that matched.
  - **C2 (L5):** a `Win32Exception` while duplicating a handle marks the parser down for the whole collection. Retry once
    with a fresh slot.
- **C2 batch-parse review (`27b65d3`; H1 solo retry ignored the collection budgets and M1 one thread per exchange were
  fixed in the follow-up commit). Remaining:**
  - **C2 (M2):** batch failures are charged to no file. A bad file costs a whole failed batch (up to 15 s + restart +
    rules reload) on every collection until it has failed solo `MaxFailuresPerFile` times. A bomb that fails only inside
    a batch is never charged. Remember the keys of files from a failed batch and send them solo first next time.
  - **C2 (M3):** the parse answer cap rose to 8 MiB, and the whole answer is deserialized in the SYSTEM engine before
    the per-file count and text caps apply (one ~8 MiB string, or >1M `null` entries). Compute the cap from the file
    count × per-file worst case, or pre-scan with `Utf8JsonReader` and reject an over-long array or string first.
  - **C2 (L3):** if `TerminateJobObject` fails after a timeout, the exchange thread stays blocked in `Read`. Log when
    the 5 s exit wait expires, and cancel the read with `CancelSynchronousIo`.
  - **C2 (L4):** missing tests: a hang inside a batch, two bad files in one batch, exact failure counts (innocent files
    0, the bad one +1 per collection), cancellation during the solo pass.
- **Flaky test:** `RemoteFileTests.AdminShare_IsRefusedByDefault_AndScannedOnlyWhenAllowed` failed once after 34 s
  under full-suite load (passes alone and in later runs), most likely an SMB timeout. Give it a generous timeout or
  mark it Slow at the section C tester pass.

**Carried over from the section B review (cross-step; Medium/Low).** H1 (`%ProgramData%\sap-AV` writable by users and
wholly excluded), H2 (admin/engine jobs following links on file opens) and H3 (one user blocking all scans with paused
jobs) are fixed in section B. M4 (startup resilience + health alerts, incl. B6 M2), M5 (pipe name in
`ProtectedPrefix\Administrators`), L1 and L2 were pulled forward and fixed too.
- **C1 (M1):** a standard user can fill the quarantine store through `QuarantineFromResult` (Suspicious results are
  accepted; there's no per-user quota or rate limit), so real auto-quarantines then get StoreFull. Add a per-requester
  quota and rate limit for pipe-requested quarantines; keep the global quota for engine-initiated ones.
- **C1, before D1 (M2):** the alert window (`AlertDispatcher`, 200 non-Malicious, 10,000 keys) and the auto-quarantine
  window (`AutoQuarantineLimiter`) are shared by everyone, so a user's own scans can push real alerts into a summary and
  use up quarantine slots (this also covers D1 L2). Give each requester/trigger its own budget; engine and real-time
  Malicious alerts are never limited by user-requested jobs; the summary lists distinct hashes.
- **B2 follow-up / C1 (M3):** restore creates files owned by SYSTEM (it can't set the original owner), and
  `AutoQuarantinePolicy` then treats them as protected, so a restored file is never auto-quarantined again. Set the owner
  to the requesting user (SeRestorePrivilege only for that call), or don't treat a SYSTEM owner as protection in
  user-writable folders.
- **F1 at the latest (M6):** `QuarantineList` isn't paged. One frame (≤ 4 MiB), so a few hundred long-path items break it
  for everyone, and each item costs a SafeTree open + AccessCheck synchronously for a standard user. Page it and estimate
  the size while building it.
- **C1 (L3):** quarantine item visibility needs only list access on the folder, while scanning needs read access on the
  file, so a user can see the SHA-256 and reasons of another user's quarantined file. Check against the stored DACL.
- **B3 L3 / C1 (L4):** `RulesPreflight` puts worker rule-error text into job warnings shown to standard users. Send counts
  only to non-admin clients.

**Carried over from the B4 review (Low).** H1 (accept loop killed by an early close), H2 (instance count reaching 0 →
pipe-name takeover), H3 (junction swap during a walk), M1 (slot exhaustion before Hello), M2 (SYSTEM following
symlinks in client roots → SMB/NTLM coercion), M3 (jobs keyed by SID only) and L1, L5, L6, L7 are fixed in B4.
- **B4 follow-up (residual from the fixes):**
  - Admin jobs still open files with `ScanFileOpener` (a following `CreateFileW`); only their roots are opened safely.
    Switch admin jobs to `SafeScanOpen` too.
  - The pipe-instance owner check on its own isn't exercised by a test (the test attacker pipe is caught by the DACL
    comparison).
  - A client that arrives while every slot is in use is dropped without an error frame.
  - B3 M1 (walker TOCTOU) is closed for all jobs by `SafeTree` (handle-bound walk).
- **B4 follow-up (L2):** ScanGet halves the page and re-serializes it up to ~8 times (≤ 4 MiB each) per request.
  Estimate the size while building the page and serialize once.
- **C1 (L3):** the excluded-folder result, the DifferentFile message (with the final file name) and open-failure statuses
  (Locked, TooLarge, …) come before the client's read-access check. Check access first; for access-restricted jobs, map
  open failures to a generic NotScanned.
- **B2 follow-up (L4):** the restore and quarantine parent-folder checks are path-based (they read a junction's own SD).
  SafeDirectory refuses the redirect today, so this is defense in depth. Run AccessCheck on the SafeDirectory handle
  inside the quarantine call.
- **B4 follow-up (L8):**
  - Anonymous-SQOS clients each log a warning with no rate limit.
  - Malformed frames and drains are parsed before the rate limiter.
  - The event queue is bounded by count, not bytes (512 × up to ~64 KB paths ≈ 32 MB per connection); bound it by bytes.
  - Document that auto-quarantine of a Malicious file in a standard user's job skips the DELETE rule quarantine-from-result
    enforces (consistent with Full Scan).

**B. Engine infrastructure (engine-dev)**

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| B1 | engine-dev | Alert model + Windows Event Log writer (source "sap-AV", structured data, event IDs per alert type). Source registered at service install. **Carried over from the A1 review:** cap `Detection.Reason` length (e.g. 1024 characters) and reject or strip control characters/newlines, so reasons can't break the Event Log payload or SIEM parsing (also relevant for B4 message size). | Writer formats the expected structured payload; registration is idempotent |
| B2 | engine-dev | Reversible quarantine: move + rename + strip execute, metadata JSON, restore | Quarantine → restore round-trip keeps content, path, timestamps |
| B3 | engine-dev | Scan job framework: bounded queue, background-priority worker threads, progress + ETA, pause/resume/cancel. **Carried over from the A2 review:** opening a file is synchronous and can't be cancelled (slow shares, held oplocks), so hashing runs on dedicated low-priority worker threads, not the shared thread pool. Benchmark sync vs `FileOptions.Asynchronous` reads on local disk and pick one | Pause stops progress; cancel ends cleanly; ETA computed from throughput |
| B4 | engine-dev | Named-pipe protocol v1 (JSON): start/pause/resume/cancel scan, progress events, results, item actions. Bad client messages are caught (`JsonException` **and** the `ArgumentException`s thrown by model validation) and must not kill the connection handler. **Carried over from the A1 review:** every path received over the pipe goes through `ScanPathPolicy` (see C1) before a scan is started. Don't register `JsonStringEnumConverter` (or any enum converter) in the pipe's `JsonSerializerOptions`: options-level converters override the models' `StrictEnumConverter<T>` attribute and would re-allow numbers and any letter case. If enum-keyed dictionaries are needed, add `ReadAsPropertyName`/`WriteAsPropertyName` to `StrictEnumConverter<T>` first. Set `AllowDuplicateProperties = false` in the pipe options, so `{"Status":"Locked", …, "Status":"Scanned"}` can't turn a skipped file into Clean | Round-trip serialization tests + in-process pipe test; malformed message → error reply, connection stays up |
| B5 | engine-dev | **Privilege separation (full reviewer pass):** all file parsing (hashing, YARA, heuristics, Authenticode, MOTW, and later the Pre-Flight PE/archive parsing, G3a) runs in a separate low-privilege **scan worker** process, never in the SYSTEM engine. The worker runs with an AppContainer (preferred) or a restricted token at Low integrity: no network capability, no write access to user files, in a Job Object with memory/CPU/process-count limits, kill-on-job-close and no child processes. The SYSTEM engine only **brokers**: it opens each file with the hardened open (A2), duplicates a read-only handle into the worker, and receives results over a private pipe that only that worker may connect to. Worker output is untrusted input: validated with the same strict JSON/model rules, with size caps. A worker crash, hang or timeout → that file is NotScanned (Error), the worker is restarted with backoff, and a file that crashes the worker repeatedly is flagged Suspicious. Known risks to solve: whether WinVerifyTrust catalog lookups work inside an AppContainer (CryptSvc/catroot access), and loading `libyara.dll` (its folder needs ACLs for "ALL APPLICATION PACKAGES"). If Authenticode can't run sandboxed, it runs in a separate restricted worker, never in the engine. B3's scan jobs dispatch to this worker; C, D and E build on it | Worker token: integrity level / AppContainer SID, no network, Job limits; the engine-side handle is read-only; a deliberately crashing test parser → NotScanned + restart, the engine keeps running; a worker sending malformed or oversized results is rejected; the EICAR end-to-end scan goes through the worker; the worker can't open a user file by path |
| B6 | engine-dev | **Dedicated `sap-AV` event log (immediate review; decision X2 M1, 2026-10-24):** `--install-eventlog-source` creates a custom log named `sap-AV` (not Application) with source `sap-AV`, and sets the log's `CustomSD` so that only SYSTEM can write (plus Administrators, for the elevated installer), and Administrators + Event Log Readers can read. Normal users can't write events to it, so they can't forge or flood alerts. Migration: an existing Application-log `sap-AV` source is moved (uninstall + reinstall into the new log; `RegisteredInOtherLog` handled explicitly). `--uninstall-eventlog-source` removes the log too. The writer (`ReportEvent` path, never auto-registering) targets the new log; event IDs are unchanged. Also: the installer refuses unless the message DLL's folder is admin-only (B1 M3) | Installer creates the log with the expected CustomSD (read back and compared); a non-admin token can't `ReportEvent` into it (elevated + `SAPAV_TEST_ALLOW_HKLM=1` test, cleaned up); migration from an Application-log source; uninstall removes both; existing writer/sink tests still pass |

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

**Notes from D1 (real-time file monitoring, built `7de7442`…`446f3b4`).** Closed in D1:
- From the A2 review: the unlock probe, BlockedByAntivirus, `\\?\` paths and the remote check.
- B3/D1 M3, L2 and L6; C1 D1 L6 (real-time part) and L7; "C1, before D1" M2; C5 D1 L1 (byte cap and path-length cap).

Deferred:
- **A7 / B5 (D1 + A2 M1, detection-dev):** byte-range-lock evasion. Read every worker content reader (hasher,
  Authenticode, heuristics, YARA) from one mapped view. Until then, real-time retries Locked files within its 2-minute
  wait and reports them Locked, never Clean.
- **C5 hardening (its own step, before D4):** C5 D1 M1 (worker-supplied verdict/hash/rules fingerprint can poison the
  cache), M2 (USB-as-fixed and VHD volumes use the cache), L7 (journal ID not bound to rows), and `quick_check`
  blocking the first scan (rest of C5 L1). C5 D1 L2 (USN moves 2–3 s after a mapped write) is inherent; real-time
  narrows it, because the probe waits while a writable view exists.
- **C6 / Full Scan:** C5 D1 M6 (root skip lists by name only) and L4 (global, depth-first entry cap).
- **Quarantine (C1 L6 rest):** O(N) metadata decryption per pipe request, and the 4 GiB global quota reachable by 8 users.
- **C1 M3 interplay:** restored files are SYSTEM-owned, so real-time treats a restored Malicious file as "needs
  confirmation" instead of quarantining it again. If restore ever sets the user as owner, real-time needs a "restored by
  the user" allowlist.
- **F:** real-time status and per-file results on the pipe.

**Section D review (no Critical; 5 High — fix round in progress, see PROGRESS).** To fix now:
- H1: D5's own-key hand-over accepts whatever state is there after the action, so malware that re-creates its value
  is accepted silently.
- H2: oplocks freeze D4's thread, D5's lock and Quick Scan. Persistence parse, target and Startup opens lack
  complete-if-oplocked; add a watchdog.
- H3: the D4 budget owner comes from the attacker-written task XML `UserId`.
- H4: a UNC/WebDAV Startup folder is "complete" with no finding.
- H5: D1 fairness is per root, not per owner.
- M4: no health alert when D1 or D4 dies (the Event Log logger is cleared).
- The cheap parts of M1, plus L3.

Remaining after the fix round:
- **D5 follow-up (M1 rest):** every Block/Restore holds the global `_one` lock for up to two 30 s collections. Use a
  per-requester lock with a short global section.
- **D3 follow-up (M2):** VirusTotal per-owner shares apply to real time only. D4 targets and a standard user's Custom
  scans draw on the global budget; apply `VirusTotalDayBudget` to every trigger.
- **D1 follow-up (M3):** a file with a deny-SYSTEM DACL in a watched folder ends as Error with no alert. Raise
  "hidden from SYSTEM" (T1222/T1564), or open with backup semantics.
- **D1/D4 follow-up (L1):** the sequential 30 s joins at shutdown overrun the host timeout. Use one shared deadline,
  and don't dispose while threads are alive.
- **L2:** closed by the H4 fix (`707690e`).
- **Fix-round notes (`3db711f`…`ff2bec6`):**
  - After a D5 action times out (2 min), its lock is released while the action thread may still run, so a second
    action could overlap. The watchdog's I/O cancel normally ends it first.
  - The D4 thread watchdog has no direct test (`ScanThreadWatch` itself is covered).
  - Machine-wide real-time folders share one "machine" owner in the per-owner queue share. Reading every file's owner
    would cost an open.
  - Flaky once: `PersistenceMonitorReviewTests.H4_KeysRewrittenOverAndOver` (registry UnauthorizedAccessException).
    Cause not found.
- **Follow-up review of the fix round (no Critical/High).** H2, H3 (except M3), H4 and M4 are confirmed closed. Fixed in
  the last round: M1 (D5 lock released while an action still ran), M2 (H1 window after the hand-over), M3 (H3 after
  the owner map clears), L1. Remaining:
  - **D1 follow-up (M4):** all machine-wide roots share one "machine" owner. A user churning Public plus Windows\Temp
    fills that share, and other users' files in machine folders are dropped. Give each machine root a reserved minimum,
    or charge files to the owner `probe.Owner` already read.
  - **D1/D4 follow-up (L2):** the loop-restart failure count never resets, so one crash weeks later waits the full
    5 min. Reset it after a healthy run.
  - **F / docs (L3):** enterprise Folder Redirection of Startup to `\\server\…` raises one Suspicious T1547.001 per
    user. Mention folder redirection in the alert text.
  - **D5 follow-up (L4):** backup records from before `09712bb` have no `EntryId`, so their restores always report
    EntryChanged. Fall back to the fingerprint check.
  - **D1 follow-up (L5):** scan turns rotate per root, not per owner, so a user with about 12 roots gets about 12 turns
    for each one a victim gets. This adds delay only; nothing is dropped.

**Notes from D2 (VirusTotal client, cache, limiter, key store; built `d279fb7`…`cfc581f`).**
- **What was decided:**
  - **Package:** no new one. Machine DPAPI is called through `CryptProtectData` directly, like the quarantine key.
  - **SQLite:** `Microsoft.Data.Sqlite` is referenced by Core as a private asset, so the scan worker ships without
    SQLite.
  - **Cache TTLs:** 7 days when any engine flagged the file; 1 day for clean or unknown (404) results. Only Found and
    NotFound are cached.
- **Known limits, for the section D review:**
  - Two lookups of the same uncached hash at the same time both send a request (no coalescing).
  - A budget slot counts even when the request then fails.
  - `vt-usage.json` has no MAC. Tampering only resets the local counter; the server quota still applies.
  - The key string can't be wiped from memory.
  - The cache MAC key file has no trusted-owner check of its own; it relies on the D3 folder ACL.

**Notes from D3 (VirusTotal wiring, protected rules and blocklist; built `b4f9191`…`c6e7086`).**
- **When a hash is looked up:**
  - signed files (Microsoft or OtherTrusted) never;
  - real time: only risky extensions;
  - scans and Persistence: only Suspicious files;
  - already Malicious files: never.
- **MITRE:** VirusTotal detections get T1204.002.
- **Data:** VirusTotal data lives in `%ProgramData%\sap-AV\VirusTotal\`. The feature is off by default; setting the key
  and turning it on or off is admin-only over the pipe.
- **Rules and blocklist:** they come from `%ProgramData%\sap-AV\Rules` and `\Blocklist`, seeded from a FolderTrust-checked
  install folder.
- **Open from the builder:**
  - **D2 L6:** a scan-cache hit skips the VirusTotal lookup, so a Suspicious file cached while VirusTotal was rate-limited
    isn't looked up again until the entry expires.
  - **Health alert:** a refused VirusTotal folder shows only as `LastProblem` and a scan note, with no Event Log alert.
  - **Duplicated helper:** `RunningAsSystemOrElevated` exists in both `QuarantineStartupService` and `EnginePipeServer`;
    move both to `EngineAccount`.
  - **Installer items:** B2 M3, B5 M-B, Installer M3/M4/M5, the configured-Root ancestors check (L5), and B6
    M1/L1/L2 still wait for the installer step.

**D3 immediate review (no Critical).** Fixed in the D3 fix round:
- H1: a user-created data root disabled the rules and blocklist; they now fall back to the trusted install folder,
  with an alert.
- M1: the cache read the blocklist by path.
- M2: the VirusTotal lookup held the worker slot.
- M3: per-owner VirusTotal budget shares.
- L2: PUP-like labels are never Malicious.
- L4 and L6.

Remaining:
- **D3 follow-up (M4):** seeding by last-write time can't remove or roll back shipped rules. A rule an update removes
  stays forever, an update with older mtimes is never applied, and an admin's blocklist additions are overwritten.
  - Ship a manifest (file name, SHA-256, package version) and sync by content hash.
  - Delete managed files the new manifest drops.
  - Keep admin content in `local-*.yar` / `blocklist.local.txt`.
- **D3 follow-up (L1):** FolderTrust checks the folder and its parent only, and seed files are re-read by path. Read
  them through handles relative to the verified folder (`SafeTree.OpenChild`).
- **B5 / D3 (L3):** a compromised worker can report a famous malware hash for an innocent file, which yields a
  convincing "VirusTotal 60/70" alert. Before a VirusTotal-only auto-quarantine, require the engine-side quarantine
  re-hash to match.
- **D3 follow-up (M2 rest):** the slot is now released before the VirusTotal lookup. The caller's file handle, which
  denies writers, is still held during the request (up to the 20 s client timeout), because quarantine needs it
  afterwards. Close it and reopen it identity-checked for quarantine, or do the lookup after the verdict handler.
- **D3 follow-up (M3 rest):** per-owner VirusTotal day counts are in memory only, so a restart resets them; the global
  `vt-usage.json` limit still holds.
- **D3 follow-up (L5):** VirusTotal lazy init (ACL checks, SQLite, DPAPI) can run on a pipe thread. Warm it up on a
  background task at start.

**Notes from D4 (real-time persistence monitoring, built `fc432d5`…`0989b7f`).**
- **How it works:**
  - registry watches with RegNotifyChangeKeyValue on HKLM and on every loaded HKU hive;
  - Startup folders and `System32\Tasks` watched through the D1 handle-bound folder watch;
  - scoped, debounced re-collection;
  - a parse cache keyed by file ID, size, times and USN;
  - an HMAC'd baseline in `%ProgramData%\sap-AV\Persistence`;
  - a 45-min safety rescan.
- **Speed:** repeat collections with nothing changed take about 10 ms for 200 task files, against 36 ms the first time.
- **Closed:** "D4 (M5)" and the first half of "D4/E4 (M10)": group-principal tasks now check every loaded
  `<SID>_Classes` COM override.
- **Deferred, detection-dev (C3 judge):**
  - M5 second half: an unregistered COM class with an unloaded hive → Unverified;
  - D4 L3: writability of the target's ancestor folders.
- **Deferred, E or a C2 follow-up:** collectors for TaskCache-only tasks, RunOnceEx, `Windows\Load`/`Run` and App Paths.
- **Still open, a collector fix:** C2 follow-up M1, bucketing task files by owner.

**D4 immediate review (no Critical).** Fixed in the D4 fix round:
- H1: a Coverage-Unverified entry was marked judged for good.
- H2: a target-file swap went unnoticed.
- H3: a deny-SYSTEM ACE silently hid an autostart key.
- H4: junk churn could starve a new entry.
- H5: a task-folder flood.
- M4: dead watches were never restarted.
- M5: budgets went to the pass owner instead of the entry's user.

Remaining:
- **D4 fix round, open (section D review):**
  - H1/H5 warnings ("still unverifiable after 5 attempts", "scope cut short 3 passes in a row") are log Warnings, not
    Event Log records (that would need new event IDs plus message-DLL entries).
  - In a hinted tasks pass, a file the watch didn't report is reused without a stamp check. Lost notifications are
    covered only by full passes on overflow or watch restart, and by the 45-min rescan.
  - Hidden-location alerts are off in non-protected debug runs.
  - Flaky: `PersistenceParsingInWorkerTests.OneBadFileInABatch(Crash)` took 15 s and failed once under full-suite load.
- **D4 follow-up (H3 rest):** read user autostart keys with `REG_OPTION_BACKUP_RESTORE` and SeBackupPrivilege, so a
  deny ACE can't hide them at all (today the denial is reported as Suspicious).
- **D4 follow-up (M1):** nothing watches `HKU\<SID>_Classes\CLSID\{X}\InprocServer32` for task COM handlers, and a hive
  load doesn't re-run the machine "scheduled tasks" scope, so a COM hijack waits up to 45 min. Watch the referenced
  CLSID keys, and mark scheduled tasks dirty on every hive load.
- **D4 follow-up (M2):** a change to `HKU\<SID>\Environment` re-collects only the registry scope. Map it to every scope
  of that SID plus the machine tasks scope.
- **D4 follow-up (M3):** a value written and removed within the 2 s settle window, or right before the hive unloads, is
  never seen. Collect Run/RunOnce on the first change and again after the settle; collect a SID right away on session
  logoff.
- **D4 follow-up (M6):** KEY_NOTIFY handles in HKU at logoff: event 1530, and with `DisableForceUnload` the hive stays
  loaded. Release that SID's watches in `OnSessionChange(SessionLogoff)` (a WindowsServiceLifetime subclass with
  `CanHandleSessionChangeEvent`).
- **D4 follow-up (M7):** a registry link key at an autostart location is only seen at the safety rescan. Detect links
  (`SymbolicLinkValue`), raise a Suspicious finding, and watch the target.
- **D4 follow-up (L1):** a failed root brings the next full plan forward for all users. Re-check only that root, with
  backoff.
- **D4 follow-up (L2):** `Services\bam` writes cause a full services collection every 60 s, and continuations
  re-collect the whole scope. Compare per-service last-write times, and keep the collection between continuations.
- **D4 follow-up (L3):** a renamed-away Startup folder that is created again goes unwatched for up to 5 min. Watch the
  parent folder for names.
- **D4 follow-up (L4):** the 30 s Join in Dispose races StopWatch and uses up the host's shutdown time. Clean up on the
  monitor thread, with a shorter join.
- **D4 follow-up (L5):** `ParsedFileCache` keeps results across worker crashes and protocol violations. Clear it then,
  and record the worker generation.
- **D4 follow-up (L6):** one owner's pass can hold the single thread for about 90 s. Cap scan time per owner per round.

**Notes from D5 (Block & remove, built `55097f0`…`bfe6fed`).**
- **What each type does:**
  - Registry values are backed up exactly, then deleted by compare-and-delete.
  - Winlogon Shell/Userinit are reset to the Windows default.
  - Services are disabled through the SCM and stopped, never deleted.
  - Tasks are disabled through the Task Scheduler API, with their XML backed up.
  - Startup items are moved into quarantine.
- **Rules:** entry IDs are re-verified by a fresh collection. Machine entries are admin-only; a user acts only where
  their own token could make the change. Backups are HMAC'd in `%ProgramData%\sap-AV\PersistenceBackups`. Event IDs
  3002/3003 (X2 table).
- **Deferred:**
  - **F5:** an admin can disable a Boot or System-start driver, which can leave the machine unbootable. Refuse it, or ask
    for an extra confirmation.
  - **D5 follow-up:**
    - A task deleted after blocking can't be re-registered from the backed-up XML; restore only re-enables.
    - Service restore doesn't start the service again.
    - The registry compare-and-delete isn't atomic (a tiny window under the same handle).
    - If the backup folder can't be created once, Block & remove stays unavailable until the engine restarts.
    - `PersistenceBackupList` reads every record and isn't rate-limited.
    - Translating a task principal name may contact a DC.
    - Startup names ending in a dot or space fail in the quarantine.
    - Restoring a deleted value is refused even when a value with the same bytes is back.
    - Judging other values in the same key can be delayed up to 2 min during an action.
  - **Not covered yet:** RunOnceEx and TaskCache-only tasks can't be blocked, because C2 doesn't collect them.
  - **D5 immediate review (no Critical).** Fixed in the D5 fix round: H1 (the ledger accepted every value in the
    acted-on key), M1 (task authorization by principal only), M2 (a user could undo an admin's block; `BlockedBy`
    added), M3 (boot-critical services are refused without `ConfirmCritical`), L2. Remaining:
    - **L1:** `ClientMaySet` checks access on a different open than the later change. Both refuse links; do the check on
      the same handle.
    - **L3:** the service hold prefix has no trailing separator (`FOO` also holds `FOOBAR`).
    - **L4:** service restore doesn't check that it's the same service (deleted and recreated under the same name).
    - **For the section review:** the SID-to-scope mapping in the scoped collector, `ClientAccess.Check` /
      `CanAddFileNextTo`, and requester handling in `QuarantineHandleAsync` weren't fully reviewed.
  - **Never run:** the gated real-Task-Scheduler round trip (`RealTaskSchedulerTests`). It needs an elevated run with
    `SAPAV_TEST_ALLOW_HKLM=1`.

**D1 immediate review (no Critical).** Fixed in the D1 fix round:
- H1: oplock holders stalled the real-time threads.
- H2: no per-root queue quota or fairness.
- M1: rescan busy-spin.
- M2: one shared real-time budget for all users.
- M3: real-time holding every worker.
- L1: Parse overflow-safe bounds, and a parse failure treated as an overflow.

Remaining:
- **D1 follow-up (M4):** storm and overflow rescans filter by timestamps the user controls (backdated `evil.exe`
  is skipped), and the 256 global rescan slots collapse a moved-in folder into a time-filtered whole-root rescan
  (moved-in files keep their old times). Recover from the USN journal from the last good USN; never collapse a
  `since: null` rescan into a time-filtered one; make the slot cap per root.
- **D1 follow-up (M5):** a byte-range-locked file ends "Scanned / Locked" and is never looked at again, but can still
  run (image mapping ignores range locks). Keep Locked files on a low-frequency recheck list and show them in status;
  see also the A7/B5 mapped-view note above.
- **D1 follow-up (M6):** the deny-writers scan open breaks apps that reopen a just-saved file for writing (SQLite,
  logs, editors). For real-time, open fully shared and rely on the change-journal check (changed during the scan →
  queue again). Keep deny-writers only for quarantine.
- **D1 follow-up (L2):** folders deeper than MaxRescanDepth (32) aren't counted as an incomplete rescan. Count them
  and log it.
- **E / D1 (L3):** alternate data streams other than Zone.Identifier are never scanned (`wscript x.txt:a.js`). Queue
  `file:stream` for non-trivial streams.
- **D1 follow-up (L4):** rescans walk by path, not from the root handle. After a root rename, events give
  DifferentFile until the next revalidation (5 min). Walk from the root handle, and revalidate on the first DifferentFile.
- **D1 follow-up (L5):** a `.part` / `.crdownload` file whose wait expired and that is closed without a rename is
  never scanned. Queue it again with a long backoff.
- **D1 follow-up (L6):** a hard link to another user's file in your own Downloads makes SYSTEM scan it, and the
  hash and verdict go to the alert. Skip or redact files with more than one link that the folder owner can't read.
- **C5 (L7):** SQLITE_FULL from a really full disk prunes 25% of the cache on every Put. Prune only near
  MaxPageCount. `max_page_count` below the current size is silently raised.
- **Docs (L8):** a file written and run within the settle delay runs before it is scanned. Files in
  `C:\Windows\Temp` are never auto-quarantined (protected folder).
- **D1 follow-up (L9):** after a 30 s join timeout at shutdown, objects are disposed while a stuck thread may still
  use them. Skip disposing when a join timed out.
- **D1 fix round, open:** the watchdog is tested directly, not from the monitor's scheduler. `RealTimeStatus` has no
  watchdog-cancellation counter (logged only). In machine-wide folders, members of one group can share a per-owner
  budget (the owner SID can be set to a group they own).
- **Tests and Defender:** Defender's ML detection (`Trojan:Script/Wacatac.H!ml`) removes test files that start with
  "MZ", have a `.pdf.exe` name and carry an internet Zone.Identifier. Test markers avoid that combination, and a removed
  test file fails with a clear "another antivirus removed it" message.

**E. Cracked-software threat pack (detection-dev, engine-dev)**

Detection rules and categories come first, then the scan-time collectors (wired into Quick + Full Scan), then the real-time
monitors, then removal. Tests never use real malware or miners. They use synthetic data, fake event feeds and temp files,
and **never change the real Defender configuration** (Defender access goes through an interface with a fake in tests).

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| E1 | detection-dev | PUP / HackTool category: add `Verdict.PotentiallyUnwanted` (order Clean < Suspicious < PotentiallyUnwanted < Malicious) and a `ThreatCategory` on `Detection` (Malware, Pup, HackTool, Infostealer, Miner, DefenderTampering, BrowserHijack). PotentiallyUnwanted is never auto-quarantined. Add the new MITRE IDs from X1 to the catalog | Ordering + worst-verdict tests; JSON round-trip with the new values; catalog tests |
| E2 | detection-dev | Third-party YARA rules: curated YARA-Forge subset (infostealer, miner, hacktool/keygen) in `data/rules/third-party/` with licenses/attribution + update script; per-file compile with skip-and-warn; scan-time budget. **YARA-X note:** some legacy YARA rules need small changes to compile under YARA-X (stricter syntax, a few unsupported or renamed features); rules that fail to compile are skipped and listed, and simple ones may be ported with a note in the file | Every vendored file compiles or is reported; rule metadata gives MITRE IDs; timing test on a temp tree. No real samples: test strings only |
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

**Notes from E1/E3/E4 (built `5f0882d`…`4b89f85`).**
- **Verdict model:** `Verdict.PotentiallyUnwanted` (Malicious is now 3) and `ThreatCategory` on Detection. Pup and
  HackTool are never Malicious, and a missing category reads as Malware.
- **Formats:**
  - Alert schema v2: an optional `Category` field; event 1003 is now produced.
  - Scan cache schema v2: v1 rows are dropped at open.
- **VirusTotal:** PUP-like labels now map to PotentiallyUnwanted (this replaces D3 L2). Local PotentiallyUnwanted
  verdicts are looked up in scans too.
- **E3:** the random-name rule (unsigned PE in AppData) and miner name/command-line rules. `MinerRules.AnalyzeCommandLine`
  is public, for E7.
- **E4:** encoded PowerShell is decoded for display. Also: mshta, rundll32 from user folders, and launcher payload
  extraction: rundll32 FileProtocolHandler/ShellExec_RunDLL/…, regsvr32 multi-DLL plus `/i:`, conhost, forfiles,
  pcalua, explorer, msiexec.
- **New MITRE IDs:** the X1 list, plus T1202 and T1218.007 (add them to X1).
- **Closed:** E4 (M4); E4 (M9) partly.
- **Deferred:**
  - **A5 follow-up, before E2 (M2, M3, M7), detection-dev:** not done yet, and it now matters more. The E3 random-name
    rule depends on PE detection, so the M2 dodge (more than 96 sections, a large `e_lfanew`, a section table past 4 KiB)
    gets past it too.
  - **E4 (M9) rest:** certutil and msbuild.
  - **D4/E4 (M10) second half:** an unregistered COM class with an unloaded hive should be Unverified. Needs a flag
    from the collector (engine-dev).
  - **E (L5) / E / D1 (L3):** named streams aren't scanned yet (engine). There is a guard test that `wscript x.txt:a.js`
    is never Clean.
  - **D4 follow-up:** the persistence baseline has no judge-rules version, so unchanged entries aren't re-judged by D4
    after a rules update (Quick and Full Scan do re-judge). Add a rules version to the baseline.
  - **Flaky once:** `ScanBrokerSupervisionTests.Crash_IsNotScanned_WorkerRestarts_AndRepeatOffenderIsSuspicious`
    took 20 s under load.
- **E1/E3/E4 immediate review (no Critical).** Fixed in the fix round: H1 (explorer/msiexec/rundll32 launcher forms
  resolved to the Microsoft binary), M1 (encoded PowerShell alone was Suspicious), L1, L2, L3, L7, L8, L9 (scans look up
  VirusTotal for Suspicious files only, as CLAUDE.md says), and A5 M2/M3/M7 (PE detection, entropy reads, SFX). Remaining:
  - **E2 (M2):** a vendored rule without `verdict` meta defaults to Malicious, so HKTL_/PUA_ rules would be
    auto-quarantined. And `category="hacktool"` on a malware rule would make it never quarantined. When vendoring, map
    categories explicitly (HKTL_/PUA_ → hacktool/pup; implants and backdoors stay malware), with a test listing every
    third-party rule's verdict and category.
  - **E3 (L5):** random-name false positives on unsigned per-user tools (`wkhtmltopdf`, `pngcrush`,
    `vcredist2015x64`). Require two of the three name signals, or exclude known tool folders.
  - **D4 follow-up (L3 rest):** the stored autostart command line, Base64 included, still appears in
    PersistenceBaseline display and monitor logs. Redact it there too.
  - **Decision (2026-11-10):** PowerShell with a hidden window plus an encoded command stays Suspicious (a stronger
    evasion signal than the encoding alone).
  - **Fix round commits:** `49ffe04` (M1, L1–L3, L7–L9), `9fc21f2` (A5 M2/M3/M7 + bidi isolates, `DetectionLogic.Version` 3),
    `3315240` (H1). Open from the fix round:
    - A 16-bit DOS program (MZ, no PE) now scores malformed 20 + unsigned 15; in Downloads with MOTW it reaches 65 (Suspicious).
      Rare, but a new false-positive path: consider no malformed points for a valid DOS stub without `e_lfanew`.
    - Entropy samples the first 16 MiB of merged section data only.
    - msiexec: `TRANSFORMS=` and other property values aren't judged as payloads; ordinal aliases of launcher entries without
      arguments still resolve to the DLL. `msiexec /x {GUID}` is now Unverified (was Clean).
    - Checked: a Run target with a trailing dot (`\\?\C:\Users\...\evil.exe.`) judged Clean only in the ScriptPersistenceTests
      harness, because `FakeAcl` matches folders by exact string. The real code is fine: `FileNameRules.ClassifyFolder` strips
      `\\?\` and the real ACL check asks the file system. Test-only (L): make `FakeAcl` normalize the prefix.
  - **E3 (L6):** miner analysis reads 256 tokens / 32K chars while `MinerScript` reads 64 KB, so padding can hide the
    miner line, and BOM-less UTF-16 scripts are decoded as UTF-8. Heuristic limits; document them.

**Notes from E2 (built `bf000ca`…`03fd7e6`).**
- **Rule set:** YARA-Forge release 20261108 (extended package), 228 curated rules: infostealer 167, miner 10, hacktool 44,
  pup 7.
- **Licenses:** DRL-1.1 115, BSD-2-Clause 91, Apache-2.0 16, MIT 6. Excluded: CC BY-SA (Malpedia, 1647), no license (546),
  GPL (201).
- **Category mapping (closes E1/E3/E4 review M2):** an explicit per-rule table in `curated-rules.txt`. Under `third-party/`
  a missing verdict loads as Suspicious, never Malicious, and a malware-named rule can't be pup or hacktool. Rules with
  hacktool names that detect malware (njRAT/AsyncRAT GUIDs, Cobalt Strike beacons) are left out.
- **Version:** `DetectionLogic.Version` is now 4.
- **Open:**
  - **Engine wiring for `YaraScanBudget` (engine-dev, at E7/C6):** one total budget per scan job (a worker protocol field
    or a reset per job). Until then the worker keeps its 30 s per-file timeout with no total.
  - **Rule seeding never removes old files:** a renamed or removed vendored file stays in
    `%ProgramData%\sap-AV\Rules\third-party` and keeps loading (engine-dev). Fix with a seed manifest.
  - **Coverage:** keygen/crack coverage is thin (few permissive rules). RAT families that come with cracks (AsyncRAT,
    XWorm, njRAT, Remcos, DCRat) aren't included, which is a scope question for later. CC BY-SA stays excluded unless the
    user approves it.
  - **Budget caveat:** parallel scans can overrun the total by one per-file timeout per thread.

**E5 (engine) immediate review (no Critical/High).** Built `d548bea`; M1–M6, L2, L4, L5 fixed in `f5a10e4` (unknown never reads as benign; raw exclusion items; first+last 256 kept with `Truncated` as a signal; `CollectedAsSystem`/`ExclusionsHiddenFromSystem`; read-only registry fallback; `DefenderExpected` on client SKUs; System.Management 11.0.0). For the E5 rules: a stopped Defender service (ServiceNotRunning) gives `DefenderIsActiveAntivirus = null`, so rules must check the read state themselves (ServiceNotRunning or NotInstalled on a client = tamper sign). Remaining:
- **L1:** the read-only guard test is easy to bypass: a `<Using Include="System.Management">` in a csproj, `.Delete(`,
  `dynamic`, MpCmdRun and Defender registry key writes aren't checked. Widen it to all engine files and csproj/props. E11
  needs a reviewed exception anyway.
- **L3:** a hung Defender provider uses up the abandoned-call cap, so the Security Center read also times out. Keep a
  counter per namespace.
- **L6:** the real-Defender test probes through the reader under test, so a reader regression makes it skip instead of
  fail. Probe with a direct query.

**Notes from E5 rules (`e7846db`).** `DefenderRules.Evaluate(snapshot)` is a pure function that returns a
`DefenderAssessment`: findings (DefenderTampering, T1562.001, "you decide"), and an outcome Clean, Unverified,
NotApplicable, Suspicious or Malicious. Unknown inputs give Unverified, never Clean. Open (for E7/E11):
- **E7:** pick a detection source for system-state findings. `ToDetection()` uses `DetectionSource.Heuristic` for now,
  and changing it touches `DetectionSource` and `PipeMapping`. An Unverified outcome marks that scan part as incomplete.
  Findings are never quarantined.
- **E11:** remove exactly the finding's raw item, list and source.
- Policy vs local exclusions aren't told apart, because the registry fallback mixes them.
- Folder writability isn't checked: a custom `D:\Dev` or a user-writable ProgramData subfolder gives no finding. Pass in
  `IPathWritability` later.
- IP exclusions and `BlankItemsDropped` aren't judged.
- **(L) 8.3 matching is worst-case:** `C:\PROGRA~2` (usually Program Files (x86)) reads as ProgramData → Malicious. Resolve
  short names against the real folders when the snapshot is collected, or treat the ambiguity as Suspicious.

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
**G. Signature features (detection-dev, engine-dev, ui-designer)**

The four features that make sap-AV "think like a SOC analyst". They build on E (process events E8, file-read monitor E10,
Remove threat E11) and F (UI). G1 and G2 steps get their own reviewer pass (SYSTEM, ACLs, telemetry), and so do the
Registry-writing G3c and the deleting G2c.

| Step | Owner | Deliverable | Done when (tests) |
|------|-------|-------------|-------------------|
| G1a | detection-dev | **Honeytoken design:** decoy set (fake browser-profile folder with decoy `Login Data` / `Cookies` / `Local State`, Exodus/Electrum-style wallet folder, Discord `Local Storage\leveldb` token file, `passwords.txt`). Values are generated per machine and obviously fake (reserved test domains such as `example.com`, invalid card/wallet checksums), never derived from real data. Allowlist of expected readers (sap-AV itself, Defender `MsMpEng.exe`, Windows Search, known backup agents) by signer + path. A read by anyone else → Malicious infostealer, T1555.003 (browser stores) / T1552.001 (token/password files) | Generation is deterministic per seed and never contains real-looking secrets; allowlist + rule tests on synthetic read events |
| G1b | engine-dev | **Honeytoken planting + trap (immediate review):** the SYSTEM service plants decoys, then: hidden + `NOT_CONTENT_INDEXED`; owned by SYSTEM, with the user allowed to *read* (a stealer running as the user must be able to open them) but not write/delete; excluded from sap-AV's own scans; recreated if deleted or changed. Locations avoid OneDrive/cloud-synced folders, and real browser data is never modified (no edits to real profiles or `Local State`). Read detection via the E10 ETW file-read monitor (primary); file SACL auditing only as an option (see Decisions). Setting: on/off (off removes all decoys) | Plant → read by a test process → alert; read by an allowlisted reader → no alert; delete → recreated; turning it off removes every decoy; the real profile folder is byte-identical before/after (test on a fake profile tree) |
| G2a | engine-dev + detection-dev | **Telemetry prerequisites (immediate review):** process monitoring moves from Phase 2 #6 into Phase 1. engine-dev: per-process network connections (ETW TCP/IP events, or `GetExtendedTcpTable` polling with owning PID as a fallback) joined with the E8 process start/stop stream. detection-dev: the suspicious parent-child chain rules (Office/Outlook → powershell/cmd/wscript/cscript/mshta, T1566.001 + T1059.x) | Fake feed tests; one integration test where a harmless child process opens a loopback connection and both show up with the right PID/parent |
| G2b | engine-dev | **Attack Story correlation (immediate review):** groups events into one incident per root cause: download (MOTW URL) → process start (parent/child) → persistence created → Defender tampering → honeytoken/credential access → network connections. Each step has a MITRE ID and a plain-language sentence. Incident store in `%ProgramData%\sap-AV\` (SQLite); export as JSON and as a readable report (HTML) | Synthetic event sequences produce the expected single story; unrelated events stay out; JSON round-trip; report contains every step in order |
| G2c | engine-dev | **Story-wide "Remove threat" (immediate review):** extends E11 to every process, file and persistence entry in the story, using one remediation record with grouped undo and the same confirm-first rules | Remove → undo round-trip on a synthetic story (HKCU test keys, temp files, fake processes); partial failure reported, earlier steps stay undoable |
| G2d | ui-designer | Attack Story timeline view: ordered steps, MITRE tags, plain-language text, export buttons, "Remove threat" for the whole story | View-model tests with a fake pipe |
| G3a | detection-dev | **Pre-Flight static analyzer.** NEVER executes the file and never extracts archives to disk. It covers signature (A3), VirusTotal hash (D2), entropy/packer (A5), PE imports → capabilities via `System.Reflection.PortableExecutable` (anti-debug T1622, injection T1055, keylogging T1056.001, credential access T1555, Defender tampering T1562.001), embedded URLs/IPs/domains (strings scan), and archive listing (zip via `System.IO.Compression`, names/sizes only, with path-traversal names flagged and size/ratio/entry-count limits against zip bombs) | Synthetic PE/zip fixtures built at test time; each capability with a positive + negative case; zip-bomb and `..\` entry tests; no process is ever started |
| G3b | detection-dev | **Risk score 0–100** from the G3a findings, with plain-language reasons and MITRE IDs; documented weights | Score ordering tests (clean signed < unsigned packed < unsigned packed + injection imports) |
| G3c | ui-designer | Pre-Flight UI: drag-and-drop onto the window + Explorer verb "Check before you run" (with F3's registry verb, immediate review); report view with score, reasons, MITRE | View-model tests; verb register/unregister under HKCU |
| G4a | detection-dev | **Exposure inventory:** after an infostealer verdict or a honeytoken read, list what was *likely* exposed by checking which stores exist on the machine (browser profiles with saved-password/cookie files, Discord, Steam, crypto wallets). Presence only: real databases are never opened or read. Recovery checklist data in `data/` with each service's official security page URL (verified, with source) | Inventory on a fake profile tree; wording always says "likely exposed"; every checklist URL is https and on the service's own domain |
| G4b | ui-designer | Exposure Report + guided recovery checklist: change passwords **from another device**, revoke all sessions, enable 2FA, move crypto funds; links open the official pages | View-model tests; the checklist order and the "another device" warning are always shown |
| G5 | reviewer | **Phase 1 security review:** a full security review of the whole codebase (privilege boundaries, the pipe, path handling, quarantine/remediation/deletion, Registry and Defender writes, honeytoken ACLs, telemetry, VirusTotal key handling, dependencies). Critical/High fixed before Phase 1 is called done | Review report with no open Critical/High |

---

## Phase 2

| # | Feature | Owner | Notes |
|---|---------|-------|-------|
| 6 | ~~Process monitoring + suspicious parent-child chains~~ **moved to Phase 1** | detection-dev (chain rules), engine-dev | Now Phase 1: the event source is E8, and the chain rules + network telemetry are G2a (prerequisite for the Attack Story). e.g. Word/Excel/Outlook → powershell/cmd/wscript/cscript/mshta. MITRE T1059.x / T1566.001 |
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
| Oversized executable padded to dodge the scan size limit (A5) | T1027.001 |
| Right-to-left override character in the file name (A5) | T1036.002 |
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
| Honeytoken read: decoy browser credential/cookie store | T1555.003 |
| Honeytoken read: decoy token / `passwords.txt` / wallet file | T1552.001 |
| Pre-Flight capabilities: anti-debug / injection / keylogging / credential access / Defender tampering | T1622 / T1055 / T1056.001 / T1555 / T1562.001 |
| Attack Story: outbound connection by a story process | T1071 (Application Layer Protocol) |

YARA rules may override with their own `mitre` meta value.

### X2. Windows Event Log (engine-dev)
- Every alert is written to a **dedicated event log named "sap-AV"** (source "sap-AV"), not the Application log. Its
  CustomSD lets only SYSTEM (and the elevated installer) write; readers are Administrators and Event Log Readers.
  Registered by the service installer (needs admin; the service runs as LocalSystem). Decided 2026-10-24, built in B6.
  (Built in B6: `6f44479`, `f28b0d1`. CustomSD `O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)`; 20 MB, overwrite
  as needed. An unmigrated Application-log source is skipped with a health warning, never written to.)
- Structured payload (JSON in the message, stable field names) for SIEM collection: timestamp, alert type, verdict, file path,
  SHA-256, signer, MITRE ID, reason(s), MOTW URL, action taken.
- Fixed event IDs per alert type (defined in B1, `src/SapAV.Engine/Alerts/AlertEventCatalog.cs`):

  | Event ID | Alert type | Entry type | Meaning |
  |---|---|---|---|
  | 1001 | MaliciousFile | Error | File with a Malicious verdict |
  | 1002 | SuspiciousFile | Warning | File with a Suspicious verdict |
  | 1003 | PotentiallyUnwantedFile | Warning | PUP / hack tool (section E) |
  | 2001 | MaliciousPersistence | Error | Autostart entry whose target is Malicious (C3) |
  | 2002 | SuspiciousPersistence | Warning | Suspicious autostart entry (C3 rules) |
  | 3001 | QuarantineRestored | Information | User restored an item from quarantine (B2) |
  | 3002 | PersistenceBlocked | Information | User's Block & remove of an autostart entry, backed up first (D5) |
  | 3003 | PersistenceRestored | Information | User restored an autostart entry from its D5 backup |
  | 9001 | AlertsSuppressed | Warning | Summary of alerts held back by aggregation/rate limits (B3) |
  | 9002 | AutoQuarantineBurst | Warning | Auto-quarantine rate limit hit (B3) |
  | 9003 | ScanRulesDegraded | Warning | Zero rules loaded, rule-file errors or a failed rule load (B3; counts only, no worker text) |
  | 9004 | QuarantineStoreFull | Error | Quarantine store over quota or below the free-space floor (B3) |
  | 9005 | QuarantineStoreUnavailable | Error | Quarantine store can't be opened (retried with backoff) (section B) |
  | 9006 | SandboxUnavailable | Error | No scan worker can start or load rules (section B) |
  | 9007 | PipeUnavailable | Error | The pipe name is taken or the server can't listen (section B) |
  | 9008 | EngineFolderUntrusted | Warning | An engine folder failed its ownership/ACL check, so it is scanned, not excluded (section B) |
  | 9009 | EventLogIntegrityDegraded | Error | The `sap-AV` log's CustomSD or message DLL location changed (section B) |
  | 9010 | RealTimeUnavailable | Error | Real-time file monitoring can't start, a thread failed, or no folder can be watched (section D review M4) |
  | 9011 | PersistenceMonitorUnavailable | Error | Persistence monitoring can't start, its thread failed, or its protected baseline store was refused (section D review M4) |

  `AlertAction.NeedsUserConfirmation` (B3) marks a Malicious file that auto-quarantine refused (protected location,
  SYSTEM/TrustedInstaller owner, or unknown owner).

  Reserved ranges: 1000–1999 file detections · 2000–2999 system-change detections (persistence, Defender tampering,
  honeytokens, process chains) · 3000–3999 user/remediation actions · 9000–9999 engine health. The engine's own ILogger
  output uses a different source, so these IDs only ever mean alerts.
- The source is registered only by `SapAV.Engine --install-eventlog-source` (elevated, from the installer path). Normal
  startup never registers it. If it's missing, alerts are skipped with one warning and re-checked every 5 minutes.

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
- **New dependencies for the threat pack (E):** **approved by the user on 2026-11-11** (all three, latest stable versions,
  pinned):
  - `Microsoft.Diagnostics.Tracing.TraceEvent`, for ETW process and file-read events (E8, E10);
  - `System.Management`, for WMI: Defender, process command lines (E5, E7);
  - `System.Diagnostics.PerformanceCounter`, for CPU/GPU counters (E9).
- **YARA-Forge licensing:** the repo is public. Vendored rules must keep their per-rule licenses, and any rule whose license
  doesn't allow redistribution is left out (or downloaded by the update script instead of committed). **Decided
  (user, 2026-11-11):** permissive only. Commit rules under DRL 1.1, MIT, Apache-2.0, BSD, CC0 or CC-BY, keeping author and
  license. Leave out GPL, non-commercial (NC) and unlicensed rules; nothing is downloaded at runtime.
- **Honeytoken read detection (G1b):** the primary method is ETW file-read events (E10, needs TraceEvent). File SACL auditing
  would also need the system-wide "Audit File System" policy turned on (`auditpol`), which changes the machine's security
  policy and fills the Security log. Offer it only as an opt-in setting, or drop it. Decide at G1b.
- **Archive formats for Pre-Flight (G3a):** zip is built in. rar/7z listing needs a new package (e.g. SharpCompress).
  Decide at G3a; zip only until then.
- **Locked files on another volume:** a reboot-time move can't cross volumes. The options are a per-volume quarantine folder,
  or a reboot-time delete after an extra confirmation. Decide at E12.

Deferred:
- **MalwareBazaar** is dropped from Phase 1 (VirusTotal only); can come back later as a second lookup source.
- **Windows 11 top-level context menu** (sparse MSIX + `IExplorerCommand`); Phase 1 uses "Show more options".
