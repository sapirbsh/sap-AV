# Project: sap-AV — Real-Time Antivirus for Windows

sap-AV is a learning / portfolio project: a real-time antivirus for Windows 10/11 with a modern, good-looking GUI.
The code is public on GitHub. Product name in the UI: "sap-AV".

## Visual identity
- Dark graphite gray + purple. Dark theme is the product's identity (light theme is not required).
- Full palette and design rules: see `.claude/agents/ui-designer.md`.

## Tech stack
- Language: C# on .NET 10 (LTS) — every project (App, Core, Engine, tests) targets net10.0-windows
  (since A3; Windows-only APIs: Authenticode, Registry, ADS, Event Log)
- SDK pinned by `global.json` (10.0.103, rollForward latestFeature), so builds never pick up an older installed SDK
- GUI: WPF + the WPF-UI library (NuGet: `WPF-UI`) for a modern Fluent look, customized to the sap-AV dark gray + purple theme
- Engine: .NET Worker Service that runs as a Windows Service
- Engine <-> GUI communication: Named Pipes (JSON messages)
- Hashing: `System.Security.Cryptography.SHA256`
- YARA: `dnYara` + `dnYara.NativePack` (bundles native libyara.dll)
- Signature check: Authenticode via `WinVerifyTrust` (P/Invoke), including catalog-signed files
- Online lookup: VirusTotal API v3 (hash lookup only)
- Local caches (VirusTotal results, scan cache): SQLite via `Microsoft.Data.Sqlite` (approved; added at step C5 / D2)
- Alert output: Windows Event Log, source "sap-AV" (structured data for SIEM)
- Threat mapping: MITRE ATT&CK technique ID on every alert
- Threat pack (planned, ROADMAP section E; packages need approval first): ETW via `Microsoft.Diagnostics.Tracing.TraceEvent`
  (process + file-read events), WMI via `System.Management` (Defender status/exclusions, process command lines),
  `System.Diagnostics.PerformanceCounter` (CPU/GPU), curated YARA-Forge rules in `data/rules/third-party/`
- Tests: xUnit

## Solution layout
```
SapAV.sln
ROADMAP.md           Feature plan, owners, and build order
global.json          Pins the .NET SDK version
Directory.Build.props  Shared MSBuild settings (suppresses MSB3246 from dnYara.NativePack's native DLL)
src/
  SapAV.Core/        Shared models, scan logic, hash DB, YARA, heuristics (no UI, no service code)
  SapAV.Engine/      Windows Service: FileSystemWatcher, scan queue, quarantine, pipe server
  SapAV.App/         WPF GUI: dashboard, scan screen, quarantine, settings, pipe client
tests/
  SapAV.Core.Tests/
  SapAV.Engine.Tests/
data/
  hashes/         Local SHA-256 blocklist (one hash per line)
  rules/          YARA rules (*.yar); third-party/ = vendored YARA-Forge subset with licenses (planned, E2)
```

## Features
Full plan, owners, and build order: see `ROADMAP.md`. Summary:
- Phase 1 (MVP): Quick / Full / Custom scan (+ Explorer "Scan with sap-AV") and a results screen; local detection engine
  (blocklist, Authenticode, YARA, heuristics); VirusTotal hash lookup; Mark-of-the-Web; real-time persistence monitoring;
  cracked-software threat pack. The pack covers:
  - infostealers, cryptominers, Defender tampering, script-based persistence and browser hijack
  - a PUP / HackTool category
  - user-confirmed "Remove threat", "Delete permanently" and reboot-time actions for locked files
  It is included in Quick and Full Scan.
- Phase 2: process parent-child monitoring, ransomware canary files, USB auto-scan, hosts file monitoring, scheduled scans.
- Cross-cutting: every alert has a MITRE ATT&CK technique ID and is written to the Windows Event Log (source "sap-AV").

## Detection pipeline (order matters)
1. Trigger: FileSystemWatcher (real-time), a scan job (Quick / Full / Custom), or a persistence entry (its target exe is scanned)
2. Real-time: wait until the file is no longer locked (it may still be downloading). Skip files over the size limit.
3. Scans: skip if unchanged since the last scan (cache: path + size + last-write time + hash)
4. SHA-256 -> local hash blocklist. A match is Malicious even if the file is signed.
5. Authenticode:
   - Signed by Microsoft (embedded or Windows catalog signature) -> Clean, skip steps 6-8. Decided by thumbprints, not name:
     a Microsoft product root AND a Microsoft first-party issuing CA. Third-party content Microsoft signs (WHQL drivers,
     Store apps, Trusted Signing / "ID Verified" customers) counts as OtherTrusted.
   - Other valid trusted signature -> skip step 8 (VirusTotal) only; YARA and heuristics still run
6. YARA rules
7. Heuristics: entropy, double extension (e.g. `.pdf.exe`), executable in Temp/Downloads/AppData, Mark-of-the-Web (internet origin)
8. (Optional, if enabled + API key set) VirusTotal hash lookup, unsigned files only, cache first, rate-limited:
   real-time = new files in watched folders with risky extensions; scans = only Suspicious files
9. Verdict: Clean / Suspicious / PotentiallyUnwanted (PUP / HackTool, planned in E1) / Malicious + reason + MITRE ID
   -> log + Event Log -> quarantine if Malicious (never PotentiallyUnwanted: the user decides) -> notify GUI

Scans and real-time monitors also produce findings that aren't about a single file: persistence entries, Defender
exclusions/status, proxy/hosts changes, process behaviour (miners, credential-store reads). These follow the same
verdict + reason + MITRE + Event Log path.

## Rules for everyone (main session and all agents)
- NEVER write, download, or commit real malware. Testing uses only the EICAR test string. This includes infostealers,
  miners and cracks: threat-pack tests use synthetic data, fake event feeds and fake store files only. Third-party
  YARA rules are allowed (rules only, never samples), with their licenses and attribution kept.
- Tests NEVER change the real Microsoft Defender configuration; Defender access goes through an interface that is faked in tests.
- The EICAR file is generated at test time into a temp folder. Never commit it to the repo.
- NEVER commit API keys. For end users, keys live in local settings on their machine (`%ProgramData%\sap-AV\`, DPAPI-encrypted);
  for development, .NET User Secrets or environment variables.
- `%ProgramData%\sap-AV\` (settings, VT cache, scan cache) has inheritance disabled and an ACL limited to SYSTEM and Administrators.
  The GUI never touches it directly; it sends settings to the engine over the pipe, and the engine never sends the API key back.
- VirusTotal: send only the SHA-256, never the file. Uploading a file happens only when the user clicks the manual upload button.
  Respect the rate limit (4 requests/minute, 500/day). Tests use a fake HTTP handler, never the real API.
- Quarantine must be reversible: move + rename + strip execute ability, keep metadata to restore.
- Never delete user files automatically. Persistence entries are removed only when the user clicks "Block & remove",
  and always backed up first so they can be restored (services are disabled, not deleted).
- "Remove threat" (kill process, remove persistence, quarantine, remove flagged Defender exclusions) runs only after the user
  confirms a list of planned changes. Every change is recorded in one remediation record that can be undone; killing the
  process is the only step that can't be undone.
- The only permanent deletion is "Delete permanently" on the quarantine screen, with double confirmation. Locked files get a
  reboot-time action: prefer a reboot-time move into quarantine, and delete at reboot only for "Delete permanently".
- PUP / HackTool findings are never quarantined automatically.
- Every alert gets a MITRE ATT&CK technique ID and is written to the Windows Event Log (source "sap-AV").
- Performance matters: scanning must not freeze the PC. Use a queue, async I/O, background (low) CPU/IO priority for scan threads,
  and skip huge files by size limit.
- Every feature gets tests before it's considered done. Tests are focused, not exhaustive:
  - cover the main behavior, the important failure cases, and every security-relevant edge case;
  - no near-duplicate or combinatorial variations (3-4 representative inputs, not 20);
  - aim for 10-30 new tests per step; more only for security-critical code;
  - tests that depend on software or certificates on this PC must skip cleanly elsewhere (`[RequiresFact]`/`[RequiresTheory]`;
    check with `SAPAV_TEST_SIMULATE_CLEAN_MACHINE=1 dotnet test`);
  - keep the existing tests.
- Small, focused commits with clear messages.

## Commands
- Build: `dotnet build`
- Test: `dotnet test`
- Run GUI: `dotnet run --project src/SapAV.App`
- Run engine (console mode for debugging): `dotnet run --project src/SapAV.Engine`

## Agents in this project
- engine-dev: file monitoring, scan queue and scan modes (Quick / Full / Custom, scan cache, priority), persistence collectors
  and real-time persistence monitoring, quarantine and "block & remove", Event Log, Windows Service, pipes; threat pack:
  Defender/proxy/hosts collectors, ETW process and file-read events, CPU/GPU monitors, "Remove threat", delete permanently,
  reboot-time actions
- detection-dev: hashing, hash DB, Authenticode, YARA, heuristics, Mark-of-the-Web, VirusTotal client + cache + rate limiter,
  persistence-entry judgement, MITRE mapping; threat pack: PUP/HackTool category, YARA-Forge rules, infostealer/miner/
  Defender/script-persistence/browser-hijack rules
- ui-designer: WPF GUI and visual design, scan and results screens, settings, alerts, Explorer context menu; threat pack:
  PUP/HackTool display, "Remove threat" flow and undo, quarantine "Delete permanently", pending reboot actions, idle-state reporting
- tester: section-level test pass (gaps, portability, flakiness) — model: sonnet
- reviewer: read-only code review (bugs, performance, security), per section and for privileged steps — model: opus
- Models: detection-dev, engine-dev, reviewer = opus; tester, ui-designer = sonnet (set in `.claude/agents/*.md`)

Workflow (details in ROADMAP.md "Workflow"):
- The main session plans and delegates each step to its owning agent. That agent writes and runs its own tests;
  the step is committed when they pass with 0 warnings.
- At the end of each section (A–F): one tester pass + one reviewer pass over the whole section, then fix until clean.
- Immediate reviewer pass right after any step that runs privileged code as SYSTEM, touches quarantine, writes/removes
  Registry entries, deletes files, or touches the pipe (the list is in ROADMAP.md).
- Review fixes: fix Critical and High findings. Medium/Low findings are listed in ROADMAP.md under the step they belong to,
  instead of extra review rounds.
- Small related steps are built in one batch by one agent (e.g. A4–A7), with one commit per step where practical.
- Machine-dependent tests (certificates, installed software, Developer Mode, SMB loopback) must skip cleanly, so the
  suite passes on a clean machine and GitHub Actions `windows-latest` (CI runs `dotnet build` + `dotnet test` on every push).

Autonomy:
- Continue from step to step without waiting for the user.
- Stop only for: a Critical security finding that can't be fixed safely, a decision that needs the user (new package,
  licensing, deviation from an approved rule), or a failing build that can't be fixed after 3 attempts.
- After each section, write a short summary to `PROGRESS.md`: what was built, what's left, open issues.
