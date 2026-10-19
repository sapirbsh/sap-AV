# Project: sap-AV — Real-Time Antivirus for Windows

sap-AV is a learning / portfolio project: a real-time antivirus for Windows 10/11 with a modern, good-looking GUI.
The code is public on GitHub. Product name in the UI: "sap-AV".

## Visual identity
- Dark graphite gray + purple. Dark theme is the product's identity (light theme is not required).
- Full palette and design rules: see `.claude/agents/ui-designer.md`.

## Tech stack
- Language: C# on .NET 10 (LTS) — target framework net10.0-windows for SapAV.App; Core, Engine and tests are net10.0 today
  and switch to net10.0-windows at ROADMAP step A3 (approved — Windows-only APIs: Authenticode, Registry, ADS, Event Log)
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
  rules/          YARA rules (*.yar)
```

## Features
Full plan, owners, and build order: see `ROADMAP.md`. Summary:
- Phase 1 (MVP): Quick / Full / Custom scan (+ Explorer "Scan with sap-AV") and a results screen; local detection engine
  (blocklist, Authenticode, YARA, heuristics); VirusTotal hash lookup; Mark-of-the-Web; real-time persistence monitoring.
- Phase 2: process parent-child monitoring, ransomware canary files, USB auto-scan, hosts file monitoring, scheduled scans.
- Cross-cutting: every alert has a MITRE ATT&CK technique ID and is written to the Windows Event Log (source "sap-AV").

## Detection pipeline (order matters)
1. Trigger: FileSystemWatcher (real-time), a scan job (Quick / Full / Custom), or a persistence entry (its target exe is scanned)
2. Real-time: wait until the file is no longer locked (it may still be downloading). Skip files over the size limit.
3. Scans: skip if unchanged since the last scan (cache: path + size + last-write time + hash)
4. SHA-256 -> local hash blocklist. A match is Malicious even if the file is signed.
5. Authenticode:
   - Signed by Microsoft (embedded or Windows catalog signature; decided by Microsoft root thumbprint, not name) -> Clean, skip steps 6-8
   - Other valid trusted signature -> skip step 8 (VirusTotal) only; YARA and heuristics still run
6. YARA rules
7. Heuristics: entropy, double extension (e.g. `.pdf.exe`), executable in Temp/Downloads/AppData, Mark-of-the-Web (internet origin)
8. (Optional, if enabled + API key set) VirusTotal hash lookup, unsigned files only, cache first, rate-limited:
   real-time = new files in watched folders with risky extensions; scans = only Suspicious files
9. Verdict: Clean / Suspicious / Malicious + reason + MITRE ID -> log + Event Log -> quarantine if Malicious -> notify GUI

## Rules for everyone (main session and all agents)
- NEVER write, download, or commit real malware. Testing uses only the EICAR test string.
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
- Every alert gets a MITRE ATT&CK technique ID and is written to the Windows Event Log (source "sap-AV").
- Performance matters: scanning must not freeze the PC. Use a queue, async I/O, background (low) CPU/IO priority for scan threads,
  and skip huge files by size limit.
- Every feature gets tests before it's considered done.
- Small, focused commits with clear messages.

## Commands
- Build: `dotnet build`
- Test: `dotnet test`
- Run GUI: `dotnet run --project src/SapAV.App`
- Run engine (console mode for debugging): `dotnet run --project src/SapAV.Engine`

## Agents in this project
- engine-dev: file monitoring, scan queue and scan modes (Quick / Full / Custom, scan cache, priority), persistence collectors
  and real-time persistence monitoring, quarantine and "block & remove", Event Log, Windows Service, pipes
- detection-dev: hashing, hash DB, Authenticode, YARA, heuristics, Mark-of-the-Web, VirusTotal client + cache + rate limiter,
  persistence-entry judgement, MITRE mapping
- ui-designer: WPF GUI and visual design, scan and results screens, settings, alerts, Explorer context menu
- tester: writes and runs tests
- reviewer: read-only code review (bugs, performance, security)

Workflow: the main session plans and builds the skeleton, then delegates.
After any agent changes code -> tester -> reviewer -> fix.
