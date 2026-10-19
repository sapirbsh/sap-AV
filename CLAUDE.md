# Project: sap-AV — Real-Time Antivirus for Windows

sap-AV is a learning / portfolio project: a real-time antivirus for Windows 10/11 with a modern, good-looking GUI.
The code is public on GitHub. Product name in the UI: "sap-AV".

## Visual identity
- Dark graphite gray + purple. Dark theme is the product's identity (light theme is not required).
- Full palette and design rules: see `.claude/agents/ui-designer.md`.

## Tech stack
- Language: C# on .NET 10 (LTS) — target framework net10.0-windows for SapAV.App, net10.0 for everything else (Core, Engine, tests)
- SDK pinned by `global.json` (10.0.103, rollForward latestFeature), so builds never pick up an older installed SDK
- GUI: WPF + the WPF-UI library (NuGet: `WPF-UI`) for a modern Fluent look, customized to the sap-AV dark gray + purple theme
- Engine: .NET Worker Service that runs as a Windows Service
- Engine <-> GUI communication: Named Pipes (JSON messages)
- Hashing: `System.Security.Cryptography.SHA256`
- YARA: `dnYara` + `dnYara.NativePack` (bundles native libyara.dll)
- Tests: xUnit

## Solution layout
```
SapAV.sln
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

## Detection pipeline (order matters)
1. New / changed file detected by FileSystemWatcher
2. Wait until the file is no longer locked (it may still be downloading)
3. SHA-256 -> check local hash blocklist
4. (Optional, if enabled in settings) Online hash lookup: MalwareBazaar / VirusTotal
5. YARA rules
6. Heuristics: entropy, double extension (e.g. `.pdf.exe`), executable in Temp/Downloads
7. Verdict: Clean / Suspicious / Malicious -> log -> quarantine if Malicious -> notify GUI

## Rules for everyone (main session and all agents)
- NEVER write, download, or commit real malware. Testing uses only the EICAR test string.
- The EICAR file is generated at test time into a temp folder. Never commit it to the repo.
- NEVER commit API keys. Keys live in .NET User Secrets or environment variables.
- Quarantine must be reversible: move + rename + strip execute ability, keep metadata to restore.
- Never delete user files automatically.
- Performance matters: scanning must not freeze the PC. Use a queue, async I/O, and skip huge files by size limit.
- Every feature gets tests before it's considered done.
- Small, focused commits with clear messages.

## Commands
- Build: `dotnet build`
- Test: `dotnet test`
- Run GUI: `dotnet run --project src/SapAV.App`
- Run engine (console mode for debugging): `dotnet run --project src/SapAV.Engine`

## Agents in this project
- engine-dev: file monitoring, scan queue, quarantine, Windows Service, pipes
- detection-dev: hashing, hash DB, online lookups, YARA, heuristics
- ui-designer: WPF GUI and visual design
- tester: writes and runs tests
- reviewer: read-only code review (bugs, performance, security)

Workflow: the main session plans and builds the skeleton, then delegates.
After any agent changes code -> tester -> reviewer -> fix.
