# sap-AV Progress

Updated after each ROADMAP section (see `ROADMAP.md` for the full plan and the open items under each step).

## Overview

| Section | Status |
|---|---|
| A — Detection engine | **Done** (A1–A7, section test + review, High fixes) |
| B — Engine infrastructure (incl. B5 scan-worker sandbox) | **Done** (B1–B6, section test + review, High fixes) |
| C — Scan modes | **In progress:** C1 starting |
| D — Real-time + VirusTotal | Not started |
| E — Cracked-software threat pack | Not started |
| F — UI | Not started |
| G — Signature features (Honeytokens, Attack Story, Pre-Flight, Exposure Report) + G5 Phase 1 security review | Not started |

Tests (after section B): Core 1179 passed + 1 skipped, Engine 353 passed + 8 skipped. Simulated clean machine: 0 failed.
Build: 0 warnings (Debug and Release). CI on windows-latest: green up to section B (check the run for `92ce762`).

## Section A — Detection engine (done)

**What was built** (all in `SapAV.Core`, `net10.0-windows`)
- **A1 — Models + MITRE:** `ScanItem`, `Detection`, `ScanResult` (verdict derived; a skipped file has no verdict, never
  Clean), `ScanStatus`, strict JSON (exact enum names, required fields), MITRE technique catalog.
- **A2 — Hashing + blocklist:** streaming SHA-256 with a size limit, on a hardened open path: device paths rejected,
  anonymous impersonation towards pipes, no cloud recall, disk-file check before any read. Hash blocklist with limits
  and a fingerprint.
- **A3 — Authenticode:** embedded + catalog signatures, no network. Microsoft = Microsoft product root **and** a
  first-party issuing CA (by thumbprint); WHQL / Store / Trusted Signing → OtherTrusted.
- **A4 — YARA-X:** switched from libyara 4.1.1 to **YARA-X v1.22.0** (official C API, downloaded at build time and
  SHA-256-pinned). Per-file compilation, import allowlist (`pe`, `math`, `hash`), memory-mapped scans only on local fixed
  disks (buffered elsewhere), safe rule swapping, timeouts, MITRE warnings.
- **A5 — Heuristics:** double extension, right-to-left override, PE section entropy, padded oversized files, broken/missing
  signature, risky folders, internet origin. Can only make a file Suspicious.
- **A6 — Mark-of-the-Web:** zone + source URL, read relative to the file handle, URLs sanitized.
- **A7 — FileScanner:** the full pipeline in the agreed order, on **one handle** for every step. Writers are denied, with a
  USN-journal check as the fallback, so a file can't be swapped between steps.
- **Section test pass:** end-to-end tests with the real components (EICAR in memory, Microsoft-signed binary, double
  extension, locked/oversized/device paths, parallel scans during a rule swap).

**Review**
- Section A review: no Critical, 3 High: H1 file swap between steps, H2 YARA-X crash safety on mapped views,
  H3 YARA module allowlist. All three are fixed.
- 13 Medium/Low findings are recorded in `ROADMAP.md` under the step they belong to
  (A5, A7, B1, B3, B5, C6, D1, D2, D3, E2).

**Open issues carried forward**
- A Rust panic or a native crash inside YARA-X still takes down the process until **B5** (scan-worker sandbox) lands.
- USN fallback gap: a writer that already holds the file open can, in rare cases, change it without a new journal record.
  D1 and B5 reduce this.
- CI on GitHub `windows-latest` is green (runs 1–16, confirmed by the user), including the `cmd.exe` Microsoft-signature test.
- Heuristic thresholds were tested on synthetic PE files only; tune them on real software (A5 follow-up).

## Section B — Engine infrastructure (done)

**Order built:** B1 → B2 → B5 → B3 → B4 → B6, then the section tester + reviewer pass.

| Step | What | Status |
|---|---|---|
| B1 | Alert model + Windows Event Log writer, `Reason` cap, SIEM-safe URLs | **Done** (`6b0e586`; review: 2 High fixed `80f29a9`) |
| B2 | Reversible quarantine | **Done** (`08fe657`; review: **Critical C1** fixed `66b91bb`, follow-up review clean) |
| B5 | Sandboxed scan worker (AppContainer, Job Object, brokered read-only handles) | **Done** (`b21a8fb`…`006ac72`; review H1 fixed and confirmed) |
| B3 | Scan jobs (queue, pause/resume/cancel, ETA, alert dispatcher, auto-quarantine policy) | **Done** (`4523493`…`ba20903`; review H1 fixed) |
| B4 | Named pipe engine ↔ GUI (identity, authorization, caps, client library) | **Done** (`009d580`…`88bac75`; review: 3 High fixed) |
| B6 | Dedicated `sap-AV` event log only SYSTEM + Administrators can write | **Done** (`6f44479`, `f28b0d1`; review clean) |

**What was built**
- **Alerts:** structured JSON alerts in a dedicated `sap-AV` event log that normal users can't write. They are aggregated
  and rate-limited, Malicious alerts are never dropped, and health alerts 9001–9009 cover suppression, store full,
  sandbox/pipe/store unavailable, untrusted engine folders and a widened log.
- **Quarantine:** reversible, scrambled storage with signed metadata, bound to the exact file that was scanned (by file ID).
  Restore never follows links or overwrites, and crash recovery leaves either the original or the stored copy intact.
- **Sandbox:** the SYSTEM engine never parses file contents. A Low-integrity AppContainer worker with no network and
  Job Object limits does all parsing on read-only handles; crashes, hangs and kept handle copies are detected.
- **Scan jobs:** low-priority dedicated threads and a handle-bound folder walk with exact names (trailing dots/spaces).
  Files open without following links. Auto-quarantine refuses system/protected files, user scans can't block admin or
  engine scans, and paused or abandoned jobs time out.
- **Pipe:** `\.\pipe\ProtectedPrefix\Administrators\sap-AV.engine`, identity from the pipe, strict 64 KiB JSON frames.
  Users can only scan what they can read, only see their own jobs, and need delete/write rights to quarantine or restore.
  The engine survives connection floods and always holds the pipe name.
- **Resilience:** one failing component never stops the engine; the store retries, and health alerts report problems.
- **Engine data folder:** `%ProgramData%\sap-AV` is created with a SYSTEM + Administrators ACL. Only verified engine
  subfolders are excluded from scanning.

**Section review:** the tester pass (`a39440b`) added end-to-end tests through the real pipe → sandboxed worker →
auto-quarantine → restore. The cross-step reviewer pass found 3 High (user-writable `%ProgramData%\sap-AV`, link-following
file opens in admin jobs, one user blocking all scans), all fixed (`06fccf1`, `369c037`, `c6b3f5f`, `92ce762`).
All Medium/Low findings are recorded in `ROADMAP.md` under the step they belong to.

**Tests after section B:** Core 1179 passed + 1 skipped, Engine 353 passed + 8 skipped; 0 failures on the simulated clean
machine; 0 build warnings.

**Open items carried forward**
- **To confirm on CI (elevated):** creating the pipe under `ProtectedPrefix\Administrators` as an elevated engine, with a
  standard user still able to connect. The test only runs elevated, so the next CI run is the real check. If it fails,
  the pipe-name fallback needs a decision.
- Admin-configured `ScanJobs:ExcludedFolders` are honoured without the ownership check (an admin setting).
- A non-elevated dev console run sees its own bin folder as unverified, so it scans it and raises health alert 9008.

## Current status (2026-10-25)

**Section B is done.** **Now:** section C (scan modes), starting with C1 (Custom Scan).

**Open for the user**
- In an **elevated** PowerShell in `C:\Projects\sap-AV`, run
  `$env:SAPAV_TEST_ALLOW_HKLM='1'; dotnet test tests/SapAV.Engine.Tests --filter "FullyQualifiedName~RealEventLogTests"`.
  It is the only check of the real Event Log service behaviour (CustomSD honoured, a filtered token refused, plus a
  positive control). It cleans up after itself (only a throwaway .evtx file and a "log cleared" record remain).
- Check the GitHub **Actions** run for `92ce762`: it is the first CI run of the elevated ProtectedPrefix pipe tests.
- Optional: delete the ~212 old empty folders in `%TEMP%\sapav-tests` (from Oct 19 and 22).

## What's left

- **C:** C1 Custom Scan → C2+C3 persistence collectors/judgement → C4 Quick Scan → C5+C6 scan cache + Full Scan,
  then the section C tester + reviewer pass.
- Then D → E → F → G, ending with the Phase 1 security review (G5).
