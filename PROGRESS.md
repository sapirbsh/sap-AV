# sap-AV Progress

Updated after each ROADMAP section (see `ROADMAP.md` for the full plan and the open items under each step).

## Overview

| Section | Status |
|---|---|
| A — Detection engine | **Done** (A1–A7, section test + review, High fixes) |
| B — Engine infrastructure (incl. B5 scan-worker sandbox) | **In progress:** B1 + B2 done, B5 done, B3 done, B4 built, review fixes in progress |
| C — Scan modes | Not started |
| D — Real-time + VirusTotal | Not started |
| E — Cracked-software threat pack | Not started |
| F — UI | Not started |
| G — Signature features (Honeytokens, Attack Story, Pre-Flight, Exposure Report) + G5 Phase 1 security review | Not started |

Tests (after B4): Core 1179 passed + 1 skipped (opt-in on-disk EICAR), Engine 243 passed + 5 skipped (elevated / opt-in
tests). Core runs in about 14 s after the slow loop tests were shortened. Simulated clean machine: 0 failed.
Build: 0 warnings (Debug and Release). CI on windows-latest: green.

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

## Section B — Engine infrastructure (in progress)

**Order:** B1 → B2 → **B5** → B3 → B4. B5 (the scan-worker sandbox) comes before B3, because B3's scan jobs hand files to
the worker. B1, B2, B4 and B5 each get their own reviewer pass right after they're built; the section tester + reviewer
pass comes at the end.

| Step | What | Status |
|---|---|---|
| B1 | Alert model + Windows Event Log writer (source "sap-AV", structured JSON, event IDs 1001/1002/1003/3001); `Reason` length cap and SIEM-safe URL sanitizing (carried over from A) | **Done** (`6b0e586`, review fixes `80f29a9`) |
| B2 | Reversible quarantine | **Done** (`08fe657`; review fixes incl. Critical C1 `66b91bb`, `ee4c38d`, `f8b7d76`; follow-up review CLEAN) |
| B5 | Privilege separation: all file parsing in a low-privilege scan worker | **Done** (`b21a8fb`…`c61d8b2`; review H1 fixed and confirmed closed; Medium/Low → ROADMAP, M-A done in B3) |
| B3 | Scan job framework (queue, background-priority workers, progress/ETA, pause/resume/cancel) | **Done** (`4523493`…`fa9a712`; review H1 fixed `e2c440d`, follow-ups `ba20903`) |
| B4 | Named-pipe protocol v1 (engine ↔ GUI) | **Built** (`009d580`…`3b12c01`); review NOT CLEAN (3 High), fixes in progress |
| B6 | Dedicated `sap-AV` event log (only SYSTEM writes), decision X2 M1 | Not started |

## Current status (2026-10-25)

**B4 (named pipe, engine ↔ GUI) is built and pushed** (`009d580`…`3b12c01`): pipe locked to local authenticated
users (SYSTEM owns it, first-instance protection), client identity from the pipe, strict 64 KiB JSON frames, `ScanPathPolicy`,
scans run with the requester's access, per-user job isolation, quarantine/restore authorization, per-user caps, sanitized
output, and a client library for the GUI (F1). B4's immediate review came back **NOT CLEAN** (3 High, 3 Medium, no Critical): a user could stop the pipe server
for good (H1), take over the pipe name after draining all instances (H2), or list another user's folders through a
junction swap during a paused scan (H3); a symlinked root could make SYSTEM authenticate to an attacker's SMB server (M2).
All are being fixed now; Low findings are in ROADMAP.md. Then **B6**, then the section B tester + reviewer pass.

**Done in section B so far**
- **B1** Event Log alerts; review found 2 High (sources auto-registering), fixed.
- **B2** reversible quarantine; review found **Critical C1** (quarantine could be redirected into deleting another
  file as SYSTEM), fixed and confirmed closed.
- **B5** sandboxed scan worker (AppContainer, Job Object, read-only brokered handles). The 0xc0000142 startup failure
  was a blocked `conhost.exe`; fixed by starting the worker detached. Review H1 (worker process DACL) fixed and confirmed.
- **B3** scan jobs (queue, pause/resume/cancel, ETA, alert aggregation, auto-quarantine policy). Review H1 (trailing
  dot/space names) fixed.
- All Medium/Low findings are recorded in `ROADMAP.md` under the step they belong to.

**Open for the user**
- Once by hand, after B6: in an **elevated** PowerShell, run `$env:SAPAV_TEST_ALLOW_HKLM=1; dotnet test`, so the real
  Event Log test actually runs. (The 2026-10-24 attempt ran while B3 was mid-edit, so the Engine tests didn't compile.)
- Decision X2 M1 is made (dedicated `sap-AV` event log, step B6). No other decisions are pending.

## What's left

- **B:** finish B4 → its review → B6 (with its review) → section B tester + reviewer pass.
- Then C → D → E → F → G, ending with the Phase 1 security review (G5).
