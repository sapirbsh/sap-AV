# sap-AV Progress

Updated after each ROADMAP section (see `ROADMAP.md` for the full plan and the open items under each step).

## Overview

| Section | Status |
|---|---|
| A — Detection engine | **Done** (A1–A7, section test + review, High fixes) |
| B — Engine infrastructure (incl. B5 scan-worker sandbox) | **In progress:** B1 built, its review is next |
| C — Scan modes | Not started |
| D — Real-time + VirusTotal | Not started |
| E — Cracked-software threat pack | Not started |
| F — UI | Not started |
| G — Signature features (Honeytokens, Attack Story, Pre-Flight, Exposure Report) + G5 Phase 1 security review | Not started |

Tests (after B1): Core 1043 passed + 1 skipped (opt-in on-disk EICAR), Engine 22 passed + 1 skipped (real Event Log test, needs an
elevated run). Simulated clean machine (after B1): Core 982 passed, 55 skipped,
0 failed. Build: 0 warnings (Debug and Release).

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
| B2 | Reversible quarantine | Built (`08fe657`); immediate review running |
| B5 | Privilege separation: all file parsing in a low-privilege scan worker | Not started |
| B3 | Scan job framework (queue, background-priority workers, progress/ETA, pause/resume/cancel) | Not started |
| B4 | Named-pipe protocol v1 (engine ↔ GUI) | Not started |

## Next session — start here (stopped 2026-10-21)

1. ~~Rerun B1's immediate review~~: done. 2 High fixed (`80f29a9`), Medium/Low recorded in ROADMAP.md. One decision is open: X2 M1, a dedicated `sap-AV` event log.
   Medium/Low in ROADMAP.md.
2. Then **B2** (reversible quarantine, with an immediate review), then **B5** (scan-worker sandbox, full review), then B3, then B4.
3. To do once by hand: from an **elevated** terminal, run `SAPAV_TEST_ALLOW_HKLM=1 dotnet test` (PowerShell: `$env:SAPAV_TEST_ALLOW_HKLM=1; dotnet test`), so the real Event Log test (skipped so far) actually runs.
4. ~~Check CI~~: **CI is green** (runs 1–16 passed on windows-latest, including the YARA-X download and hash check on the runner; reported by the user 2026-10-22).

The working tree is clean, and everything is committed and pushed.

## What's left

- **B:** finish B1–B5 as above, then the section B tester + reviewer pass.
- Then C → D → E → F → G, ending with the Phase 1 security review (G5).
