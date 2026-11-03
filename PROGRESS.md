# sap-AV Progress

Updated after each ROADMAP section (see `ROADMAP.md` for the full plan and the open items under each step).

## Overview

| Section | Status |
|---|---|
| A — Detection engine | **Done** (A1–A7, section test + review, High fixes) |
| B — Engine infrastructure (incl. B5 scan-worker sandbox) | **Done** (B1–B6, section test + review, High fixes) |
| C — Scan modes | **Done** (C1–C6, section test + review, 9 High fixed) |
| D — Real-time + VirusTotal | Not started |
| E — Cracked-software threat pack | Not started |
| F — UI | Not started |
| G — Signature features (Honeytokens, Attack Story, Pre-Flight, Exposure Report) + G5 Phase 1 security review | Not started |

Tests (after section C): Core 1354 passed + 1 skipped, Engine 600 passed + 12 skipped. Simulated clean machine: 0 failed.
Build: 0 warnings (Debug and Release). CI on windows-latest: green (`32ce339`).

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

## Section C — Scan modes (done)

| Step | What | Status |
|---|---|---|
| C1 | Custom Scan, access-first reporting, per-user quarantine/alert budgets | **Done** (`77be4e0`…`83b78d7`; review H1 fixed `7a63104`) |
| C2 | Read-only autostart collectors (Run/RunOnce, Winlogon, IFEO, services, Startup shortcuts, scheduled tasks) | **Done** (`ee7e59b`…`b5846c9`) |
| C3 | Autostart judgement (point rules, MITRE, alerts 2001/2002) | **Done** (`f92aa33`, `f335c8e`) |
| C4 | Quick Scan (pluggable checks: processes, autostarts, risky folders, last 7 days) | **Done** (`0e57d9c`…`c8ecff3`; review clean) |
| C5 | SQLite scan cache keyed by file identity | **Done** (`f5a0e88`, `8b8024e`) |
| C6 | Full Scan over all fixed drives | **Done** (`1eed55a`, `28c2263`) |

**What was built**
- **Custom / Quick / Full Scan** as admin- or user-requested jobs through the pipe. Quick Scan runs four phases in one
  3-minute job (running programs, autostart entries, high-risk folders of every profile, files changed in the last 7 days).
  Full Scan covers every fixed drive with no time limit. Each file is scanned once per job.
- **Autostart collection and judgement:** read-only, as SYSTEM. Shortcut and task-XML parsing run **only in the sandboxed
  worker**. Command lines are resolved the way CreateProcess and cmd.exe do (switch forms, `^` escapes, `&` chains,
  unquoted paths). An entry whose real payload wasn't scanned is **Unverified, never Clean**; expected cases (e.g. inline
  commands) are counted, while coverage gaps mark the phase Incomplete.
- **Scan cache:** SQLite in the protected engine folder, HMAC-signed rows, valid only with a change journal (NTFS/ReFS),
  matching file ID, path, size, times and USN, the same rules and engine version, and at most 14 days old. Blocklist
  updates re-check cached hashes without re-reading. Repeat scans were 15.6× faster on a test tree.
- **Evasion fixes:** `attrib +O` and user-made "cloud placeholder" folders no longer hide files (a folder is skipped only
  inside a sync root Windows confirms); user folder settings can't steer or starve the folder phases.

**How it was reviewed**
- Immediate reviews of C1 and C4; a section tester pass (`9eae100`); a section reviewer pass (5 High: crashes from a Run
  value and from a task file, `attrib +O`, false Clean on autostart entries, stale cache without a journal) and a
  follow-up review (4 more High: cmd switch forms, false "missing" targets, shortcut ID lists, user-made placeholders).
  All fixed (`edeeb2f`…`b27eb60`). A real bug found by a flaky test was fixed too: a job out of its time budget could end
  Completed instead of TimedOut (`ae0c245`).
- Medium/Low findings are recorded in `ROADMAP.md` under C/D/E steps (e.g. the user-writable Tasks folder flooding
  collection, launcher-argument tricks for E4, cache hardening for D1).

**Decisions the builders made (open to change):** autostart collection budget 60 s (and at most ~25% of a Quick Scan's
remaining time); a cloud reparse tag alone counts as a hydrated file and gets scanned; the debug in-process mode doesn't
collect tasks and shortcuts; a 5 s parse timeout.

**Tests after section C:** Core 1351 passed + 1 skipped, Engine 590 passed + 10 skipped; 0 failures on the simulated
clean machine; three combined runs in a row green; 0 build warnings.

**Open items carried forward**
- **Elevated collection timings (from CI, `1fc1d95`):** 34.2 s for 927 entries, of which **scheduled tasks 32.6 s**
  (212 task files, 28.8 s in sandbox parsing, about 136 ms per file, one sandbox request per file). Registry and services
  take milliseconds. **Fixed** (`27b65d3`, review fixes `b336fcd`). The cause was not per-request work but waiting:
  each pipe exchange waited for a thread-pool thread, plus one background-priority round trip per file. Now up to 32
  files go in one request, served by one dedicated I/O thread per worker. Local results for 200 files: idle 79 ms →
  30 ms; busy CPU 3.5 s → 0.3 s; starved thread pool 15.8 s → 44 ms. Immediate review: no Critical. H1 (solo retries
  ignored the collection budgets) and M1 (one thread per exchange) are fixed. M2/M3/L3/L4 are listed in ROADMAP
  under section C. **Elevated CI after the fix (`32ce339`): 9.4 s total** (was 34.2 s), scheduled tasks 7.8 s for 212
  files (6.9 s parsing, about 32 ms per file, was 136 ms), Startup folders 1.5 s (mostly the first worker start). Still
  above the 5 s goal on the CI runner; look at it again with the D4 real-time persistence work (only changed tasks
  need parsing there).
- **Quick Scan folder phases** were cut short by the 3-minute budget on this dev PC (large AppData); tune with the cache.
- **Autostart judging is an arms race** (every launcher has its own argument tricks). The rule kept: if sap-AV can't see
  the real payload, the entry is Unverified, never Clean. Remaining launcher tricks are listed under E4.

## Current status (2026-11-03)

**Section C is done**, including the task-parsing performance fix (see above). **D1 (real-time file monitoring) is
being built now.** **Next:** section D (real-time file monitoring, VirusTotal, real-time persistence monitoring,
Block & remove).

**Open for the user**
- **Please remove `C:\ProgramData\sap-AV` (elevated):** a test run on 2026-10-29 accidentally created the real engine
  data folder, owned by your user account. The code is fixed and a test guard now prevents it. Left in place, the real
  engine would refuse it as "untrusted owner" and turn off quarantine and the sandbox. In an **elevated** PowerShell:
  `Get-ChildItem -Force C:\ProgramData\sap-AV` (should be empty), then `Remove-Item C:\ProgramData\sap-AV`.
- **Optional, elevated:** remove the leftover test folder
  `C:\Users\user\AppData\Local\Temp\claude\c--Projects-sap-AV\643feb91-23ce-4618-9c16-35ba94238a87\scratchpad\cf`
  (a cloud-tag experiment; it can't be opened or deleted without elevation).
- ~~Elevated Event Log test~~: passed 2/2 on 2026-10-28.

## What's left

- **D:** real-time file monitoring (D1), VirusTotal (D2, D3), real-time persistence monitoring (D4), Block & remove (D5),
  then the section D tester + reviewer pass.
- Then E → F → G, ending with the Phase 1 security review (G5).
