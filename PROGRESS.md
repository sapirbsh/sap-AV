# sap-AV Progress

Updated after each ROADMAP section (see `ROADMAP.md` for the full plan and the open items under each step).

## Overview

| Section | Status |
|---|---|
| A — Detection engine | **Done** (A1–A7, section test + review, High fixes) |
| B — Engine infrastructure (incl. B5 scan-worker sandbox) | **Done** (B1–B6, section test + review, High fixes) |
| C — Scan modes | **Done** (C1–C6, section test + review, 9 High fixed) |
| D — Real-time + VirusTotal | **Done** (D1–D5, section test + review, 5 High fixed + follow-up review) |
| E — Cracked-software threat pack | In progress (E1, E3, E4 built and reviewed; review fixes done) |
| F — UI | Not started |
| G — Signature features (Honeytokens, Attack Story, Pre-Flight, Exposure Report) + G5 Phase 1 security review | Not started |

Tests (after section D): Core 1431 passed + 1 skipped, Engine 780 passed + 16 skipped. Simulated clean machine: 0 failed.
Build: 0 warnings (Debug and Release). CI on windows-latest: green (`9628568`).

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

## Section D — Real-time + VirusTotal (done)

**Summary:**
- **Real-time file protection:** each user's download, desktop, documents, temp and Startup folders, plus the
  machine-wide ones, are watched in real time. New files are scanned in the sandbox and Malicious ones are
  quarantined.
- **VirusTotal:** optional; hash-only and off by default. It checks unsigned risky files, under a per-user daily
  budget.
- **Autostart monitoring:** Run keys, services, Winlogon, IFEO, Startup folders and tasks are watched in real time
  against a protected baseline.
- **Block & remove:** any autostart entry can be blocked by the user, with a backup and a restore.
- **Protected rules and blocklist:** they live only in admin-only folders.
- **Reviews:** every step got an immediate review; then a section tester pass, a section reviewer pass (5 High,
  fixed), a follow-up review of the fixes (no Critical or High; 3 Medium fixed anyway), and a last fix round.
- **Tests at the end of D:** Core 1431 passed + 1 skipped, Engine 780 passed + 16 skipped (from 600 + 12 at the end of
  C). The clean-machine run is green, and CI is green.
- **New event IDs:** 3002/3003 (block and restore), 9010/9011 (real-time or autostart monitor unavailable).
- **Open:** the Medium/Low items are listed per step in ROADMAP ("Notes from D1…D5", "D… immediate review",
  "Section D review", "Follow-up review of the fix round"). The main ones:
  - byte-range-lock evasion (needs mapped-view reading in the worker);
  - storm/overflow rescans trust timestamps the user controls (use the USN journal);
  - a manifest for the shipped rules;
  - releasing HKU handles at logoff;
  - the per-owner VirusTotal budget for scans;
  - one shared "machine" owner in the real-time queue.
- **Never run yet:** the gated real-Task-Scheduler test. It needs an elevated run with `SAPAV_TEST_ALLOW_HKLM=1`.
- **CI timing noise:** elevated collection on CI varies between 2.6 s and 17 s per run, depending on the runner.
  Repeat collections with nothing changed take about 35–75 ms.

### Per step

**D1 (real-time file monitoring) is done** (`7de7442`…`5953ced`):
- **Watched folders:** each user's Downloads, Desktop, Documents, Temp and Startup, plus the machine Temp, Public and
  the all-users Startup.
- **Watching:** `ReadDirectoryChangesExW` on link-safe folder handles, not FileSystemWatcher, which follows junctions
  as SYSTEM.
- **Before scanning:** a separate "wait until unlocked" probe with backoff, capped at 2 minutes. Browser in-progress
  downloads are scanned at their final rename.
- **Queue:** events for one file are merged. Mark-of-the-Web files go first. Each folder has its own quota and folders
  take turns. A storm or buffer overflow switches that folder to a bounded "rescan later".
- **Folder re-checks:** every 5 minutes, so a folder that becomes a link stops being watched.
- **Scanning:** through the existing sandboxed pipeline. Alert and quarantine budgets are per user. Only Malicious
  files are quarantined automatically.
- **Scan cache:** now also capped in bytes.

**D1 immediate review: no Critical.** Fixed:
- H1: an oplock holder could hang the real-time threads (`FILE_COMPLETE_IF_OPLOCKED` plus a `CancelSynchronousIo`
  watchdog);
- H2: one user's event storm could block real-time for everyone (per-folder quotas, round-robin);
- M1–M3 and L1.

The remaining Medium/Low items are in ROADMAP under "D1 immediate review".

Two flaky tests fixed:
- Defender's ML detection removed a test file (`MZ` + `.pdf.exe` + an internet zone);
- a Full Scan pause test had a timing race.

D1 after the push:
- **CI failure, fixed:** one real-time test assumed new files are owned by the user. On the elevated CI runner they're
  owned by Administrators, so the code correctly used the engine's own budget (`9628568`).
- **CI annotations:** the "Annotate failed tests" step had crashed. It's now robust and also reports test-host crash
  messages (`d20eedb`).

**D2 (VirusTotal client) is done** (`d279fb7`…`cfc581f`), in SapAV.Core, not wired yet:
- **Client:** hash-only `GET /api/v3/files/{sha256}` to www.virustotal.com, no redirects. Strict, size-capped
  response parsing; status mapping (404 unknown, 401/403 bad key, 429 quota back-off, 5xx transient).
- **Rate limiter:** 4 per minute, 500 per UTC day, persisted across restarts.
- **Cache:** SQLite with HMAC rows; 7 days for flagged results, 1 day for clean or unknown.
- **API key:** stored with machine DPAPI; it never appears in logs, ToString or JSON.
- **Tests:** 34 test methods (66 cases), all with a fake HTTP handler and a fake clock.
- **Package:** no new one needed.

Elevated collection timings on CI now vary between 3.5 s and 9 s per run (24.9 s once, on a slow runner). They used to
be 34 s.

**D3 (VirusTotal wiring + protected data folders) is done** (`b4f9191`…`efbd9d4`):
- **When VirusTotal is asked:**
  - never for signed files;
  - real time: only risky extensions;
  - scans and autostarts: only Suspicious files.
- **Verdict from VirusTotal:**
  - 5 or more engines say "malicious": Malicious;
  - 3 or more: Suspicious;
  - PUP or HackTool labels are never more than Suspicious, so they're never auto-quarantined;
  - MITRE T1204.002.
- **When there's no answer:** rate limited, no key or an error leave a scan note, never Clean.
- **Daily budget:** 500 requests, with 100 kept for scans. Each user gets at most 125 a day for real time, so one user
  can't use up everyone's budget.
- **Pipe:** status for everyone, but never the key. Setting the key and turning the feature on or off are admin-only.
  The feature is off by default.
- **Rules and blocklist:** they load only from `%ProgramData%\sap-AV\Rules` and `\Blocklist`, seeded from the trusted
  install folder. If a user pre-creates the data folder, the engine falls back to the install folder and raises an
  alert, never "no rules".
- **Immediate review:** no Critical. Fixed: H1 (that pre-created folder), M1 (the cache read the blocklist by path),
  M2 (the lookup held a worker slot), M3 (per-owner budget), L2, L4, L6. The rest is in ROADMAP under D3.

**D4 (real-time persistence monitoring) is done** (`fc432d5`…`b63b789`):
- **Registry:** change watches on HKLM and on every loaded user hive.
- **Folders:** Startup folders and `System32\Tasks` watched link-safely.
- **Re-collection:** debounced, and only the affected scope or user is re-collected. Only changed task files are
  parsed again: about 10 ms for 200 unchanged task files.
- **Baseline:** HMAC-protected. New or changed entries are judged and alerted; removals are logged.
- **Safety rescan:** every 45 min.
- **Immediate review:** no Critical; 5 High fixed. Each was a way for a user to keep their autostart from being judged:
  - a target that wasn't scanned was marked judged;
  - a target-file swap after judgement;
  - a deny-SYSTEM ACE on their own key, now itself a Suspicious alert (T1564);
  - junk churn starving the queue, now first in, first out;
  - flooding the user-writable Tasks folder.
- **Also fixed:** M4 (dead watches) and M5 (budgets per entry user). The rest is in ROADMAP under D4.

**D5 (Block & remove) is done** (`55097f0`…`6a93fa7`). Nothing happens automatically; every action is an explicit
request over the pipe, and everything is backed up first.
- **What each type does:**
  - **Registry autostarts:** the exact value is backed up and deleted.
  - **Winlogon Shell/Userinit:** reset to the Windows default.
  - **Services:** disabled and stopped, never deleted. Boot or critical services need an explicit confirmation.
  - **Scheduled tasks:** disabled through the Task Scheduler.
  - **Startup items:** moved into quarantine.
- **Restore:** puts back exactly what was removed, and refuses if something else is there now.
- **Who may do what:**
  - Machine-wide entries are admin-only.
  - A standard user may act only on their own entries, and only where their own account could make the change.
  - A user can't undo an administrator's block.
- **Event IDs:** 3002 (blocked) and 3003 (restored).
- **Immediate review:** no Critical. Fixed:
  - H1: blocking one Run value silently accepted the other values in the same key;
  - M1: task authorization went by "runs as" instead of the task's own permissions;
  - M2: a user could undo an admin's block;
  - M3: an admin could disable boot-critical drivers in one click;
  - L2.

CI is green after D5 (`4c72989`); elevated collection took 2.6 s.

**Section D tester pass (done, `b0044c2`):**
- 5 cross-step tests, all through the real broker, the real VirusTotal stack (fake HTTP only) and the real verdict
  handler:
  - real-time → VirusTotal → quarantine;
  - VirusTotal offline means never Malicious;
  - a VirusTotal-only hit on a protected file needs confirmation;
  - a new Run value whose target VirusTotal calls malicious → alert;
  - planted user-made data folders → everything fails safe.
- Three timing-sensitive tests made tolerant of a loaded machine.
- No product bugs found. 3 full runs, a clean-machine run, and the D test classes looped 5 times: all green.

**Section D reviewer pass (done): no Critical, 5 High.** Mostly cross-step gaps the per-step reviews couldn't see:
- **H1:** malware that re-creates its Run value right after Block & remove was accepted silently.
- **H2:** a user's oplock could freeze the autostart monitor, Block & remove and Quick Scan. The D1 oplock fix covered
  only real-time opens.
- **H3:** fake task files in the user-writable Tasks folder could spend another user's (or the engine's) alert budget.
- **H4:** a Startup folder pointed at a network or WebDAV share evaded both monitors.
- **H5:** real-time fairness was per folder, not per user.
- **Also fixed:** health alerts 9010/9011 when real-time or the autostart monitor dies (with automatic restart),
  and two small items.

**Fix rounds:**
- `3db711f`…`ff2bec6`: all 5 High plus the health alerts.
- A follow-up review confirmed them closed (no Critical or High).
- `bce673b`…`78d25bb`: 3 Medium fixed anyway, because they touched reversibility and the H1/H3 fixes:
  - a timed-out Block could still run after the user restored, so the backup was lost;
  - a value re-created right after the post-action check;
  - task budgets after a cache reset.

## Current status (2026-11-11)

**Sections A, B, C and D are done.** Section E is in progress:
- **Built:** E1 (PotentiallyUnwanted verdict and threat categories), E3 (static infostealer and miner heuristics),
  E4 (script-persistence rules and launcher payloads).
- **Review fixes:** M1, L1, L2, L3, L7, L8 and L9 are in `49ffe04`.
- **Also fixed:** the A5 follow-up for PE detection (M2, M3, M7; `9fc21f2`) and the E4 review H1 (`3315240`, launcher forms are judged by
  their payload).
- **Next:** E2 (YARA-Forge rules, with explicit category mapping), then E5–E12.

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

- **E:** cracked-software threat pack. Left: E2 and E5–E12, then the section test and review passes.
- **F:** the GUI (F1–F8).
- **G:** signature features (G1–G5), ending with the Phase 1 security review (G5).
- **Progress:** 27 of 60 build steps done (about 45%).
