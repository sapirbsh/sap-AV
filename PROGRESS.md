# sap-AV Progress

Updated after each ROADMAP section (see `ROADMAP.md` for the full plan and the open items under each step).

## Section A — Detection engine (in progress)

**Built so far**
- A1 — core models (`ScanItem`, `Detection`, `ScanResult`, `ScanStatus`), strict JSON, MITRE catalog.
- A2 — streaming SHA-256 hasher on a hardened open path (device paths rejected, anonymous pipe impersonation,
  no cloud recall, GetFileType check) and the hash blocklist.
- A3 — Authenticode check (embedded + catalog). Microsoft = Microsoft product root **and** a first-party issuing CA,
  by thumbprint; WHQL / Store / Trusted Signing → OtherTrusted. All projects on `net10.0-windows`.
  Machine-dependent tests skip cleanly (`SAPAV_TEST_SIMULATE_CLEAN_MACHINE=1`).

**Left in section A:** A4–A7 (YARA, heuristics, Mark-of-the-Web, FileScanner), then the section tester + reviewer pass, then straight on to section B (all UI work stays in section F).

**Open issues:** see "Carried over" notes in `ROADMAP.md` (A5, A7, B1, B3, B4, C1, C5, C6, D1, D3).
