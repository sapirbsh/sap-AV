# YARA rules

Place `*.yar` rule files here (subfolders are loaded too, e.g. `third-party/`). Never commit real malware samples.

- Each file is compiled on its own first; a file that doesn't compile is skipped and reported, the rest still load.
- Each file is its own YARA namespace (its relative path), so rule names may repeat across files. `include` is disabled.
- The bundled engine is **YARA 4.1.1** (dnYara.NativePack 2.1.0.3). Features added after 4.1 don't compile.

Meta fields sap-AV reads:

| Meta | Values | Default |
|------|--------|---------|
| `verdict` | `"malicious"`, `"suspicious"` (also `"pup"`, `"hacktool"` → Suspicious for now) | Malicious. Unknown values → Suspicious + a load warning |
| `mitre` | One or more ATT&CK IDs, e.g. `"T1059.001, T1027.010"` (first is primary) | T1204.002 (no warning). Invalid tokens are dropped with a load warning |
| `description` | Free text, shown with the detection | — |
