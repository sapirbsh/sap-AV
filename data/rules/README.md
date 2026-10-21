# YARA rules

Place `*.yar` rule files here (subfolders are loaded too, e.g. `third-party/`). Never commit real malware samples.

The engine is **YARA-X** (pinned version in `native/yara-x/YaraX.targets`), not classic libyara.

- Each file is compiled on its own first; a file that doesn't compile is skipped and reported, the rest still load.
- Each file is its own namespace (its relative path), so rule names may repeat across files.
- `include` is disabled.
- **Module allowlist:** only `import "pe"`, `import "math"` and `import "hash"`. A file importing anything else
  (`console`, `dotnet`, `elf`, `cuckoo`, `magic`, ...) is rejected and reported. The check uses the compiled
  rules' imports, so an `import` inside a comment or string doesn't count.

## YARA-X syntax notes (differences from classic YARA that matter for third-party rules)

- Regular expressions are stricter: invalid escapes (e.g. `\R`) and unescaped `{`/`}` that YARA accepted are errors
  (YARA-X has a relaxed mode for this, which sap-AV does not enable).
- Slow patterns and potentially slow loops are compiler warnings, reported as load warnings.
- `include` paths: write them with forward slashes (backslash escapes are rejected); includes are disabled here anyway.
- `private` rules work as usual (never reported as matches).
- See https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/ for the full list.

## Meta fields sap-AV reads

| Meta | Values | Default |
|------|--------|---------|
| `verdict` | `"malicious"`, `"suspicious"` (also `"pup"`, `"hacktool"` → Suspicious for now) | Malicious. Unknown values → Suspicious + a load warning |
| `mitre` | One or more ATT&CK IDs, e.g. `"T1059.001, T1027.010"` (first is primary) | T1204.002 (no warning). Invalid tokens are dropped with a load warning |
| `description` | Free text, shown with the detection | — |
