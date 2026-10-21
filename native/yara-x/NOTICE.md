# YARA-X (third-party native component)

sap-AV uses the YARA-X C API library (`yara_x_capi.dll`) as its YARA engine.

| | |
|---|---|
| Project | YARA-X, https://github.com/VirusTotal/yara-x |
| License | BSD-3-Clause, see `LICENSE` in this folder (copied from the v1.22.0 tag) |
| Version | 1.22.0 |
| Asset | `yara-x-capi-v1.22.0-x86_64-pc-windows-msvc.zip` |
| URL | https://github.com/VirusTotal/yara-x/releases/download/v1.22.0/yara-x-capi-v1.22.0-x86_64-pc-windows-msvc.zip |
| Asset SHA-256 | `40317f65781e3a17bffe31f9837143a51c1c28ce5061eac2b90695fbb30e1664` (matches the digest GitHub publishes for this release asset) |
| `yara_x_capi.dll` SHA-256 | `bb5c112bf479d1b1706fbecf85275d3806321ee2912dea4f36750289d0294848` |

The binary is **not** committed. `YaraX.targets` (imported by `src/SapAV.Core`) downloads the asset once into the
git-ignored `native/yara-x/<version>/` cache, verifies both hashes on every build (a mismatch deletes the file and fails
the build), and copies the DLL to the build output.

To upgrade: take the new release's C API asset for `x86_64-pc-windows-msvc`, compare its SHA-256 with the digest on the
GitHub release, then update the version and both hashes in `YaraX.targets` and in this file.
