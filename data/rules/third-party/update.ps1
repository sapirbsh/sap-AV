#Requires -Version 5.1
<#
.SYNOPSIS
    Regenerates sap-AV's curated third-party YARA rules (ROADMAP E2) from a pinned YARA-Forge release.

.DESCRIPTION
    Run by a developer when updating the vendored rules. The product never downloads rules at runtime.

    1. Downloads the pinned YARA-Forge release asset from GitHub (or uses -ArchivePath) and verifies its SHA-256.
    2. Takes only the rules listed in curated-rules.txt (rule name, category, verdict, optional MITRE IDs).
    3. Keeps a rule only if
       - its license is approved: DRL-1.1, MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, CC0-1.0, CC-BY-4.0
         (the rule's own license meta, or else the source repository's license). GPL, non-commercial (NC),
         share-alike, missing and unknown licenses are excluded;
       - its YARA-Forge quality and score are at least -MinQuality / -MinScore;
       - it uses no module other than pe, math and hash;
       - it compiles on its own under the pinned YARA-X (yara_x_capi.dll, hash-checked) with slow patterns and slow
         loops treated as errors (atom-quality lint, review L5), with no compiler warning outside $BenignWarnings.
    4. Adds sap-AV meta at the top of each rule's meta section (verdict, category, mitre, license_spdx; plus license
       when the rule had none), keeps all original meta (author, reference, license, ...), and writes one file per
       category and source, the source license texts (licenses\) and NOTICE.md. Excluded rules are listed with the
       reason in NOTICE.md.

    Needs the YARA-X DLL that the build downloads: run `dotnet build` once first.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File data\rules\third-party\update.ps1
#>
[CmdletBinding()]
param(
    [string]$Release = '20261108',
    [string]$Package = 'extended',
    [string]$Sha256 = '8b812dedcab15f7911c2e0c6382566e3248e8affddd3e7f425dd1761170cefbd',
    # An already downloaded release zip (still hash-checked).
    [string]$ArchivePath,
    [string]$YaraXDll,
    [int]$MinQuality = 70,
    [int]$MinScore = 65
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Here = $PSScriptRoot
$RepoRoot = (Resolve-Path (Join-Path $Here '..\..\..')).Path
$YaraXVersion = '1.22.0'
$YaraXDllSha256 = 'bb5c112bf479d1b1706fbecf85275d3806321ee2912dea4f36750289d0294848'
if (-not $YaraXDll) { $YaraXDll = Join-Path $RepoRoot "native\yara-x\$YaraXVersion\yara_x_capi.dll" }

$AllowedModules = @('pe', 'math', 'hash')
$KnownModules = @('pe', 'math', 'hash', 'dotnet', 'elf', 'macho', 'dex', 'lnk', 'time', 'console', 'string', 'cuckoo', 'magic', 'vt', 'crx', 'test_proto2', 'test_proto3')
$ApprovedLicenses = @('DRL-1.1', 'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'CC0-1.0', 'CC-BY-4.0')
# Default MITRE technique per category (a curated-rules.txt line may give its own).
$CategoryMitre = @{
    'infostealer' = 'T1555.003, T1539'
    'miner'       = 'T1496.001'
    'hacktool'    = 'T1003'
    'pup'         = 'T1204.002'
}
$CategoryVerdicts = @{
    'infostealer' = @('malicious', 'suspicious')
    'miner'       = @('malicious', 'suspicious')
    'hacktool'    = @('hacktool')
    'pup'         = @('pup')
}
# Small YARA-X ports that keep a rule's meaning, so the vendored set loads without compiler warnings. Each port applied to a
# rule is recorded in its sapav_port meta and in the file header.
# 1. Per rule: rule name -> @{ Find = regex; Replace = text; Note = why }.
$Ports = @{
    'SEKOIA_Stealer_Win_Luca'            = @{ Find = 'pe\.rich_signature\.toolid \( 0 , 0 \) and'; Replace = 'pe.rich_signature.toolid ( 0 , 0 ) != 0 and'; Note = 'integer used as boolean written as != 0 (same meaning)' }
    'DITEKSHEN_MALWARE_Win_Agentteslav3' = @{ Find = '6 of \( \$\* \)'; Replace = '6 of ( $s*, $g*, $m* )'; Note = '$* written as its pattern groups $s*, $g*, $m* (same set)' }
}
# 2. All rules, condition only: fields YARA-X deprecates, replaced by the equivalent it suggests.
$ConditionPorts = @(
    @{ Find = '\bpe\.number_of_sections\b'; Replace = 'pe.sections.len()'; Note = 'pe.number_of_sections -> pe.sections.len()' }
    @{ Find = '\bpe\.number_of_signatures\b'; Replace = 'pe.signatures.len()'; Note = 'pe.number_of_signatures -> pe.signatures.len()' }
    @{ Find = '\bpe\.number_of_resources\b'; Replace = 'pe.resources.len()'; Note = 'pe.number_of_resources -> pe.resources.len()' }
)

# 3. All rules, strings only: a hex pattern of printable ASCII bytes only, written as the same text literal (YARA-X text_as_hex).
function Convert-PrintableHex([string]$StringsPart, [ref]$Changed) {
    return [regex]::Replace($StringsPart, '(?m)^(?<lead>\s*\$\w*\s*=\s*)\{(?<hex>\s*[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}|[0-9A-Fa-f]{2})*\s*)\}(?<tail>[ \t]*(?:private[ \t]*)?)$', {
            param($m)
            $bytes = @([regex]::Matches($m.Groups['hex'].Value, '[0-9A-Fa-f]{2}') | ForEach-Object { [Convert]::ToInt32($_.Value, 16) })
            if (@($bytes | Where-Object { ($_ -lt 0x20 -or $_ -gt 0x7e) -and $_ -ne 0x09 -and $_ -ne 0x0a -and $_ -ne 0x0d }).Count -gt 0) { return $m.Value }
            $text = -join ($bytes | ForEach-Object {
                    switch ($_) { 0x5c { '\\' } 0x22 { '\"' } 0x09 { '\t' } 0x0a { '\n' } 0x0d { '\r' } default { [string][char]$_ } }
                })
            $Changed.Value = $true
            return $m.Groups['lead'].Value + '"' + $text + '"' + $m.Groups['tail'].Value
        })
}

function Invoke-GenericPorts([string]$RuleText, [ref]$Notes) {
    $ci = $RuleText.IndexOf("`tcondition:")
    if ($ci -lt 0) { $ci = $RuleText.IndexOf('condition:') }
    if ($ci -lt 0) { return $RuleText }
    $head = $RuleText.Substring(0, $ci)
    $condition = $RuleText.Substring($ci)
    foreach ($p in $ConditionPorts) {
        if ($condition -match $p.Find) { $condition = $condition -replace $p.Find, $p.Replace; $Notes.Value += $p.Note }
    }

    $si = $head.IndexOf('strings:')
    if ($si -ge 0) {
        $changed = $false
        $strings = Convert-PrintableHex $head.Substring($si) ([ref]$changed)
        if ($changed) { $head = $head.Substring(0, $si) + $strings; $Notes.Value += 'printable hex patterns written as text literals (same bytes)' }
    }

    return $head + $condition
}

$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

function Write-Text([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, ($Text -replace "`r`n", "`n"), $Utf8NoBom)
}

function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Get-Slug([string]$Name) { (($Name.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')) }

# The SPDX id of a license text, or a marker for an excluded / unknown one.
function Get-LicenseId([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text) -or $Text -match '^\s*(N/A|NO LICENSE SET)\s*$') { return 'none' }
    if ($Text -match 'GNU (Lesser |Affero )?General Public|\bL?A?GPL') { return 'GPL' }
    if ($Text -match 'NonCommercial|Non-Commercial|\bBY-NC\b|\bNC\b') { return 'NC' }
    if ($Text -match 'BY-SA|ShareAlike|Share-Alike') { return 'CC-BY-SA' }
    if ($Text -match 'Detection Rule License|\bDRL\b|DRL-1\.1') { return 'DRL-1.1' }
    if ($Text -match 'Apache License') { return 'Apache-2.0' }
    if ($Text -match '^\s*MIT\s*$|MIT License|Permission is hereby granted, free of charge') { return 'MIT' }
    if ($Text -match '3-Clause|Neither the name') { return 'BSD-3-Clause' }
    if ($Text -match '2-Clause|Redistribution and use in source and binary forms') { return 'BSD-2-Clause' }
    if ($Text -match '\bCC0\b|CC-0|Public Domain Dedication') { return 'CC0-1.0' }
    if ($Text -match 'CC[ -]BY( 4\.0)?\b|Creative Commons Attribution 4\.0') { return 'CC-BY-4.0' }
    return 'unknown'
}

function Get-Meta([string]$RuleText, [string]$Name) {
    $m = [regex]::Match($RuleText, '(?m)^\s*' + [regex]::Escape($Name) + '\s*=\s*(?<v>"(?:[^"\\]|\\.)*"|-?\d+|true|false)\s*$')
    if (-not $m.Success) { return $null }
    $v = $m.Groups['v'].Value
    if ($v.StartsWith('"')) { return $v.Substring(1, $v.Length - 2) }
    return $v
}

# Modules a rule's condition uses (quoted strings removed first, so "kernel32.dll" doesn't count).
function Get-UsedModules([string]$RuleText) {
    $i = $RuleText.IndexOf('condition:')
    if ($i -lt 0) { return @() }
    $condition = [regex]::Replace($RuleText.Substring($i), '"(?:[^"\\]|\\.)*"', '""')
    $found = @()
    foreach ($m in [regex]::Matches($condition, '(?<![\w$.])([a-z_][a-z0-9_]*)\s*\.\s*[a-z_]')) {
        $mod = $m.Groups[1].Value
        if ($KnownModules -contains $mod -and $found -notcontains $mod) { $found += $mod }
    }
    return $found
}

# --- YARA-X compile check (P/Invoke into the pinned yara_x_capi.dll) ---

if (-not (Test-Path -LiteralPath $YaraXDll)) { throw "YARA-X DLL not found at $YaraXDll. Run 'dotnet build' first (it downloads and hash-checks it)." }
if ((Get-Sha256 $YaraXDll) -ne $YaraXDllSha256) { throw "YARA-X DLL hash mismatch at $YaraXDll." }
if (-not [Environment]::Is64BitProcess) { throw 'Run this script in 64-bit PowerShell (yara_x_capi.dll is x64).' }

if (-not ('SapAvYaraXCheck' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class SapAvYaraXCheck
{
    private const string Dll = "yara_x_capi.dll";
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr LoadLibraryW(string path);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)] private static extern int yrx_compiler_create(uint flags, out IntPtr compiler);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)] private static extern void yrx_compiler_destroy(IntPtr compiler);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)] private static extern int yrx_compiler_add_source(IntPtr compiler, byte[] source);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)] private static extern int yrx_compiler_errors_json(IntPtr compiler, out IntPtr buffer);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)] private static extern int yrx_compiler_warnings_json(IntPtr compiler, out IntPtr buffer);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)] private static extern IntPtr yrx_compiler_build(IntPtr compiler);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)] private static extern void yrx_rules_destroy(IntPtr rules);
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)] private static extern void yrx_buffer_destroy(IntPtr buffer);

    public static void Load(string path)
    {
        if (LoadLibraryW(path) == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }

    /// <summary>Errors JSON (null if it compiled) and warnings JSON of one source.</summary>
    public static string[] Check(string source, uint flags)
    {
        IntPtr compiler;
        if (yrx_compiler_create(flags, out compiler) != 0) throw new InvalidOperationException("yrx_compiler_create failed");
        try
        {
            if (yrx_compiler_add_source(compiler, Encoding.UTF8.GetBytes(source + "\0")) != 0)
            {
                return new[] { Take(compiler, true) ?? "[]", null };
            }

            string warnings = Take(compiler, false);
            IntPtr rules = yrx_compiler_build(compiler);
            if (rules != IntPtr.Zero) yrx_rules_destroy(rules);
            return new[] { null, warnings };
        }
        finally
        {
            yrx_compiler_destroy(compiler);
        }
    }

    private static string Take(IntPtr compiler, bool errors)
    {
        IntPtr buffer;
        int result = errors ? yrx_compiler_errors_json(compiler, out buffer) : yrx_compiler_warnings_json(compiler, out buffer);
        if (result != 0 || buffer == IntPtr.Zero) return null;
        try
        {
            IntPtr data = Marshal.ReadIntPtr(buffer);
            int length = checked((int)Marshal.ReadIntPtr(buffer, IntPtr.Size).ToInt64());
            byte[] bytes = new byte[length];
            if (length > 0) Marshal.Copy(data, bytes, 0, length);
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            yrx_buffer_destroy(buffer);
        }
    }
}
'@
}
[SapAvYaraXCheck]::Load($YaraXDll)
# YRX_ERROR_ON_SLOW_PATTERN (4) | YRX_ERROR_ON_SLOW_LOOP (8) | YRX_DISABLE_INCLUDES (32)
$CompileFlags = [uint32]44

# Compiler warnings that don't change what a rule matches; a rule with only these is kept (and listed in NOTICE.md).
$BenignWarnings = @('text_as_hex', 'deprecated_field', 'unintended_pattern_in_set', 'non_bool_expr')

function ConvertFrom-Reports([string]$Json) {
    $list = @()
    if ([string]::IsNullOrWhiteSpace($Json)) { return $list }
    try {
        $parsed = ConvertFrom-Json $Json
        foreach ($x in @($parsed)) { $list += [pscustomobject]@{ Code = [string]$x.code; Title = [string]$x.title } }
    }
    catch {
        $list += [pscustomobject]@{ Code = 'unparsed'; Title = $Json }
    }
    return $list
}

# Error = why the rule is excluded (null if kept); Warnings = the benign warning codes it was kept with.
function Test-Compile([string]$Source) {
    $r = [SapAvYaraXCheck]::Check($Source, $CompileFlags)
    if ($null -ne $r[0]) {
        $reports = @(ConvertFrom-Reports $r[0])
        return [pscustomobject]@{ Error = 'YARA-X error: ' + (($reports | ForEach-Object { "$($_.Code): $($_.Title)" } | Sort-Object -Unique) -join '; '); Warnings = @() }
    }

    $warnings = @(ConvertFrom-Reports $r[1])
    $bad = @($warnings | Where-Object { $BenignWarnings -notcontains $_.Code })
    if ($bad.Count -gt 0) {
        return [pscustomobject]@{ Error = 'YARA-X warning: ' + (($bad | ForEach-Object { "$($_.Code): $($_.Title)" } | Sort-Object -Unique) -join '; '); Warnings = @() }
    }

    return [pscustomobject]@{ Error = $null; Warnings = @($warnings | ForEach-Object { $_.Code } | Sort-Object -Unique) }
}

# --- Download and verify the pinned release ---

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("sapav-yaraforge-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $assetName = "yara-forge-rules-$Package.zip"
    $assetUrl = "https://github.com/YARAHQ/yara-forge/releases/download/$Release/$assetName"
    if ($ArchivePath) {
        $zip = (Resolve-Path -LiteralPath $ArchivePath).Path
    }
    else {
        $zip = Join-Path $work $assetName
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Host "Downloading $assetUrl"
        Invoke-WebRequest -Uri $assetUrl -OutFile $zip -UseBasicParsing
    }

    $actual = Get-Sha256 $zip
    if ($actual -ne $Sha256.ToLowerInvariant()) { throw "SHA-256 mismatch for $assetName`: expected $Sha256, got $actual." }
    Write-Host "SHA-256 OK ($actual)"

    $extract = Join-Path $work 'x'
    Expand-Archive -LiteralPath $zip -DestinationPath $extract
    $yarFile = Join-Path $extract "packages\$Package\yara-rules-$Package.yar"
    $text = [System.IO.File]::ReadAllText($yarFile) -replace "`r`n", "`n"

    $packageHeader = [regex]::Match($text, '(?s)\A/\*.*?\*/').Value
    $forgeVersion = [regex]::Match($packageHeader, 'YARA-Forge Version: (\S+)').Groups[1].Value
    $creationDate = [regex]::Match($packageHeader, 'Creation Date: (\S+)').Groups[1].Value

    # --- Parse repositories and rules ---

    $repos = [ordered]@{}
    $rules = @{}
    $blocks = $text -split "\n/\*\n \* YARA Rule Set\n"
    for ($b = 1; $b -lt $blocks.Count; $b++) {
        $block = $blocks[$b]
        $repo = [pscustomobject]@{
            Name       = [regex]::Match($block, 'Repository Name: (.*)').Groups[1].Value.Trim()
            Url        = [regex]::Match($block, 'Repository: (.*)').Groups[1].Value.Trim()
            Commit     = [regex]::Match($block, 'Git Commit: (.*)').Groups[1].Value.Trim()
            Retrieved  = [regex]::Match($block, 'Retrieval Date: (.*)').Groups[1].Value.Trim()
            LicenseRaw = [regex]::Match($block, '(?s)\* LICENSE\n \* \n(.*?)\*/').Groups[1].Value
        }
        $repo.LicenseRaw = ($repo.LicenseRaw -replace '(?m)^ \* ?', '').Trim()
        $repoLicense = Get-LicenseId $repo.LicenseRaw
        $repo | Add-Member -NotePropertyName LicenseId -NotePropertyValue $repoLicense
        $repo | Add-Member -NotePropertyName Slug -NotePropertyValue (Get-Slug $repo.Name)
        $key = $repo.Name
        if ($repos.Contains($key)) { $key = "$($repo.Name) ($($repo.Url))" }
        $repos[$key] = $repo

        foreach ($m in [regex]::Matches($block, '(?ms)^(?:(?:private|global) )*rule\s+(?<name>\w+)[^\n]*\n\{.*?\n\}')) {
            $ruleText = $m.Value
            $ownLicense = Get-Meta $ruleText 'license'
            if (-not $ownLicense) {
                # Some sources name it after themselves (e.g. malpedia_license).
                $alt = [regex]::Match($ruleText, '(?m)^\s*\w+_license\s*=\s*"(?<v>[^"]*)"')
                if ($alt.Success) { $ownLicense = $alt.Groups['v'].Value }
            }
            $licenseId = $repoLicense
            $licenseFrom = 'repository'
            if ($ownLicense -and $ownLicense -notmatch '^\s*See license at') {
                $licenseId = Get-LicenseId $ownLicense
                $licenseFrom = 'rule'
            }

            $rules[$m.Groups['name'].Value] = [pscustomobject]@{
                Name        = $m.Groups['name'].Value
                Text        = $ruleText
                Repo        = $repo
                RepoKey     = $key
                OwnLicense  = $ownLicense
                HasLicense  = [bool](Get-Meta $ruleText 'license')
                LicenseId   = $licenseId
                LicenseFrom = $licenseFrom
                Quality     = [int](@(Get-Meta $ruleText 'quality') + '0')[0]
                Score       = [int](@(Get-Meta $ruleText 'score') + '0')[0]
            }
        }
    }
    Write-Host "Parsed $($rules.Count) rules from $($repos.Count) repositories."

    # --- Curated list ---

    $curated = @()
    $lineNo = 0
    foreach ($line in [System.IO.File]::ReadAllLines((Join-Path $Here 'curated-rules.txt'))) {
        $lineNo++
        $t = $line.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
        $parts = $t -split '\s+'
        if ($parts.Count -lt 3 -or $parts.Count -gt 4) { throw "curated-rules.txt line ${lineNo}: expected <rule> <category> <verdict> [<mitre>]." }
        $category = $parts[1].ToLowerInvariant()
        $verdict = $parts[2].ToLowerInvariant()
        if (-not $CategoryVerdicts.ContainsKey($category)) { throw "curated-rules.txt line ${lineNo}: unknown category '$category'." }
        if ($CategoryVerdicts[$category] -notcontains $verdict) { throw "curated-rules.txt line ${lineNo}: verdict '$verdict' doesn't fit category '$category'." }
        $mitre = $CategoryMitre[$category]
        if ($parts.Count -eq 4) { $mitre = ($parts[3] -split ',') -join ', ' }
        if (@($curated | Where-Object { $_.Name -eq $parts[0] }).Count -gt 0) { throw "curated-rules.txt line ${lineNo}: duplicate rule '$($parts[0])'." }
        $curated += [pscustomobject]@{ Name = $parts[0]; Category = $category; Verdict = $verdict; Mitre = $mitre }
    }

    # --- Filter ---

    $kept = @()
    $excluded = @()
    foreach ($c in $curated) {
        if (-not $rules.ContainsKey($c.Name)) { $excluded += [pscustomobject]@{ Name = $c.Name; Category = $c.Category; Reason = "not in YARA-Forge release $Release ($Package)" }; continue }
        $r = $rules[$c.Name]
        if ($ApprovedLicenses -notcontains $r.LicenseId) {
            $excluded += [pscustomobject]@{ Name = $c.Name; Category = $c.Category; Reason = "license $($r.LicenseId) (from the $($r.LicenseFrom)) is not approved" }; continue
        }
        if ($r.Quality -lt $MinQuality -or $r.Score -lt $MinScore) {
            $excluded += [pscustomobject]@{ Name = $c.Name; Category = $c.Category; Reason = "YARA-Forge quality $($r.Quality) / score $($r.Score) below $MinQuality / $MinScore" }; continue
        }

        $modules = @(Get-UsedModules $r.Text)
        $bad = @($modules | Where-Object { $AllowedModules -notcontains $_ })
        if ($bad.Count -gt 0) {
            $excluded += [pscustomobject]@{ Name = $c.Name; Category = $c.Category; Reason = "uses module(s) $($bad -join ', ') (allowed: $($AllowedModules -join ', '))" }; continue
        }

        $ruleText = $r.Text
        $notes = @()
        if ($Ports.ContainsKey($c.Name)) {
            $p = $Ports[$c.Name]
            $ported = [regex]::Replace($ruleText, $p.Find, $p.Replace)
            if ($ported -eq $ruleText) { throw "The port for $($c.Name) no longer applies (the upstream rule changed); review it." }
            $ruleText = $ported
            $notes += $p.Note
        }

        $ruleText = Invoke-GenericPorts $ruleText ([ref]$notes)
        $portNote = if ($notes.Count -gt 0) { 'YARA-X port: ' + ($notes -join '; ') } else { $null }

        # sap-AV meta first (the loader takes the first value of a meta name).
        $metaMatch = [regex]::Match($ruleText, '(?m)^(?<indent>[ \t]*)meta:[ \t]*\n(?<inner>[ \t]*)')
        if (-not $metaMatch.Success) { $excluded += [pscustomobject]@{ Name = $c.Name; Category = $c.Category; Reason = 'no meta section' }; continue }
        $in = $metaMatch.Groups['inner'].Value
        $add = "${in}verdict = `"$($c.Verdict)`"`n${in}category = `"$($c.Category)`"`n${in}mitre = `"$($c.Mitre)`"`n${in}license_spdx = `"$($r.LicenseId)`"`n"
        if (-not $r.HasLicense) { $add += "${in}license = `"$($r.LicenseId) (license of the source repository, see licenses/$($r.Repo.Slug).txt)`"`n" }
        if ($portNote) { $add += "${in}sapav_port = `"$portNote`"`n" }
        $insertAt = $metaMatch.Index + $metaMatch.Length - $in.Length
        $ruleText = $ruleText.Insert($insertAt, $add)

        $imports = ($modules | Sort-Object | ForEach-Object { "import `"$_`"`n" }) -join ''
        $compile = Test-Compile ($imports + $ruleText)
        if ($compile.Error) { $excluded += [pscustomobject]@{ Name = $c.Name; Category = $c.Category; Reason = $compile.Error }; continue }

        $kept += [pscustomobject]@{ Name = $c.Name; Category = $c.Category; Verdict = $c.Verdict; Rule = $r; Text = $ruleText; Modules = $modules; Port = $portNote; Warnings = $compile.Warnings }
    }

    # --- Write rule files, licenses, NOTICE.md ---

    Get-ChildItem -LiteralPath $Here -Filter '*.yar' | Remove-Item
    $licenseDir = Join-Path $Here 'licenses'
    if (-not (Test-Path $licenseDir)) { New-Item -ItemType Directory -Path $licenseDir | Out-Null }
    Get-ChildItem -LiteralPath $licenseDir -Filter '*.txt' | Where-Object { $_.Name -notlike 'standard-*' } | Remove-Item

    $files = @()
    foreach ($group in ($kept | Group-Object { "$($_.Category)|$($_.Rule.RepoKey)" } | Sort-Object Name)) {
        $first = $group.Group[0]
        $repo = $first.Rule.Repo
        $fileName = "$($first.Category)-$($repo.Slug).yar"
        $licenses = ($group.Group | ForEach-Object { $_.Rule.LicenseId } | Sort-Object -Unique) -join ', '
        $mods = @($group.Group | ForEach-Object { $_.Modules } | Sort-Object -Unique)
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("/*`n * sap-AV third-party YARA rules: $($first.Category) rules from $($repo.Name)`n")
        [void]$sb.Append(" * Source: $($repo.Url) (commit $($repo.Commit), retrieved $($repo.Retrieved))`n")
        [void]$sb.Append(" * Via YARA-Forge release $Release ($Package package), https://github.com/YARAHQ/yara-forge`n")
        [void]$sb.Append(" * License: $licenses. Each rule keeps its original author, reference and license meta;`n")
        [void]$sb.Append(" * see NOTICE.md and licenses/ in this folder.`n")
        [void]$sb.Append(" * GENERATED by update.ps1 from curated-rules.txt. Do not edit by hand.`n")
        $ported = @($group.Group | Where-Object { $_.Port })
        if ($ported.Count -gt 0) { foreach ($p in $ported) { [void]$sb.Append(" * sap-AV port of $($p.Name): $($p.Port)`n") } }
        else { [void]$sb.Append(" * No rule in this file was changed except for the added sap-AV meta (verdict, category, mitre, license_spdx).`n") }
        [void]$sb.Append(" */`n`n")
        foreach ($mod in $mods) { [void]$sb.Append("import `"$mod`"`n") }
        if ($mods.Count -gt 0) { [void]$sb.Append("`n") }
        foreach ($k in ($group.Group | Sort-Object Name)) { [void]$sb.Append($k.Text).Append("`n`n") }
        Write-Text (Join-Path $Here $fileName) ($sb.ToString().TrimEnd() + "`n")
        $files += [pscustomobject]@{ File = $fileName; Count = $group.Count }
    }

    # License texts of the source repositories whose license applies to a vendored rule.
    $usedRepos = @($kept | ForEach-Object { $_.Rule.RepoKey } | Sort-Object -Unique)
    foreach ($key in $usedRepos) {
        $repo = $repos[$key]
        if ($repo.LicenseId -eq 'none' -or $repo.LicenseId -eq 'unknown') { continue }
        Write-Text (Join-Path $licenseDir "$($repo.Slug).txt") ("License of $($repo.Name) ($($repo.Url)), as published in that repository at commit $($repo.Commit):`n`n" + $repo.LicenseRaw + "`n")
    }

    # NOTICE.md
    $n = New-Object System.Text.StringBuilder
    [void]$n.Append("# Third-party YARA rules (YARA-Forge subset)`n`n")
    [void]$n.Append("sap-AV ships a curated subset of public YARA rules for infostealers, cryptominers and hack tools (ROADMAP E2).`n")
    [void]$n.Append("These are **rules only**; no malware samples are included or used. The files here are generated by ``update.ps1``;`n")
    [void]$n.Append("the selection and the sap-AV verdict / category / MITRE mapping are in ``curated-rules.txt``.`n`n")
    [void]$n.Append("## Source`n`n| | |`n|---|---|`n")
    [void]$n.Append("| Project | YARA-Forge, https://github.com/YARAHQ/yara-forge (rule packages built from the public repositories listed below) |`n")
    [void]$n.Append("| Release | ``$Release`` (YARA-Forge $forgeVersion, package created $creationDate) |`n")
    [void]$n.Append("| Asset | ``$assetName`` |`n| URL | $assetUrl |`n| Asset SHA-256 | ``$($Sha256.ToLowerInvariant())`` |`n")
    [void]$n.Append("| Filters | approved license; YARA-Forge quality >= $MinQuality and score >= $MinScore; modules ``pe``, ``math``, ``hash`` only; compiles alone under YARA-X $YaraXVersion with slow patterns/loops as errors and only benign compiler warnings |`n`n")
    [void]$n.Append("Rules are never downloaded at runtime. To update: change ``-Release`` / ``-Sha256`` in ``update.ps1`` (compare the hash with the digest GitHub publishes for the asset), run it, review the diff, and run the tests.`n`n")
    [void]$n.Append("## Licensing`n`n")
    [void]$n.Append("Only rules under DRL 1.1, MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, CC0-1.0 or CC-BY-4.0 are committed (decided 2026-11-11).`n")
    [void]$n.Append("A rule's own ``license`` meta decides; if it has none, its source repository's license applies (then ``update.ps1`` adds a ``license`` meta naming it).`n")
    [void]$n.Append("Every vendored rule also gets ``license_spdx``. GPL, non-commercial (NC), share-alike (CC BY-SA), missing and unknown licenses are excluded.`n`n")
    [void]$n.Append("### Vendored rules by license`n`n| License | Rules |`n|---|---|`n")
    foreach ($g in ($kept | Group-Object { $_.Rule.LicenseId } | Sort-Object Name)) { [void]$n.Append("| $($g.Name) | $($g.Count) |`n") }
    [void]$n.Append("| **Total** | **$($kept.Count)** |`n`n")
    [void]$n.Append("### Vendored rules by category`n`n| Category | sap-AV verdict | Rules |`n|---|---|---|`n")
    foreach ($g in ($kept | Group-Object { "$($_.Category)|$($_.Verdict)" } | Sort-Object Name)) {
        $cv = $g.Name -split '\|'
        $shown = switch ($cv[1]) { 'malicious' { 'Malicious' } 'suspicious' { 'Suspicious' } default { 'PotentiallyUnwanted (never quarantined automatically)' } }
        [void]$n.Append("| $($cv[0]) | $shown | $($g.Count) |`n")
    }
    [void]$n.Append("`n### Attribution`n`nThe rules were written by the authors named in each rule's ``author`` meta and published in these repositories:`n`n")
    [void]$n.Append("| Source | Repository | Commit | License | Rules | License text |`n|---|---|---|---|---|---|`n")
    foreach ($key in $usedRepos) {
        $repo = $repos[$key]
        $count = @($kept | Where-Object { $_.Rule.RepoKey -eq $key }).Count
        $ids = (@($kept | Where-Object { $_.Rule.RepoKey -eq $key } | ForEach-Object { $_.Rule.LicenseId }) | Sort-Object -Unique) -join ', '
        $licFile = if ($repo.LicenseId -eq 'none' -or $repo.LicenseId -eq 'unknown') { 'per-rule license meta; `licenses/standard-*.txt`' } else { "``licenses/$($repo.Slug).txt``" }
        $commit = if ($repo.Commit.Length -ge 12) { $repo.Commit.Substring(0, 12) } else { $repo.Commit }
        [void]$n.Append("| $($repo.Name) | $($repo.Url) | ``$commit`` | $ids | $count | $licFile |`n")
    }
    [void]$n.Append("`nStandard license texts for licenses given per rule: ``licenses/standard-Apache-2.0.txt``, ``licenses/standard-DRL-1.1.txt``.`n")
    [void]$n.Append("YARA-Forge itself is licensed under the GNU GPL v3; its code is not included here, only rule text from the repositories above under their own licenses.`n`n")
    [void]$n.Append("## Files`n`n| File | Rules |`n|---|---|`n")
    foreach ($f in $files) { [void]$n.Append("| ``$($f.File)`` | $($f.Count) |`n") }
    [void]$n.Append("`n## Excluded from the curated list`n`n")
    if ($excluded.Count -eq 0) { [void]$n.Append("None.`n") }
    else {
        [void]$n.Append("These rules are listed in ``curated-rules.txt`` but were not vendored. A rule that fails to compile under YARA-X is skipped here and listed with the compiler's message.`n`n| Rule | Category | Reason |`n|---|---|---|`n")
        foreach ($e in ($excluded | Sort-Object Name)) { [void]$n.Append("| ``$($e.Name)`` | $($e.Category) | $(($e.Reason -replace '\|', '/') -replace '\s+', ' ') |`n") }
    }
    $warned = @($kept | Where-Object { $_.Warnings.Count -gt 0 })
    [void]$n.Append("`n## Vendored with YARA-X compiler warnings`n`n")
    if ($warned.Count -eq 0) { [void]$n.Append("None.`n") }
    else {
        [void]$n.Append("Only warnings that don't change what a rule matches are accepted ($($BenignWarnings -join ', ')); the engine logs them as rule load warnings.`n`n| Rule | Warnings |`n|---|---|`n")
        foreach ($w in ($warned | Sort-Object Name)) { [void]$n.Append("| ``$($w.Name)`` | $($w.Warnings -join ', ') |`n") }
    }
    [void]$n.Append("`n## Whole release by license (for reference)`n`nAll $($rules.Count) rules of the release package by effective license; only the approved ones may be vendored.`n`n| License | Rules | Approved |`n|---|---|---|`n")
    foreach ($g in ($rules.Values | Group-Object LicenseId | Sort-Object Count -Descending)) {
        $ok = if ($ApprovedLicenses -contains $g.Name) { 'yes' } else { 'no' }
        $label = switch ($g.Name) { 'none' { 'none (no license set)' } 'GPL' { 'GPL (any version)' } 'NC' { 'non-commercial (NC)' } 'CC-BY-SA' { 'CC BY-SA (share-alike)' } default { $g.Name } }
        [void]$n.Append("| $label | $($g.Count) | $ok |`n")
    }
    Write-Text (Join-Path $Here 'NOTICE.md') $n.ToString()

    Write-Host ""
    Write-Host "Kept $($kept.Count) of $($curated.Count) curated rules in $($files.Count) files; excluded $($excluded.Count):"
    $kept | Group-Object Category | ForEach-Object { Write-Host ("  {0,-12} {1}" -f $_.Name, $_.Count) }
    $excluded | ForEach-Object { Write-Host ("  EXCLUDED {0}: {1}" -f $_.Name, $_.Reason) }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
