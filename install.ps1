<#
.SYNOPSIS
    Install netwatch as a command on Windows.

.DESCRIPTION
    Puts a `netwatch` command in %LOCALAPPDATA%\Programs\netwatch and adds that
    folder to your user PATH, so you can run `netwatch` from any terminal.

    Everything is per-user: no administrator rights are needed and nothing
    machine-wide is touched. Only your own PATH is changed, and -Uninstall puts
    it back.

    Run from a git clone and the command runs netwatch from that clone, so
    `git pull` updates it. Point -Exe at a downloaded netwatch.exe instead and
    that gets installed, with no Python needed.

.PARAMETER Exe
    Install this netwatch.exe rather than running from source.

.PARAMETER Prefix
    Install somewhere other than %LOCALAPPDATA%\Programs\netwatch.

.PARAMETER Uninstall
    Remove the command and the PATH entry.

.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -Exe .\netwatch.exe
.EXAMPLE
    .\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string] $Exe,
    [string] $Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\netwatch'),
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Say([string] $Label, [string] $Value) {
    Write-Host ("  {0,-19} {1}" -f $Label, $Value)
}
function Fail([string] $Message) {
    Write-Host ""
    Write-Host "[!] $Message" -ForegroundColor Red
    exit 1
}

# Windows PowerShell 5.1 turns a native command's stderr into an error record
# when $ErrorActionPreference is Stop, so probes get their own relaxed scope.
function Test-PythonSnippet([string] $Python, [string] $Code) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Python -c $Code 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Get-PythonOutput([string] $Python, [string] $Code) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Python -c $Code 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { return ($out | Select-Object -First 1).Trim() }
        return ''
    } catch {
        return ''
    } finally {
        $ErrorActionPreference = $previous
    }
}

# --- PATH handling (user scope only) ----------------------------------------
function Get-UserPath {
    $value = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $value) { return '' }
    return $value
}

function Add-ToUserPath([string] $Dir) {
    $current = Get-UserPath
    $entries = $current -split ';' | Where-Object { $_ -ne '' }
    foreach ($entry in $entries) {
        if ($entry.TrimEnd('\') -ieq $Dir.TrimEnd('\')) { return $false }
    }
    $updated = (@($entries) + $Dir) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    return $true
}

function Remove-FromUserPath([string] $Dir) {
    $entries = (Get-UserPath) -split ';' | Where-Object {
        $_ -ne '' -and $_.TrimEnd('\') -ine $Dir.TrimEnd('\')
    }
    [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'User')
}

# --- uninstall ---------------------------------------------------------------
if ($Uninstall) {
    if (Test-Path $Prefix) {
        Remove-Item -Recurse -Force $Prefix
        Write-Host ""
        Write-Host "Removed $Prefix"
    } else {
        Write-Host ""
        Write-Host "Nothing installed at $Prefix"
    }
    Remove-FromUserPath $Prefix
    Write-Host "Removed it from your user PATH."
    Write-Host "The clone at $RepoDir is untouched."
    Write-Host ""
    exit 0
}

Write-Host ""
Write-Host "netwatch setup"
Write-Host "=============="
Write-Host ""
Say "platform" ("Windows {0}" -f [Environment]::OSVersion.Version)

# --- tshark, which netwatch reads packets with -------------------------------
$tshark = Get-Command tshark -ErrorAction SilentlyContinue
if (-not $tshark) {
    foreach ($candidate in @(
        "$env:ProgramFiles\Wireshark\tshark.exe",
        "${env:ProgramFiles(x86)}\Wireshark\tshark.exe")) {
        if (Test-Path $candidate) { $tshark = Get-Item $candidate; break }
    }
}
if ($tshark) {
    # Get-Command yields .Source; Get-Item yields .FullName. No ternary in 5.1.
    $tsharkPath = $tshark.Source
    if (-not $tsharkPath) { $tsharkPath = $tshark.FullName }
    Say "tshark" $tsharkPath
} else {
    Write-Host ""
    Write-Host "tshark is required -- netwatch reads packets with it."
    Write-Host ""
    Write-Host "    winget install WiresharkFoundation.Wireshark"
    Write-Host ""
    Write-Host "(or download it from https://www.wireshark.org)"
    Fail "Re-run this script once Wireshark is installed."
}

# --- decide what to install --------------------------------------------------
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
$shim = Join-Path $Prefix 'netwatch.cmd'
$version = 'unknown'

if ($Exe) {
    if (-not (Test-Path $Exe)) { Fail "no such file: $Exe" }
    Copy-Item -Force $Exe (Join-Path $Prefix 'netwatch.exe')
    if (Test-Path $shim) { Remove-Item -Force $shim }
    Say "installed" (Join-Path $Prefix 'netwatch.exe')
    $launcher = Join-Path $Prefix 'netwatch.exe'
    try { $version = (& $launcher --version) -replace 'netwatch\s*','' } catch { }
} else {
    # Running from source: find a Python new enough to run netwatch.
    $python = $null
    foreach ($name in @('python', 'python3', 'py')) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $found) { continue }
        $ok = Get-PythonOutput $found.Source "import sys; print(1 if sys.version_info >= (3,10) else 0)"
        if ($ok -eq '1') { $python = $found.Source; break }
    }
    if (-not $python) {
        Fail "Python 3.10+ not found. Install it, or use -Exe with a downloaded netwatch.exe."
    }
    Say "python" $python
    $entry = Join-Path $RepoDir 'netwatch.py'
    if (-not (Test-Path $entry)) { Fail "netwatch.py not found next to this script." }

    # A .cmd shim rather than a copy, so `git pull` updates the command too.
    @"
@echo off
rem Generated by netwatch install.ps1 -- runs netwatch from its git clone.
"$python" "$entry" %*
"@ | Set-Content -Path $shim -Encoding ascii
    Say "command" $shim
    $found = Get-PythonOutput $python "import sys; sys.path.insert(0,r'$RepoDir'); from netwatch_version import __version__; print(__version__)"
    if ($found) { $version = $found }
}

# --- optional: organisation names for bare addresses ------------------------
if (-not $Exe) {
    if (Test-PythonSnippet $python "import maxminddb") {
        $dbOk = Test-PythonSnippet $python "import sys; sys.path.insert(0,r'$RepoDir'); import asn_lookup; sys.exit(0 if asn_lookup.available() else 1)"
        if ($dbOk) {
            Say "ASN database" "ok"
        } else {
            Say "ASN database" "missing -- bare addresses will stay unnamed"
            Write-Host "        netwatch asn --fetch"
        }
    } else {
        Say "maxminddb" "not installed (optional, names address owners)"
        Write-Host "        pip install maxminddb"
        Write-Host "        netwatch asn --fetch"
    }
}

# --- PATH --------------------------------------------------------------------
$added = Add-ToUserPath $Prefix
if ($added) {
    Say "PATH" "added $Prefix"
} else {
    Say "PATH" "already contains $Prefix"
}

Write-Host ""
Write-Host "Done -- netwatch $version is installed."
Write-Host ""
if ($added) {
    Write-Host "  Open a new terminal for the PATH change to take effect."
    Write-Host ""
}
Write-Host "  See interfaces      netwatch interfaces"
Write-Host "  Watch live          netwatch live -i Ethernet     (elevated terminal)"
Write-Host "  Read a capture      netwatch read capture.pcapng"
if (-not $Exe) {
    Write-Host "  Update              cd $RepoDir; git pull"
}
Write-Host "  Uninstall           $RepoDir\install.ps1 -Uninstall"
Write-Host ""
