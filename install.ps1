<#
.SYNOPSIS
    Install crowsnest as a command on Windows.

.DESCRIPTION
    One line, from any PowerShell prompt:

        irm https://raw.githubusercontent.com/t0mbo192/crowsnest/main/install.ps1 | iex

    Or from a clone: .\install.ps1

    Puts a `crowsnest` command in %LOCALAPPDATA%\Programs\crowsnest and adds that
    folder to your user PATH, so you can run `crowsnest` from any terminal.

    Everything is per-user: no administrator rights are needed and nothing
    machine-wide is touched. Only your own PATH is changed, and -Uninstall puts
    it back.

    Run from a clone and the command runs crowsnest from that clone, so
    `git pull` updates it. Piped from the web there is no clone, so the source is
    fetched into the install folder first -- git if you have it, a zip download
    if you do not.

    Anything missing -- Python, Wireshark -- is reported with the exact command
    that would fix it, and installed only if you say yes. Nothing runs unasked.

    To pass a flag through the one-line form, use the script block version:

        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/t0mbo192/crowsnest/main/install.ps1))) -Uninstall

.PARAMETER Exe
    Install this crowsnest.exe rather than running from source.

.PARAMETER Prefix
    Install somewhere other than %LOCALAPPDATA%\Programs\crowsnest.

.PARAMETER Yes
    Answer yes to every prompt (unattended).

.PARAMETER Uninstall
    Remove the command, the source it fetched, and the PATH entry.

.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -Exe .\crowsnest.exe
.EXAMPLE
    .\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string] $Exe,
    [string] $Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\crowsnest'),
    [switch] $Yes,
    [switch] $Uninstall
)

# Restored at the end: piped into iex this runs in the caller's own session, and
# leaving their preference changed would be rude.
$PreviousEAP = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

$RepoUrl = 'https://github.com/t0mbo192/crowsnest.git'
$ZipUrl = 'https://codeload.github.com/t0mbo192/crowsnest/zip/refs/heads/main'

# Whether this is a real script on disk decides two things: where the source
# comes from, and whether it is safe to call exit. Under iex, exit would close
# the user's console.
$SelfPath = $MyInvocation.MyCommand.Path

function Say([string] $Label, [string] $Value) {
    Write-Host ("  {0,-19} {1}" -f $Label, $Value)
}

# Throws rather than exits, so the one-line form cannot take the window with it.
function Fail([string] $Message) { throw $Message }

function Ask([string] $Question) {
    if ($Yes) { return $true }
    if (-not [Environment]::UserInteractive) {
        Write-Host "  $Question [y/N] no console to ask on, assuming no"
        return $false
    }
    $answer = Read-Host "  $Question [y/N]"
    return ($answer -match '^\s*(y|yes)\s*$')
}

# What is printed is exactly what runs -- one string, shown then executed, so
# the two can never drift apart.
function Offer([string] $What, [string] $Command, [string] $Why) {
    Write-Host ""
    if ($Why) {
        Write-Host "  $What is required -- $Why."
    } else {
        Write-Host "  $What is required."
    }
    Write-Host ""
    if (-not $Command) {
        Write-Host "      (no known command for this system)"
        Write-Host ""
        return $false
    }
    Write-Host "      $Command"
    Write-Host ""
    if (-not (Ask "Run that now?")) { return $false }
    Write-Host ""
    Invoke-Expression $Command
    return $true
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

function Find-Python {
    foreach ($name in @('python', 'python3', 'py')) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $found) { continue }
        $ok = Get-PythonOutput $found.Source "import sys; print(1 if sys.version_info >= (3,10) else 0)"
        if ($ok -eq '1') { return $found.Source }
    }
    return $null
}

function Find-Tshark {
    $found = Get-Command tshark -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    foreach ($candidate in @(
        "$env:ProgramFiles\Wireshark\tshark.exe",
        "${env:ProgramFiles(x86)}\Wireshark\tshark.exe")) {
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
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

function Get-Source([string] $Into) {
    <#
        Fetch crowsnest itself. git keeps `git pull` working as the update path;
        without it a zip is enough, since crowsnest is pure Python and nothing
        here compiles.
    #>
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git -and (Test-Path (Join-Path $Into '.git'))) {
        & git -C $Into pull --ff-only --quiet
        if ($LASTEXITCODE -ne 0) { Fail "could not update $Into -- delete it and re-run" }
        Say "source" "$Into (updated)"
        return $true
    }
    if ($git -and -not (Test-Path $Into)) {
        & git clone --quiet --depth 1 $RepoUrl $Into
        if ($LASTEXITCODE -ne 0) { Fail "could not clone $RepoUrl" }
        Say "source" $Into
        return $true
    }
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("crowsnest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    try {
        $zip = Join-Path $temp 'crowsnest.zip'
        # Progress rendering makes Invoke-WebRequest dramatically slower.
        $prevProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try { Invoke-WebRequest -Uri $ZipUrl -OutFile $zip -UseBasicParsing }
        finally { $ProgressPreference = $prevProgress }
        Expand-Archive -Path $zip -DestinationPath $temp -Force
        $inner = Get-ChildItem -Directory $temp | Select-Object -First 1
        if (-not $inner) { Fail "downloaded archive was empty" }
        New-Item -ItemType Directory -Force -Path $Into | Out-Null
        Copy-Item -Path (Join-Path $inner.FullName '*') -Destination $Into -Recurse -Force
        Say "source" "$Into (no git -- re-run the installer to update)"
    } finally {
        Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
    }
    return $false
}

$Failed = $false
try {
    $shim = Join-Path $Prefix 'crowsnest.cmd'

    # --- uninstall -----------------------------------------------------------
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
        if ($SelfPath) {
            Write-Host "The clone at $(Split-Path -Parent $SelfPath) is untouched."
        }
        Write-Host ""
        return
    }

    Write-Host ""
    Write-Host "crowsnest setup"
    Write-Host "==============="
    Write-Host ""
    Say "platform" ("Windows {0}" -f [Environment]::OSVersion.Version)

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Say "winget" "not available -- missing pieces will be reported, not offered"
    }

    # --- where the source is -------------------------------------------------
    # Running from a clone means this file sits next to crowsnest.py. Piped into
    # iex there is no file at all, so test for the source rather than for how we
    # were invoked.
    $RepoDir = $null
    if ($SelfPath) {
        $dir = Split-Path -Parent $SelfPath
        if (Test-Path (Join-Path $dir 'crowsnest.py')) { $RepoDir = $dir }
    }
    $bootstrap = -not $RepoDir
    if ($bootstrap) { $RepoDir = Join-Path $Prefix 'src' }

    # --- python --------------------------------------------------------------
    $python = $null
    if (-not $Exe) {
        $python = Find-Python
        if (-not $python) {
            $cmd = ''
            if ($winget) { $cmd = 'winget install --id Python.Python.3.12' }
            Offer "Python 3.10 or newer" $cmd | Out-Null
            $python = Find-Python
            if (-not $python) {
                Fail "Python 3.10+ not found. Install it, or use -Exe with a downloaded crowsnest.exe."
            }
        }
        Say "python" $python
    }

    # --- tshark --------------------------------------------------------------
    $tshark = Find-Tshark
    if (-not $tshark) {
        $cmd = ''
        if ($winget) { $cmd = 'winget install --id WiresharkFoundation.Wireshark' }
        Offer "Wireshark" $cmd "crowsnest reads packets with its tshark" | Out-Null
        $tshark = Find-Tshark
        if (-not $tshark) {
            Write-Host "(or download it from https://www.wireshark.org)"
            Fail "Re-run this once Wireshark is installed."
        }
    }
    Say "tshark" $tshark

    # --- the source ----------------------------------------------------------
    New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
    $updateHint = ''
    if ($bootstrap -and -not $Exe) {
        $viaGit = Get-Source $RepoDir
        if (-not (Test-Path (Join-Path $RepoDir 'crowsnest.py'))) {
            Fail "crowsnest.py missing from $RepoDir"
        }
        if ($viaGit) { $updateHint = "cd $RepoDir; git pull" }
        else { $updateHint = "re-run the install command" }
    } elseif (-not $Exe) {
        $updateHint = "cd $RepoDir; git pull"
    }

    # --- what to install -----------------------------------------------------
    $version = 'unknown'
    if ($Exe) {
        if (-not (Test-Path $Exe)) { Fail "no such file: $Exe" }
        Copy-Item -Force $Exe (Join-Path $Prefix 'crowsnest.exe')
        if (Test-Path $shim) { Remove-Item -Force $shim }
        Say "installed" (Join-Path $Prefix 'crowsnest.exe')
        $launcher = Join-Path $Prefix 'crowsnest.exe'
        try { $version = (& $launcher --version) -replace 'crowsnest\s*', '' } catch { }
        $updateHint = "download the new crowsnest.exe from Releases"
    } else {
        $entry = Join-Path $RepoDir 'crowsnest.py'
        if (-not (Test-Path $entry)) { Fail "crowsnest.py not found at $entry" }

        # A .cmd shim rather than a copy, so updating the source updates the
        # command too.
        @"
@echo off
rem Generated by crowsnest install.ps1 -- runs crowsnest from its source folder.
"$python" "$entry" %*
"@ | Set-Content -Path $shim -Encoding ascii
        Say "command" $shim
        $found = Get-PythonOutput $python "import sys; sys.path.insert(0,r'$RepoDir'); from crowsnest_version import __version__; print(__version__)"
        if ($found) { $version = $found }
    }

    # --- optional: organisation names for bare addresses ---------------------
    if (-not $Exe) {
        if (Test-PythonSnippet $python "import maxminddb") {
            $dbOk = Test-PythonSnippet $python "import sys; sys.path.insert(0,r'$RepoDir'); import asn_lookup; sys.exit(0 if asn_lookup.available() else 1)"
            if ($dbOk) {
                Say "ASN database" "ok"
            } else {
                Say "ASN database" "missing -- bare addresses will stay unnamed"
                Write-Host "        crowsnest asn --fetch"
            }
        } else {
            Say "maxminddb" "not installed (optional, names address owners)"
            Write-Host "        pip install maxminddb"
            Write-Host "        crowsnest asn --fetch"
        }
    }

    # --- PATH ----------------------------------------------------------------
    $added = Add-ToUserPath $Prefix
    if ($added) {
        Say "PATH" "added $Prefix"
    } else {
        Say "PATH" "already contains $Prefix"
    }

    Write-Host ""
    Write-Host "Done -- crowsnest $version is installed."
    Write-Host ""
    if ($added) {
        Write-Host "  Open a new terminal for the PATH change to take effect."
        Write-Host ""
    }
    # Numbered because it is a sequence: step 2 needs a number that step 1
    # prints. The old text named an interface as though it were a safe guess and
    # never mentioned --dashboard at all, which is the view people install this
    # for -- it is the one in the screenshot.
    Write-Host "  To watch traffic:"
    Write-Host ""
    Write-Host "    1.  crowsnest interfaces             marks the one your traffic uses"
    Write-Host "    2.  crowsnest live -i N --dashboard  with that number"
    Write-Host ""
    Write-Host "  Press q to leave the dashboard. Drop --dashboard for a plain"
    Write-Host "  list that prints each host once and then stays quiet."
    Write-Host ""
    Write-Host "  Live capture may need an administrator terminal, depending on"
    Write-Host "  how Npcap was installed with Wireshark. Reading a saved capture"
    Write-Host "  never does:"
    Write-Host ""
    Write-Host "    crowsnest read capture.pcapng"
    Write-Host ""
    if ($updateHint) {
        Write-Host "  Update:     $updateHint"
    }
    Write-Host "  Uninstall:  see -Uninstall in the help"
    Write-Host ""
} catch {
    Write-Host ""
    Write-Host "[!] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    $Failed = $true
} finally {
    $ErrorActionPreference = $PreviousEAP
}

# Only a real script may exit: piped into iex, this would close the console.
if ($Failed -and $SelfPath) { exit 1 }
