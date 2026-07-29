[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DefaultRepository = "https://github.com/kappa9999/white-hat-agent"
$DefaultRef = "main"
$DefaultPython = "3.12"
$DefaultUvInstaller = "https://astral.sh/uv/install.ps1"

function Get-WhiteHatEnvironmentValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Default
    )

    $Value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }
    return $Value
}

function Resolve-WhiteHatUv {
    $Requested = [Environment]::GetEnvironmentVariable("WHA_UV_BIN")
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        if (Test-Path -LiteralPath $Requested -PathType Leaf) {
            return (Resolve-Path -LiteralPath $Requested).Path
        }
        $RequestedCommand = Get-Command $Requested -ErrorAction SilentlyContinue
        if ($null -ne $RequestedCommand) {
            return $RequestedCommand.Source
        }
        throw "WHA_UV_BIN does not resolve to an executable: $Requested"
    }

    $UvCommand = Get-Command uv -ErrorAction SilentlyContinue
    if ($null -ne $UvCommand) {
        return $UvCommand.Source
    }

    $Candidates = [System.Collections.Generic.List[string]]::new()
    $UvInstallDirectory = [Environment]::GetEnvironmentVariable("UV_INSTALL_DIR")
    if (-not [string]::IsNullOrWhiteSpace($UvInstallDirectory)) {
        $Candidates.Add((Join-Path $UvInstallDirectory "uv.exe"))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $Candidates.Add((Join-Path $env:USERPROFILE ".local\bin\uv.exe"))
        $Candidates.Add((Join-Path $env:USERPROFILE ".cargo\bin\uv.exe"))
    }

    foreach ($Candidate in $Candidates) {
        if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $Candidate).Path
        }
    }
    return $null
}

$Repository = (Get-WhiteHatEnvironmentValue -Name "WHA_REPOSITORY" -Default $DefaultRepository).TrimEnd("/")
$Ref = Get-WhiteHatEnvironmentValue -Name "WHA_REF" -Default $DefaultRef
$PythonVersion = Get-WhiteHatEnvironmentValue -Name "WHA_PYTHON" -Default $DefaultPython
$UvInstallerUrl = Get-WhiteHatEnvironmentValue -Name "WHA_UV_INSTALLER_URL" -Default $DefaultUvInstaller
$SourceUrl = Get-WhiteHatEnvironmentValue -Name "WHA_SOURCE_URL" -Default "$Repository/archive/refs/heads/$Ref.zip"
$Package = Get-WhiteHatEnvironmentValue -Name "WHA_PACKAGE" -Default "white-hat-agent @ $SourceUrl"

$Uv = Resolve-WhiteHatUv
if ([string]::IsNullOrWhiteSpace($Uv)) {
    Write-Host "white-hat-agent: uv was not found; downloading the official uv installer"
    $Installer = Invoke-RestMethod -Uri $UvInstallerUrl
    & ([ScriptBlock]::Create([string]$Installer))
    $Uv = Resolve-WhiteHatUv
}
if ([string]::IsNullOrWhiteSpace($Uv)) {
    throw "uv installation completed but the executable could not be located"
}

Write-Host "white-hat-agent: installing or refreshing White Hat Agent Core with Python $PythonVersion"
& $Uv tool install --reinstall --refresh --python $PythonVersion $Package
if ($LASTEXITCODE -ne 0) {
    throw "uv tool install failed with exit code $LASTEXITCODE"
}

if ((Get-WhiteHatEnvironmentValue -Name "WHA_SKIP_PATH_UPDATE" -Default "0") -ne "1") {
    & $Uv tool update-shell
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not update the shell profile automatically."
    }
}

$BinDirectory = (& $Uv tool dir --bin | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($BinDirectory)) {
    throw "uv did not report its tool executable directory"
}
$Executable = Join-Path $BinDirectory "wha.exe"
if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
    throw "installation finished but wha.exe was not found in $BinDirectory"
}

$PathEntries = $env:Path -split [IO.Path]::PathSeparator
if ($PathEntries -notcontains $BinDirectory) {
    $env:Path = "$BinDirectory$([IO.Path]::PathSeparator)$env:Path"
}
$Version = & $Executable --version

Write-Host ""
Write-Host "$Version is ready."
Write-Host "Executable: $Executable"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  wha init white-hat-workspace"
Write-Host "  Set-Location white-hat-workspace"
Write-Host "  wha doctor"
