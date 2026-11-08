# k1_down.ps1 -- tear down one K1 run.
#
# Copies /work/artifacts out first (when the app container exists), then
# removes only k1-<RunId>-app, k1-<RunId>-pg, k1-<RunId>-net and the run dir.
# It never runs `docker stop`, never prunes anything, never stops Docker or
# Docker Desktop, and never touches pg2a/pg2b. Missing pieces are fine.
#
# Exit codes: 0 = teardown complete or already absent.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [switch]$WhatIf,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Continue'

function Refuse([string]$Code, [string]$Message) {
    [Console]::Error.WriteLine("k1_down: refused: ${Code}: $Message")
    exit 2
}

# docker cp cannot read a tmpfs mount (it resolves host paths). Stream the same
# tree with `docker exec ... tar` while the container is still running.
function Copy-ArtifactsViaTar([string]$Container, [string]$Directory) {
    $tarPath = Join-Path $Directory 'artifacts.tar'
    $errPath = Join-Path $Directory 'artifacts.tar.err'
    try {
        $proc = Start-Process -FilePath 'docker' `
            -ArgumentList @('exec', $Container, 'tar', '-C', '/work', '-cf', '-', 'artifacts') `
            -RedirectStandardOutput $tarPath -RedirectStandardError $errPath `
            -Wait -NoNewWindow -PassThru
        if ($proc.ExitCode -ne 0) {
            $message = (Get-Content -LiteralPath $errPath -ErrorAction SilentlyContinue | Out-String).Trim()
            return @{ Ok = $false; Message = $message }
        }
        & tar -x -f $tarPath -C $Directory
        if ($LASTEXITCODE -ne 0) {
            return @{ Ok = $false; Message = 'tar extract failed' }
        }
        return @{ Ok = $true; Message = '' }
    }
    finally {
        Remove-Item -LiteralPath $tarPath, $errPath -Force -ErrorAction SilentlyContinue
    }
}

if ([string]::IsNullOrWhiteSpace($RunId) -or
    $RunId -notmatch '^[A-Za-z0-9._-]+$' -or
    $RunId -eq '.' -or $RunId -eq '..' -or
    $RunId.Length -gt 48) {
    Refuse 'BAD_RUN_ID' '-RunId must match ^[A-Za-z0-9._-]+$, must not be . or .., and must be at most 48 chars'
}

$RunRoot = Join-Path (Join-Path $env:LOCALAPPDATA 'Temp\opencode') 'k1'
$RunDir = Join-Path $RunRoot $RunId
$Net = "k1-$RunId-net"
$Pg = "k1-$RunId-pg"
$App = "k1-$RunId-app"
$Artifacts = Join-Path $RunDir 'artifacts'

if ($WhatIf) {
    Write-Output "docker cp ${App}:/work/artifacts $Artifacts   # only if the app container exists; ignore 'no such file'"
    Write-Output "docker rm -f $App"
    Write-Output "docker rm -f $Pg"
    Write-Output "docker network rm $Net"
    if ($KeepArtifacts) {
        Write-Output "# keep run dir $RunDir (-KeepArtifacts)"
    }
    else {
        Write-Output "Remove-Item -LiteralPath $RunDir -Recurse -Force"
    }
    exit 0
}

& docker info *> $null
$dockerUp = ($LASTEXITCODE -eq 0)
if (-not $dockerUp) {
    Write-Output 'docker engine: down; skipping container/network removal (ok)'
    if (Test-Path -LiteralPath $RunDir) {
        Write-Output 'warning: artifacts were not copied; use -KeepArtifacts to keep the run dir'
    }
}

if ($dockerUp) {
    # --- artifacts before the container goes away -----------------------
    & docker inspect $App *> $null
    if ($LASTEXITCODE -eq 0) {
        New-Item -ItemType Directory -Path $RunDir -Force -ErrorAction SilentlyContinue | Out-Null
        $copyOutput = (& docker cp "${App}:/work/artifacts" $Artifacts 2>&1 | Out-String)
        if ($LASTEXITCODE -eq 0) {
            Write-Output "artifacts: copied to $Artifacts"
        }
        elseif ($copyOutput -match 'no such file|Could not find the file|not found') {
            $running = (& docker inspect -f '{{.State.Running}}' $App 2>$null)
            if ($LASTEXITCODE -eq 0 -and "$running".Trim() -eq 'true') {
                $fallback = Copy-ArtifactsViaTar -Container $App -Directory $RunDir
                if ($fallback.Ok) {
                    Write-Output "artifacts: copied to $Artifacts (tmpfs tar fallback)"
                }
                elseif ($fallback.Message -match 'Not found|not found|No such file|no such file') {
                    Write-Output "artifacts: none in $App (ok)"
                }
                else {
                    Write-Output "artifacts: copy failed (continuing): $($fallback.Message)"
                }
            }
            else {
                Write-Output "artifacts: none in $App (ok; container not running)"
            }
        }
        else {
            Write-Output "artifacts: copy failed (continuing): $($copyOutput.Trim())"
        }
    }
    else {
        Write-Output "app container ${App}: not found (ok)"
    }

    # --- containers: rm -f only, never stop ------------------------------
    foreach ($name in @($App, $Pg)) {
        & docker inspect $name *> $null
        if ($LASTEXITCODE -eq 0) {
            & docker rm -f $name | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Output "container ${name}: removed"
            }
            else {
                Write-Output "container ${name}: remove failed (continuing)"
            }
        }
        else {
            Write-Output "container ${name}: not found (ok)"
        }
    }

    # --- network ---------------------------------------------------------
    & docker network inspect $Net *> $null
    if ($LASTEXITCODE -eq 0) {
        & docker network rm $Net | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Output "network ${Net}: removed"
        }
        else {
            Write-Output "network ${Net}: remove failed (continuing)"
        }
    }
    else {
        Write-Output "network ${Net}: not found (ok)"
    }
}

# --- run dir -------------------------------------------------------------
if (Test-Path -LiteralPath $RunDir) {
    if ($KeepArtifacts) {
        Write-Output "run dir: kept $RunDir (-KeepArtifacts)"
    }
    else {
        Remove-Item -LiteralPath $RunDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "run dir: removed $RunDir"
    }
}
else {
    Write-Output "run dir: not found (ok) $RunDir"
}

exit 0
