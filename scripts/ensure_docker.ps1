# ensure_docker.ps1 -- bring the Docker engine and named containers up if down.
# No pull, no build, no create, no run, no volume deletion. Existing containers
# only. Owner-facing wrapper for the auditor and builder.
# -EngineOnly stops after the engine is ready; it never inspects or starts a
# container (used by scripts/k1_up.ps1 before it creates k1 resources).

[CmdletBinding()]
param(
    [string[]]$Containers = @('pg2a', 'pg2b'),

    [switch]$All,

    [switch]$EngineOnly,

    [switch]$WhatIf,

    [int]$TimeoutSec = 120
)

$ErrorActionPreference = 'Stop'

function Refuse([string]$Message) {
    [Console]::Error.WriteLine("ensure_docker: refused: $Message")
    exit 2
}

function Test-Docker {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & docker info *> $null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    return ($code -eq 0)
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Refuse 'docker not found on PATH'
}

# 1. Engine.
if (-not (Test-Docker)) {
    $service = Get-Service com.docker.service -ErrorAction SilentlyContinue
    $engine = Get-Service docker -ErrorAction SilentlyContinue
    $desktop = @(
        'C:\Program Files\Docker\Docker\Docker Desktop.exe',
        'C:\Program Files\Docker\Docker\Docker Desktop.exe'
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if ($WhatIf) {
        Write-Output 'would start: com.docker.service or docker service (if present and stopped)'
        Write-Output "would start: Docker Desktop ($desktop)"
        Write-Output "would wait up to $TimeoutSec s for docker info"
    }
    else {
        foreach ($svc in @($engine, $service)) {
            if ($null -eq $svc -or $svc.Status -eq 'Running') { continue }
            try {
                Start-Service -Name $svc.Name -ErrorAction Stop
                Write-Output "started service $($svc.Name)"
            }
            catch {
                Write-Output "service $($svc.Name) start failed: $($_.Exception.Message)"
            }
        }

        if ($desktop -and -not (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)) {
            try {
                Start-Process -FilePath $desktop -WindowStyle Minimized | Out-Null
                Write-Output 'started Docker Desktop'
            }
            catch {
                Write-Output "Docker Desktop start failed: $($_.Exception.Message)"
            }
        }

        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        while ((Get-Date) -lt $deadline -and -not (Test-Docker)) {
            Start-Sleep -Seconds 2
        }
        if (-not (Test-Docker)) {
            Refuse "docker engine did not become ready within $TimeoutSec s; start Docker Desktop manually"
        }
    }
}

if (-not $WhatIf) {
    $version = (& docker info --format '{{.ServerVersion}}' 2>$null)
    Write-Output "docker engine: ready $("$version".Trim())"
}

# -EngineOnly: no container loop, no missing-container refusal.
if ($EngineOnly) {
    exit 0
}

# 2. Existing containers only. -All starts every stopped container.
$targets = if ($All) {
    @(& docker ps -a --format '{{.Names}}')
}
else {
    @($Containers | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
$missing = @()
foreach ($name in $targets) {
    if (-not $name) { continue }

    if ($WhatIf -and -not (Test-Docker)) {
        Write-Output "would start container $name (engine down)"
        continue
    }

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $running = (& docker inspect -f '{{.State.Running}}' $name 2>$null)
    $inspectCode = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($inspectCode -ne 0) {
        Write-Output "container ${name}: not found"
        $missing += $name
        continue
    }
    if ("$running".Trim() -eq 'true') {
        Write-Output "container ${name}: running"
        continue
    }

    if ($WhatIf) {
        Write-Output "would start container $name"
        continue
    }

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & docker start $name 2>$null | Out-Null
    $startCode = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($startCode -ne 0) {
        Refuse "docker start $name failed with exit $startCode"
    }
    Write-Output "container ${name}: started"
}

if ($missing.Count -gt 0) {
    [Console]::Error.WriteLine("ensure_docker: container(s) not found: $($missing -join ', ')")
    exit 2
}

exit 0
