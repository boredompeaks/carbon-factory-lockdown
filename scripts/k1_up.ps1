# k1_up.ps1 -- start one K1 sandbox run: internal network, tmpfs Postgres, app.
#
# It never pulls and never builds. The app image must already exist locally.
# It never touches pg2a/pg2b, Docker Desktop, or any resource that is not named
# k1-<RunId>-*; it does not stop Docker.
#
# Exit codes: 0 = up, 1 = runtime failure (created resources cleaned up),
# 2 = refusal before/without changes, 3 = IMAGE_MISSING.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$Base,
    [Parameter(Mandatory = $true)][string]$Head,
    [string]$Repo = $null,
    [string]$AppImage = 'k1-app:latest',
    [string]$PgImage = 'postgres:17-alpine',
    [switch]$WhatIf
)

$ErrorActionPreference = 'Continue'

$script:Created = @{ RunDir = $false; Net = $false; Pg = $false; App = $false }

function Refuse([string]$Code, [string]$Message, [int]$CodeExit = 2) {
    [Console]::Error.WriteLine("k1_up: refused: ${Code}: $Message")
    exit $CodeExit
}

function Fail([string]$Message) {
    throw $Message
}

function Test-Exists([string]$Name) {
    & docker inspect $Name *> $null
    return ($LASTEXITCODE -eq 0)
}

function Remove-Excluded([string]$Root) {
    $removed = 0
    foreach ($relative in @('backend\venv', 'backend\.venv', 'quality')) {
        $path = Join-Path $Root $relative
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
            $removed++
        }
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Recurse -Force -Filter '.env*' -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
        $removed++
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Recurse -Force -Directory -Filter 'venv' -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
        $removed++
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Recurse -Force -Directory -Filter 'quality' -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
        $removed++
    }
    return $removed
}

# --- args ---------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($RunId) -or
    $RunId -notmatch '^[A-Za-z0-9._-]+$' -or
    $RunId -eq '.' -or $RunId -eq '..' -or
    $RunId.Length -gt 48) {
    Refuse 'BAD_RUN_ID' '-RunId must match ^[A-Za-z0-9._-]+$, must not be . or .., and must be at most 48 chars'
}

# Real runs require a full SHA-1 (40) or SHA-256 (64). -WhatIf also accepts an
# abbreviated 7-64 hex id so the documented dry run works before a commit is
# resolved; nothing is executed in that mode anyway.
$shaPattern = if ($WhatIf) { '^[0-9a-fA-F]{7,64}$' } else { '^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$' }
if ($Base -notmatch $shaPattern) {
    Refuse 'BAD_SHA' '-Base must be a 40/64 hex commit id (7-64 hex accepted with -WhatIf)'
}
if ($Head -notmatch $shaPattern) {
    Refuse 'BAD_SHA' '-Head must be a 40/64 hex commit id (7-64 hex accepted with -WhatIf)'
}

# Discover the worktree when -Repo is omitted (git rev-parse --show-toplevel).
if ([string]::IsNullOrWhiteSpace($Repo)) {
    $discovered = (& git rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -eq 0 -and "$discovered".Trim()) { $Repo = "$discovered".Trim() }
    else { $Repo = (Get-Location).Path }
}

if (-not (Test-Path -LiteralPath $Repo -PathType Container)) {
    Refuse 'REPO_MISSING' "repository not found: $Repo"
}

$RunRoot = Join-Path (Join-Path $env:LOCALAPPDATA 'Temp\opencode') 'k1'
$RunDir = Join-Path $RunRoot $RunId
$Net = "k1-$RunId-net"
$Pg = "k1-$RunId-pg"
$App = "k1-$RunId-app"

# --- engine -------------------------------------------------------------
$ensure = Join-Path $PSScriptRoot 'ensure_docker.ps1'
if (-not (Test-Path -LiteralPath $ensure)) {
    Refuse 'ENSURE_MISSING' "missing $ensure"
}
$ensureArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ensure, '-EngineOnly')
if ($WhatIf) { $ensureArgs += '-WhatIf' }
$hostExe = (Get-Process -Id $PID).Path
& $hostExe @ensureArgs
$ensureExit = $LASTEXITCODE
if (-not $WhatIf -and $ensureExit -ne 0) {
    Refuse 'DOCKER_DOWN' "ensure_docker.ps1 -EngineOnly failed with exit $ensureExit"
}

# --- preflight (real run only; -WhatIf executes nothing) ----------------
if (-not $WhatIf) {
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Refuse 'DOCKER_DOWN' 'docker engine is not ready after ensure_docker'
    }

    & docker image inspect $AppImage *> $null
    if ($LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine("k1_up: refused: IMAGE_MISSING: $AppImage is not present locally (not pulling, not building)")
        [Console]::Error.WriteLine("k1_up: build it first (owner/FDE only): docker build --pull=false -t $AppImage files/docker/k1")
        exit 3
    }
    & docker image inspect $PgImage *> $null
    if ($LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine("k1_up: refused: IMAGE_MISSING: $PgImage is not present locally (not pulling)")
        exit 3
    }

    & git -C $Repo rev-parse --git-dir *> $null
    if ($LASTEXITCODE -ne 0) {
        Refuse 'REPO_NOT_GIT' "$Repo is not a git work tree"
    }
    foreach ($sha in @($Base, $Head)) {
        & git -C $Repo cat-file -e "$sha^{commit}"
        if ($LASTEXITCODE -ne 0) {
            Refuse 'COMMIT_NOT_FOUND' "commit $sha not found in $Repo"
        }
    }

    foreach ($name in @($Net, $Pg, $App)) {
        if (Test-Exists $name) {
            Refuse 'NAME_EXISTS' "$name already exists; run scripts\k1_down.ps1 -RunId $RunId first"
        }
    }
    if (Test-Path -LiteralPath $RunDir) {
        Refuse 'RUN_DIR_EXISTS' "$RunDir already exists; run scripts\k1_down.ps1 -RunId $RunId first"
    }
}
else {
    Write-Output "# k1_up -WhatIf RunId=$RunId (no command is executed)"
}

$rngBytes = New-Object 'byte[]' 12
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($rngBytes)
$rng.Dispose()
$pgPass = -join ($rngBytes | ForEach-Object { $_.ToString('x2') })

try {
    # --- repo archives ---------------------------------------------------
    if ($WhatIf) {
        Write-Output "New-Item -ItemType Directory -Force $RunDir\repo-base"
        Write-Output "New-Item -ItemType Directory -Force $RunDir\repo-head"
    }
    else {
        New-Item -ItemType Directory -Path (Join-Path $RunDir 'repo-base') -Force -ErrorAction Stop | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $RunDir 'repo-head') -Force -ErrorAction Stop | Out-Null
        $script:Created.RunDir = $true
        Write-Output "run dir: $RunDir"
    }

    foreach ($spec in @(
            @{ Sha = $Base; Sub = 'repo-base'; Tar = 'base.tar'; Label = 'base' },
            @{ Sha = $Head; Sub = 'repo-head'; Tar = 'head.tar'; Label = 'head' }
        )) {
        $dest = Join-Path $RunDir $spec.Sub
        $tar = Join-Path $RunDir $spec.Tar
        if ($WhatIf) {
            Write-Output "git -C $Repo cat-file -e $($spec.Sha)^{commit}"
            Write-Output "git -C $Repo archive --format=tar --output=$tar $($spec.Sha) backend"
            Write-Output "tar -x -f $tar -C $dest"
            Write-Output "# remove excluded under ${dest}: .env*, quality/**, backend/venv"
        }
        else {
            & git -C $Repo archive --format=tar --output=$tar $spec.Sha backend
            if ($LASTEXITCODE -ne 0) {
                Fail "git archive $($spec.Sha) backend failed (exit $LASTEXITCODE)"
            }
            & tar -x -f $tar -C $dest
            if ($LASTEXITCODE -ne 0) {
                Fail "tar extract $($spec.Tar) failed (exit $LASTEXITCODE)"
            }
            Remove-Item -LiteralPath $tar -Force -ErrorAction SilentlyContinue
            $removed = Remove-Excluded -Root $dest
            Write-Output "archive: $($spec.Label) $($spec.Sha) -> $dest (excluded=$removed)"
        }
    }

    # --- network ---------------------------------------------------------
    if ($WhatIf) {
        Write-Output "docker network create --internal $Net"
    }
    else {
        & docker network create --internal $Net | Out-Null
        $netExit = $LASTEXITCODE
        if (Test-Exists $Net) { $script:Created.Net = $true }
        if ($netExit -ne 0) { Fail "docker network create $Net failed (exit $netExit)" }
        Write-Output "network: $Net (internal)"
    }

    # --- postgres --------------------------------------------------------
    $pgDisplay = "docker run -d --name $Pg --network $Net --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,size=96m --memory 256m --cpus 0.5 --shm-size 32m --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETGID --cap-add SETUID --security-opt no-new-privileges -e POSTGRES_PASSWORD=<random-24> -e POSTGRES_DB=k1 $PgImage"
    if ($WhatIf) {
        Write-Output $pgDisplay
        Write-Output "docker exec $Pg pg_isready -U postgres -d k1   # retry up to 60 s"
    }
    else {
        $pgArgs = @(
            'run', '-d', '--name', $Pg, '--network', $Net,
            '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=96m',
            '--memory', '256m', '--cpus', '0.5', '--shm-size', '32m',
            '--cap-drop', 'ALL',
            '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'FOWNER',
            '--cap-add', 'SETGID', '--cap-add', 'SETUID',
            '--security-opt', 'no-new-privileges',
            '-e', "POSTGRES_PASSWORD=$pgPass", '-e', 'POSTGRES_DB=k1', $PgImage
        )
        & docker @pgArgs | Out-Null
        $pgExit = $LASTEXITCODE
        if (Test-Exists $Pg) { $script:Created.Pg = $true }
        if ($pgExit -ne 0) { Fail "docker run $Pg failed (exit $pgExit)" }

        $deadline = (Get-Date).AddSeconds(60)
        $ready = $false
        while ((Get-Date) -lt $deadline) {
            & docker exec $Pg pg_isready -U postgres -d k1 *> $null
            if ($LASTEXITCODE -eq 0) { $ready = $true; break }

            $running = (& docker inspect -f '{{.State.Running}}' $Pg 2>$null)
            if ($LASTEXITCODE -ne 0 -or "$running".Trim() -ne 'true') {
                & docker logs --tail 20 $Pg 2>&1 | ForEach-Object { [Console]::Error.WriteLine("pg log: $_") }
                Fail "pg container $Pg exited during startup"
            }
            Start-Sleep -Seconds 2
        }
        if (-not $ready) {
            & docker logs --tail 30 $Pg 2>&1 | ForEach-Object { [Console]::Error.WriteLine("pg log: $_") }
            Fail 'pg_isready timed out after 60 s'
        }
        Write-Output "pg: $Pg ready ($PgImage, tmpfs /var/lib/postgresql/data)"
    }

    # --- app -------------------------------------------------------------
    $appDisplay = "docker run -d --name $App --network $Net --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges --memory 384m --memory-swap 384m --cpus 1 --pids-limit 256 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=1777 --tmpfs /run:rw,noexec,nosuid,nodev,size=8m --tmpfs /work:rw,exec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0755 --tmpfs /home/k1:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0755 -v $RunDir\repo-base:/repo/base:ro -v $RunDir\repo-head:/repo/head:ro -e DATABASE_URL=postgresql://postgres:<redacted>@${Pg}:5432/k1 -e FAKE_PROVIDER_URL=http://127.0.0.1:8081 --log-driver local --log-opt max-size=1m --log-opt max-file=1 --log-opt compress=false $AppImage"
    if ($WhatIf) {
        Write-Output $appDisplay
        Write-Output "docker exec $App python -c `"import urllib.request;urllib.request.urlopen('http://127.0.0.1:8081/health')`"   # retry up to 60 s"
    }
    else {
        $appArgs = @(
            'run', '-d', '--name', $App, '--network', $Net,
            '--read-only', '--user', '10001:10001',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--memory', '384m', '--memory-swap', '384m', '--cpus', '1', '--pids-limit', '256',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=1777',
            '--tmpfs', '/run:rw,noexec,nosuid,nodev,size=8m',
            '--tmpfs', '/work:rw,exec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0755',
            '--tmpfs', '/home/k1:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0755',
            '-v', "$RunDir\repo-base:/repo/base:ro",
            '-v', "$RunDir\repo-head:/repo/head:ro",
            '-e', "DATABASE_URL=postgresql://postgres:$pgPass@${Pg}:5432/k1",
            '-e', 'FAKE_PROVIDER_URL=http://127.0.0.1:8081',
            '--log-driver', 'local', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1',
            '--log-opt', 'compress=false',
            $AppImage
        )
        & docker @appArgs | Out-Null
        $appExit = $LASTEXITCODE
        if (Test-Exists $App) { $script:Created.App = $true }
        if ($appExit -ne 0) { Fail "docker run $App failed (exit $appExit)" }

        $health = "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8081/health')"
        $deadline = (Get-Date).AddSeconds(60)
        $healthy = $false
        while ((Get-Date) -lt $deadline) {
            & docker exec $App python -c $health *> $null
            if ($LASTEXITCODE -eq 0) { $healthy = $true; break }

            $running = (& docker inspect -f '{{.State.Running}}' $App 2>$null)
            if ($LASTEXITCODE -ne 0 -or "$running".Trim() -ne 'true') {
                & docker logs --tail 20 $App 2>&1 | ForEach-Object { [Console]::Error.WriteLine("app log: $_") }
                Fail "app container $App exited during startup"
            }
            Start-Sleep -Seconds 2
        }
        if (-not $healthy) {
            & docker logs --tail 30 $App 2>&1 | ForEach-Object { [Console]::Error.WriteLine("app log: $_") }
            Fail 'app /health timed out after 60 s'
        }
        Write-Output "app: $App healthy (fake provider http://127.0.0.1:8081)"
    }

    if ($WhatIf) {
        Write-Output "k1 up (whatif): $RunId app=$App pg=$Pg net=$Net"
    }
    else {
        Write-Output "k1 up: $RunId app=$App pg=$Pg net=$Net"
    }
}
catch {
    [Console]::Error.WriteLine("k1_up: FAILED: $($_.Exception.Message)")
    if (-not $WhatIf) {
        if ($script:Created.App) {
            & docker rm -f $App | Out-Null
            Write-Output "cleanup: removed app $App"
        }
        if ($script:Created.Pg) {
            & docker rm -f $Pg | Out-Null
            Write-Output "cleanup: removed pg $Pg"
        }
        if ($script:Created.Net) {
            & docker network rm $Net 2>$null | Out-Null
            Write-Output "cleanup: removed network $Net"
        }
        if ($script:Created.RunDir -and (Test-Path -LiteralPath $RunDir)) {
            Remove-Item -LiteralPath $RunDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Output "cleanup: removed run dir $RunDir"
        }
    }
    exit 1
}

exit 0
