# watch_checks.ps1 -- run exactly one gh pr checks watch for one PR.
# No polling loop, no re-run, no merge.

[CmdletBinding()]
param(
    [int]$Number,

    [string]$Repo = $null,

    [switch]$WhatIf,

    [switch]$Help
)

$ErrorActionPreference = 'Stop'

function Refuse([string]$Message) {
    [Console]::Error.WriteLine("watch_checks: refused: $Message")
    exit 2
}

$usage = @"
watch_checks.ps1 -Number <pr-number> [-Repo <worktree>] [-WhatIf] [-Help]
Runs exactly one command: gh pr checks <pr-number> --watch --interval 30
Exit codes: 0 = every check passed; 1 = a check failed; 8 = checks still
pending or the watch timed out; 2 = refusal; other = gh's own error.
"@

if ($Help) {
    Write-Output $usage
    exit 0
}

if ($Number -le 0) {
    Refuse 'Number must be a positive pull-request number'
}

# Discover the worktree when -Repo is omitted (git rev-parse --show-toplevel).
if ([string]::IsNullOrWhiteSpace($Repo)) {
    $discovered = $null
    $discoveryCode = 1
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $discovered = (& git rev-parse --show-toplevel 2>$null)
        $discoveryCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($discoveryCode -eq 0 -and "$discovered".Trim()) { $Repo = "$discovered".Trim() }
    else { $Repo = (Get-Location).Path }
}

$inside = $null
$insideCode = 1
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { $inside = (& git -C $Repo rev-parse --is-inside-work-tree 2>$null); $insideCode = $LASTEXITCODE } finally { $ErrorActionPreference = $previousPreference }
if ($insideCode -ne 0 -or "$inside".Trim() -ne 'true') {
    Refuse "not a git worktree: $Repo"
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Refuse 'gh not found on PATH'
}

$command = "gh pr checks $Number --watch --interval 30"
if ($WhatIf) {
    Write-Output "cd `"$Repo`"; $command"
    exit 0
}

# The one and only watch invocation. Its exit status is returned unchanged.
Push-Location $Repo
try {
    & gh pr checks $Number --watch --interval 30
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
