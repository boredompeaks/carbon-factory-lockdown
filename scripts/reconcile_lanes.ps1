# reconcile_lanes.ps1 -- merge permanent lane refs into spec-comp.
# Runs in the integration worktree, fetches origin, merges each lane with
# --no-ff, prints every merge sha, and stops at the first conflict. Never pushes.

[CmdletBinding()]
param(
    [string]$Repo = $null,

    [string[]]$Lanes = @('lane/a', 'lane/b'),

    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

function Refuse([string]$Message) {
    [Console]::Error.WriteLine("reconcile_lanes: refused: $Message")
    exit 2
}

# 1. Normalize -Lanes (array or one comma-separated string) and validate.
$normalized = @()
foreach ($lane in $Lanes) {
    foreach ($part in ("$lane" -split ',')) {
        $candidate = $part.Trim()
        if ($candidate) {
            $normalized += $candidate
        }
    }
}
if ($normalized.Count -eq 0) {
    Refuse 'no lanes given'
}

$seen = @{}
foreach ($lane in $normalized) {
    if ($lane -cnotmatch '^lane/[A-Za-z0-9][A-Za-z0-9._-]*$') {
        Refuse "lane '$lane' is not a lane/<name> ref"
    }
    if ($lane.Contains('..')) {
        Refuse "lane '$lane' contains '..'; path traversal is not allowed"
    }
    if ($lane.Contains('+')) {
        Refuse "lane '$lane' contains '+'; force refspecs are not allowed"
    }
    if ($lane.StartsWith('-')) {
        Refuse "lane '$lane' starts with '-'; option injection is not allowed"
    }
    if ($lane -match '\s') {
        Refuse "lane '$lane' contains whitespace"
    }
    if ($seen.ContainsKey($lane)) {
        Refuse "duplicate lane '$lane'"
    }
    $seen[$lane] = $true
}

# 1a. Discover the worktree when -Repo is omitted (git rev-parse --show-toplevel).
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

# 2. The worktree must be a git worktree on spec-comp.
$inside = $null
$insideCode = 1
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { $inside = (& git -C $Repo rev-parse --is-inside-work-tree 2>$null); $insideCode = $LASTEXITCODE } finally { $ErrorActionPreference = $previousPreference }
if ($insideCode -ne 0 -or "$inside".Trim() -ne 'true') {
    Refuse "not a git worktree: $Repo"
}

$branch = (& git -C $Repo rev-parse --abbrev-ref HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or -not "$branch".Trim()) {
    Refuse "cannot read HEAD branch in $Repo"
}
$branch = "$branch".Trim()
if ($branch -cne 'spec-comp') {
    Refuse "worktree $Repo is on '$branch', not 'spec-comp' (no merge)"
}

# 3. A real run requires a clean worktree. A dry run prints the commands and
#    reports the dirty state without refusing.
$dirty = (& git -C $Repo status --porcelain 2>$null)
$dirtyText = ($dirty -join "`n").Trim()
if ($dirtyText) {
    if (-not $WhatIf) {
        Refuse "worktree $Repo is dirty; commit or stash before reconciling"
    }
    Write-Output "# note: worktree is dirty; a real run would refuse"
}

# 4. -WhatIf prints the exact command sequence, merges nothing.
$commands = @("git -C `"$Repo`" fetch origin")
foreach ($lane in $normalized) {
    $commands += "git -C `"$Repo`" merge --no-ff origin/$lane"
}
if ($WhatIf) {
    foreach ($command in $commands) {
        Write-Output $command
    }
    exit 0
}

# 5. Fetch once, then merge each lane in the order given.
& git -C $Repo fetch origin
if ($LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine("reconcile_lanes: git fetch origin failed with exit $LASTEXITCODE (no push performed)")
    exit $LASTEXITCODE
}

foreach ($lane in $normalized) {
    $remoteRef = "refs/remotes/origin/$lane"
    $remoteSha = (& git -C $Repo rev-parse --verify $remoteRef 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not "$remoteSha".Trim()) {
        Refuse "origin/$lane not found after fetch"
    }

    & git -C $Repo merge --no-ff "origin/$lane"
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $conflicts = (& git -C $Repo diff --name-only --diff-filter=U 2>$null)
        $conflictText = ($conflicts -join ', ').Trim()
        if ($conflictText) {
            [Console]::Error.WriteLine("reconcile_lanes: conflict merging origin/$lane; unmerged paths: $conflictText")
            [Console]::Error.WriteLine("reconcile_lanes: stopped at $lane; resolve in $Repo and re-run (no push performed)")
            exit 3
        }
        [Console]::Error.WriteLine("reconcile_lanes: merge of origin/$lane failed with exit $code (no push performed)")
        exit $code
    }

    $mergeSha = (& git -C $Repo rev-parse HEAD 2>$null)
    Write-Output "merged ${lane}: $("$mergeSha".Trim())"
}

$reconciledHead = (& git -C $Repo rev-parse HEAD 2>$null)
$reconciledTree = (& git -C $Repo rev-parse 'HEAD^{tree}' 2>$null)
Write-Output "reconciled head: $("$reconciledHead".Trim())"
Write-Output "reconciled tree: $("$reconciledTree".Trim())"
Write-Output "reconcile complete: $($normalized -join ', ') merged into spec-comp (no push)"
exit 0
