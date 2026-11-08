# sync_worktrees.ps1 -- reverse-merge origin into local worktrees.
# No push, no force, no bare pull. Refuses a missing, wrong-branch, or dirty
# worktree; stops at the first conflict and never auto-aborts.

[CmdletBinding()]
param(
    [ValidateSet('factory', 'frontend', 'all')]
    [string]$Set = 'factory',

    [string]$Repo = $null,

    [string]$WorktreeRoot = $null,

    [switch]$WhatIf,

    [switch]$NoFetch
)

$ErrorActionPreference = 'Stop'

function Refuse([string]$Message) {
    [Console]::Error.WriteLine("sync_worktrees: refused: $Message")
    exit 2
}

# Topology is discovered from `git worktree list` (branch -> path).
# Factory is the active lane pair; frontend is opt-in and
# may diverge/conflict. -Repo/-WorktreeRoot are optional discovery anchors.
$anchor = $Repo
if (-not $anchor) { $anchor = $WorktreeRoot }
if (-not $anchor) { $anchor = (Get-Location).Path }
$branchToPath = @{}
$worktreeList = @()
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { $worktreeList = @(& git -C $anchor worktree list --porcelain 2>$null) } finally { $ErrorActionPreference = $previousPreference }
$currentWorktree = $null
foreach ($line in $worktreeList) {
    if ($line -match '^worktree\s+(.+)$') {
        $currentWorktree = $Matches[1].Trim()
    }
    elseif ($line -match '^branch\s+refs/heads/(.+)$') {
        if ($currentWorktree) {
            $branchToPath[$Matches[1].Trim()] = $currentWorktree
        }
    }
}
function Get-WorktreePath([string]$BranchName) {
    if ($branchToPath.ContainsKey($BranchName)) { return $branchToPath[$BranchName] }
    if ($WorktreeRoot) {
        $leaf = $BranchName -replace '/', '-'
        $candidate = Join-Path $WorktreeRoot $leaf
        if (Test-Path -LiteralPath $candidate -PathType Container) { return $candidate }
    }
    if ($Repo) {
        $leaf = $BranchName -replace '/', '-'
        # Only reuse -Repo when it already has the requested branch checked out.
        $current = $null
        $currentCode = 1
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { $current = (& git -C $Repo branch --show-current 2>$null); $currentCode = $LASTEXITCODE } finally { $ErrorActionPreference = $previousPreference }
        if ($currentCode -eq 0 -and "$current".Trim() -ceq $BranchName) { return $Repo }
    }
    return ''
}

$factory = @(
    [pscustomobject]@{
        Path     = (Get-WorktreePath 'spec-comp')
        Branch   = 'spec-comp'
        Upstream = 'origin/spec-comp'
    },
    [pscustomobject]@{
        Path     = (Get-WorktreePath 'lane/a')
        Branch   = 'lane/a'
        Upstream = 'origin/lane/a'
    },
    [pscustomobject]@{
        Path     = (Get-WorktreePath 'lane/b')
        Branch   = 'lane/b'
        Upstream = 'origin/lane/b'
    }
)

$frontend = @(
    [pscustomobject]@{
        Path     = (Get-WorktreePath 'ui/cf-storefront')
        Branch   = 'ui/cf-storefront'
        Upstream = 'origin/feat/add-frontend'
    },
    [pscustomobject]@{
        Path     = (Get-WorktreePath 'ui/t1')
        Branch   = 'ui/t1'
        Upstream = 'origin/feat/add-frontend'
    },
    [pscustomobject]@{
        Path     = (Get-WorktreePath 'ui/t2')
        Branch   = 'ui/t2'
        Upstream = 'origin/feat/add-frontend'
    },
    [pscustomobject]@{
        Path     = (Get-WorktreePath 'ui/t3')
        Branch   = 'ui/t3'
        Upstream = 'origin/feat/add-frontend'
    }
)

$items = @()
if ($Set -in @('factory', 'all')) { $items += $factory }
if ($Set -in @('frontend', 'all')) { $items += $frontend }
if ($items.Count -eq 0) {
    Refuse "no worktrees selected for set '$Set'"
}

# 1. Validate every mapped worktree before any network or merge action.
#    A missing/wrong-branch/dirty worktree is skipped, not allowed to block the
#    clean ones; the final exit is 2 if anything was skipped.
$active = @()
$skipped = @()
foreach ($item in $items) {
    $path = $item.Path

    if ($item.Branch -ceq 'master' -or $item.Upstream -ceq 'origin/master') {
        Refuse "master is not a sync target"
    }
    if ($item.Branch.Contains('+') -or $item.Upstream.Contains('+')) {
        Refuse "force refspecs are not allowed ($path)"
    }
    if ($item.Upstream.Contains('..') -or $item.Upstream.StartsWith('-')) {
        Refuse "invalid upstream '$($item.Upstream)' for $path"
    }

    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Container)) {
        Write-Output "sync_worktrees: skipped $($item.Branch): worktree not found: $path"
        $skipped += $item.Branch
        continue
    }

    $inside = $null
    $insideCode = 1
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $inside = (& git -C $path rev-parse --is-inside-work-tree 2>$null); $insideCode = $LASTEXITCODE } finally { $ErrorActionPreference = $previousPreference }
    if ($insideCode -ne 0 -or "$inside".Trim() -ne 'true') {
        Write-Output "sync_worktrees: skipped $($item.Branch): not a git worktree: $path"
        $skipped += $item.Branch
        continue
    }

    $branch = (& git -C $path branch --show-current 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not "$branch".Trim()) {
        Write-Output "sync_worktrees: skipped $($item.Branch): cannot read current branch in $path"
        $skipped += $item.Branch
        continue
    }
    $branch = "$branch".Trim()
    if ($branch -cne $item.Branch) {
        Write-Output "sync_worktrees: skipped $($item.Branch): worktree $path is on '$branch'"
        $skipped += $item.Branch
        continue
    }

    $dirty = @(& git -C $path status --porcelain 2>$null)
    $dirtyText = ($dirty -join '; ').Trim()
    if ($dirtyText) {
        if ($WhatIf) {
            Write-Output "# note: worktree $path is dirty; it would be skipped"
        }
        else {
            Write-Output "sync_worktrees: skipped $($item.Branch): worktree $path is dirty: $dirtyText"
        }
        $skipped += $item.Branch
        continue
    }

    $active += $item
}

if ($active.Count -eq 0 -and -not $WhatIf) {
    [Console]::Error.WriteLine("sync_worktrees: no clean worktree to sync; skipped: $($skipped -join ', '); no push performed")
    exit 2
}

# 2. Fetch origin once unless -NoFetch. -WhatIf prints the fetch and merges
#    nothing.
$fetchPath = if ($active.Count -gt 0) { $active[0].Path } else { $items[0].Path }
if (-not $NoFetch -and $active.Count -gt 0) {
    if ($WhatIf) {
        Write-Output "git -C `"$fetchPath`" fetch origin"
    }
    else {
        & git -C $fetchPath fetch origin
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("sync_worktrees: git fetch origin failed with exit $LASTEXITCODE (no push performed)")
            exit $LASTEXITCODE
        }
    }
}

# 3. The upstream ref must exist (even a -NoFetch run checks the local mirror).
$ready = @()
foreach ($item in $active) {
    $ref = "refs/remotes/$($item.Upstream)"
    $sha = (& git -C $item.Path rev-parse --verify $ref 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not "$sha".Trim()) {
        Write-Output "sync_worktrees: skipped $($item.Branch): $ref not found in $($item.Path)"
        $skipped += $item.Branch
        continue
    }
    $ready += $item
}
$active = $ready

if ($active.Count -eq 0 -and -not $WhatIf) {
    [Console]::Error.WriteLine("sync_worktrees: no upstream to merge; skipped: $($skipped -join ', '); no push performed")
    exit 2
}

# 4. -WhatIf prints the exact merge command per planned item and exits 0.
if ($WhatIf) {
    foreach ($item in $active) {
        Write-Output "git -C `"$($item.Path)`" merge --no-ff --no-edit $($item.Upstream)"
    }
    if ($skipped.Count -gt 0) {
        Write-Output "# skipped: $($skipped -join ', ')"
    }
    exit 0
}

# 5. Reverse-merge each upstream: skip when already an ancestor, otherwise
#    merge --no-ff --no-edit. Stop at the first conflict; never abort or push.
foreach ($item in $active) {
    $before = (& git -C $item.Path rev-parse --verify "refs/heads/$($item.Branch)" 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not "$before".Trim()) {
        Refuse "local ref refs/heads/$($item.Branch) does not exist in $($item.Path)"
    }
    $before = "$before".Trim()

    & git -C $item.Path merge-base --is-ancestor $item.Upstream $item.Branch 2>$null
    $ancestorCode = $LASTEXITCODE
    if ($ancestorCode -eq 0) {
        Write-Output "up-to-date $($item.Branch) @ $before"
        continue
    }
    if ($ancestorCode -ne 1) {
        [Console]::Error.WriteLine("sync_worktrees: merge-base check failed for $($item.Branch) with exit $ancestorCode (no push performed)")
        exit $ancestorCode
    }

    $behind = (& git -C $item.Path rev-list --count "$($item.Branch)..$($item.Upstream)" 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not "$behind".Trim()) {
        [Console]::Error.WriteLine("sync_worktrees: cannot count commits behind $($item.Branch) (no push performed)")
        exit 1
    }
    $behind = "$behind".Trim()

    Write-Output "git -C `"$($item.Path)`" merge --no-ff --no-edit $($item.Upstream)"
    & git -C $item.Path merge --no-ff --no-edit $item.Upstream
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $conflicts = @(& git -C $item.Path diff --name-only --diff-filter=U 2>$null)
        $conflictText = ($conflicts -join ', ').Trim()
        if ($conflictText) {
            [Console]::Error.WriteLine("conflicted: $conflictText")
            [Console]::Error.WriteLine("sync_worktrees: conflict in $($item.Branch); resolve or run git merge --abort")
            exit 3
        }
        [Console]::Error.WriteLine("sync_worktrees: merge of $($item.Upstream) in $($item.Branch) failed with exit $code (no push performed)")
        exit $code
    }

    $after = (& git -C $item.Path rev-parse --verify HEAD 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not "$after".Trim()) {
        [Console]::Error.WriteLine("sync_worktrees: cannot read HEAD after merging $($item.Branch) (no push performed)")
        exit 1
    }
    $after = "$after".Trim()

    Write-Output "synced $($item.Branch): $before -> $after (behind $behind)"
}

if ($skipped.Count -gt 0) {
    [Console]::Error.WriteLine("sync_worktrees: skipped $($skipped.Count) worktree(s): $($skipped -join ', '); no push performed")
    exit 2
}

exit 0
