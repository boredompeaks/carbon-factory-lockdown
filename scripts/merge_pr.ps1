# merge_pr.ps1 -- merge one already-approved PR, pinned to an exact head commit.
# Merge method comes from files/policies/ci.json (merge, squash, or rebase).
# Deliberately exposes no --admin, --auto, --force, or --delete-branch option.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int]$Number,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$MatchHeadCommit,

    [string]$Repo = $null
)

$ErrorActionPreference = 'Stop'

function Refuse([string]$Message) {
    [Console]::Error.WriteLine("merge_pr: refused: $Message")
    exit 2
}

# 0a. Discover the worktree when -Repo is omitted (git rev-parse --show-toplevel).
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

# 1. Repo must be a git worktree.
$inside = $null
$insideCode = 1
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { $inside = (& git -C $Repo rev-parse --is-inside-work-tree 2>$null); $insideCode = $LASTEXITCODE } finally { $ErrorActionPreference = $previousPreference }
if ($insideCode -ne 0 -or "$inside".Trim() -ne 'true') {
    Refuse "not a git worktree: $Repo"
}

# 2. Pin the local HEAD to the caller-supplied commit before any network call.
$head = (& git -C $Repo rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or -not "$head".Trim()) {
    Refuse "cannot read HEAD in $Repo"
}
$head = "$head".Trim()
if ($head -ne $MatchHeadCommit) {
    Refuse "HEAD $head does not match -MatchHeadCommit $MatchHeadCommit (head pin mismatch; nothing merged)"
}

# 3. gh must be available; refuse before invoking anything.
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Refuse "gh not found on PATH"
}

# 4. Merge method comes from the policy file, never from a flag.
$ciPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'files\policies\ci.json'
if (-not (Test-Path -LiteralPath $ciPath)) {
    Refuse "policy file not found: $ciPath"
}
$ci = Get-Content -Raw -LiteralPath $ciPath | ConvertFrom-Json
$method = "$($ci.merge_method)".Trim().ToLowerInvariant()
switch ($method) {
    'merge'  { $methodFlag = '--merge' }
    'squash' { $methodFlag = '--squash' }
    'rebase' { $methodFlag = '--rebase' }
    default  { Refuse "ci.json merge_method '$method' is not merge, squash, or rebase" }
}

# 5. The one and only merge command. No extra flags exist in this script.
& gh pr merge $Number --match-head-commit $MatchHeadCommit $methodFlag
$code = $LASTEXITCODE
if ($code -ne 0) {
    exit $code
}

# 6. Report the merged commit, its tree, and return gh's exit code.
$mergeSha = (& gh pr view $Number --json mergeCommit --jq '.mergeCommit.oid' 2>$null)
$viewCode = $LASTEXITCODE
if ($viewCode -ne 0) {
    exit $viewCode
}
$mergeSha = "$mergeSha".Trim()
if (-not $mergeSha -or $mergeSha -eq 'null' -or $mergeSha -notmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') {
    Write-Output "merged sha: (none reported)"
} else {
    Write-Output "merged sha: $mergeSha"
    $mergedTree = (& git -C $Repo rev-parse "$mergeSha^{tree}" 2>$null)
    if ($LASTEXITCODE -eq 0 -and "$mergedTree".Trim()) {
        Write-Output "merged tree: $("$mergedTree".Trim())"
    }
}
exit $code
