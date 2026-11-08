# push_ref.ps1 -- push exactly one permanent ref to origin.
# Allowed refs: refs/heads/spec-comp, refs/heads/lane/a, refs/heads/lane/b.
# Explicit refspec, fast-forward only: no --force, no "+", no other ref.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Branch,

    [string]$Repo,

    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

function Refuse([string]$Message) {
    [Console]::Error.WriteLine("push_ref: refused: $Message")
    exit 2
}

# 1. Branch contract (checked explicitly so every refusal exits 2).
$allowedBranches = @('spec-comp', 'lane/a', 'lane/b')

if ($Branch -cnotin $allowedBranches) {
    Refuse "Branch '$Branch' is not one of spec-comp, lane/a, lane/b"
}
if ($Branch.Contains('+')) {
    Refuse "Branch '$Branch' contains '+'; force refspecs are not allowed"
}
if ($Branch.Contains('..')) {
    Refuse "Branch '$Branch' contains '..'; path traversal is not allowed"
}
if ($Branch.StartsWith('-')) {
    Refuse "Branch '$Branch' starts with '-'; option injection is not allowed"
}
if ($Branch -match '\s') {
    Refuse "Branch '$Branch' contains whitespace"
}

# 2. Discover the worktree when -Repo is omitted (git rev-parse --show-toplevel).
# -Repo overrides the discovery; the worktree must have $Branch checked out.
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

# 3. Repo must be a git worktree.
$inside = $null
$insideCode = 1
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { $inside = (& git -C $Repo rev-parse --is-inside-work-tree 2>$null); $insideCode = $LASTEXITCODE } finally { $ErrorActionPreference = $previousPreference }
if ($insideCode -ne 0 -or "$inside".Trim() -ne 'true') {
    Refuse "not a git worktree: $Repo"
}

# 4. The worktree must have the requested branch checked out.
$headBranch = (& git -C $Repo rev-parse --abbrev-ref HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or -not "$headBranch".Trim()) {
    Refuse "cannot read HEAD branch in $Repo"
}
$headBranch = "$headBranch".Trim()
if ($headBranch -cne $Branch) {
    Refuse "worktree $Repo is on '$headBranch', not '$Branch' (no push)"
}

# 5. The local ref must exist and its commit is the sha this script pushes.
$ref = "refs/heads/$Branch"
$sha = (& git -C $Repo rev-parse --verify $ref 2>$null)
if ($LASTEXITCODE -ne 0 -or -not "$sha".Trim()) {
    Refuse "local ref $ref does not exist in $Repo"
}
$sha = "$sha".Trim()

# 6. Dry run: show the exact command, push nothing.
if ($WhatIf) {
    Write-Output "git -C `"$Repo`" push origin `"${ref}:${ref}`""
    exit 0
}

# 7. The one and only push command. No force, no "+" refspec.
& git -C $Repo push origin "${ref}:${ref}"
$code = $LASTEXITCODE
if ($code -ne 0) {
    exit $code
}

# 8. Report the sha that was pushed and return git's exit code.
Write-Output "pushed sha: $sha"
exit 0
