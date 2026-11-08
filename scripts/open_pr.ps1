# open_pr.ps1 -- reuse an open promotion PR or create one. Never merges.
# The PR body is composed from ids and hashes only.

[CmdletBinding()]
param(
    [string]$Base,

    [string]$Head,

    [string]$Repo = $null,

    [string]$Title,

    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

function Refuse([string]$Message) {
    [Console]::Error.WriteLine("open_pr: refused: $Message")
    exit 2
}

function Test-BranchName([string]$Name, [string]$Label) {
    if (-not $Name -or $Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$') {
        Refuse "$Label '$Name' is not a valid branch name"
    }
    if ($Name.Contains('+')) {
        Refuse "$Label '$Name' contains '+'; force refspecs are not allowed"
    }
    if ($Name.Contains('..')) {
        Refuse "$Label '$Name' contains '..'; path traversal is not allowed"
    }
    if ($Name.StartsWith('-')) {
        Refuse "$Label '$Name' starts with '-'; option injection is not allowed"
    }
    if ($Name -match '\s') {
        Refuse "$Label '$Name' contains whitespace"
    }
}

# 0. Base/head default to policies/ci.json; an explicit flag still wins.
$ciPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'files\policies\ci.json'
if (-not (Test-Path -LiteralPath $ciPath)) {
    Refuse "policy file not found: $ciPath"
}
$ci = Get-Content -Raw -LiteralPath $ciPath | ConvertFrom-Json
if (-not $PSBoundParameters.ContainsKey('Base')) { $Base = "$($ci.promotion_branch)".Trim() }
if (-not $PSBoundParameters.ContainsKey('Head')) { $Head = "$($ci.base_branch)".Trim() }
if (-not $Base) { Refuse 'Base is empty (pass -Base or set promotion_branch in ci.json)' }
if (-not $Head) { Refuse 'Head is empty (pass -Head or set base_branch in ci.json)' }

Test-BranchName $Base 'Base'
Test-BranchName $Head 'Head'
if ($Base -ceq $Head) {
    Refuse "Base and Head are the same branch '$Base'"
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

# 1. Repo must be a git worktree and the head ref must exist locally.
$inside = $null
$insideCode = 1
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { $inside = (& git -C $Repo rev-parse --is-inside-work-tree 2>$null); $insideCode = $LASTEXITCODE } finally { $ErrorActionPreference = $previousPreference }
if ($insideCode -ne 0 -or "$inside".Trim() -ne 'true') {
    Refuse "not a git worktree: $Repo"
}

$headSha = (& git -C $Repo rev-parse --verify "refs/heads/$Head" 2>$null)
if ($LASTEXITCODE -ne 0 -or -not "$headSha".Trim()) {
    Refuse "local ref refs/heads/$Head does not exist in $Repo"
}
$headSha = "$headSha".Trim()

$headTree = (& git -C $Repo rev-parse "$Head^{tree}" 2>$null)
if ($LASTEXITCODE -ne 0 -or -not "$headTree".Trim()) {
    Refuse "cannot read tree for $Head in $Repo"
}
$headTree = "$headTree".Trim()

# 2. gh must be available before any network call.
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Refuse 'gh not found on PATH'
}

# 3. Reuse an open PR when one exists.
Push-Location $Repo
try {
    $existingJson = (& gh pr list --head $Head --base $Base --state open --json number,url,headRefOid,baseRefOid 2>$null)
    $listCode = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($listCode -ne 0) {
    [Console]::Error.WriteLine("open_pr: gh pr list failed with exit $listCode")
    exit $listCode
}

$existing = @()
if ("$existingJson".Trim()) {
    $parsed = "$existingJson" | ConvertFrom-Json
    $existing = @($parsed | Where-Object { $_ -ne $null })
}
if ($existing.Count -gt 0) {
    foreach ($pr in $existing) {
        Write-Output "reuse PR #$($pr.number) $($pr.url) head=$($pr.headRefOid) base=$($pr.baseRefOid)"
    }
    exit 0
}

# 4. Compose the ids/hashes-only body and title.
if (-not $Title) {
    $Title = "promotion: $Head -> $Base"
}
$bodyObject = [ordered]@{
    schema    = 'promotion-pr/1'
    base      = $Base
    head      = $Head
    head_sha  = $headSha
    head_tree = $headTree
}
$body = $bodyObject | ConvertTo-Json -Compress

# 5. Dry run: print create-or-reuse, create nothing.
if ($WhatIf) {
    Write-Output "create PR: base=$Base head=$Head head_sha=$headSha"
    Write-Output "gh pr create --base $Base --head $Head --title `"$Title`" --body `"$body`""
    exit 0
}

# 6. The one and only create command. No merge flag exists in this script.
Push-Location $Repo
try {
    $created = (& gh pr create --base $Base --head $Head --title $Title --body $body 2>&1 | Out-String).Trim()
    $createCode = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($createCode -ne 0) {
    [Console]::Error.WriteLine("open_pr: gh pr create failed with exit $createCode")
    [Console]::Error.WriteLine($created)
    exit $createCode
}

# 7. Report the created PR with its live head/base ids when gh can read them.
$prNumber = '?'
$createdUrl = (($created -split "`r?`n") | Where-Object { $_ -match '^https?://' } | Select-Object -Last 1)
if (-not $createdUrl) {
    $createdUrl = $created
}
$prUrl = $createdUrl
$headOid = $headSha
$baseOid = ''
Push-Location $Repo
try {
    $viewJson = (& gh pr view $createdUrl --json number,url,headRefOid,baseRefOid 2>$null)
    $viewCode = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($viewCode -eq 0 -and "$viewJson".Trim()) {
    $view = "$viewJson" | ConvertFrom-Json
    $prNumber = $view.number
    $prUrl = $view.url
    $headOid = $view.headRefOid
    $baseOid = $view.baseRefOid
}
Write-Output "created PR #$prNumber $prUrl head=$headOid base=$baseOid"
exit 0
