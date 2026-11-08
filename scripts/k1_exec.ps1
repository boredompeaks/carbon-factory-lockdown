# k1_exec.ps1 -- run one command inside the K1 app container as uid 10001 in /work.
#
# The command string is executed through /bin/sh -c inside the container so
# quoting, pipes and redirection behave like a shell command line. Its exit
# code is propagated unchanged. Only k1-<RunId>-app is touched.
#
# Exit codes: the command's own exit code; 2 = refusal (bad args, Docker down,
# app container absent/not running).

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$Command,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Continue'

function Refuse([string]$Code, [string]$Message) {
    [Console]::Error.WriteLine("k1_exec: refused: ${Code}: $Message")
    exit 2
}

if ([string]::IsNullOrWhiteSpace($RunId) -or
    $RunId -notmatch '^[A-Za-z0-9._-]+$' -or
    $RunId -eq '.' -or $RunId -eq '..' -or
    $RunId.Length -gt 48) {
    Refuse 'BAD_RUN_ID' '-RunId must match ^[A-Za-z0-9._-]+$, must not be . or .., and must be at most 48 chars'
}
if ([string]::IsNullOrWhiteSpace($Command)) {
    Refuse 'BAD_COMMAND' '-Command must not be empty'
}

$App = "k1-$RunId-app"
$display = "docker exec -u 10001 -w /work $App /bin/sh -c $Command"

if ($WhatIf) {
    Write-Output $display
    exit 0
}

& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Refuse 'DOCKER_DOWN' 'docker engine is not ready'
}

$running = (& docker inspect -f '{{.State.Running}}' $App 2>$null)
if ($LASTEXITCODE -ne 0 -or "$running".Trim() -ne 'true') {
    Refuse 'APP_NOT_RUNNING' "container $App is not running (run scripts\k1_up.ps1 first)"
}

& docker exec -u 10001 -w /work $App /bin/sh -c $Command
$code = $LASTEXITCODE
if ($code -eq 0) {
    Write-Output 'k1_exec: exit=0'
}
else {
    [Console]::Error.WriteLine("k1_exec: exit=$code")
}
exit $code
