# S5a / Gate 0 -- the auditor's ONLY shell entry point.
#
# The auditor role is allowed exactly one bash command:
#   powershell -NoProfile -ExecutionPolicy Bypass -File <this file> -Workdir <tree> -Label <tests>
#
# It runs the named test label with the runner's own summary intact and exits
# with the runner's exit code. It never pipes through Select-Object, Tee-Object,
# Out-File or `|| true`, so the wrapper cannot manufacture a green.
param(
    [Parameter(Mandatory = $true)][string]$Workdir,
    [Parameter(Mandatory = $true)][string]$Label,
    [ValidateSet("sqlite", "postgres")][string]$Engine = "sqlite",
    [switch]$Coverage
)

$ErrorActionPreference = "Stop"
$backend = Join-Path $Workdir "backend"
if (-not (Test-Path $backend)) {
    Write-Output "AUDIT_RUNNER_ERROR=no backend directory under $Workdir"
    exit 90
}

$python = Join-Path $backend "venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Output "AUDIT_RUNNER_ERROR=no venv python under $backend"
    exit 90
}

Push-Location $backend
try {
    if ($Engine -eq "postgres") {
        $env:DATABASE_URL = "postgresql://perfume:pg2a_local_test_only@127.0.0.1:5432/perfume_store"
    } else {
        $env:DATABASE_URL = "sqlite:///db.sqlite3"
    }

    if ($Coverage) {
        & $python -m coverage run manage.py test $Label --verbosity 1 --noinput
        $runnerExit = $LASTEXITCODE
        & $python -m coverage report
        $coverageExit = $LASTEXITCODE
        Write-Output "AUDIT_RUNNER_EXIT=$runnerExit"
        Write-Output "AUDIT_COVERAGE_EXIT=$coverageExit"
    } else {
        & $python manage.py test $Label --verbosity 1 --noinput
        $runnerExit = $LASTEXITCODE
        Write-Output "AUDIT_RUNNER_EXIT=$runnerExit"
    }
}
finally {
    Remove-Item Env:\DATABASE_URL -ErrorAction SilentlyContinue
    Pop-Location
}

exit $runnerExit
