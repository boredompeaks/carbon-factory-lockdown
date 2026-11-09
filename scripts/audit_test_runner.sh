#!/usr/bin/env bash
# S5a / Gate 0 -- POSIX mirror of audit_test_runner.ps1.
#
# The auditor role is allowed exactly one shell entry point; on POSIX this
# file is the counterpart of the PS1 wrapper. It runs the named test label
# with the runner's own summary intact and exits with the runner's exit
# code. It never pipes through grep/sed/tee or `|| true`, so the wrapper
# cannot manufacture a green.
#
# Usage:
#   bash audit_test_runner.sh -Workdir <tree> -Label <tests> [-Engine sqlite|postgres] [-Coverage]
#   POSIX long form is also accepted: --workdir/--label/--engine/--coverage
#   (= forms such as --workdir=<tree> work too).
#
# Python resolution mirrors PS1's venv gate on POSIX: prefer
#   <Workdir>/backend/venv/bin/python   (POSIX counterpart of venv\Scripts\python.exe)
# falling back to <Workdir>/backend/venv/bin/python3 and then system python3.
# Exit 90 when no usable interpreter is found (mirrors PS1's "no venv python").

# No `set -e`: a failing runner must still emit AUDIT_RUNNER_EXIT and exit
# with the runner's code (mirrors PS1 try/finally, not early abort).
set -u

WORKDIR=""
LABEL=""
ENGINE="sqlite"
COVERAGE=0

usage() {
    echo "Usage: $0 -Workdir <tree> -Label <tests> [-Engine sqlite|postgres] [-Coverage]" >&2
    echo "   also accepts: --workdir <tree> --label <tests> [--engine sqlite|postgres] [--coverage]" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -Workdir|--workdir|--Workdir|-workdir)
            if [ "$#" -lt 2 ]; then
                echo "AUDIT_RUNNER_ERROR=missing value for -Workdir" >&2
                usage
                exit 2
            fi
            WORKDIR="$2"
            shift 2
            ;;
        -Workdir=*|--workdir=*|--Workdir=*|-workdir=*)
            WORKDIR="${1#*=}"
            shift
            ;;
        -Label|--label|--Label|-label)
            if [ "$#" -lt 2 ]; then
                echo "AUDIT_RUNNER_ERROR=missing value for -Label" >&2
                usage
                exit 2
            fi
            LABEL="$2"
            shift 2
            ;;
        -Label=*|--label=*|--Label=*|-label=*)
            LABEL="${1#*=}"
            shift
            ;;
        -Engine|--engine|--Engine|-engine)
            if [ "$#" -lt 2 ]; then
                echo "AUDIT_RUNNER_ERROR=missing value for -Engine" >&2
                usage
                exit 2
            fi
            ENGINE="$2"
            shift 2
            ;;
        -Engine=*|--engine=*|--Engine=*|-engine=*)
            ENGINE="${1#*=}"
            shift
            ;;
        -Coverage|--coverage|--Coverage|-coverage)
            COVERAGE=1
            shift
            ;;
        -h|--help|-help|--Help)
            usage
            exit 0
            ;;
        *)
            echo "AUDIT_RUNNER_ERROR=unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [ -z "$WORKDIR" ]; then
    echo "AUDIT_RUNNER_ERROR=missing required -Workdir" >&2
    usage
    exit 2
fi
if [ -z "$LABEL" ]; then
    echo "AUDIT_RUNNER_ERROR=missing required -Label" >&2
    usage
    exit 2
fi

case "$ENGINE" in
    sqlite|postgres)
        ;;
    *)
        echo "AUDIT_RUNNER_ERROR=invalid -Engine '$ENGINE' (expected sqlite or postgres)" >&2
        usage
        exit 2
        ;;
esac

BACKEND="$WORKDIR/backend"
if [ ! -d "$BACKEND" ]; then
    echo "AUDIT_RUNNER_ERROR=no backend directory under $WORKDIR"
    exit 90
fi

# Python resolution: venv first (mirrors PS1), python3 fallback for POSIX.
if [ -x "$BACKEND/venv/bin/python" ]; then
    PYTHON="$BACKEND/venv/bin/python"
elif [ -x "$BACKEND/venv/bin/python3" ]; then
    PYTHON="$BACKEND/venv/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    echo "AUDIT_RUNNER_ERROR=no venv python under $BACKEND"
    exit 90
fi

# Remember origin for the finally-equivalent cleanup.
OLDPWD_SAVED="$PWD"
cd "$BACKEND" || {
    echo "AUDIT_RUNNER_ERROR=cannot enter backend directory $BACKEND"
    exit 90
}

cleanup() {
    unset DATABASE_URL
    cd "$OLDPWD_SAVED" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ "$ENGINE" = "postgres" ]; then
    export DATABASE_URL="postgresql://perfume:pg2a_local_test_only@127.0.0.1:5432/perfume_store"
else
    export DATABASE_URL="sqlite:///db.sqlite3"
fi

runnerExit=0
if [ "$COVERAGE" -eq 1 ]; then
    "$PYTHON" -m coverage run manage.py test "$LABEL" --verbosity 1 --noinput
    runnerExit=$?
    "$PYTHON" -m coverage report
    coverageExit=$?
    echo "AUDIT_RUNNER_EXIT=$runnerExit"
    echo "AUDIT_COVERAGE_EXIT=$coverageExit"
else
    "$PYTHON" manage.py test "$LABEL" --verbosity 1 --noinput
    runnerExit=$?
    echo "AUDIT_RUNNER_EXIT=$runnerExit"
fi

# Trap fires cleanup (unset DATABASE_URL, restore cwd); exit with runner code.
trap - EXIT
cleanup
exit "$runnerExit"
