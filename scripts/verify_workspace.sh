#!/usr/bin/env bash
# Verify a session-root workspace: shared-tree symlinks, generated config
# drift, carbon MCP discovery, and .agt policy load. Exit non-zero on any
# failure with a one-line reason.
set -uo pipefail

FACTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="${1:-}"
if [[ -z "$WORKSPACE" ]]; then
  echo "verify_workspace: usage: $0 <workspace-dir>" >&2
  exit 2
fi
WORKSPACE="$(cd "$WORKSPACE" 2>/dev/null && pwd)" || {
  echo "verify_workspace: no such workspace: ${1}" >&2
  exit 2
}

fail() {
  echo "verify_workspace: FAIL: $*" >&2
  exit 1
}

# 1. Shared trees must be symlinks to the factory (no copies, no drift).
for pair in ".opencode:.opencode" ".agt:.agt" ".agents:.agents"; do
  link="${pair%%:*}"
  target="${pair##*:}"
  path="$WORKSPACE/$link"
  [[ -L "$path" ]] || fail "$link is not a symlink (stale copy?)"
  want="$(readlink -f "$FACTORY/$target" 2>/dev/null || true)"
  got="$(readlink -f "$path" 2>/dev/null || true)"
  [[ -n "$want" && "$got" == "$want" ]] ||
    fail "$link -> ${got:-<broken>} (expected $want)"
  echo "symlink: $link -> $got"
done

# 2. Generated config must match the generator byte-for-byte (drift gate).
python3 "$FACTORY/scripts/gen_opencode_config.py" --workspace "$WORKSPACE" --check ||
  fail "opencode.json drift (run gen_opencode_config.py --workspace $WORKSPACE --write)"
echo "config: $WORKSPACE/opencode.json in sync"

# 3. The carbon server must actually spawn and answer tools/list.
python3 "$FACTORY/scripts/mcp_discover.py" \
  --server carbon-orchestrator \
  --config "$WORKSPACE/opencode.json" >/dev/null ||
  fail "mcp_discover failed for carbon-orchestrator"
echo "mcp: carbon-orchestrator discovery OK"

# 4. The authz policy file must be valid JSON.
python3 - "$WORKSPACE/.agt/policy.json" <<'PY' || fail ".agt/policy.json missing or invalid"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    policy = json.load(fh)
if not isinstance(policy, dict) or not policy:
    raise SystemExit("policy must be a non-empty object")
PY
echo "policy: .agt/policy.json loads"

echo "verify_workspace: OK ($WORKSPACE)"
