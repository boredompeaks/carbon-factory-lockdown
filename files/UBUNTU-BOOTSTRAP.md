# Ubuntu bootstrap

Fresh clone on Ubuntu (harness root). `opencode.json` is gitignored
(host paths); regenerate it below. Tracked plugin `agt.js` is required.

## Prerequisites

- `python3` (Ubuntu >=22.04: no bare `python`)
- `git`, `gh`, `docker`, `gitleaks`, `ruff`
- `basemind` Linux ELF on `PATH` (or set `BASEMIND_BIN`)

## Bootstrap commands

```sh
python3 scripts/gen_opencode_config.py --write
python3 scripts/check_harness_config.py
GITLEAKS_BIN=$(command -v gitleaks) python3 files/tools/gate_control.py --repo . --write
```

Then verify: `gate_control.py --verify`, `--verify-chain`,
`scripts/policy_manifest.py --verify`, `gate_all_controls.py`,
`files/tools/mcp/core/test_core.py`.

## Re-seal note

The gate digest is host-bound (`opencode.json` embeds the host
interpreter and binary paths). A digest sealed on Windows does not
reproduce on Ubuntu: cut a new tag after re-sealing here.

## Cross-platform flags

- `CARBON_RELEASE_NATIVE=1` forces the native `gh`/`git` path in
  `release.handlers` (POSIX default; Windows uses `.ps1` otherwise).
- `CARBON_K1_NATIVE=1` forces the native `docker` CLI in `k1.handlers`
  (POSIX default; Windows uses `scripts/*.ps1` otherwise).

## `basemind_git` revoked

`basemind_git` is not available for v1 for any role. It reads git
history without `basemind.toml` excludes, so it leaks excluded files.
Use carbon `git.*` for history/diff questions instead.
