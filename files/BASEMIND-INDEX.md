# Basemind index — per-worktree scan roots and excludes

**Host:** OS-agnostic — typed tools are canonical (`pr.open`, `k1.up`, `worktrees.sync`, …); the `.ps1` wrapper is Windows-only (powershell) — the Windows implementation; the POSIX implementation is native.

## Scope: one index per worktree

Basemind indexes **per worktree**, not per harness. Each git worktree
(`<worktree>`, `<lane-a-worktree>`, `wt-async`, …) is a separate scan root with
its own basemind index, keyed by workspace. The harness root itself is not
scanned as a workspace; agents reach worktree code via `basemind_code`,
`basemind_graph`, `basemind_memory`, `basemind_web`, and
`basemind_workspace` where the role holds those grants (see each agent's
Tool surface). No role adds a grant for this document.

## Exclude list (from `basemind.toml` `[scan].exclude`)

At minimum these globs are always excluded from every worktree index:

` **/.env*`, `**/*.pem`, `**/*.key`, `**/id_rsa*`, `**/secrets/**`,
`**/.opencode/**`, `**/.git/**`, `**/node_modules/**`, `**/venv/**`,
`**/__pycache__/**`, `**/policy-manifest.json`, `**/*.sqlite`, `**/db.sqlite3`

The live `basemind.toml` exclude list is identical in `[scan]` and
`[documents]`. It also sets aside the generated and sensitive surfaces:
**` **/policies/**`** (covers `files/policies/policy-manifest.json` —
itself matched by ` **/policy-manifest.json` — plus
`files/policies/schemas/**` and `files/policies/*.json` control
definitions), ` **/files/tools/out/**`, ` **/files/quality/**` (ledger /
seal evidence), ` **/quality/ledger/**`, ` **/*.ipynb`, ` **/files.zip`,
` **/commits_raw.json`, `report/**`, `quality-scan/**`, ` **/*.png`,
` **/.ruff_cache/**`, ` **/.playwright-mcp/**`, ` **/.agents/**`,
` **/audit-scratch/**`, ` **/.agt/**`, and the opencode config entries.
Secrets and key material (`*.pem`, `*.key`, `id_rsa*`) are additionally
covered by the basemind floor so no credential becomes searchable.

Agent-facing factory sources **are** indexed: `files/sop/**`,
`files/*.md` personas/docs, and `files/tools/**/*.py`. The manifest
hash tree and policy internals stay out of the agent-searchable index —
do not treat basemind search as a policy source.

## `files/policies/**` is hard-excluded (preserved)

`files/policies/policy-manifest.json` (the hash tree), `files/policies/schemas/**`,
and the `files/policies/*.json` control/policy definitions are hard-excluded from
the index by `**/policies/**` and `**/policy-manifest.json` in both
`[scan].exclude` and `[documents].exclude` — this exclusion is preserved even
though `files/**` is now indexed, so the manifest and policy internals must stay
out of the agent-searchable index. Agents hit the same deny through the
permission wall (`read`/`grep`/`glob` deny on `**/policy-manifest.json`) and
through `basemind_git` being unavailable (see below). Do not treat basemind
search results as a policy source.

## `basemind_git` is revoked (history bypasses excludes)

`basemind_git` is **not available** for v1 for every role. Basemind git reads
history without `basemind.toml` excludes, so it leaks excluded files (a
deleted `.env` or a secret that has since been removed from HEAD is still
reachable via history). History and diff questions must go through carbon
`git.*` instead (`git.state`, `git.status`, `git.log`, `git.diff`,
`git.read_file`), which enforce the same path denies. `basemind_shell` is
`ask` only, `basemind_admin` / `basemind_agents` are never granted — see each
agent's Tool surface; this document adds no grant.

## Scan statistics (2026-11-09)

Measured with timed `basemind rescan` (a daemon-held `watch` makes
`basemind scan` refuse with a collision error; `rescan` is the refresh
path). The index lives in the machine-global cache
(`~/.local/share/basemind/cache/workspaces/b51b55b3…/`, keyed by
workspace); nothing is written into the repo.

| run | files (code) / corpus | indexed entries | time | peak RSS |
| --- | --- | --- | --- | --- |
| before (cold) | 26 / 276,679 B | 137 | 60.45 s | 58.5 MB |
| before (warm) | 26 / 276,679 B | 137 | 0.14 s | 58.5 MB |
| after (full re-index) | 91 / 1,026,476 B | 226 | 182.49 s | 56.7 MB |
| after (post-fix incremental) | 91 / 1,026,476 B | 226 | 31.71 s | 56.5 MB |
| after (warm) | 91 / 1,026,476 B | 226 | 19.87 s | 56.2 MB |

Working tree total is ~30 MB / 1,942 files. Scan cost is dominated by
per-file L2 extraction, document embedding, and git-history sync through
the daemon — not corpus size. The ~1.2 GB figure tracks the
machine-global cache (~502 MB across workspaces), not the corpus.
Indexed surface now includes `files/sop/**`, `files/*.md`, and
`files/tools/**/*.py` (verified: 4 `sop` files, 61 `tools` Python files,
zero `files/policies/**` / manifest / schema hits in the index).
