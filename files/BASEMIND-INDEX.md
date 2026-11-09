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

The live `basemind.toml` `exclude` list is a superset of that floor (it also
lists `**/files/**`, `**/.agents/**`, `**/quality/ledger/**`,
`**/audit-scratch/**`, `**/.agt/**`, `opencode.json` / `**/opencode.json`,
`.opencode` variants, and the `[documents].exclude` mirror). Secrets and key
material (`*.pem`, `*.key`, `id_rsa*`) are additionally covered by the
basemind floor so no credential becomes searchable.

## `files/policies/**` lives outside every scanned root

`files/policies/**` (including `files/policies/policy-manifest.json` and
`files/policies/` schemas) lives in the harness root, outside every
worktree scan root. It is therefore never indexed by basemind. Agents hit
the same deny through the permission wall (`read`/`grep`/`glob` deny on
`**/policy-manifest.json`) and through `basemind_git` being unavailable (see
below). Do not treat basemind search results as a policy source.

## `basemind_git` is revoked (history bypasses excludes)

`basemind_git` is **not available** for v1 for every role. Basemind git reads
history without `basemind.toml` excludes, so it leaks excluded files (a
deleted `.env` or a secret that has since been removed from HEAD is still
reachable via history). History and diff questions must go through carbon
`git.*` instead (`git.state`, `git.status`, `git.log`, `git.diff`,
`git.read_file`), which enforce the same path denies. `basemind_shell` is
`ask` only, `basemind_admin` / `basemind_agents` are never granted — see each
agent's Tool surface; this document adds no grant.
