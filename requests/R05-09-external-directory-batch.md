# R05-09 — External-directory grants for the factory (single batch)

**Status:** IMPLEMENTING
**Owner:** harness operator (works *on* the factory, not under it)
**Scope:** permissions only. No product code, no policy semantics, no control minima.

## 1. Incident

The orchestrator emitted:

```
schema      orchestrator-decision/1
task_id     PRISTINE-13d1
step        capability
action      HALT
reason_code NO_ACCEPTANCE_REF
predicates  P-CTRL PASS, P-CLEAN PASS
```

because `read` of the PRISTINE ledger returned `Permission denied:
external_directory` for all four paths:

- `comp-wt/backend/docs/spec-run-state.md`
- `comp-wt/backend/run/PRISTINE-tasks.md`
- `comp-wt/backend/run/PRISTINE-PLAN.md`
- `comp-wt/backend/run/BUILD-QUEUE.md`

The release engineer hit the same wall: `git -C <worktree> ...` and the same
four reads were denied. It could report only the heads that
`sync_worktrees.ps1` printed on stdout (`spec-comp @ 12c96d1`, `lane/a @
ea52f62`, `lane/b @ e0a113f`). With no readable ledger, no base/head/tree, and
no acceptance refs, no valid capability could be authored — hence
`NO_ACCEPTANCE_REF`.

## 2. Root cause

Role `read` rules are workspace-scoped to
`C:\Users\Admin\Documents\umairnlp`. The product repo and every worktree live
under `C:\Users\Admin\AppData\Local\Temp\opencode\`, outside that root.
`external_directory` is deny/ask by default, so even a `read **` rule cannot
cross the boundary. This is not a role bug; it is a missing grant.

## 3. Decision: one batch, root globs, one seal

Grant by **root**, not by individual worktree or run id. A new worktree, lane,
or K1 run under an approved root is then covered without a new seal. A new
*root*, a new *role*, or a change to a carve-out is the only thing that forces
another seal.

## 4. Grant matrix (verified inventory)

The external roots the factory actually touches:

| Path root | Read | Tool-write | Roles | Why |
|---|---|---|---|---|
| `C:\Users\Admin\AppData\Local\Temp\opencode\*` | yes | role edit rules only | orchestrator, builder, auditor, hacker, RE, compliance | 11 worktrees + K1 + scratch, one root |
| `C:\Users\Admin\Downloads\backend\*` | yes | RE/builders via git only | orchestrator, builder, auditor, RE | main worktree `UI/UX` + shared `.git` object store |
| `C:\Users\Admin\.local\share\opencode\*` | operator/FDE only | no | operator | session DB, transcripts, shell output |
| `C:\Users\Admin\Documents\umairnlp\*` | already granted | role-scoped | all | harness root (ledger, policies, quality, tools) |

Verified inventory (2026-11-07):

- **11 worktrees** under `%TEMP%\opencode`: `comp-wt` (`spec-comp`, 324.5 MB),
  `spec-comp-wt` (`lane/a`, 265 MB), `wt-async` (`lane/b`, 256 MB), `wt-c`
  (`lane/c`, 252 MB), `wt-d` (`lane/d`, 252 MB), `ui-wt` (`ui/cf-storefront`,
  672 MB), `ui-wt-t1/t2/t3`, `par-wt` (`ui/par-01`), `pre-854` (detached).
  The last five are empty skeletons (only a `.git` file).
- Every worktree `.git` is a **file** pointing at
  `C:/Users/Admin/Downloads/backend/.git/worktrees/<name>`. The object store,
  refs, packed-refs and config are in the main `.git` (64.2 MB, 2,998 files).
  A worktree-only grant is insufficient: `git status/diff/log` and
  `git archive` need the shared object store. Git's own writes (index, refs,
  objects) are OS-level, not `edit`-tool writes.
- **K1**: run root `%TEMP%\opencode\k1\<RunId>\{repo-base,repo-head,artifacts}`;
  containers bind `repo-base`/`repo-head` read-only; no named volumes; no
  published ports. `repo-base`/`repo-head` stay read-only by design.
- **No `quality/` exists in any worktree or in repo `HEAD`.** The Chinese wall
  is `files/quality/**` + `quality-scan/**` in the harness root, plus
  `Temp\mutation\**` fixture copies (which are not the live ledger).
- Hacker surfaces: `Temp\hacker-scratch` (empty, write target),
  `Temp\security-audit-skill`, `Temp\h1..h3`, and
  `.opencode\skills\hacker-exploit\**` in the harness root. These stay denied
  to builder/auditor/orchestrator.
- Session state: `C:\Users\Admin\.local\share\opencode\{opencode.db,log,shell,
  storage,tool-output,snapshot,worktree,repos}`; `auth.json` /
  `mcp-auth.json` remain FDE-only.

`files/tools/out`, `files/quality/ledger`, `files/drain`, `quality-scan` are
already inside the harness root; no external grant is needed for them.

## 5. Chinese wall (must stay denied after the grants)

- **builder**: `**/hacker-scratch/**`, `**/audit-scratch/**`, audit verdicts,
  quality verdict rows. The grant is worktree product code, not verdicts.
- **auditor**: the hacker skill (`files/hacker.md`, `.opencode/skills/hacker*`)
  — it audits the exploit, it does not read the hacker's instructions.
- **hacker**: `quality/**` and `files/quality/**` — no verdict shopping.
- **all roles**: `**/policy-manifest.json` (owner-only) and root
  `.env`/`*.pem`/`*.key`/secret reads stay hard-denied.

## 6. Why this prevents re-sealing per change

Today each new external path is a new permission edit. After this record:

- a new worktree under `%TEMP%\opencode\` is already readable;
- a new K1 run under `%TEMP%\opencode\k1\` is already readable;
- a new lane branch needs no permission change, only a capability;
- only a genuinely new root (e.g. a second repo) requires a new grant + seal.

## 7. Verify + seal (after edits)

Verified against `files/tools/gate_control.py` and
`scripts/policy_manifest.py`: an `external_directory` rule lives only in the
agent contracts (`files/<role>.md` + `.opencode/agents/<role>.md`). That is a
**manifest-only** artifact. It is not one of the five gated policies, not a
tool body/fixture, and not `opencode.json`/`.agt/policy.json`, so it moves
**none** of `policy_digest`, `control_set_sha`, `gate_impl_digest`, `gate_sha`.

Therefore:

- **No new seal is written for this batch.** `0006` stays newest and keeps
  verifying. This is deliberate: the grant must not churn the chain.
- **A manifest rewrite is required**, because `check_harness_config.py` runs
  `policy_manifest.py --verify` as one of its checks.

```
python scripts\policy_manifest.py --write       # records the edited contracts
python scripts\policy_manifest.py --verify      # PASS, drift []
python scripts\check_harness_config.py          # PASS (107)
python files\tools\gate_control.py --verify-chain   # still 0006 PASS
python files\tools\validatedrain.py             # still PASS
permission resolver                             # LEAKS 0, GAPS 0
```

Live probes are mandatory, because neither the checker nor the resolver tests
`external_directory`:

- positive: a granted role reads `comp-wt/backend/docs/spec-run-state.md`;
- negative: the same role is still denied outside the approved root;
- RE shell: `git -C <worktree> rev-parse HEAD` with the worktree as cwd;
- builder: still gets the `ask` prompt (the read ask is unchanged).

A **seal (0007)** is written only if a later change also touches a digest-tier
artifact (`opencode.json`, `.agt/policy.json`, a tool body/fixture, or one of
the five gated policies). If that ever happens, the order is: re-seal first,
then manifest write, then verify.

## 8. Result (2026-11-07)

Applied to all 7 contracts (source + byte-identical twin): `orchestrator`,
`builder`, `auditor`, `hacker`, `release-engineer`, `compliance`,
`crouton-alpha`.

```yaml
- { action: external_directory, resource: "C:/Users/Admin/AppData/Local/Temp/opencode/**", effect: allow }
- { action: external_directory, resource: "C:/Users/Admin/Downloads/backend/**", effect: allow }   # not hacker
```

Orchestrator also gained read-only git shell allows (`rev-parse`, `status`,
`diff`, `log`, `merge-base`, `worktree list`, `branch`); `git push*` stays
denied. RE gained `merge-base` + `worktree list`.

Verification:

| Check | Result |
|---|---|
| `check_harness_config.py` | `PASS (107)` |
| `policy_manifest.py --verify` | `PASS`, 203 files, `drift []` (hash recomputed on write) |
| `gate_control.py --verify-chain` | newest `0006`, chain 6, `PASS` |
| `validatedrain.py` | `PASS`, 3 records |
| resolver | `LEAKS 0`, `GAPS 0`, 7/7 twins identical |
| digests | `policy_digest c8471186…`, `control_set_sha 971f1fda…`, `gate_impl_digest 0fe32eea…` — unchanged, **no seal** |

Live probe (orchestrator, `opencode run --standalone --agent orchestrator`):

```
read C:\...\comp-wt\backend\docs\spec-run-state.md
  EXIT 0  PARSED "# Spec run state" | "## Latest promotion (2026-10-24)" | "- PR #50 MERGED @ e77e9ca…"
read C:\Windows\win.ini
  EXIT 1  PARSED "Permission denied: external_directory"
```

## 9. Follow-up found by the probe

`comp-wt\backend\run\` does not exist. The real PRISTINE ledger is
`comp-wt\backend\docs\run\PRISTINE-tasks.md`; `PRISTINE-PLAN.md` does not
exist. Corrected in the handoff and pilot prompt. The ledger also conflicts
with `spec-comp-wt\backend\docs\changes.md` (`13d1`, `13d2a` shipped; `16`
SHIPPED), so the factory must reconcile before resuming.

One remaining design gap (not a permission): the builder's `read` ask for
`Temp/opencode/**` is still `effect: ask`. In a headless subagent run an `ask`
auto-denies, so the builder must either be spawned with `cwd` inside its lane
worktree (relative reads, which are allowed) or the ask must be deliberately
scoped. Do not silently convert it to `allow`.
