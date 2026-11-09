---
name: commit-cadence
description: Use before committing, pushing, opening or merging a PR in this repo. Records the observed git rhythm — one spec row per commit, a paired "chore: ledger" commit after nearly every feature commit, spec-comp linear with stacked promotion PRs into feat/add-frontend, master frozen, no wip: commits, who is allowed to push — with the measured numbers from 404 commits.
---

# Commit cadence

Measured from all 404 commits across every branch (`git log --all`). Use these
numbers as the shape to match, not as a style preference.

## The unit of work is one spec row, not one file and not one feature

| Metric | Value |
|---|---|
| Commits on `spec-comp` | 349 with **0 merges** up to the two-lane era (strictly linear, rebase-free); since 2026-10-08 the only merge commits allowed are the orchestrator/RE lane integrations (`merge lane/a\|lane/b … into spec-comp`) |
| Non-docs source files per `feat:`/`fix:` commit | **median 4**, mean 2.56 across all commits |
| Source lines per commit | mean +190; steady-state batch **~100–400 lines** |
| Largest commit | 78 files / +8451 — day-1 Next.js import, not a steady-state example |
| A "train" (one promotion PR) | **22–35 commits** |

If your diff is 40 files, you have taken on multiple spec rows. Split it.

## Every feature commit is followed by a ledger commit

**166 of 404 commits (41%) are `chore: ledger …`. 199 of 404 (49%) touch zero
source files.** Median gap between consecutive `spec-comp` commits: **13.3 min**
(p25 5.5, p75 23.8). The rhythm is a strict pair:

```
<sha>  feat(orders): SPEC-1-B07a - ReturnRequest lifecycle core
<sha>  chore: ledger - SPEC-1-B07a IN-AUDIT (floor 1690->1698, cov 100%, 7980 stmts)
```

The ledger commit is bookkeeping. It goes in immediately, it is small, and it is
what makes the next audit a **delta** audit instead of a fresh one. Skipping it
is what forces cycle 3 to re-derive cycle 1's ground.

`wip:` appears **0 times in 404 commits.** There are no dirty intermediate
commits. Every commit is a clean checkpoint; unfinished state lives in the
ledger, not in the branch.

## Who commits and who pushes

Roles are **not** expressed in git identity — all 403 real commits are authored
by the same human account. Role separation exists only in subject text. You
cannot audit authorship from metadata; read the message.

Observed division of labour, from the agent prompts in `.opencode/agents/`:

| Role | Commits | Pushes | Merges |
|---|---|---|---|
| builder | yes, one per task + one per fix cycle | **never** (`git push*: deny`) | never |
| auditor | yes, `chore: ledger …` | **yes** — durability backup + PR head updates; a lane auditor pushes its lane branch (lane branches get no PRs) | never |
| orchestrator | ledger rows / queue sizing | no | never |
| release-engineer (RE) | ledger rows, gate verdicts | yes | **owns every merge** |
| human | owner actions only | yes | resolves GitGuardian incidents, sets repo vars |

Branch policy, encoded in the prompts and confirmed by history:
- `spec-comp` is the work branch. Linear **except** lane-integration merges (2026-10-08+): a builder never merges; the orchestrator/RE reconcile the lanes into it after every task.
- `feat/add-frontend` is advanced **only by promotion PRs from `spec-comp`**.
  Local `feat/add-frontend` is a stale fork — work off `origin/feat/add-frontend`.
- `master` receives **no product code**. Its only post-09-18 commits are the
  human allowlisting GitGuardian false positives.
- PRs are **stacked, not serial**: five promotions merged on 2026-10-01.
  Standing directive recorded in `aa01edf`: *"no idle unless RE escalates,
  stack PRs."*
- Push withheld on escalation (see `audit-cycle-protocol` Rule 1).

## Merge discipline

Merges are all `Merge pull request #N from boredompeaks/spec-comp`, #2–#21,
every one `spec-comp → feat/add-frontend`. The orchestrator **verifies the merge
independently** rather than trusting the PR UI — recorded as
"orchestrator-verified mergeCommit == origin/feat/add-frontend tip".

Before you claim a promotion landed, check it yourself:

```bash
git fetch origin
git rev-parse origin/feat/add-frontend     # must equal the PR merge commit
git merge-base --is-ancestor <your-sha> origin/feat/add-frontend && echo PROMOTED
```

## Commit message vocabulary (grep-able, and the ledger depends on it)

Prefix distribution across 404 subjects: `chore:` 185, `feat:` 91, `fix:` 61,
`docs:` 26, `test:` 7, `refactor:` 2, `style:` 2, `ci:` 1.

Token frequency — these are how state is tracked, so use them:
`SPEC-` 296 · `ledger` 179 · `cycle` 80 · `SHIPPED` 68 · `GATE`/`RE ` 46 ·
`floor` 50 · `IN-AUDIT` 23 · `BUG-` 21 · `P3` 22 · `P2` 18 · `BUGS-FOUND` 14 ·
`P1` 12 · `escalat` 10 · `RE-AUDIT` 8.

Subjects are long and carry the finding, not just the topic. Real examples:

```
chore: ledger - SPEC-1-B07b ESCALATED at 3/3 (BUG-4 P2 byte-corrupted changelog -
  8 new control bytes ate characters and fused paragraphs; 3xP3 stale figures;
  ZERO product risk, all 5 product files AST-equal)
chore: ledger - SPEC-1-B07f-a SHIPPED (3 cycles, RE-AUDIT c3, pushed 9f00987;
  floor 1758->1769, cov 100%, 8815 stmts); the killed-builder rescue found a P1
  in the inherited diff
```

The `builder` word appears in only **2** subjects. The reviewer role is called
**RE** (46) and **auditor** (11). Use those words.

## Never commit

`.env`, `db.sqlite3`, `media/`, `venv/`, `.coverage`, `htmlcov/`,
`node_modules/`, `.next/`, `test-results/`, `.opencode-web/` (local tooling).

`frontend/scripts/demo_walkthrough.mjs` is **user-owned and stays untracked by
explicit consent**. It contains demo credentials and a real Razorpay card flow.
`git status` will perpetually show it as `??`. **Never commit it, never modify
it, never flag it in a diff-scope review.** This is recorded as a standing
escalation in the ledger, not as an oversight.

Also never: `git push` from a builder lane, `git merge`, `git rebase`,
`git worktree`, `git checkout`/`switch` off your handoff branch, and
`git revert` (0 in history — fix forward with a `fix:` commit).

## Before every commit

```bash
git branch --show-current          # must equal your handoff branch, else BLOCKED
git status --porcelain             # nothing outside your declared scope
git diff --stat                    # median 4 source files; more means you over-scoped
git diff                           # read it as the auditor will
git log --oneline -5               # confirm the previous ledger row is present
```

Then: re-read the diff for stubs, dead code, hardcoded values, weakened
assertions, and scope creep. Fix those before reporting, not after.

## Figures are printed, not typed (2026-10-04+)

Changelog floor and mutation figures come from
`scripts/changelog_figures.py floor --task <id>` / `mutation --task <id>`,
which measure and print the bullet to paste. `check --base <sha>` fails any
changelog row whose figure has no artifact behind it, and CI runs that check
(wired `f89d121`, made honest `457993d`). The only exemption is the committed
inventory `scripts/changelog_figures_baseline.json`, written solely by an
explicit `check --update-baseline` with a written reason. A hand-typed figure
is a finding — this exact defect class cost B07b and B07d their cycles.

## Encoding hazard

Shell redirection corrupted files twice in this repo's history: a PowerShell
backtick-escape wrote a literal `0x08` into a source file, and a separate edit
left UTF-8 BOM damage that needed a byte-level restore from `6a9c7db^`. Both
cost an extra fix cycle. **Edit files with file-editing tools, never shell
redirection.** If a diff is mysteriously larger than your change, suspect
encoding before you suspect logic, and verify on the committed blob.