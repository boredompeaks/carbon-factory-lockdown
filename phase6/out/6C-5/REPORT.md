# 6C-5 Dummy capability end-to-end — REPORT

WP: 6C-5 (phase6c). Fresh-child integration smoke: dummy capability through
orchestrator -> builder -> auditor -> hacker -> release-engineer in K1
against a throwaway bare remote.
Status: DONE (MERGED to throwaway branch; ledger hash chain 5/5 intact;
no seal push, no tag, no legacy-move).

## Result — MERGED

| Item | Value |
|---|---|
| Base (master HEAD) | `1e4a93f86c57de338c1b5f762b4b5232cff70861` |
| Dummy commit (task/6c5-dummy) | `be440ad60fc0cb517fa706d62e0e19cdf8422161` |
| Dummy tree | `57856716976f2873d5c4a9f521af5d3aa0947270` |
| Merged branch (throwaway) | `6c5-dummy-merged -> be440ad60fc0cb517fa706d62e0e19cdf8422161` (fast-forward, same commit/tree) |
| Throwaway bare | `C:\Users\Admin\AppData\Local\Temp\opencode\6c5-remote-4a01a295.git` (forward-slash URL verified at closeout; see path-encoding note) |
| K1 RunId | `6c5smoke4a01` (real Docker, internal-only, removed after run) |
| Real K1 dummy proof | `cat /repo/head/backend/dummy_6c5.py` + `python /repo/head/backend/dummy_6c5.py; echo DUMMY_PARSE_OK` -> rc 0 inside `k1-6c5smoke4a01-app` |
| Origin / seal | **Not pushed** (origin untouched; master remains `1e4a93f`) |
| Tags / legacy | **None created; no `files/legacy/` move** |

Remote verification at closeout (re-pushed and re-verified with forward-slash
URL, because the first push used a backslash path that git resolves
unreliably on this host; content identical, same SHA):

```
be440ad60fc0cb517fa706d62e0e19cdf8422161 refs/heads/6c5-dummy-merged
be440ad60fc0cb517fa706d62e0e19cdf8422161 refs/heads/task/6c5-dummy
```

Local branches `task/6c5-dummy` and `6c5-dummy-merged` (both -> `be440ad`)
are kept for inspection; `master` (`1e4a93f`) has no `backend/` file.
Evidence JSON (chain, SHAs, K1 id):
`C:\Users\Admin\AppData\Local\Temp\opencode\6c5-evidence-4a01a295.json`.
Smoke script (re-runnable, forward-slash remote): `C:\Users\Admin\AppData\Local\Temp\opencode\smoke_6c5.py`.

## What ran (typed MCP dispatch + real effects)

**Orchestrator** (`Server("orchestrator")`):
`ledger.append capability` (genesis `0*64` -> `25f15e66…`) then `ledger.append dispatch`
(-> `13420181…`). Capability: `backend/dummy_6c5.py` scope, tier `none`,
`task_branch task/6c5-dummy`, UUID `capability_id` for hacker probe binding.

**Builder** (`Server("builder")`, capability bound head/base/tree/branch/scope):
real FS write `backend/dummy_6c5.py` (`DUMMY_6C5 = 1`), typed `code.write`
(single-line content — `validate.py` rejects `\n` as control char),
`evidence.hash`, `check.run` SCOPE/SUITE/TEST_SET/TEST_INFRA/CHANGELOG/SECRETS
(all PASS, sandbox), `git add` + real **`git.commit`** handler
(`be440ad`, tree `57856716…`), precheck BASE_FAIL_HEAD_PASS + CONVENTION PASS.

**Auditor** (`Server("auditor")`, ledger head synced `13420181…`):
typed `k1.up/status/exec(boot test)` leases (stub, TTL 600), then **real**
`scripts/k1_up.ps1 -RunId 6c5smoke4a01 -Base be440ad -Head be440ad`:
internal net `k1-6c5smoke4a01-net`, pg tmpfs ready, app healthy
(`fake provider http://127.0.0.1:8081`), archives both `backend/` mounts.
Real `k1_exec.ps1` quote-free (`python --version`, `cat` + `python dummy_6c5.py`)
rc 0. `check.run` GATE_CONTROLS/POLICY_DIGEST/BOOTTEST PASS,
`gate.control gate/mcp verify` sealed, `scratch.write` (auditor ns),
`acceptance.materialize` (path `artifacts/6c5/materialized.txt` — `audit-scratch/`
and `quality/ledger/` are deny-listed), `ledger.append verdict PASS`
(-> `c609a838…`), real `k1_down.ps1` + typed `k1.down`.

**Hacker** (`Server("hacker")`):
`hacker.probe AUTHZ-ROUTE/hacker-high` -> `REFUTED` (4/4 blocked, run `1b81371fadf8`),
`scratch.write` (hacker ns), `repro.run` (`audit-scratch/6c5/repro` — dot-free
per registry pattern) PASS, `static.scan` read-only 1 finding.
Auditor then `ledger.append attack-log` (-> `bb46bdda…`).

**Release-engineer** (`Server("release-engineer")`, ledger head synced):
auditor `git.push_ref` typed (fast-forward-only), real `git push throwaway`
task branch, typed `pr.open` (410) / `pr.watch(1)` / `pr.merge(squash, no admin)`,
real `git merge --ff-only be440ad` onto `6c5-dummy-merged` from base,
real push merged branch, `ledger.append release` (-> `34c2255e…`),
plus `worktrees.list` + `drain.validate` stub OK.

## Hash chain intact

In-memory ledger chain (per `files/tools/mcp/ledger/chain.py next_prev_hash`),
5 links, each recomputed in order from genesis `0*64`:

| # | record_type | prev | new |
|---|---|---|---|
| 1 | capability | `0000…` | `25f15e66…05b87e` |
| 2 | dispatch | `25f15e66…` | `13420181…87970` |
| 3 | verdict (PASS) | `13420181…` | `c609a838…da2dbdda` |
| 4 | attack-log | `c609a838…` | `bb46bdda…71b61c8` |
| 5 | release | `bb46bdda…` | `34c2255e…4f7` (head) |

`CHAIN-VERIFY PASS (5 links)`, `CHAIN_HEAD 34c2255eb1359559ce90b19de87b1c3d8f4d2ed44005500bded14a07816e34f7`.
Recomputation uses one shared `prev` threaded across role Servers
(auditor/release `_ledger_prev_hash` synced explicitly; each `Server`
starts at genesis by design, so cross-role threading is the harness's job).

**Gate-control file chain** (`files/tools/gate_control.py --verify-chain --json`):
`FAIL (exit 1, chain_size 9)` — **pre-existing at master, not caused by 6C-5**:
record 0009 pins `gate_sha a8754a8…` but HEAD is `1e4a93f` (the 6C-4 commit itself
touches gate paths). This is the documented seal-lifecycle: every seal commit
moves its own `gate_sha` (“The final seal must roll the chain forward”,
6C-4 REPORT). 6C-5’s dummy commit (`backend/` only) does not touch gate paths
and does not advance `gate_sha`. Verified at base: same 9 problems with `master`
checked out. No chain break was introduced by this smoke.

## Deviations / host notes (no harness code changed)

1. **Local `k1-app` image is pre-6B-7** (no `/opt/k1/probe_client.py` baked;
   Dockerfile now copies it). Auditor never rebuilds per K1 README; health was
   proven by `k1_up.ps1`’s own `/health` poll + quote-free execs.
2. **Quote-free K1 execs**: `k1_exec.ps1` pipes via `/bin/sh -c`; nested
   `python -c "…"` loses quotes under PowerShell. Used `python --version`,
   `cat`, `python <file>` instead.
3. **Throwaway remote URL must be forward-slash** (`C:/…`): first push used a
   backslash string; `ls-remote` inside the run saw refs but the bare did not
   persist as addressed. Closeout re-pushed with forward slashes and
   `show-ref`/`ls-remote` verified both branches at `be440ad`.
4. **`backend/` is untracked on master** and `k1_up.ps1` archives only `backend/`.
   K1 ran with `base == head == be440ad` (both contain `backend/`) — the
   `base == 1e4a93f` archive would fail (`HEAD:backend` absent). Typed `k1.up`
   used the same `be440ad/be440ad` pair.
5. **String hygiene**: `code.write content` with `\n` rejects `REJECT_PATTERN`
   (control chars); single-line content used for the stub dispatch while the
   on-disk file keeps newlines.

## Exit test (harness root)

```
python C:\Users\Admin\AppData\Local\Temp\opencode\smoke_6c5.py   # MERGED=PASS, exit 0
git ls-remote throwaway  (forward-slash remote)                  # both refs -> be440ad
python files/tools/gate_control.py --verify-chain --json         # FAIL at base too (pre-existing, § above)
```

## Open questions

- None blocking 6C-5. Final seal must roll the gate-control chain forward
  (6C-4 open question) and rebuild `k1-app` so the 6B-7 probe client is baked
  (owner/FDE only). Neither was done here: **NO seal push, no tag, no legacy-move.**
