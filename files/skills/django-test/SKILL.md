---
name: Django Test
description: Runs Django tests inside K1 via k1.exec and collects SUITE, THREAD_RACE and BASE_FAIL_HEAD_PASS evidence via check.run; use when collecting suite, thread-race and base-fail/head-pass evidence.
metadata:
  opencode/autoinvoke: false
---
# django-test
`invocation:` call typed tools only:
```
docker.ensure({ action: "ensure" })
k1.up({ run_id: "<id>", base: "<40-hex-sha>", head: "<40-hex-sha>" })
k1.exec({ run_id: "<id>", action: "django test" })
check.run({ check_id: "SUITE", tree: "<40-hex-sha>", engine: "sqlite"|"postgres"|"none" })
k1.down({ run_id: "<id>" })
```
For head-only suite evidence either `k1.exec` (`django test` action) or `check.run` (`SUITE`) suffices; for `THREAD_RACE` and `BASE_FAIL_HEAD_PASS` always use `check.run` so the dispatcher pins the tree, engine and runner.

`serves:` `SUITE`, `THREAD_RACE`, `BASE_FAIL_HEAD_PASS` (registry `check.run.check_id`).

`args:`
- `k1.exec`: `{ run_id, action: "django test" }` (auditor only; no label arg, no free-form shell).
- `check.run`: `{ check_id, tree, engine, base?, head?, line?, removed_id?, covered_by? }` (`tree`/`base`/`head` ^[a-f0-9]{40}$; `engine` `sqlite`|`postgres`|`none`; `check_id` one of `SUITE`|`THREAD_RACE`|`BASE_FAIL_HEAD_PASS` for this skill).
- `SUITE` runners: builder, auditor, ci; `THREAD_RACE`/`BASE_FAIL_HEAD_PASS` runners: builder, auditor (registry `check_runners`).

`output schema:` `k1.exec` returns Django runner text (`Ran N tests in X.XXXs` plus `OK` or `FAILED (errors=N|failures=N)`); `check.run` returns the dispatcher result envelope (`result_type` `RESULT`, `exit_code`, `findings`). Parse `Ran N tests` + `OK|FAILED` from the runner text; the shell/tool exit is corroboration, never the verdict.

`exit codes:` refusal is `REJECT_*` (bad `tree`/`check_id`/`engine`); `check.run` exit `0` = accept (no findings), `1` = reject (findings), `2` = tool error. For `k1.exec`, a missing `Ran N tests`/`OK|FAILED` summary is `UNMEASURED`, never a pass.

`failure modes:`
- unknown test module/class at the tree: the runner reports a loader error with `FAILED (errors=1)`; this is an error, not evidence the test ran.
- `engine: "postgres"` against an unreachable database: connection error, not a pass; retry with the declared engine only.
- `BASE_FAIL_HEAD_PASS`: the same label must run at `base` and at `head` and be compared; quoting a head-only pass without a base comparison is not `BASE_FAIL_HEAD_PASS` evidence.

`worked example:` (tool calls only)
```
check.run({ check_id: "SUITE", tree: "12c96d1117c1a581eafe4a5c780a12f45808e30c", engine: "sqlite" })
k1.exec({ run_id: "smoke", action: "django test" })  # after k1.up
```
`verified:` 2026-11-08, tool names per registry (`k1.exec` action `django test`, `check.run` `SUITE`/`THREAD_RACE`/`BASE_FAIL_HEAD_PASS`); text verdict (`Ran N tests` + `OK|FAILED`) retained from the Django runner.
