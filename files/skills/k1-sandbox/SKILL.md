---
name: K1 Sandbox
description: Starts, executes in, and tears down one isolated K1 run (internal network, tmpfs Postgres, read-only non-root app) via docker.ensure, k1.up, k1.exec, k1.status and k1.down; never pulls, builds, stops Docker, prunes anything, or touches pg2a/pg2b.
metadata:
  opencode/autoinvoke: false
---
# k1-sandbox
`skill-level name:` k1-sandbox

`invocation:` call typed tools only (auditor):
```
docker.ensure({ action: "ensure" })
k1.up({ run_id: "<id>", base: "<40-hex-sha>", head: "<40-hex-sha>" })
k1.exec({ run_id: "<id>", action: "django test" })
k1.status({ run_id: "<id>" })
k1.down({ run_id: "<id>" })
```

The auditor runs `docker.ensure` before `k1.up` and `k1.down` in a `finally` block after the hacker pass (also on hacker failure). The hacker never gets `k1.up`/`k1.exec`; it reaches the K1 runtime only through `hacker.probe` (see hacker-exploit).

`serves:` one isolated K1 lifecycle: internal network, tmpfs Postgres, read-only non-root app with two read-only repo mounts. Only names `k1-<run_id>-net`, `k1-<run_id>-pg` and `k1-<run_id>-app` are ever touched. Runs expire under the TTL lease reaper.

`args:`
- `docker.ensure`: `{ action: "ensure" }` (roles builder, auditor; starts the engine/Desktop only; never pulls, builds, creates, runs or deletes anything).
- `k1.up`: `{ run_id, base, head }` (auditor only; `run_id` ^[a-z0-9][a-z0-9_-]{0,63}$; `base`/`head` ^[a-f0-9]{40}$ and must resolve).
- `k1.exec`: `{ run_id, action, node? }` (auditor only; `action` enum `django test` | `migrate` | `makemigrations check` | `boot test`; no free-form command strings; `node` optional ^[a-z0-9][a-z0-9_-]{0,63}$).
- `k1.status`: `{ run_id }` (auditor only).
- `k1.down`: `{ run_id }` (auditor only; idempotent).

`what k1.up does:` ensures the engine via `docker.ensure`, refuses `IMAGE_MISSING` without pulling or building, resolves `base`/`head` at the git object id, extracts `backend` from the tree into read-only base/head mounts (excludes `.env*`, `quality/**`, `venv/`), creates the internal network, starts Postgres on tmpfs (96m, 256m, 0.5 CPU) and waits `pg_isready` up to 60 s, then starts the app read-only non-root (uid 10001, 384m, 1 CPU) with tmpfs `/tmp` 32m, `/run` 8m, `/work` 64m, `/home/k1` 8m plus `DATABASE_URL`/`FAKE_PROVIDER_URL`, and waits `/health` up to 60 s.

`output schema:` `k1.up` returns the run ids/names on success or a `REJECT_*` refusal (bad args, missing commit, engine down, name collision); `k1.exec` returns the action output (Django runner text for `django test`); `k1.status` returns stack state; `k1.down` returns completion or already-absent.

`exit codes:` tool errors are `REJECT_ROLE` / `REJECT_ARG` / `REJECT_PATTERN` with no state change; `k1.exec` also surfaces the action's own exit code in its result.

`failure modes:`
1. Engine down after `docker.ensure`: `k1.up` refuses; do not retry with a different tool. `k1.down` never starts or stops Docker; it skips container removal when the engine is down and still removes the run dir.
2. Image absent: `k1.up` refuses without pulling or building; the owner build command is printed for the owner/FDE only, never run by auditor/hacker.
3. Postgres/app fails to start or `/health` misses 60 s: `k1.up` removes only the resources it created and refuses.
4. `k1.exec` against a stopped/absent app: refusal; run `k1.status` to confirm.
5. `/work` is tmpfs: artifacts must be copied out before `k1.down`; `k1.down` copies them out first.
6. Name or run-dir collision: `k1.up` refuses; run `k1.down` for that `run_id` first.

`hard rules:` never pull or build, never stop Docker/Desktop, never `docker stop`/`system prune`/`volume prune`, never publish ports, never touch `pg2a`/`pg2b` or any name outside `k1-<run_id>-*`.

`worked example:` (tool calls only)
```
docker.ensure({ action: "ensure" })
k1.up({ run_id: "smoke", base: "9b10e00", head: "12c96d1" })  # rejected unless 40-hex
k1.exec({ run_id: "smoke", action: "django test" })
k1.down({ run_id: "smoke" })
```
`verified:` 2026-11-08, tool names per registry (`k1.up`/`k1.exec`/`k1.down`/`k1.status`/`docker.ensure`); run ids and 40-hex pins per registry patterns.
