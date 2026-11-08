# K1 hardening — F-13 resolution (6B-7)

**Status (reconciled): IMPLEMENTED but UNSEALED.** `files/K1-CONTAINER-PLAN.md`
says IMPLEMENTED and smoke-tested; `files/FACTORY-POLICY-MAP.md` says not
ready. Both are correct at different seals: the sandbox runs, but the image
pins are not yet recorded in `policy-manifest.json`. Until the postgres pin
below lands, treat K1 as unsealed and do not cite it as gate evidence.

Evidence:

| F-13 item | Finding | Hardening (this WP) |
| --- | --- | --- |
| Unpinned base | `FROM python:3.14-slim` tag-only, digest TODO | `Dockerfile` pinned to `python:3.14-slim@sha256:0514bc…bee9b1e1` (digest from the local-image TODO); `image-pins.json` records it |
| Postgres pin placeholder | `postgres:17-alpine@sha256:<pin>` placeholder | `compose.yaml` sidecar on the internal network with the pin **pending**: owner records the digest in `image-pins.json` + manifest before seal; no pull (offline) |
| Postgres on 0.0.0.0 | pg2a/pg2b published `0.0.0.0:5432/5433` | K1 network is `internal: true` with **no published ports**; provider binds `127.0.0.1:8081` inside the container (loopback only). pg2a/pg2b are outside K1 and untouched |
| /work exec | `/work exec` in the plan (hacker-scratch exec) | **DECIDED noexec**: `compose.yaml` mounts `/work` `noexec,nosuid,nodev`; the probe client is baked into the image (`/opt/k1/probe_client.py`), so probes never execute from `/work` |
| Docs drift | Plan says IMPLEMENTED, map says not ready | This file reconciles: IMPLEMENTED (runs) but UNSEALED (pins pending). The 6C seal must add the MCP server + registry + probe client to `gate_impl_digest` and record the postgres pin |

Files (owned by 6B-7 only): `docker/k1/Dockerfile`, `docker/k1/compose.yaml`,
`docker/k1/probe_client.py`, `docker/k1/image-pins.json`, `docker/k1/HARDENING.md`.
No factory worktrees or live agent files were touched.
