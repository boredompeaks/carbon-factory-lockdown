# K1 app image build context (canonical: files/docker/k1/)

Small, hardening-oriented runtime for one K1 sandbox run. The image contains
**no application code**: the sealed repo is mounted read-only at `/repo/base`
and `/repo/head` by `scripts/k1_up.ps1`, and app code is imported from
`/repo/head/backend` (`PYTHONPATH`).

Contents:

| File | Purpose |
|---|---|
| `Dockerfile` | multi-stage, pinned `python:3.14-slim@sha256:0514bc…bee9b1e1`, non-root uid/gid 10001, read-only-rootfs runtime |
| `compose.yaml` | hardened runtime shape; pg pinned `postgres:17-alpine@sha256:b0f956…2b24`, internal network, no published ports, /work noexec |
| `image-pins.json` | both digests + local-inspect source; F-13 evidence |
| `probe_client.py` | baked into image at `/opt/k1/probe_client.py` (stdlib only, 127.0.0.1:8081) |
| `HARDENING.md` | F-13 reconciliation, canonical-path note |
| `fake_provider.py` | stdlib fake payment provider on `127.0.0.1:8081`, deterministic ids, call log at `/work/provider-calls.jsonl` |
| `entrypoint.sh` | starts the provider, waits for `/health`, `exec "$@"` |
| `seed.py` | idempotent PII-free SQLite/Postgres fixture seeder |

## Build (owner/FDE only)

From the repo root, with no pull and no network:

```
docker build --pull=false -t k1-app:latest files/docker/k1
```

The auditor and hacker never build or pull `k1-app:latest`. If it is absent,
`scripts/k1_up.ps1` refuses with `IMAGE_MISSING` and prints this command.

`FROM python:3.14-slim@sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1`
is pinned; verified 2026-11-08 against the local image (Id = RepoDigest, 178 MB).
Postgres sidecar is pinned in `compose.yaml` to
`postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`
(local Id = RepoDigest, 423 MB). See `image-pins.json`.

Validated: `python:3.14-slim` pin was already done in the 6B-7 worktree
(`docker/k1/Dockerfile` + `image-pins.json` python entry) and is now unified
into this canonical `Dockerfile`.

## Runtime

Started only by `scripts/k1_up.ps1` as `k1-<RunId>-app` on the internal
`k1-<RunId>-net`, with a read-only rootfs and tmpfs for `/tmp`, `/run`, `/work`
and `/home/k1`. Or `docker compose -f files/docker/k1/compose.yaml up`
(manual; scripts are the audited path). The default `CMD` is `sleep infinity`;
probes run through `scripts/k1_exec.ps1`.

`seed.py` defaults to SQLite at `/work/sqlite/k1.sqlite3`. Postgres seeding
(`--database-url postgresql://...`) needs `psycopg` or `psycopg2`; add the
pinned driver to `requirements.txt` when the owner builds the image.

## Path note

Canonical path is `files/docker/k1/` per `files/K1-CONTAINER-PLAN.md` §8 and
`files/policies/policy-manifest.json` (`docker:files/docker/k1/*`).
`docker/k1/` at the repo root is now a stub README only.
