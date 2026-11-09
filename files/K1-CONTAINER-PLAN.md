# K1 container plan — tmpfs, light footprint, loopback-only

**Host:** OS-agnostic — typed tools are canonical (`pr.open`, `k1.up`, `worktrees.sync`, …); the canonical path is `files/tools/mcp/k1/handlers.py` (`k1.up`/`k1.exec`/`k1.down`/`k1.status`, `docker.ensure`). The `scripts/*.ps1` wrappers in the §1 deprecation table are legacy/Windows-only — do not use them as the live path.

Status: IMPLEMENTED and smoke-tested (2026-11-07). `k1-app:latest` is built
locally (143.7 MB) from the product requirements; the base digest pin is still
TODO. Section 8 records the exact invocation, limits and image
state; the design below remains the source of truth.

## 1. Current footprint (measured 2026-11-07)

Docker server 28.5.1, overlayfs, cgroup 2, 8.17 GB RAM, 24 CPU, root
`/var/lib/docker`. The measured host was Windows (service + GUI VM, see the
deprecation table in §1 below); on POSIX the engine is a native daemon and a
cold start needs only the native daemon (see §6).

| Container | Image | Data dir | Data | RSS | Limits |
|---|---|---|---|---|---|
| pg2a | postgres:17-alpine (423 MB) | named volume on ext4 `/dev/sdf` | 121.9 MB | 74.66 MiB | none |
| pg2b | postgres:17-alpine (423 MB) | named volume on ext4 `/dev/sdf` | 79.5 MB | 41.62 MiB | none |

Both are `bridge`, published on `127.0.0.1:5432` / `127.0.0.1:5433`
(loopback-only for host-published ports; the all-interfaces bind is
deprecated — see the deprecation table below), `shm=64m`,
rootfs read-write, no `cap-drop`, no `no-new-privileges`, no tmpfs. **They do
not run on tmpfs.** Their data survives restarts because it is a named volume.

Host totals: images 50.81 GB (99% reclaimable), volumes 1.643 GB (1.432 GB
reclaimable), build cache 10.1 GB (all reclaimable), containers 49 kB. A prune
is an owner decision; the K1 build does not depend on it.

### Canonical handlers and deprecated Windows wrappers (P3-9 / P3-11)

Canonical implementation is `files/tools/mcp/k1/handlers.py`
(`k1.up` / `k1.exec` / `k1.down` / `k1.status`, `docker.ensure`). The native
handlers are canonical on every host; the 11 `scripts/*.ps1` wrappers below
are deprecated / Windows-only legacy and must not be invoked on POSIX.
Host-published ports bind `127.0.0.1` only (loopback). The rows below are
the deprecation table: every stale literal in this plan lives here, not in
live instructions.

| Deprecated artifact (Windows-only / legacy) | Status | Canonical replacement |
|---|---|---|
| `scripts/k1_up.ps1` | deprecated, Windows-only | `k1.up` in `files/tools/mcp/k1/handlers.py` |
| `scripts/k1_exec.ps1` | deprecated, Windows-only | `k1.exec` in `files/tools/mcp/k1/handlers.py` |
| `scripts/k1_down.ps1` | deprecated, Windows-only | `k1.down` in `files/tools/mcp/k1/handlers.py` |
| `scripts/ensure_docker.ps1` | deprecated, Windows-only | `docker.ensure` in `files/tools/mcp/k1/handlers.py` |
| `scripts/open_pr.ps1` | deprecated, Windows-only | typed `pr.open` (native handler) |
| `scripts/push_ref.ps1` | deprecated, Windows-only | typed `git` / PR handlers (native) |
| `scripts/merge_pr.ps1` | deprecated, Windows-only | typed `pr.open` / merge handlers (native) |
| `scripts/sync_worktrees.ps1` | deprecated, Windows-only | typed `worktrees.sync` (native) |
| `scripts/reconcile_lanes.ps1` | deprecated, Windows-only | typed lane handlers (native) |
| `scripts/audit_test_runner.ps1` | deprecated, Windows-only | typed test-runner handler (native) |
| `scripts/watch_checks.ps1` | deprecated, Windows-only | typed checks handler (native) |
| `pg2a`/`pg2b` on `0.0.0.0:5432` / `0.0.0.0:5433` | deprecated all-interfaces bind | `127.0.0.1:5432` / `127.0.0.1:5433` loopback |
| Docker Desktop VM / `Docker Desktop.exe` / `com.docker.service` | deprecated Windows-only engine | native daemon + `docker.ensure` |

## 2. K1 design (default: isolated, tmpfs)

Two containers on one **internal** Docker network, no published ports:

```
k1-internal (internal: true)
  k1-app   app runtime + fake payment provider + SQLite   (127.0.0.1:8081 inside)
  k1-pg    postgres:17-alpine, data on tmpfs              (k1-pg:5432)
```

The app calls the fake provider on loopback and Postgres on `k1-pg:5432`.
`--internal` gives no route off the bridge; there is no host port mapping.

### k1-app

- Base: `python:3.14-slim` pinned by digest (already local, 178 MB).
- Multi-stage build: builder installs `backend/requirements.txt` into
  `/install`; runtime copies `/install`, drops build tools and pip cache.
- Non-root `k1` uid/gid 10001; `--read-only` rootfs; writable paths are tmpfs.
- App code is **not** baked in: the sealed repo is mounted read-only at
  `/repo/base` and `/repo/head`; `PYTHONPATH=/repo/head/backend`.
- Fake provider: stdlib `http.server` on `127.0.0.1:8081`, deterministic
  responses, call log in `/work/provider-calls.jsonl`. No network.
- SQLite: `/work/sqlite/k1.sqlite3` (tmpfs).
- tmpfs:
  - `/tmp` 32m `noexec,nosuid,nodev`
  - `/run` 8m `noexec,nosuid,nodev`
  - `/work` 64m `exec,nosuid,nodev` (hacker-scratch; exec is required to run probes)
  - `/home/k1` 8m `noexec,nosuid,nodev`
- Limits: `--memory 384m --memory-swap 384m --cpus 1 --pids-limit 256
  --ulimit nofile=1024:1024 --shm-size 32m`.
- Hardening: `--cap-drop ALL --security-opt no-new-privileges --read-only`,
  `--tmpfs` flags above, `--log-driver local --log-opt max-size=1m
  --log-opt max-file=1 --log-opt compress=false` (compression conflicts with
  `max-file=1`).

### k1-pg

- `postgres:17-alpine` pinned by digest (local, 423 MB).
- `--tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,size=96m` — **no volume**;
  the database is destroyed with the container.
- `POSTGRES_PASSWORD` generated per run; `POSTGRES_DB=k1`; no host port.
- `--memory 256m --cpus 0.5 --shm-size 32m --cap-drop ALL
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETGID
  --cap-add SETUID --security-opt no-new-privileges` (the official entrypoint
  must chown the tmpfs data dir; without these it exits 255).
- Healthcheck `pg_isready -U postgres -d k1`.

### Repo mounts and artifacts

- `-v <run>/repo-base:/repo/base:ro`
- `-v <run>/repo-head:/repo/head:ro`
- `quality/**`, `.env*`, `media/`, `venv/` are excluded from the archives.
- `/work` is tmpfs; before teardown the harness runs
  `docker cp k1-app:/work/artifacts <run>/artifacts` and content-hashes them.

## 3. Build sketch

```dockerfile
# syntax=docker/dockerfile:1.7
FROM python:3.14-slim@sha256:<pin> AS build
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /install
COPY backend/requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

FROM python:3.14-slim@sha256:<pin>
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
RUN useradd --uid 10001 --create-home --shell /bin/bash k1
COPY --from=build /install /usr/local
COPY k1/fake_provider.py k1/seed.py k1/entrypoint.sh /opt/k1/
RUN chmod 0555 /opt/k1/entrypoint.sh
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/opt/k1/entrypoint.sh"]
CMD ["sleep", "infinity"]
```

Run shape:

```bash
docker network create --internal k1-internal
docker run -d --name k1-pg --network k1-internal \
  --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,size=96m \
  --memory 256m --cpus 0.5 --shm-size 32m --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --cap-add SETGID --cap-add SETUID --security-opt no-new-privileges \
  -e POSTGRES_PASSWORD=$pgPass -e POSTGRES_DB=k1 \
  postgres:17-alpine@sha256:<pin>
docker run -d --name k1-app --network k1-internal \
  --read-only --user 10001:10001 --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 384m --memory-swap 384m --cpus 1 --pids-limit 256 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=1777 \
  --tmpfs /run:rw,noexec,nosuid,nodev,size=8m \
  --tmpfs /work:rw,exec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0755 \
  --tmpfs /home/k1:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0755 \
  -v "$run/repo-base:/repo/base:ro" -v "$run/repo-head:/repo/head:ro" \
  -e DATABASE_URL="postgresql://postgres:$pgPass@k1-pg:5432/k1" \
  -e FAKE_PROVIDER_URL="http://127.0.0.1:8081" \
  k1-app:latest
```

## 4. Footprint budget

| Item | Budget |
|---|---|
| k1-app image | 143.7 MB measured (python:3.14-slim + product requirements) |
| k1-pg image | 423 MB (already local) |
| app RSS | 120–200 MB (limit 384 MB) |
| pg RSS | 40–80 MB (limit 256 MB) |
| tmpfs caps | 32+8+64+8+96 = 208 MB max |
| container rw | < 1 MB (read-only rootfs) |
| build cache | 0 (multi-stage, no cache) |
| per-run lifetime | created on run, removed on teardown; no volumes |

That is ~1.5 GB lighter than a single 654 MB runner image per run and leaves
no database volume behind.

## 5. Lifecycle scripts (IMPLEMENTED 2026-11-07)

Prefer the typed tool (`pr.open`, `k1.up`, `worktrees.sync`, …); the canonical
implementation is `files/tools/mcp/k1/handlers.py`
(`k1.up` / `k1.exec` / `k1.down` / `k1.status`, `docker.ensure`). The 11
`scripts/*.ps1` wrappers are deprecated Windows-only legacy (see the
deprecation table in §1).

- `k1.up({ run_id, base, head })` via `handlers.py`: `git archive` base
  and head from `<worktree>` into the run dir, create the internal network, start
  `k1-pg`, wait `pg_isready`, start `k1-app`, wait `/health`, print ids.
- `k1.exec({ run_id, action })` via `handlers.py`: `docker exec -u 10001` in
  `/work`; captures exit and log tail.
- `k1.down({ run_id })` via `handlers.py`: `docker cp` artifacts, remove both
  containers and the network, delete the run dir.
- `k1.up` calls `docker.ensure({ action: "ensure" })` first; `k1.exec` refuses when
  the app container is not running; `k1.down` is idempotent and never starts or
  stops Docker.

## 6. Docker start capability

`docker.ensure({ action: "ensure" })` via `handlers.py` (auditor + builder only;
the PowerShell wrapper is deprecated — see the deprecation table in §1):
- checks `docker info`; if down, starts the engine service (Windows service; on POSIX the engine is a native daemon),
  waits up to 120 s, re-checks;
- starts the named existing containers (`pg2a,pg2b` by default,
  all stopped containers when requested);
- `-WhatIf` prints the plan; it never pulls, builds, creates, or runs a
  container, and never touches volumes.

The auditor and builder get `docker.ensure` via `handlers.py` + the `ensure-docker` skill.
The hacker never gets Docker; it gets `k1_exec` / `repro-run` only.

## 7. Open decisions

1. **pg2a/pg2b**: leave them on named volumes (persistent lane data) or convert
   to tmpfs? Conversion destroys the current data and requires a re-init; do
   not do it without owner sign-off. K1 gets its own tmpfs sidecar instead.
2. **Postgres or host pg for the lean profile**: the default is the isolated
   sidecar; a `lean` profile can point the app at the existing `pg2a`/`pg2b` on
   a dedicated bridge, but that weakens the FS/network cell.
3. **Image pinning**: replace the `sha256:<pin>` placeholders with the real
   digests at build time and record them in `policy-manifest.json`.
4. **Artifact retention**: tmpfs means artifacts must be copied out before
   `k1_down`; the ledger stores content hashes, not the scratch tree.

## 8. Implementation record (2026-11-07)

Status: scripts **IMPLEMENTED**; image **BUILT** locally (143.7 MB, product requirements).

Files:
- Canonical: `files/tools/mcp/k1/handlers.py` — `k1.up` / `k1.exec` / `k1.down` / `k1.status` and `docker.ensure` (native; see the deprecation table in §1).
- Deprecated / Windows-only legacy: the 11 `scripts/*.ps1` wrappers listed in the §1 deprecation table (kept for historical Windows runs only).
- `files/docker/k1/{Dockerfile,requirements.txt,fake_provider.py,seed.py,entrypoint.sh,README.md}`
  — implemented; no app code baked in.
- `.opencode/skills/k1-sandbox/SKILL.md` — implemented.

Image status: `k1-app:latest` is **BUILT** locally (143.7 MB, image id
`sha256:2e4d5c018b7248f8ad4cd836b30f071f73b4d965ca8a0b9b3c172acb7d4e71fe`);
it contains `requirements.lock` (Django 6.1.1 etc.). A host without the image
still gets `IMAGE_MISSING` (exit 3) and no pull/build. Owner/FDE build:

```
docker build --pull=false -t k1-app:latest files/docker/k1
```

`FROM python:3.14-slim` uses the local tag; the digest pin is TODO(pin) in the
Dockerfile (observed local digest
`sha256:0514bc76712d64f8bb48adcb95b1ab0d88c69fee95d62fe4c18ee948bee9b1e1`).
`postgres:17-alpine` is present locally.

Exact invocations:

```
k1.up({ run_id: "<id>", base: "<40|64hex>", head: "<40|64hex>" })
k1.exec({ run_id: "<id>", action: "<enum>" })
k1.down({ run_id: "<id>" })
```

Prefer the typed tool (`pr.open`, `k1.up`, `worktrees.sync`, …); the canonical
implementation is `files/tools/mcp/k1/handlers.py` (`k1.up` / `k1.exec` /
`k1.down` / `k1.status`, `docker.ensure`). The historical PowerShell
invocations are deprecated Windows-only legacy and are listed only in the §1
deprecation table; on POSIX the native daemon is used.

`-WhatIf` on all three prints only. `-WhatIf` accepts abbreviated 7-64 hex
Base/Head; real runs require 40/64 hex and resolve them with
`git cat-file -e <sha>^{commit}`.

Names: run dir `%LOCALAPPDATA%\Temp\opencode` (Windows) / `$XDG_CACHE_HOME/opencode` or `/tmp/opencode` (Linux) + `/k1/<RunId>` (POSIX) or `\k1\<RunId>` (Windows), network
`k1-<id>-net` (internal), pg `k1-<id>-pg`, app `k1-<id>-app`.

Limits/tmpfs actually implemented:

- k1-pg: `--tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,size=96m
  --memory 256m --cpus 0.5 --shm-size 32m --cap-drop ALL
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETGID
  --cap-add SETUID --security-opt no-new-privileges`; `POSTGRES_PASSWORD`
  random 24 hex; `POSTGRES_DB=k1`.
- k1-app: `--read-only --user 10001:10001 --cap-drop ALL --security-opt
  no-new-privileges --memory 384m --memory-swap 384m --cpus 1 --pids-limit 256`;
  tmpfs `/tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=1777`,
  `/run:rw,noexec,nosuid,nodev,size=8m`,
  `/work:rw,exec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0755`,
  `/home/k1:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0755`;
  read-only mounts `<run>/repo-base:/repo/base:ro` and
  `<run>/repo-head:/repo/head:ro`; `--log-driver local --log-opt max-size=1m
  --log-opt max-file=1 --log-opt compress=false`.
  (Plan §2's `--ulimit nofile=1024:1024` is not applied; the log opts are.)
- `k1_exec` runs the command string through `/bin/sh -c` so quoting/pipes work;
  the shell exit code is propagated.
- `k1_down` attempts `docker cp` first; Docker cannot read tmpfs mounts, so when
  cp reports missing and the app is still running it streams `/work/artifacts`
  with `docker exec ... tar` and extracts it to `<run>/artifacts` (use
  `-KeepArtifacts` to keep the run dir and therefore the copy).
- Archives use `git archive --output=<tar>` + `tar -x -f` (no binary pipeline);
  `.env*`, `quality/**`, `venv/` are removed after extraction.
- `files/docker/k1/requirements.txt` is the product pointer and
  `files/docker/k1/requirements.lock` is the hashed lock, copied from
  `<worktree>/backend` into the build context; no app code is baked in. The built
  image imports Django 6.1.1 inside K1.

Smoke evidence (2026-11-07): `postgres:17-alpine` on
`--tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,size=96m` reported
`tmpfs 96.0M ... /var/lib/postgresql/data`; `pg_isready` passed; the container
was removed with `docker rm -f` and `docker ps` showed no k1 container.

Full lifecycle smoke: `k1_up -RunId smoke2 -Base 9b10e00... -Head 12c96d1...`
-> `pg: k1-smoke2-pg ready (tmpfs)`, `app: k1-smoke2-app healthy`; `k1_exec`
printed `6.1.1` (Django); `k1_down` removed app/pg/network and the run dir;
`pg2a`/`pg2b` stayed Up and Docker stayed up. The app image is 143.7 MB.

Note: `pg2a`/`pg2b` were briefly stopped by a Docker engine restart during the
K1 work (they were restarted with `docker.ensure({ action: "ensure" })` via `handlers.py`;
data volumes are intact at 121.9 MB / 79.5 MB). `k1_down` never touches them.

`k1_up`/`k1_exec`/`k1_down` never touch `pg2a`/`pg2b`, never stop Docker, never
prune, and `k1_down` only uses `docker rm -f` and `docker network rm`.
