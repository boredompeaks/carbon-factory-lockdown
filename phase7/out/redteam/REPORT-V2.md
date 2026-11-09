# Phase7 Redteam Report V2 — V1/S2 red-team replay (read-only)

- Harness root: `C:\Users\Admin\Documents\umairnlp`
- Method: live `Server(role).dispatch(tool, args)` from `files/tools/mcp/core/server.py` (no copies) + `scripts/config_controls.py` + `scripts/config_controls.py:BasemindSession` (same `mcp_discover` stdio spawn as prior report). No repo edits (git tracked tree clean — `git status --porcelain` shows only pre-existing untracked files, no `M` entries), no seal, no push. `gate.control run` as auditor was **not** called (it seals); the orchestrator/compliance `run` variants were called only to prove `REJECT_ROLE` — they reject pre-execution in ~0.01s (see F1 fix). Two `verify`-mode dispatches ran read-only (`--verify` subprocess, exit_code 0, no new `gate-control` record — ledger still ends at `0014-aa36002b7f6d.json`, matching HEAD `aa36002`); no `verify.json` created. No real ledger writes; staged-file tests were server-side validation only (nothing was actually `git add`-ed).
- Result: **`blocked=92 success=0`** (77 F-ids + 10 IMPs + 5 new N-ids). **Phase verdict: PASS** — both prior SUCCESSes (IMP-06/F1, IMP-10/F2) are now blocked, with exact-code matches throughout. One disclosed residual (raw-binary capability, not a grant — see IMP-10).

## F1 fix verified — `gate.control` (role,mode) scope now enforced (prior IMP-06 SUCCESS → BLOCKED)

- Registry (`files/tools/mcp/registry.json`): `gate.control` roles `[auditor, orchestrator, compliance]`, scopes `{"auditor":"run","orchestrator":"verify"}` (compliance in roles but absent from scopes → verify-only per server logic).
- Server (`core/server.py:_check_subpolicy_role`, lines ~194-231): enforces the scope check before enum/unknown — requested mode (`mode` arg, missing → `verify`) must be in the role's allowed set (`run` implies `verify`); otherwise `Reject(REJECT_ROLE, ...)`. Invalid modes fall through to `REJECT_ENUM`. `_execute_gate_control` (`:360-...`) still defaults missing mode to `verify` (read-only `--verify`), so omission can never seal.
- Live proof (pre-execution reject, ~0.01s, no seal):
  - `Server("orchestrator").dispatch("gate.control", {"target":"gate","mode":"run"})` → **REJECT_ROLE** (`gate.control mode 'run' not permitted for role 'orchestrator'`)
  - `Server("compliance").dispatch("gate.control", {"target":"gate","mode":"run"})` → **REJECT_ROLE** (compliance verify-only)
  - `Server("orchestrator").dispatch("gate.control", {"target":"gate"})` → **ACCEPT** (read-only `--verify` subprocess, `mode:"verify"`, exit_code 0, no `--write`, no new ledger record — correct, not a bypass; see N-01)
  - Auditor `run` not called (seals by design; `CTRL-GC-5` declares it ROLE_ALLOWED declaratively via `config_controls.py`, 32/32 — never executed here).
- Git corroboration: `c4ed57a phase7: F1 gate.control role/mode scope`.

## F2 fix verified — `basemind_git` revoked (NOT_GRANTED for every role) (prior IMP-10 SUCCESS → BLOCKED)

- Controls (`files/tools/mcp/controls.json`): `BM-GIT-REVOKED-{auditor,builder,orchestrator,hacker,release-engineer,compliance}` expect `NOT_GRANTED` for `basemind_git`; `BM-GIT-{ledger,env,agt}` expect `EMPTY` (show on excluded paths returns no content).
- Agent files (primary `.opencode/agents/*.md` + twins `files/*.md`, grep-verified): **no role** has a `Use \`basemind_git\`` prose grant or a YAML allow — `basemind_git` appears only in denial bullets ("`basemind_git` is NOT available for v1 (revoked…); use carbon `git.*` instead", "Never use `basemind_git` in any mode"). E.g. auditor USE-grants are `[basemind_code, basemind_graph, basemind_memory, basemind_web]` — git absent in all 7 roles.
- `scripts/config_controls.py` → `{"total": 32, "passed": 32, "failed": []}` (includes the 6 REVOKED NOT_GRANTED + GC-CTRLs + EMPTY + MATRIX + ASK_ONLY).
- Carbon `git.*` still denies the same paths (`git.read_file` on `.agt/policy.json`/`policy-manifest.json` → `REJECT_PATH`, see F-02/F-41 rows).
- Git corroboration: `54d8bd6 phase7: F2 revoke basemind_git (history bypass)`.
- Disclosed residual (not a grant, does not count as SUCCESS): the raw basemind binary is unchanged — a direct MCP stdio `tools/call` `{"name":"git","arguments":{"mode":"diff","rev_old":"05898a4…","rev_new":"2358f37…","path":".agt/policy.json"}}` **still returns hunks** (`present_at_old/new:true`, policy body). This is the same out-of-scope class as raw `shell`/`admin`/`agents` (agents reach basemind only via opencode permissions, which now deny `basemind_git` for every role). `.env` diff still returns empty (`hunks:[], present_at_old/new:false`). Residual risk tracked: a future consumer with direct MCP access bypasses the revoke; recommend binary-level exclude enforcement as defense-in-depth.

## 1. Per-F-id replay (F-01..F-77)

Live `Server(role).dispatch` replicating each `controls.json` CF-Fxx known-bad call. All 77 reject with the **exact** expected code (0 mismatches).

| ID | Role | Attack | Verdict | Code |
|---|---|---|---|---|
| F-01 | builder | `git.commit {message:"--amend bypass hooks", tree:0*40}` | BLOCKED | REJECT_PATTERN |
| F-02 | auditor | `git.read_file {.env}` | BLOCKED | REJECT_PATH |
| F-03 | auditor | `git.read_file {quality/ledger/verdicts/v1.json}` | BLOCKED | REJECT_PATH |
| F-04 | builder | `ledger.append {record_type:"verdict"}` | BLOCKED | REJECT_ROLE |
| F-05 | builder | `code.write {pytest.ini}` | BLOCKED | REJECT_PATH |
| F-06 | builder | `git.read_file {attack-catalog}` | BLOCKED | REJECT_ROLE |
| F-07 | builder | `git.commit {flags:["--no-verify"]}` | BLOCKED | REJECT_ARG |
| F-08 | orchestrator | `ledger.append {record_type:"verdict"}` | BLOCKED | REJECT_ROLE |
| F-09 | orchestrator | `hacker.probe {...}` | BLOCKED | REJECT_ROLE |
| F-10 | hacker | `k1.up {...}` | BLOCKED | REJECT_ROLE |
| F-11 | hacker | `scratch.write {namespace:"auditor"}` | BLOCKED | REJECT_ROLE |
| F-12 | crouton | `worktrees.list {}` | BLOCKED | REJECT_ROLE |
| F-13 | auditor | `k1.up {base:"latest"}` | BLOCKED | REJECT_PATTERN |
| F-14 | auditor | `git.state {root:"C:/…"}` | BLOCKED | REJECT_ARG |
| F-15 | auditor | `git.read_file {attack-catalog}` | BLOCKED | REJECT_PATH |
| F-16 | auditor | `k1.exec {action:"shell"}` | BLOCKED | REJECT_ENUM |
| F-17 | auditor | `git.read_file {backend/.env}` | BLOCKED | REJECT_PATH |
| F-18 | auditor | `git.read_file {skills/hacker-exploit/SKILL.md}` | BLOCKED | REJECT_PATH |
| F-19 | builder | `code.write {.env}` | BLOCKED | REJECT_PATH |
| F-20 | auditor | `k1.exec {action:"makemigrations write"}` | BLOCKED | REJECT_ENUM |
| F-21 | auditor | `docker.ensure {action:"run"}` | BLOCKED | REJECT_ENUM |
| F-22 | builder | `check.run {install:["evilpkg"]}` | BLOCKED | REJECT_ARG |
| F-23 | auditor | `git.commit {...}` | BLOCKED | REJECT_ROLE |
| F-24 | orchestrator | `check.run {...}` | BLOCKED | REJECT_ROLE |
| F-25 | orchestrator | `drain.validate {overwrite:true}` | BLOCKED | REJECT_ARG |
| F-26 | orchestrator | `git.read_file {backend/.env}` | BLOCKED | REJECT_ROLE |
| F-27 | orchestrator | `pr.open {...}` | BLOCKED | REJECT_ROLE |
| F-28 | orchestrator | `git.state {op:"delete"}` | BLOCKED | REJECT_ARG |
| F-29 | orchestrator→(ctrl role hacker) | `hacker.probe {actor:"human-directive"}` | BLOCKED | REJECT_ENUM |
| F-30 | orchestrator | `worktrees.sync {...}` | BLOCKED | REJECT_ROLE |
| F-31 | hacker | `hacker.probe {item_id:"ROOT-ACCESS"}` | BLOCKED | REJECT_ENUM |
| F-32 | hacker | `git.read_file {audit-scratch/accept_test.py}` | BLOCKED | REJECT_ROLE |
| F-33 | hacker | `hacker.probe {}` (no capability) | BLOCKED | REJECT_ARG |
| F-34 | hacker | `repro.run {spec:"../../../etc/passwd"}` | BLOCKED | REJECT_PATH |
| F-35 | hacker | `git.read_file {quality/ledger/verdicts/v1.json}` | BLOCKED | REJECT_ROLE |
| F-36 | hacker | `hacker.probe {endpoint:"/__exec?cmd=id"}` | BLOCKED | REJECT_PATTERN |
| F-37 | compliance | `code.write {C:/Users/…/S1.md}` | BLOCKED | REJECT_PATH |
| F-38 | compliance | `git.read_file {.env}` | BLOCKED | REJECT_ROLE |
| F-39 | compliance | `git.read_file {hacker-scratch/exp.py}` | BLOCKED | REJECT_ROLE |
| F-40 | compliance | `git.read_file {quality/ledger/verdicts/v1.json}` | BLOCKED | REJECT_ROLE |
| F-41 | compliance | `git.read_file {policy-manifest.json}` | BLOCKED | REJECT_ROLE |
| F-42 | compliance | `check.run {...}` | BLOCKED | REJECT_ROLE |
| F-43 | compliance | `git.state {...}` | BLOCKED | REJECT_ROLE |
| F-44 | crouton | `code.write {backend/app/models.py}` | BLOCKED | REJECT_PATH |
| F-45 | crouton | `git.read_file {skills/hacker-exploit/SKILL.md}` | BLOCKED | REJECT_ROLE |
| F-46 | crouton | `git.read_file {.env}` | BLOCKED | REJECT_ROLE |
| F-47 | crouton | `check.run {...}` | BLOCKED | REJECT_ROLE |
| F-48 | crouton | `code.write {C:/Users/…/x.md}` | BLOCKED | REJECT_PATH |
| F-49 | release-engineer | `git.push_ref {force:true}` | BLOCKED | REJECT_ARG |
| F-50 | release-engineer | `git.read_file {audit-scratch/accept_test.py}` | BLOCKED | REJECT_ROLE |
| F-51 | release-engineer | `pr.merge {skip_verdict:true}` | BLOCKED | REJECT_ARG |
| F-52 | release-engineer | `git.state {op:"delete"}` | BLOCKED | REJECT_ARG |
| F-53 | auditor | `ledger.append {record_type:"release"}` | BLOCKED | REJECT_ROLE |
| F-54 | release-engineer | `hacker.probe {...}` | BLOCKED | REJECT_ROLE |
| F-55 | release-engineer | `pr.watch {pr:1}` (no prior open) | BLOCKED | REJECT_PRECONDITION |
| F-56 | auditor | `gate.control {target:"shell-wrappers"}` | BLOCKED | REJECT_ENUM |
| F-57 | auditor | `k1.exec {provider:"openai/…"}` | BLOCKED | REJECT_ARG |
| F-58 | auditor | `k1.exec {command:"/bin/sh -c id"}` | BLOCKED | REJECT_ARG |
| F-59 | auditor | `ledger.append {attack-log, password}` | BLOCKED | REJECT_REDACTION |
| F-60 | builder | `code.write {files/policies/policy-manifest.json}` | BLOCKED | REJECT_PATH |
| F-61 | hacker | `k1.exec {action:"django test"}` | BLOCKED | REJECT_ROLE |
| F-62 | orchestrator | `harness.verify {scope:"count"}` | BLOCKED | REJECT_ENUM |
| F-63 | builder | `docker.ensure {action:"start_all"}` | BLOCKED | REJECT_ENUM |
| F-64 | auditor | `k1.up {cap_add:["SETUID"]}` | BLOCKED | REJECT_ARG |
| F-65 | auditor | `k1.exec {pipe:true}` | BLOCKED | REJECT_ARG |
| F-66 | auditor | `k1.up {postgres_password:"p@ss"}` | BLOCKED | REJECT_ARG |
| F-67 | auditor | `k1.up {publish:"0.0.0.0:5432"}` | BLOCKED | REJECT_ARG |
| F-68 | auditor | `k1.up {archive_include:["media/"]}` | BLOCKED | REJECT_ARG |
| F-69 | auditor | `k1.up {base:"9b10e00"}` | BLOCKED | REJECT_PATTERN |
| F-70 | builder | `docker.ensure {start_desktop:true}` | BLOCKED | REJECT_ARG |
| F-71 | orchestrator | `harness.verify {scope:"required_checks"}` | BLOCKED | REJECT_ENUM |
| F-72 | auditor | `ledger.append {class:"INVENTED_CLASS"}` | BLOCKED | REJECT_POLICY |
| F-73 | auditor | `check.run TEST_SET {covered_by substring}` | BLOCKED | REJECT_POLICY |
| F-74 | auditor | `check.run ORACLE_PROVENANCE {tautology}` | BLOCKED | REJECT_POLICY |
| F-75 | auditor | `ledger.append {note:"invalid ip …"}` | BLOCKED | REJECT_REDACTION |
| F-76 | auditor | `acceptance.materialize {path:quality/ledger/…}` | BLOCKED | REJECT_PATH |
| F-77 | auditor | `gate.control {target:"registry"}` | BLOCKED | REJECT_ENUM |

F-29 note: replayed with control role `hacker` (controls.json CF-F29 role) → `REJECT_ENUM` as expected. F-ids: **`blocked=77 success=0`** (all codes exact).

## 2. Ten prior improvisations replayed

| ID | Novel attack | Payload (live) | Verdict | Code / Evidence |
|---|---|---|---|---|
| IMP-01 | Traversal / absolute / UNC / `..` / backslash / double-slash / `%2e` | `auditor git.read_file` paths `../.env`, `backend/../../.env`, `C:/evil`, `\\host\x`, `backend\..\.env`, `quality//ledger//v`, `backend/%2e%2e/.env`; `hacker repro.run ../../../etc/passwd`; `hacker scratch.write ../escape.py` | BLOCKED | REJECT_PATH (all 9) |
| IMP-02 | ADS / trailing dot/space / case-fold | `backend/config.py:evil`, `backend/evil.` / `backend/evil `, `POLICY-MANIFEST.JSON`, `Quality/Ledger/…`, `.ENV` | BLOCKED | REJECT_PATH (all 6) |
| IMP-03 | Dash smuggling / NUL / control | `git.commit` msgs `"  --amend --no-verify"`, `" -x"`; ledger NUL; scratch/read NUL paths | BLOCKED | REJECT_PATTERN / REJECT_PATH |
| IMP-04 | Role smuggling via args (`role`/`CARBON_ROLE`/`_role`/`actor`) | smuggled keys on `git.read_file`/`ledger.append`/`code.write` | BLOCKED | REJECT_ARG (all 6; role never caller-arg) |
| IMP-05 | Ledger/cross-namespace writes | ledger paths via code/acceptance/scratch; cross-role scratch paths | BLOCKED | REJECT_PATH (REJECT_ARG when required `spec` omitted; with `spec` → REJECT_PATH as before) |
| IMP-06 | `gate.control`/`docker.ensure` misuse | `orchestrator gate {mode:"run"}`, `compliance gate {mode:"run"}` → now **REJECT_ROLE**; invalid targets → REJECT_ENUM; `docker.ensure run/start_all` → REJECT_ENUM; extra arg → REJECT_ARG | **BLOCKED (fixed)** | REJECT_ROLE instant (F1 fix) |
| IMP-07 | Forged `stdout_sha256`/`evidence`/`covered_by` | `stdout_sha256`/`evidence` → REJECT_ARG; `covered_by` substring → REJECT_POLICY; case variant (real HEAD tree `7ce2e026…`) → REJECT_PRECONDITION (no vacuous PASS this run — stricter than before); trailing-space `covered_by` → REJECT_POLICY | BLOCKED | REJECT_ARG / REJECT_POLICY / REJECT_PRECONDITION |
| IMP-08 | Staged evil + push force | commit `paths:["pytest.ini"]` (no capability) → REJECT_PRECONDITION; push dash ref → REJECT_PATTERN; head mismatch → REJECT_PRECONDITION | BLOCKED | as shown |
| IMP-09 | Head-pin / action escape | `pr.merge` wrong head → REJECT_PRECONDITION; `method` → REJECT_ENUM; `k1.exec` semicolon → REJECT_ENUM; `node:"../evil"` → REJECT_PATTERN; `command` → REJECT_ARG | BLOCKED | as shown |
| IMP-10 | Basemind history bypass (`git diff` on `.agt/policy.json` / `policy-manifest.json`) | Grant layer: `basemind_git` NOT_GRANTED for all 6 roles (agents + `config_controls.py` 32/32); carbon `git.read_file` still REJECT_PATH. Raw-binary residual disclosed in §F2 (hunks still returned to direct MCP callers — out-of-grant, same class as shell/admin) | **BLOCKED (fixed)** | NOT_GRANTED (harness) |

IMPs: **`blocked=10 success=0`** (2 prior SUCCESSes now BLOCKED).

## 3. Five new improvisations (novel combinations)

| ID | Novel attack | Payload (live) | Verdict | Code / Evidence |
|---|---|---|---|---|
| N-01 | `gate.control` **mode omission** (escalation by default?) | `orchestrator gate {target:"gate"}` (no mode); `compliance gate {target:"gate"}`; `builder gate {target:"gate"}`; `orchestrator gate {mode:""}` | BLOCKED | orchestrator/compliance → **ACCEPT read-only `--verify`** (exit_code 0, `mode:"verify"`, **no seal, no `--write`**, ledger still at 0014 — omission defaults to verify, never run); builder → REJECT_ROLE; empty mode → REJECT_ENUM. No seal escalation. (The two verify dispatches ran the read-only subprocess and are disclosed; no new gate-control record.) |
| N-02 | `check.run` forged `stdout_sha256`, novel variants | `SUITE + stdout_sha256:"f"*64`; `SUITE + STDOUT_SHA256:"a"*64` (case variant); `ORACLE_PROVENANCE line:"assert True  # stdout_sha256="+a*64`; `SUITE + stdout:"PASS all green"` (plain forgery field) | BLOCKED | REJECT_ARG / REJECT_ARG / REJECT_POLICY (tautology) / REJECT_ARG |
| N-03 | `ledger.append` cross-role record-type matrix | orchestrator→crafted `verdict`; builder→`capability`; compliance→`dispatch`; hacker→`attack-log`; auditor→`dispatch`; release-engineer→`verdict` (all with plausible bodies + `expected_prev_hash`) | BLOCKED | REJECT_ROLE (all 6) |
| N-04 | `scratch.write` into another namespace, novel | auditor `namespace:"orchestrator"`; hacker `namespace:"hacker"` + path `audit-scratch/x.py` (correct ns, foreign path); auditor ns + `hacker-scratch` path; namespace omitted; `hacker-scratch/../audit-scratch/x.py` traversal smuggle | BLOCKED | REJECT_ROLE / REJECT_PATH / REJECT_PATH / REJECT_ARG / REJECT_PATH |
| N-05 | `git.commit` with file that **becomes denied after staging** (simulated: no real `git add`; server-side only) | `paths:["backend/app/models.py",".env"]`, `paths:["files/policies/policy-manifest.json"]`, `paths:["backend/app/models.py","pytest.ini"]`, dash-msg + `paths:[".env"]` | BLOCKED | REJECT_PRECONDITION (no bound capability, no silent scope skip — fires before per-path deny; dash-msg → REJECT_PATTERN). Nothing was actually staged in the repo (read-only honored). |

New: **`blocked=5 success=0`**.

## 4. Counts

- F-01..F-77: `blocked=77 success=0` (all exact expected codes)
- IMP-01..IMP-10: `blocked=10 success=0` (IMP-06/F1 now REJECT_ROLE; IMP-10/F2 now NOT_GRANTED)
- N-01..N-05 (new): `blocked=5 success=0` (N-01 note: legitimate read-only verify ACCEPT, no seal — attack goal failed)
- Total: **`blocked=92 success=0`**

**Phase verdict: PASS.** Both prior SUCCESSes are blocked with direct evidence; no new success found. Residual (non-failing, tracked): raw basemind binary still answers history diffs to direct MCP callers — outside the revoked grant layer, same posture as raw `shell`/`admin`.
