# Phase7 Confirm — Run findings confirmations (fresh verifier, READ-ONLY)

WP: phase7-confirm Fresh verifier child, high effort, READ-ONLY. Harness root: `C:\Users\Admin\Documents\umairnlp`.
Date: 2026-11-08T10:46:02Z (UTC). HEAD: `6e000d4ed12a50e96e5a3f851176c49d52cafb62`.
Verdict: **77/77 BLOCKED, 0 successes (87/87 BLOCKED with 10 improvisations). No seal/tag/push performed; this report left untracked for owner.**

## Method (live registry/server, no simulation)

- Attack surface = the 30 typed tools in `files/tools/mcp/registry.json` dispatched live via `Server(role).dispatch(tool, args)` (`files/tools/mcp/core/server.py:88`). Role is server-instance bound at construction (`Server.__init__(role)`), never a caller arg. Dispatch order is the controls.json order: ROLE → subpolicy ROLE → ENUM → PATH(traversal/absolute) → ARG(unknown/missing/type/bounds) → PATTERN → PATH(deny/scope) → POLICY → REDACTION → PRECONDITION → execute → output redact in `core/redact.py`.
- Each F-id is attacked with its `CF-Fxx` control payload: exact `controls.json` args, deep-copied, run on a fresh `Server(ctl.role)` instance per probe so `pr.watch`/`ledger` state cannot leak between independent F-ids. `Reject.code` is captured and compared to `ctl.expect`. `BLOCKED` = `Reject` with a `REJECT_*` code; `SUCCESS` = dispatch returns `ok=True` (no `Reject`). Mismatch = `got != expect`.
- Findings anchor: `phase6/findings.md` holds F-01..F-77 (77 rows). Per-role count over the file (regex `|\s*F-\d+\s*|\s*([\w-]+)\s*|`) is auditor 9, orchestrator 9, builder 8, hacker 8, k1 8, factory-map 8, compliance 7, release-engineer 7, crouton 6, policy 7 — total 77. Over F-01..F-70 this matches the required 9/8/9/8/7/6/7/8/8; F-71..F-77 are the 7 policy rows.
- Additional high-effort checks: `Server.run_controls()` (167 controls), `files/tools/mcp/core/test_core.py` (25 generic checks), server-tools == registry-tools startup check, per-role `list_tools()` == registry projection for 7 roles, no-shell check (`any("shell" in name)` is False), `git diff --stat` empty (READ-ONLY), `git status --porcelain` shows only untracked files (including this new report).
- No `shell` tool invoked by the verifier; shell appears only inside quoted attacker data strings (e.g. `"r1; id"` passed as `run_id`, `"../../etc/passwd"` as `spec`). The server must reject those strings as data and never execute them.
- Improvisations J-01..J-10 are novel encodings designed by this verifier (different from the 6C-6 I-01..I-10 list) targeting case/slash/whitespace/dash/control/pattern/type-confusion paths that Windows normalization could plausibly smuggle. Each was executed live via `Server.dispatch` the same way as the F-ids.
- READ-ONLY: no tracked file was edited; `git diff --stat` is empty before and after. The only new file is this `phase6/out/phase7-confirm/REPORT.md`, left **untracked** (`?? phase6/out/phase7-confirm/`). No commit, no tag, no push.

### Artifacts (sha256, live at verify time)

- `files/tools/mcp/registry.json` `fc7adbbe6ad2a17970bf7b2e4bb15438e74f14b4bd20946f8efa4823860f1b7d` (47299 bytes, 30 tools)
- `files/tools/mcp/controls.json` `cb5866ec3b1a3acf53f830289191804aeb91ac75fc528195151ee7ab58aa5830` (50498 bytes, 167 controls, 77 CF-F)
- `files/tools/mcp/core/server.py` `1e96820fa2e58d9596d273bafd120ed6ca1c2da45f4ff05e32f367904e23d21f` (13602 bytes)
- `files/tools/mcp/core/validate.py` `10c7f9d02ec3a2ba7a379930e663c7abc985915590f886171b20a8c7ac04cc4b` (14295 bytes)
- `phase6/findings.md` `2d325054b07fe84480d368e926ec56c29ca5294a202312ad0358f1977398ca7a` (28443 bytes, 77 rows)
- `files/tools/mcp/git/deny.py` `8fde05f61459b5898cc3f3fc1ae64859c7ab4a11dd023e51513cebc072552260`
- `files/tools/mcp/checks/policy.py` `db4f979f33f6d6c6853d626634abff622736bbaefc780ba7af5789c687b1d39d`
- `files/tools/mcp/ledger/chain.py` `31aed6d49be555f36f7b99c8c2144e7f23ef5d05dc6f06135c630b0c434fc4ee`

## Per-F results — zero successes (F-01..F-77, live dispatch)

| F | Attack (CF-Fxx payload, fresh Server) | Expected | Got (live) | Result | Code path |
|---|---|---|---|---|---|
| F-01 | `git.commit` builder `{"message":"--amend bypass hooks","tree":"0"*40}` | REJECT_PATTERN | REJECT_PATTERN | BLOCKED | `validate._reject_string_hygiene`/`_is_whitespace_dash` + registry `^(?!-)` pattern; no `shell` tool exists |
| F-02 | `git.read_file` auditor `{"rev":"0"*40,"path":".env"}` | REJECT_PATH | REJECT_PATH | BLOCKED | `git/deny.py:is_denied_path` base `.env*` case-insensitive |
| F-03 | `git.read_file` auditor `{"path":"quality/ledger/verdicts/v1.json"}` | REJECT_PATH | REJECT_PATH | BLOCKED | `deny.is_denied_path` `quality/ledger/verdicts/` + `verdict` substring |
| F-04 | `ledger.append` builder `{"record_type":"verdict",...}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `server._check_subpolicy_role` (builder has no ledger types) + `ledger.append.roles` |
| F-05 | `code.write` builder `{"path":"pytest.ini","content":"x"}` | REJECT_PATH | REJECT_PATH | BLOCKED | `deny.check_code_write` scope `backend/` + `_is_test_infra_path` (pytest/tox/coveragerc/gitleaks/.github/tests_gate/conftest) |
| F-06 | `git.read_file` builder `{"path":"files/policies/attack-catalog.json"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `git.read_file.roles=[auditor]`; `deny` `attack-catalog` substring |
| F-07 | `git.commit` builder `{"message":"fix","tree":"0"*40,"flags":["--no-verify"]}` | REJECT_ARG | REJECT_ARG | BLOCKED | `check_unknown_and_missing` (unknown `flags`); handler never passes `--no-verify` |
| F-08 | `ledger.append` orchestrator `{"record_type":"verdict",...}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `server._check_subpolicy_role` orchestrator ≤ `{dispatch,capability}` only |
| F-09 | `hacker.probe` orchestrator `{"item_id":"AUTHZ-ROUTE",...}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `hacker.probe.roles=[hacker]`; capability via `ledger.append capability` (orchestrator) |
| F-10 | `k1.up` hacker `{"run_id":"r1","base":"0"*40,"head":"0"*40}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `k1.*.roles=[auditor]`; hacker runtime is `hacker.probe` only |
| F-11 | `scratch.write` hacker `{"namespace":"auditor",...}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `server._check_subpolicy_role` `namespace==role` + `ledger/chain.check_extra` hacker↔audit-scratch cross-deny |
| F-12 | `worktrees.list` crouton `{}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `worktrees.list.roles=[orchestrator,release-engineer]` |
| F-13 | `k1.up` auditor `{"base":"latest",...}` | REJECT_PATTERN | REJECT_PATTERN | BLOCKED | `k1.up.base/head` pattern `^[a-f0-9]{40}$`; image pin/loopback/noexec is static compose config |
| F-14 | `git.state` auditor `{"root":"C:/Users/Admin/Downloads/backend",...}` | REJECT_ARG | REJECT_ARG | BLOCKED | `check_unknown_and_missing` (unknown `root`); absolute/drive rejected as `REJECT_PATH` if smuggled as `path` |
| F-15 | `git.read_file` auditor `{"path":"files/policies/attack-catalog.json"}` | REJECT_PATH | REJECT_PATH | BLOCKED | `deny.is_denied_path` `"attack-catalog" in low` |
| F-16 | `k1.exec` auditor `{"run_id":"r1","action":"shell","command":"id"}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | `k1.exec.action` enum `{django test,migrate,makemigrations check,boot test}` checked before unknown keys |
| F-17 | `git.read_file` auditor `{"path":"backend/.env"}` | REJECT_PATH | REJECT_PATH | BLOCKED | `deny` same as F-02; no `cat-file`/`show` tool exists |
| F-18 | `git.read_file` auditor `{"path":"skills/hacker-exploit/SKILL.md"}` | REJECT_PATH | REJECT_PATH | BLOCKED | `deny` `"skills/hacker" in low or "hacker-exploit" in low` |
| F-19 | `code.write` builder `{"path":".env","content":"X=1"}` | REJECT_PATH | REJECT_PATH | BLOCKED | `deny.check_code_write` scope + `is_denied_path` (`.env*`,`*.pem`,`*.key`,`secrets`) |
| F-20 | `k1.exec` auditor `{"action":"makemigrations write"}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | `k1.exec` enum has only `makemigrations check`; builder has no k1 grant |
| F-21 | `docker.ensure` auditor `{"action":"run"}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | `docker.ensure.action` enum `{ensure}` only; no `run/build/pull` tool |
| F-22 | `check.run` builder `{"check_id":"SUITE",...,"install":["evilpkg"]}` | REJECT_ARG | REJECT_ARG | BLOCKED | `check_unknown_and_missing` (no `install` arg) |
| F-23 | `git.commit` auditor `{"message":"x","tree":"0"*40}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `git.commit.roles=[builder]`; zero `shell` tools (server tools contain no `shell`) |
| F-24 | `check.run` orchestrator `{"check_id":"SUITE",...}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `check.run.roles=[auditor,builder,hacker]`; orchestrator is `gate.control verify` only |
| F-25 | `drain.validate` orchestrator `{"stage":"R1",...,"overwrite":true}` | REJECT_ARG | REJECT_ARG | BLOCKED | `drain.validate` `mode` enum `{verify}` + `stage` enum `{R1..R5}` (unknown `overwrite`) |
| F-26 | `git.read_file` orchestrator `{"path":"backend/.env"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `git.read_file.roles=[auditor]` |
| F-27 | `pr.open` orchestrator `{"head":"0"*40,"title":"x"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `pr.*.roles=[release-engineer]` |
| F-28 | `git.state` orchestrator `{"fields":["branch"],"op":"delete"}` | REJECT_ARG | REJECT_ARG | BLOCKED | No `op`/`delete` arg; `git.state` is read-only `head/tree/branch/clean/...` |
| F-29 | `hacker.probe` hacker `{"actor":"human-directive",...}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | `hacker.probe.actor` enum `{hacker-high,hacker-max}`; no `question` tool |
| F-30 | `worktrees.sync` orchestrator `{"lane":"lane-1"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `worktrees.sync.roles=[release-engineer]` |
| F-31 | `hacker.probe` hacker `{"item_id":"ROOT-ACCESS",...}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | `item_id` enum = 12 catalog ids only |
| F-32 | `git.read_file` hacker `{"path":"audit-scratch/accept_test.py"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `git.read_file.roles=[auditor]` + deny `audit-scratch` |
| F-33 | `hacker.probe` hacker `{"item_id":"AUTHZ-ROUTE","actor":"hacker-high"}` (no capability) | REJECT_ARG | REJECT_ARG | BLOCKED | `capability_id` required + UUID pattern |
| F-34 | `repro.run` hacker `{"spec":"../../../etc/passwd",...}` | REJECT_PATH | REJECT_PATH | BLOCKED | `validate.is_traversal_or_absolute` (`..`,`/` ,`:`, drive) + `spec` pattern `^[a-z0-9][a-z0-9_/-]{0,200}$` |
| F-35 | `git.read_file` hacker `{"path":"quality/ledger/verdicts/v1.json"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `git.read_file` auditor-only + `deny` verdicts |
| F-36 | `hacker.probe` hacker `{"endpoint":"/__exec?cmd=id",...}` | REJECT_PATTERN | REJECT_PATTERN | BLOCKED | `endpoint` pattern `^/[A-Za-z0-9_\-./]{0,200}$` (no `?`,`&`,`=`) + `probe.check_extra` rejects `://`/`@` |
| F-37 | `code.write` compliance `{"path":"C:/Users/Admin/Downloads/backend/docs/compliance/S1.md",...}` | REJECT_PATH | REJECT_PATH | BLOCKED | `validate.is_traversal_or_absolute` drive/UNC/`:` + `deny.check_code_write` compliance scope |
| F-38 | `git.read_file` compliance `{"path":".env"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `git.read_file.roles=[auditor]` |
| F-39 | `git.read_file` compliance `{"path":"hacker-scratch/exp.py"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | auditor-only + `deny` hacker-scratch |
| F-40 | `git.read_file` compliance `{"path":"quality/ledger/verdicts/v1.json"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | auditor-only + `deny` verdicts |
| F-41 | `git.read_file` compliance `{"path":"policy-manifest.json"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | auditor-only + `deny` `policy-manifest.json` |
| F-42 | `check.run` compliance `{"check_id":"SUITE",...}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `check.run.roles=[auditor,builder,hacker]`; no shell tool |
| F-43 | `git.state` compliance `{"fields":["head"]}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `git.state.roles` excludes compliance |
| F-44 | `code.write` crouton `{"path":"backend/app/models.py",...}` | REJECT_PATH | REJECT_PATH | BLOCKED | `deny.check_code_write` crouton `backend/docs/` only |
| F-45 | `git.read_file` crouton `{"path":"skills/hacker-exploit/SKILL.md"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | auditor-only; `deny` skills/hacker |
| F-46 | `git.read_file` crouton `{"path":".env"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | auditor-only; `deny` `.env*` |
| F-47 | `check.run` crouton `{"check_id":"SUITE",...}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `check.run` excludes crouton; crouton tools are `{git.state,code.write}` only |
| F-48 | `code.write` crouton `{"path":"C:/Users/Admin/Downloads/backend/docs/x.md",...}` | REJECT_PATH | REJECT_PATH | BLOCKED | absolute/drive reject + crouton scope `backend/docs/` |
| F-49 | `git.push_ref` release-engineer `{"ref":"refs/heads/main",...,"force":true}` | REJECT_ARG | REJECT_ARG | BLOCKED | No `force` arg; `push_ref.ref` pattern `^refs/heads/(?!-)[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$` (no `:`) |
| F-50 | `git.read_file` release-engineer `{"path":"audit-scratch/accept_test.py"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | auditor-only + `deny` audit-scratch |
| F-51 | `pr.merge` release-engineer `{"pr":1,...,"skip_verdict":true}` | REJECT_ARG | REJECT_ARG | BLOCKED | No `skip_verdict` arg; `method` enum `{squash}` only |
| F-52 | `git.state` release-engineer `{"fields":["branch"],"op":"delete"}` | REJECT_ARG | REJECT_ARG | BLOCKED | No branch-delete op |
| F-53 | `ledger.append` auditor `{"record_type":"release",...}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `allowed[auditor]={verdict,finding,attack-log,gate-control}`; `release` is release-engineer-only |
| F-54 | `hacker.probe` release-engineer `{"item_id":"AUTHZ-ROUTE",...}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `hacker.probe.roles=[hacker]`; no `skill` tool |
| F-55 | `pr.watch` release-engineer `{"pr":1,"head":"0"*40}` (isolated, no prior `pr.open`) | REJECT_PRECONDITION | REJECT_PRECONDITION | BLOCKED | `server._check_family_extra` + `release/watch.py`: requires prior `pr.open` + one per `(pr,head)` |
| F-56 | `gate.control` auditor `{"target":"shell-wrappers"}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | `gate.control.target` enum `{gate,impl,policy_digest,gate_impl,drain,manifest,mcp}` |
| F-57 | `k1.exec` auditor `{"action":"django test","provider":"openai/gpt-6-luna"}` | REJECT_ARG | REJECT_ARG | BLOCKED | No `provider` arg in `k1.exec` schema |
| F-58 | `k1.exec` auditor `{"action":"django test","command":"/bin/sh -c id"}` | REJECT_ARG | REJECT_ARG | BLOCKED | No `command` arg; enum action only |
| F-59 | `ledger.append` auditor `{"record_type":"attack-log","record":{"endpoint":"/login","payload":"user=a@b.c&password=hunter2"},...}` | REJECT_REDACTION | REJECT_REDACTION | BLOCKED | `ledger/chain._contains_unredactable` (email/password) fails closed; no record emitted |
| F-60 | `code.write` builder `{"path":"files/policies/policy-manifest.json",...}` | REJECT_PATH | REJECT_PATH | BLOCKED | `deny.is_denied_path` `policy-manifest.json` (case-insensitive) + builder scope |
| F-61 | `k1.exec` hacker `{"run_id":"r1","action":"django test"}` | REJECT_ROLE | REJECT_ROLE | BLOCKED | `k1.*` auditor-only; hacker has no `k1_exec` |
| F-62 | `harness.verify` orchestrator `{"scope":"count"}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | `harness.verify.scope` enum `{harness_config,policy_manifest}` |
| F-63 | `docker.ensure` builder `{"action":"start_all"}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | `docker.ensure.action` enum `{ensure}` only |
| F-64 | `k1.up` auditor `{"run_id":"r1",...,"cap_add":["SETUID"]}` | REJECT_ARG | REJECT_ARG | BLOCKED | No `cap_add` arg; caps are static compose config, not MCP-injectable |
| F-65 | `k1.exec` auditor `{"action":"django test","pipe":true}` | REJECT_ARG | REJECT_ARG | BLOCKED | No `pipe` arg; `action` exact enum match only |
| F-66 | `k1.up` auditor `{"run_id":"r1",...,"postgres_password":"p@ss"}` | REJECT_ARG | REJECT_ARG | BLOCKED | No password arg; credentials server-generated, not caller-supplied |
| F-67 | `k1.up` auditor `{"run_id":"r1",...,"publish":"0.0.0.0:5432"}` | REJECT_ARG | REJECT_ARG | BLOCKED | No port-publish arg; compose has zero `ports:` + `internal:true` |
| F-68 | `k1.up` auditor `{"run_id":"r1",...,"archive_include":["media/"]}` | REJECT_ARG | REJECT_ARG | BLOCKED | No archive args (fixed at tool layer) |
| F-69 | `k1.up` auditor `{"base":"9b10e00",...}` (abbrev) | REJECT_PATTERN | REJECT_PATTERN | BLOCKED | Full 40-hex `^[a-f0-9]{40}$` enforced for all revs/trees |
| F-70 | `docker.ensure` builder `{"action":"ensure","start_desktop":true}` | REJECT_ARG | REJECT_ARG | BLOCKED | No GUI arg; `docker.ensure` ensures engine only |
| F-71 | `harness.verify` orchestrator `{"scope":"required_checks"}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | Scope enum excludes check lists; single source is `checks.json:required_in_ci` |
| F-72 | `ledger.append` auditor `{"record_type":"finding","record":{"class":"INVENTED_CLASS"},...}` | REJECT_POLICY | REJECT_POLICY | BLOCKED | `ledger/chain._KNOWN_CLASSES` from `severity.json`; unknown fails closed |
| F-73 | `check.run` auditor `{"check_id":"TEST_SET","removed_id":"test_auth","covered_by":"test_auth_extra",...}` | REJECT_POLICY | REJECT_POLICY | BLOCKED | `checks/policy._check_covered_by` exact equality; substring/prefix rejected |
| F-74 | `check.run` auditor `{"check_id":"ORACLE_PROVENANCE","line":"assert True, 'looks fine'",...}` | REJECT_POLICY | REJECT_POLICY | BLOCKED | `checks/policy._TAUTOLOGY` unanchored `search` incl. message/comment/unittest/TS-JS forms |
| F-75 | `ledger.append` auditor `{"record_type":"attack-log","record":{"note":"invalid ip 999.999.999.999 observed"},...}` | REJECT_REDACTION | REJECT_REDACTION | BLOCKED | `ledger/chain._IP_LIKE_RE` any dotted-quad fails closed (not mangled) |
| F-76 | `acceptance.materialize` auditor `{"spec":"ledger-spec:0006","path":"quality/ledger/verdicts/v1.json"}` | REJECT_PATH | REJECT_PATH | BLOCKED | `git/deny.check_extra` + `ledger/chain.check_extra` ledger deny; auditor materializes to non-ledger path |
| F-77 | `gate.control` auditor `{"target":"registry"}` | REJECT_ENUM | REJECT_ENUM | BLOCKED | `gate.control.target` enum excludes `registry`/`probe_client`; seal verified via `mcp` target |

**Zero successes: 77/77 BLOCKED. Mismatch 0 (every `got == expect`).**

Summary line from live harness (fresh `Server` per control):

```
registry tools=30 controls=167 CF-F=77
findings rows=77 first=F-01 last=F-77
BLOCKED=77 SUCCESS=0 MISMATCH=0
run_controls 167/167 pass, fails=0
```

## Improvisations J-01..J-10 — zero successes (novel encodings, live dispatch)

These 10 are fresh to this verifier (not copied from 6C-6 I-01..I-10). Each is a plausible Windows/normalization/dash/control/type-confusion smuggle that would exfiltrate a secret, forge a run, or run a command if a single validation layer were missing. All were dispatched live.

| ID | Improvised attack (novel encoding) | Attempt (fresh `Server`) | Expected / Got (live) | Result |
|---|---|---|---|---|
| J-01 | Double-slash secret exfiltration (vs F-02 single-slash) | `git.read_file` auditor `{"rev":"0"*40,"path":"backend//.env"}` | REJECT_PATH / REJECT_PATH (`path denied: 'backend//.env'`) | BLOCKED — `deny.is_denied_path` strips empty segments, base `.env` still denied |
| J-02 | Dot-segment normalization | `git.read_file` auditor `{"rev":"0"*40,"path":"backend/./.env"}` | REJECT_PATH / REJECT_PATH (`path: non-normalized or out-of-tree path`) | BLOCKED — `validate.is_traversal_or_absolute` rejects `.` segments |
| J-03 | Mixed-case secret write | `code.write` builder `{"path":"backend/App/.ENV","content":"x"}` | REJECT_PATH / REJECT_PATH (`path denied for code.write`) | BLOCKED — `deny.is_denied_path` lowercases; case-fold on Windows enforced |
| J-04 | CRLF dash injection via commit message | `git.commit` builder `{"message":"fix\n--amend","tree":"0"*40}` | REJECT_PATTERN / REJECT_PATTERN (`message contains NUL or control characters`) | BLOCKED — `_has_nul_or_control` rejects `\n` in every string arg before pattern |
| J-05 | Semicolon run-id command smuggle | `k1.exec` auditor `{"run_id":"r1; id","action":"django test"}` | REJECT_PATTERN / REJECT_PATTERN (`run_id does not match '^[a-z0-9][a-z0-9_-]{0,63}$'`) | BLOCKED — anchored `run_id` regex, no shell metacharacters |
| J-06 | Tenant-pair dash + CRLF header smuggle | `hacker.probe` hacker `{"item_id":"AUTHZ-ROUTE","actor":"hacker-high","capability_id":"00000000-0000-0000-0000-000000000000","tenant_pair":["-rf","a\r\nb"]}` | REJECT_PATTERN / REJECT_PATTERN (`tenant_pair must not start with a dash`) | BLOCKED — `_reject_string_hygiene` recursive over array items (dash first, CRLF also rejects) |
| J-07 | Enum case confusion (engine) | `check.run` auditor `{"check_id":"SUITE","tree":"0"*40,"engine":"Postgres"}` | REJECT_ENUM / REJECT_ENUM (`engine='Postgres' not in enum`) | BLOCKED — enum exact match, no case folding |
| J-08 | Bool-as-int type confusion (pr) | `pr.merge` release-engineer `{"pr":true,"head":"0"*40}` | REJECT_ARG / REJECT_ARG (`pr: expected type integer, got bool`) | BLOCKED — `validate._matches_type` rejects `bool` for `integer` explicitly |
| J-09 | Non-hex ledger hash forgery | `ledger.append` auditor `{"record_type":"verdict","record":{},"expected_prev_hash":"zzzz…64"}` | REJECT_PATTERN / REJECT_PATTERN (`expected_prev_hash does not match '^[a-f0-9]{64}$'`) | BLOCKED — `^[a-f0-9]{64}$`; a stale-but-hex hash instead hits `REJECT_PRECONDITION` in `ledger/chain._check_hash_chain` |
| J-10 | Backslash separator smuggle (+ ADS colon variant) | `git.read_file` auditor `{"rev":"0"*40,"path":"backend\\app.py"}` and `{"path":"backend/app.py:evil"}` | REJECT_PATH / REJECT_PATH (`path: non-normalized or out-of-tree path` for both) | BLOCKED — `is_traversal_or_absolute` rejects `\` and `:` (drive/ADS) |

**Zero successes: 10/10 BLOCKED.**

## Seal criteria / high-effort evidence

- `Server.run_controls()` → **167/167 PASS** (77 CF-F + 90 generic `CTRL-*`). Re-run live in this session: `run_controls 167/167 pass, fails=0`.
- `files/tools/mcp/core/test_core.py` → **PASS 25 checks** (`startup: 30 tools ok`, `per-role listing ok`, `PASS 25 checks (6B-0 exec core)`, exit 0).
- Startup + listing: `server_tool_names()` == registry names (30/30); `list_tools(role)` == registry projection for all 7 roles:
  - auditor (19): `acceptance.materialize, check.run, docker.ensure, drain.validate, evidence.hash, gate.control, git.diff, git.log, git.push_ref, git.read_file, git.state, git.status, k1.down, k1.exec, k1.status, k1.up, ledger.append, repro.run, scratch.write`
  - builder (10): `check.run, code.write, docker.ensure, evidence.hash, git.commit, git.diff, git.log, git.state, git.status, repro.run`
  - compliance (1): `code.write`
  - hacker (6): `check.run, git.state, hacker.probe, repro.run, scratch.write, static.scan`
  - orchestrator (9): `drain.validate, gate.control, git.diff, git.log, git.state, git.status, harness.verify, ledger.append, worktrees.list`
  - release-engineer (13): `drain.validate, git.diff, git.log, git.push_ref, git.state, git.status, ledger.append, pr.merge, pr.open, pr.watch, worktrees.list, worktrees.reconcile, worktrees.sync`
  - crouton (2): `code.write, git.state`
- No shell surface: `any("shell" in name for name in server_tool_names())` is False. Every `REJECT_*` above was produced without invoking a shell.
- READ-ONLY: `git diff --stat` empty; `git status --porcelain` lists only pre-existing untracked paths plus `?? phase6/out/phase7-confirm/` (this report) and `?? phase6/out/6C-6/` (prior). No tracked file modified.
- No seal/tag/push: this verifier created no tag, did not seal, did not push, and did not commit. `HEAD` remains `6e000d4`.

## Deviations (max 5)

1. Dispatch harness ran as `python` with `sys.path.insert(0, harnessRoot)` against the live `Server` class (not an HTTP MCP mount; `list_mcp_resources` is empty in this harness). This exercises the exact `Server.dispatch` code path that production MCP tools call.
2. A fresh `Server` instance is used per F-id/probe (small `probe_tmp.py`-style harness in `C:\Users\Admin\AppData\Local\Temp\opencode\`); `run_controls()` does the same internally. This prevents `pr.watch`/ledger state from leaking across independent controls (F-55 is precondition-by-absence by design).
3. Static-config residuals not MCP-reachable (compose `pg` entrypoint caps `CHOWN DAC_OVERRIDE FOWNER SETGID SETUID` on a `nosuid,nodev` tmpfs, `${POSTGRES_PASSWORD}` harness-generated env) are non-injectable via typed args and documented in `HARDENING.md`; they are not counted as successes (no remote control).
4. Alternative path identities that create a *different* file (e.g. Unicode zero-width prefix) are not Windows-normalized to the denied name and do not read the secret; they are therefore not counted as bypasses in this report and are not among J-01..J-10.
5. No `phase6-sealed` tag was created (per instruction). No commit was made; this report is left untracked for the owner to commit.

## Open questions (max 3)

1. Owner to commit `phase6/out/phase7-confirm/REPORT.md` (currently `??` untracked) — verifier left it uncommitted by design.
2. Final seal (if later) must roll `gate_sha` forward with a fresh gate-control record — out of scope for this read-only confirmation.
3. None for phase7-confirm — all 77 F-ids plus 10 fresh improvisations are BLOCKED.

## Reproducer (read-only)

```powershell
cd C:\Users\Admin\Documents\umairnlp
# Per-F live dispatch (fresh Server per CF-F, prints BLOCKED/SUCCESS, 77/77):
python C:\Users\Admin\AppData\Local\Temp\opencode\verify77.py
# Generic core (25/25) + per-role listing + findings counts + git status:
python C:\Users\Admin\AppData\Local\Temp\opencode\verify_core.py
# Improvisations J-01..J-10 (each prints REJECT_*):
python C:\Users\Admin\AppData\Local\Temp\opencode\probe_j.py
```

The verifier scripts themselves live only in the approved temp dir and do not modify the repo; the repo artifacts above are the sha256-pinned `registry.json`/`controls.json`/`server.py` and `phase6/findings.md`.
