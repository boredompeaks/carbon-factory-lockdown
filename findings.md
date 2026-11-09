ID
Finding
F-01
Wildcard shell globs (gate_run.py, manage.py test, python hacker-scratch/*) match any command containing the substring, in every role
F-02
Auditor can run makemigrations (a write) and git show rev:.env, bypassing read denies
F-03
Auditor A1 says no access to quality/, yet grants read on quality/ledger/
F-04
Auditor promises ledger verdict writes, but edit and write are blanket denied
F-05
Builder can edit any test file except tests_gate* and conftest.py; write is not denied on pytest.ini, tox.ini, .coveragerc, .github, .gitleaks.toml
F-06
Builder can read attack-catalog and tiers and tune code to known probes
F-07
Builder git commit* allows --no-verify (bypasses B6 hook); git add* allows -f
F-08
Orchestrator has edit quality/** with no deny for verdict, finding, release, risk-acceptance records
F-09
Orchestrator cannot create capability.json and lacks subagent allows for hacker-high, hacker-max, design-research
F-10
Hacker has no k1_exec or probe grant, though the K1 contract expects runtime attacks
F-11
Hacker writes audit-scratch/**, where the auditor stores its re-derived acceptance test
F-12
crouton-alpha: no orchestrator subagent allow; lacks the grep and glob denies for policy-manifest.json
F-13
K1 plan says IMPLEMENTED and smoke-tested; FACTORY-POLICY-MAP says not ready (no pinned image, Postgres on 0.0.0.0); digest pin is a placeholder; /work tmpfs is exec
F-71
Check-set drift: ci.json (9), branch-protection.json (8, no AUTHZ_MATRIX), release-engineer.md (7)
F-72
severity.json lacks BARE_EXCEPT, AGT_PARITY_MISMATCH, AGT_AUDIT_GAP; TEST_SET and ERROR_HANDLING are never emitted
F-73
test-removal-reasons covered_by is a substring match; require exact id
F-74
assert-rules: tautology regexes miss trailing messages and comments, unittest forms, and all TS/JS
F-75
redaction.json: phone_nanp and ipv4 mangle evidence; entropy fallback trips on session and CSRF tokens; runner patch not implemented
F-76
Auditor acceptance re-derivation (audit-scratch) has no write path; drain R3 has no owner able to write the test
F-77
The MCP server and probe client are not in gate_impl_digest