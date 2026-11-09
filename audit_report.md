# Toolchain/Gate Audit (comp-wt)

## 1 Ruff
backend/pyproject.toml [tool.ruff]: line-length=88; extend-exclude=["*.md"]; select=["E","F","W","I"]; ignore=["E501"]; per-file-ignores 1 (common/totp.py F841). Disabled families measured: RUF167, SIM57, BLE10, C4 9, FURB14, PLW5, DTZ2, UP3, RET2, ISC2, B2, TRY1, PIE1. Config admits only 4 rule families; no S/bandit/async/pathlib/pyupgrade.

## 2 Type checking
[tool.mypy] scope common/ + orders/state.py only; ignore_missing_imports=true, check_untyped_defs=true; 2 overrides disable attr-defined/misc/arg-type. 221 `type: ignore`, 2009 `Any` across 498 .py. Sample 30 not run. TIER-2/GATE-MYPY-1 artifacts in pyproject comments. No mypy in pre-commit.

## 3 Import linter
Absent: no .importlinter, no config, no CI mention.

## 4 Mutation
mutmut 2.5.1, paths_to_mutate="orders/state.py,common/permissions.py", use_coverage=true. Weekly non-blocking (mutation-weekly.yml), no threshold, --CI exits 0. "mutmut 40% survive" claim not found in scripts/*.json or docs/mutation/*.md; unverified.

## 5 Pre-commit
6 hooks: ruff-check, ruff-format (local), trailing-whitespace, check-yaml, check-merge-conflict, detect-private-key. No mypy, no bandit, no lint-staged. Redundancy: ruff duplicated with CI lint job (intentional). Custom bash interpreter discovery.

## 6 CI workflows
9 workflows. backend-tests.yml 46KB is main gate. mutation-weekly non-blocking. Gates in docs but not CI: mypy scope only, no import-linter, no SAST/DAST.

## 7 Security
Present: gitleaks (.gitleaks.toml + secret-scan.yml), gitguardian (.gitguardian.yaml + .gitguardian.yml duplicate). renovate.json valid (dropped separateMultipleMajor in BUG-5). Absent: bandit, semgrep, CodeQL, pip-audit, safety, trivy, osv-scanner, dependabot, OWASP ZAP, IAST. renovate osvVulnerabilityAlerts=true.

## 8 Custom linters
doc_claims.py 70KB + tests 84KB; changelog_figures.py 42KB + tests 45KB; redteam_t1a 67KB; redteam_t1b 77KB. Total ~340KB. Off-the-shelf: markdownlint/vale/lychee for doc claims; no direct replacement for redteam. Verdict: keep doc_claims (domain-specific), replace changelog_figures with standard changelog tooling.

## 9 TMPFS/I/O
docker-compose.yml bind mounts; named volumes? inspect. Windows/Docker-Desktop viability limited (host SSD). Recommendation: use named volumes for node_modules, tmpfs for test DB.

## 10 POSIX/BOM/encoding
pg_gate.py lines 87-97 sniff BOM/UTF-16. doc_claims reads utf-8. Keep pg_gate; nuke ad-hoc sniffers, use charset-normalizer.

## Findings
| ID | Gate | Current | Enterprise baseline | Replace with | Effort |
|---|---|---|---|---|---|
| R1 | Ruff rules | E,F,W,I only | S,B,UP,PTH,ASYNC | extend select | M |
| T1 | Mypy scope | 2 files | whole backend | django-stubs + widen | L |
| I1 | Import linter | absent | present | import-linter | M |
| M1 | Mutation | weekly, no threshold | blocking 80% | mutmut --CI + threshold | M |
| P1 | Pre-commit | 6 hooks, no mypy | mypy + bandit | add hooks | S |
| S1 | SAST | absent | bandit/semgrep | bandit + semgrep | M |
| S2 | Secret scan | duplicated gitguardian | single config | consolidate | S |
| C1 | Custom linters | 340KB | standard tools | markdownlint/vale | M |
| IO1 | TMPFS | bind mounts | named volumes | docker volumes | M |
| E1 | Encoding sniffers | pg_gate ad-hoc | charset-normalizer | standard lib | S |