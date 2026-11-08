#!/usr/bin/env python3
"""Factory configuration invariants, asserted from resolved files.

This replaces the pre-purge validator. It checks the V2 permission contract,
role-model independence (policies/models.json), the installed-vs-source agent
copies, and the absence of the purged UI/Codex roles.

Exit 0 only when every assertion passes.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

HARNESS = Path(r"C:\Users\Admin\Documents\umairnlp")
FACTORY = HARNESS / "files"
AGENTS = HARNESS / ".opencode" / "agents"
CONFIG = HARNESS / "opencode.json"
MODELS = FACTORY / "policies" / "models.json"

ROLES = ("orchestrator", "builder", "auditor", "hacker", "release-engineer")

failures: list[str] = []
checks = 0


def check(condition: bool, label: str, detail: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"PASS  {label}")
    else:
        print(f"FAIL  {label}" + (f"  [{detail}]" if detail else ""))
        failures.append(label)


def frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    return yaml.safe_load(match.group(1)) if match else {}


def model_family(model: str) -> str:
    """Return the provider-family token used by policies/models.json."""
    name = model.rsplit("/", 1)[-1].split("#", 1)[0]
    first = name.split("-", 1)[0]
    return first


config = json.loads(CONFIG.read_text(encoding="utf-8"))
models = json.loads(MODELS.read_text(encoding="utf-8"))

# --- default agent -------------------------------------------------------
default_agent = config.get("default_agent")
orchestrator_mode = frontmatter(AGENTS / "orchestrator.md").get("mode")
check(bool(default_agent), "default_agent is set", str(default_agent))
check(
    default_agent == "orchestrator" and orchestrator_mode == "primary",
    "default_agent names a primary agent",
    f"{default_agent=} {orchestrator_mode=}",
)

# --- purged roles stay purged -------------------------------------------
check("ui-auditor" not in config.get("agent", {}), "no ui-auditor config override")
check("ui-auditor" not in config.get("agents", {}), "no ui-auditor agents override")
check(not (HARNESS / ".codex").exists(), "no Codex config tree")
check(
    all((AGENTS / f"{role}.md").is_file() for role in ROLES),
    "all five active agent files are installed",
)

# --- installed copies match the factory source --------------------------
for role in ROLES:
    source = (FACTORY / f"{role}.md").read_text(encoding="utf-8")
    installed = (AGENTS / f"{role}.md").read_text(encoding="utf-8")
    check(source == installed, f"{role}.md installed copy matches files/", role)

# --- V2 permission contract --------------------------------------------
for role in ROLES:
    meta = frontmatter(AGENTS / f"{role}.md")
    rules = meta.get("permissions")
    check(isinstance(rules, list) and bool(rules), f"{role} uses V2 permissions list")
    check("permission" not in meta, f"{role} does not use the V1 permission map")
    if isinstance(rules, list) and rules:
        first = rules[0]
        check(
            first.get("action") == "*"
            and first.get("resource") == "*"
            and first.get("effect") == "deny",
            f"{role} starts from a blanket deny",
            json.dumps(first, sort_keys=True),
        )
        actions = {(rule.get("action"), rule.get("effect")) for rule in rules}
        check(("edit", "allow") in actions or role in ("auditor", "release-engineer"),
              f"{role} edit policy is explicit",
              f"{role} has no edit allow")

# --- model independence -------------------------------------------------
role_models = {role: frontmatter(AGENTS / f"{role}.md").get("model") for role in ROLES}
role_models["hacker-high"] = role_models["hacker"]
role_models["hacker-max"] = role_models["hacker"]
for role, spec in models["roles"].items():
    if role == "hacker-max":
        # The max-tier hacker model is a dispatch-time override (the
        # orchestrator passes it to subagent); the agent file carries the
        # high-tier default. Its family still participates in the
        # independence check below.
        continue
    expected = f"{spec['provider']}/{spec['model']}"
    if spec.get("variant"):
        expected += f"#{spec['variant']}"
    check(
        role_models.get(role) == expected,
        f"{role} model matches policies/models.json",
        f"{role_models.get(role)!r} != {expected!r}",
    )

families = {
    role: (models["roles"].get(role, {}).get("family") or model_family(model or ""))
    for role, model in role_models.items()
}
for role, rule in models["independence"].items():
    if rule.get("enforced") is False:
        continue
    exempt = set(rule.get("exempt_edges") or [])
    enforced_targets = [other for other in rule["family_not_in"] if other not in exempt]
    forbidden = {families.get(other) for other in enforced_targets}
    check(
        families.get(role) not in forbidden,
        f"{role} family differs from {sorted(enforced_targets)}",
        f"{families.get(role)!r} in {forbidden!r}",
    )

# --- model policy enum invariants ----------------------------------------
_expected_roles = {"orchestrator", "builder", "auditor", "hacker-high", "hacker-max", "release-engineer"}
check(
    set(models.get("independence") or {}) == _expected_roles and set(models.get("roles") or {}) == _expected_roles,
    "independence covers 6 roles",
    f"independence={sorted((models.get('independence') or {}).keys())} roles={sorted((models.get('roles') or {}).keys())}",
)
check(
    "builder" in ((models.get("independence") or {}).get("orchestrator") or {}).get("family_not_in", []),
    "orchestrator lists builder",
    f"{((models.get('independence') or {}).get('orchestrator') or {}).get('family_not_in')}",
)
check(
    set(((models.get("independence") or {}).get("release-engineer") or {}).get("family_not_in", [])) == {"builder", "auditor", "hacker-high", "hacker-max"},
    "release-engineer expanded vs builder+auditor+hacker-high+max",
    f"{((models.get('independence') or {}).get('release-engineer') or {}).get('family_not_in')}",
)
check(
    "hacker-max" in ((models.get("independence") or {}).get("hacker-high") or {}).get("family_not_in", [])
    and "hacker-high" in ((models.get("independence") or {}).get("hacker-max") or {}).get("family_not_in", []),
    "hacker mutual forbid",
    f"hacker-high={((models.get('independence') or {}).get('hacker-high') or {}).get('family_not_in')} hacker-max={((models.get('independence') or {}).get('hacker-max') or {}).get('family_not_in')}",
)
check(
    set((models.get("independence_scope") or {}).get("triangle", [])) == {"builder", "auditor", "hacker-high", "hacker-max"},
    "triangle scope",
    f"{(models.get('independence_scope') or {}).get('triangle')}",
)
check(
    models.get("acceptance_author_role") == "hacker-high"
    and models.get("acceptance_author_role") in (models.get("acceptance_author_role_enum") or []),
    "acceptance canonical in enum",
    f"{models.get('acceptance_author_role')!r} in {models.get('acceptance_author_role_enum')}",
)
check(
    (models.get("acceptance_author_role_aliases") or {}).get("hacker") == "hacker-high",
    "legacy hacker alias",
    f"{models.get('acceptance_author_role_aliases')}",
)
check(
    models.get("acceptance_author_family_derived")
    == ((models.get("roles") or {}).get(models.get("acceptance_author_role") or "", {}) or {}).get("family"),
    "derived family equals roles family",
    f"derived={models.get('acceptance_author_family_derived')!r}",
)

check("agent" not in config or not config["agent"], "no per-agent model override in opencode.json")
check("agents" not in config or "auditor" not in config.get("agents", {}),
      "no auditor override under agents")

# --- auditor has no write surface --------------------------------------
auditor = frontmatter(AGENTS / "auditor.md")
auditor_rules = auditor.get("permissions") or []
edit_allows = [
    rule["resource"]
    for rule in auditor_rules
    if rule.get("action") == "edit" and rule.get("effect") == "allow"
]
write_allows = [
    rule["resource"]
    for rule in auditor_rules
    if rule.get("action") == "write" and rule.get("effect") == "allow"
]
check(not edit_allows, "auditor has no edit allows", str(edit_allows))
check(not write_allows, "auditor has no write allows", str(write_allows))
check(
    any(rule.get("action") == "edit" and rule.get("resource") == "*" and rule.get("effect") == "deny"
        for rule in auditor_rules),
    "auditor denies edit globally",
)
check(
    not any(rule.get("action") == "shell" and rule.get("resource") == "*" and rule.get("effect") == "allow"
            for rule in auditor_rules),
    "auditor has no blanket shell allow",
)

# --- builder asks before risky actions ----------------------------------
# Last-match-wins ask rules: a risky action prompts once instead of being
# silently denied. The hard denies are re-asserted after these in the file.
BUILDER_ASKS = (
    ("read", "../**"),
    ("read", "C:/Users/Admin/AppData/Local/Temp/opencode/**"),
    ("read", "C:/Users/Admin/Documents/umairnlp/**"),
    ("shell", "*docker pull*"),
    ("shell", "*docker build*"),
    ("shell", "*docker run*"),
    ("shell", "*docker create*"),
    ("shell", "*docker compose*"),
    ("shell", "*git clone*"),
    ("shell", "*python -m venv*"),
    ("shell", "*venv*Scripts*activate*"),
    ("shell", "*venv/bin/activate*"),
    ("shell", "*pip install*"),
    ("shell", "*pip3 install*"),
    ("shell", "*npm install*"),
    ("shell", "*pnpm install*"),
)
builder_rules = frontmatter(AGENTS / "builder.md").get("permissions") or []
for action, resource in BUILDER_ASKS:
    check(
        any(
            rule.get("action") == action
            and rule.get("resource") == resource
            and rule.get("effect") == "ask"
            for rule in builder_rules
        ),
        f"builder asks for {resource}",
        f"{action} {resource}",
    )

# --- auditor owns the K1 lifecycle around the hacker --------------------
k1_missing = [
    f"shell {resource}"
    for resource in ("*k1_up.ps1*", "*k1_exec.ps1*", "*k1_down.ps1*")
    if not any(
        rule.get("action") == "shell"
        and rule.get("resource") == resource
        and rule.get("effect") == "allow"
        for rule in auditor_rules
    )
]
if not any(
    rule.get("action") == "skill"
    and rule.get("resource") == "k1-sandbox"
    and rule.get("effect") == "allow"
    for rule in auditor_rules
):
    k1_missing.append("skill k1-sandbox")
check(not k1_missing, "auditor can run K1 lifecycle", ", ".join(k1_missing))

# --- owner-only policy manifest ----------------------------------------
# The manifest is a full inventory (all policies, agents, twins, skills,
# wrappers, tools, fixtures). No factory agent may read, edit, write, or
# shell-open it. The harness verifier may.
for path in sorted(AGENTS.glob("*.md")):
    rules = frontmatter(path).get("permissions") or []
    for action in ("read", "edit", "write", "grep", "glob"):
        check(
            any(
                rule.get("action") == action
                and rule.get("resource") == "**/policy-manifest.json"
                and rule.get("effect") == "deny"
                for rule in rules
            ),
            f"{path.stem} denies {action} on policy-manifest.json",
        )
    check(
        any(
            rule.get("action") == "shell"
            and rule.get("resource") == "*policy-manifest.json*"
            and rule.get("effect") == "deny"
            for rule in rules
        ),
        f"{path.stem} denies shell access to policy-manifest.json",
    )

manifest_tool = HARNESS / "scripts" / "policy_manifest.py"
if manifest_tool.is_file():
    process = subprocess.run(
        [sys.executable, str(manifest_tool), "--verify"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    check(
        process.returncode == 0,
        "policy manifest verifies",
        (process.stdout or process.stderr).strip()[-240:],
    )

# --- skill convention guards (lightweight, no new deps) -----------------
SKILL_ALLOWLIST = {"hacker-exploit"}  # known non-wrapper: no title block
_skill_files = sorted((FACTORY / "skills").glob("*/SKILL.md")) + sorted((HARNESS / ".opencode" / "skills").glob("*/SKILL.md"))
_skill_bad = []
for _sk in _skill_files:
    _txt = _sk.read_text(encoding="utf-8")
    _id = _sk.parent.name
    if _id in SKILL_ALLOWLIST:
        continue
    if f"# {_id}" not in _txt:
        _skill_bad.append(f"{_id}: title")
    if "scripts/" in _txt and f"`skill-level name:` {_id}" not in _txt:
        _skill_bad.append(f"{_id}: skill-level")
check(not _skill_bad, "SKILL.md header convention", ", ".join(_skill_bad[:6]))

_known_full = set()
_known_base = set()
_known_prov = set()
for _prov, _pinfo in config.get("provider", {}).items():
    _known_prov.add(_prov)
    for _m in (_pinfo.get("models") or {}):
        _known_full.add(f"{_prov}/{_m}"); _known_base.add(f"{_prov}/{_m}")
        _opts = ((_pinfo.get("models") or {}).get(_m, {})) or {}
        for _fb in ((_opts.get("options", {}).get("fallbacks", []) if isinstance(_opts.get("options", {}), dict) else [])):
            if isinstance(_fb, dict) and _fb.get("model"):
                _known_full.add(_fb["model"]); _known_base.add(_fb["model"].split("#", 1)[0]); _known_prov.add(_fb["model"].split("/")[0])
for _ap in sorted(AGENTS.glob("*.md")):
    _am = frontmatter(_ap).get("model")
    if isinstance(_am, str) and _am:
        _known_full.add(_am); _known_base.add(_am.split("#", 1)[0]); _known_prov.add(_am.split("/")[0])
_model_bad = []
for _sk in _skill_files:
    _txt = _sk.read_text(encoding="utf-8")
    for _tok in re.findall(r"[A-Za-z][A-Za-z0-9-]*-[A-Za-z0-9-]*/[A-Za-z][A-Za-z0-9_./:#-]*", _txt):
        _tok = _tok.rstrip(".,;:!?)")
        if _tok.split("/")[0] not in _known_prov:
            continue
        if _tok not in _known_full and _tok.split("#", 1)[0] not in _known_base:
            _model_bad.append(f"{_sk.parent.name}:{_tok}")
check(not _model_bad, "SKILL.md models resolve", ", ".join(_model_bad[:6]))

_ROLE_SET = ("orchestrator", "builder", "auditor", "hacker", "release-engineer", "compliance")
_skill_allow = {}
for _ap in sorted(AGENTS.glob("*.md")):
    _rules = frontmatter(_ap).get("permissions") or []
    _skill_allow[_ap.stem] = {r.get("resource") for r in _rules if r.get("action") == "skill" and r.get("effect") == "allow"}
_serves_bad = []
for _sk in _skill_files:
    _txt = _sk.read_text(encoding="utf-8")
    _id = _sk.parent.name
    _start = _txt.find("`serves:`")
    if _start == -1:
        continue
    _end = _txt.find("\n`args:", _start)
    _block = _txt[_start:_end] if _end != -1 else _txt[_start:_start + 1500]
    def _drop_multi(_m):
        _n = sum(1 for _r in _ROLE_SET if re.search(rf"\b{_r}\b", _m.group(1)))
        return "" if _n >= 2 else _m.group(0)
    _block = re.sub(r"\(([^)]*)\)", _drop_multi, _block)
    _block = re.sub(r"(?m)^\s*\d+\.\s*", " ", _block)
    _first = _block.split(".")[0]
    for _role in _ROLE_SET:
        if re.search(rf"\b{_role}\b", _first) and _id not in _skill_allow.get(_role, set()):
            _serves_bad.append(f"{_id}:{_role}")
check(not _serves_bad, "skill serves cross-ref", ", ".join(_serves_bad[:6]))

# --- single-source policy completeness (generated from checks.json) ---
POLICIES = FACTORY / "policies"
pol_checks = json.loads((POLICIES / "checks.json").read_text(encoding="utf-8"))["checks"]
pol_gate = json.loads((POLICIES / "gate.json").read_text(encoding="utf-8"))
pol_ci = json.loads((POLICIES / "ci.json").read_text(encoding="utf-8"))
pol_tiers = json.loads((POLICIES / "tiers.json").read_text(encoding="utf-8"))
pol_runners = json.loads((POLICIES / "check-runners.json").read_text(encoding="utf-8"))
check(set(pol_gate["gate_checks"]) == set(pol_checks), "gate covers exactly all checks", f"gate_diff={sorted(set(pol_gate['gate_checks']) ^ set(pol_checks))}")
_ci_req, _ci_not = set(pol_ci["required_checks"]), set(pol_ci["not_run_in_ci"])
check(_ci_req | _ci_not == set(pol_checks) and _ci_req & _ci_not == set(), "ci buckets partition all checks disjointly", f"union_diff={sorted((_ci_req | _ci_not) ^ set(pol_checks))} overlap={sorted(_ci_req & _ci_not)}")
check(set(pol_runners["checks"]) == set(pol_checks), "check-runners mirror all checks", f"runners_diff={sorted(set(pol_runners['checks']) ^ set(pol_checks))}")
check(set(pol_runners["ci_self_audit"]) == _ci_req, "ci_self_audit matches ci required", f"audit_diff={sorted(set(pol_runners['ci_self_audit']) ^ _ci_req)}")
check(set(pol_tiers["none"]["required_checks"]) <= set(pol_tiers["high"]["required_checks"]) <= set(pol_tiers["max"]["required_checks"]) == set(pol_checks), "tiers required_checks monotonic to max == all checks", f"max_diff={sorted(set(pol_tiers['max']['required_checks']) ^ set(pol_checks))} high_not_none={sorted(set(pol_tiers['high']['required_checks']) - set(pol_tiers['none']['required_checks']))}")

print()
if failures:
    print(f"RESULT: FAIL ({len(failures)}/{checks})")
    for item in failures:
        print(f"  - {item}")
    sys.exit(1)
print(f"RESULT: PASS ({checks} checks)")
