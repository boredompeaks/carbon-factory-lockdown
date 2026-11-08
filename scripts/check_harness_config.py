#!/usr/bin/env python3
"""Factory configuration invariants, asserted from resolved files.

This replaces the pre-purge validator. It checks the V2 permission contract,
role-model independence (policies/models.json), the installed-vs-source agent
copies, and the absence of the purged UI/Codex roles.

Exit 0 only when every assertion passes.
"""

from __future__ import annotations

import csv
import hashlib
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
REGISTRY = FACTORY / "tools" / "mcp" / "registry.json"
MATRIX = HARNESS / "phase6" / "matrix.csv"
MANIFEST_PATH = FACTORY / "policies" / "policy-manifest.json"
DISPATCH_PATH = FACTORY / "policies" / "dispatch-rules.json"

ROLES = ("orchestrator", "builder", "auditor", "hacker", "release-engineer")

# Installed roles observed on disk (crouton-alpha may be absent pre-6C-1c;
# compliance/crouton are cut over by 6C-1c). INV checks iterate all
# installed agent files, not this 5-tuple.
INSTALLED_ROLES = ("orchestrator", "builder", "auditor", "hacker", "compliance", "release-engineer", "crouton-alpha")

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
    """Parse YAML frontmatter; return {} with a parse-error marker on failure.

    A broken file (e.g. crouton-alpha.md mid-cutover with an unquoted
    colon in `description`) must not crash the checker. The marker lets
    INV checks report FAIL with the parse error instead.
    """
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not match:
        return {}
    try:
        loaded = yaml.safe_load(match.group(1))
        return loaded if isinstance(loaded, dict) else {}
    except Exception as exc:  # noqa: BLE001 -- report as check failure, never crash
        return {"__parse_error__": f"{type(exc).__name__}: {exc}"}


def model_family(model: str) -> str:
    """Return the provider-family token used by policies/models.json."""
    name = model.rsplit("/", 1)[-1].split("#", 1)[0]
    first = name.split("-", 1)[0]
    return first


# opencode.json is gitignored after purge-prep (71d0137) and may be absent
# on disk. Do not crash: treat a missing file as an empty config so the
# default_agent checks report FAIL with a usable detail instead.
try:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
except FileNotFoundError:
    config = {}
except json.JSONDecodeError:
    config = {}
models = json.loads(MODELS.read_text(encoding="utf-8"))

# ============================================================================
# INV-1..7: typed-tool lockdown invariants (phase 6C-3)
# ============================================================================
# Each invariant is a pure function over a synthetic state so the same logic
# runs live (built from resolved files below) and in --fixtures mode (built
# from phase6/out/6C-3/fixtures/*.json). A fixture is a JSON object with:
#   agents: {role: {permissions: [{action,resource,effect}]}}
#   registry: {tools: [{name,roles}]}; matrix_rows: [{role,disposition}]
#   manifest: {covers, files: [{path,sha256}], hashes: {path: sha}}
#   dispatch: {rules: [{dispatch_first, require_before}]}
#   orchestrator_targets: [enum targets routed by the orchestrator]
#   expect_fails: [INV ids this fixture must fail] ([] for clean.json)
# Live roles are the installed .opencode/agents/*.md files; the matrix and
# registry cover 7 roles (incl. crouton). Missing agent files are reported
# by the structural checks, not as INV rule failures.

MANIFEST_DENY = "**/policy-manifest.json"
INV6_REQUIRED_COVERS = (
    "files/tools/mcp/registry.json",
    "files/tools/mcp/core/server.py",
    "files/tools/mcp/controls.json",
    "files/docker/k1/probe_client.py",
)
INV_IDS = ("INV-1", "INV-2", "INV-3", "INV-4", "INV-5", "INV-6", "INV-7")


def _norm_subagent(name: str) -> str:
    """hacker-high/max are model-tier overrides of the hacker agent."""
    return "hacker" if name in ("hacker-high", "hacker-max") else name


def _get_covers(manifest: dict) -> list:
    covers = []
    try:
        covers = (manifest.get("dependencies") or {}).get("gate_impl_digest", {}).get("covers") or []
    except AttributeError:
        covers = []
    if covers:
        return list(covers)
    return list(manifest.get("covers") or [])


def _get_filemap(manifest: dict) -> dict:
    files = manifest.get("files") or []
    return {f.get("path"): f.get("sha256") for f in files if isinstance(f, dict) and f.get("path")}


def inv1(agents: dict) -> tuple[bool, str]:
    """INV-1: no shell action in any agent (any effect, any resource)."""
    bad = []
    for role, data in sorted(agents.items()):
        if "__parse_error__" in data:
            bad.append(f"{role}: frontmatter parse error: {data['__parse_error__']}")
            continue
        perms = (data.get("permissions") if isinstance(data, dict) else data) or []
        shell = [p for p in perms if isinstance(p, dict) and p.get("action") == "shell"]
        if shell:
            res = ", ".join(str(p.get("resource")) for p in shell[:4])
            bad.append(f"{role}: {len(shell)} shell rules ({res})")
    return (not bad), "; ".join(bad)


def inv2(agents: dict) -> tuple[bool, str]:
    """INV-2: no edit/write allow on quality/** (ledger.append is the only path)."""
    bad = []
    for role, data in sorted(agents.items()):
        if "__parse_error__" in data:
            bad.append(f"{role}: frontmatter parse error: {data['__parse_error__']}")
            continue
        perms = (data.get("permissions") if isinstance(data, dict) else data) or []
        viol = [
            p for p in perms
            if isinstance(p, dict)
            and p.get("action") in ("edit", "write")
            and p.get("effect") in ("allow", "ask")
            and "quality/" in str(p.get("resource") or "")
        ]
        if viol:
            bad.append(f"{role}: " + ", ".join(str(p.get("resource")) for p in viol))
    return (not bad), "; ".join(bad)


def inv3(agents: dict) -> tuple[bool, str]:
    """INV-3: only hacker reaches hacker-scratch writes, only via scratch.write."""
    bad = []
    for role, data in sorted(agents.items()):
        if "__parse_error__" in data:
            bad.append(f"{role}: frontmatter parse error: {data['__parse_error__']}")
            continue
        perms = (data.get("permissions") if isinstance(data, dict) else data) or []
        direct = [
            p for p in perms
            if isinstance(p, dict)
            and p.get("action") in ("edit", "write", "shell")
            and p.get("effect") in ("allow", "ask")
            and "hacker-scratch" in str(p.get("resource") or "")
        ]
        # Every role, including hacker, must not have direct path writes.
        # The hacker difference is the tool grant below.
        if direct:
            bad.append(f"{role}: direct hacker-scratch write " + ", ".join(f"{p.get('action')} {p.get('resource')}" for p in direct[:3]))
    hacker = agents.get("hacker") or {}
    hacker_perms = (hacker.get("permissions") if isinstance(hacker, dict) else hacker) or []
    if "__parse_error__" not in hacker and "hacker" in agents:
        has_tool = any(
            isinstance(p, dict) and p.get("action") == "tool" and p.get("resource") == "scratch.write" and p.get("effect") == "allow"
            for p in hacker_perms
        )
        if not has_tool:
            bad.append("hacker: missing tool allow scratch.write")
    return (not bad), "; ".join(bad)


def inv4(agents: dict) -> tuple[bool, str]:
    """INV-4: every role denies grep/glob/read on **/policy-manifest.json."""
    bad = []
    for role, data in sorted(agents.items()):
        if "__parse_error__" in data:
            bad.append(f"{role}: frontmatter parse error: {data['__parse_error__']}")
            continue
        perms = (data.get("permissions") if isinstance(data, dict) else data) or []
        for action in ("read", "grep", "glob"):
            found = any(
                isinstance(p, dict) and p.get("action") == action and p.get("resource") == MANIFEST_DENY and p.get("effect") == "deny"
                for p in perms
            )
            if not found:
                bad.append(f"{role}: missing {action} deny")
    return (not bad), "; ".join(bad)


def inv5(registry: dict, matrix_rows: list) -> tuple[bool, str]:
    """INV-5: per-role tool list (registry) equals matrix TOOL dispositions."""
    regby: dict[str, set] = {}
    for tool in (registry.get("tools") or []):
        if not isinstance(tool, dict) or not tool.get("name"):
            continue
        for role in (tool.get("roles") or []):
            if role == "ci":
                continue
            regby.setdefault(role, set()).add(tool["name"])
    matby: dict[str, set] = {}
    for row in matrix_rows:
        disp = str((row.get("disposition") or "")).strip()
        if disp.startswith("TOOL:"):
            matby.setdefault(str(row.get("role") or "").strip(), set()).add(disp[len("TOOL:"):])
    mism = []
    for role in sorted(set(regby) | set(matby)):
        if regby.get(role, set()) != matby.get(role, set()):
            mism.append(
                f"{role}: registry={sorted(regby.get(role, set()))} matrix={sorted(matby.get(role, set()))}"
            )
    return (not mism), "; ".join(mism)


def inv6(manifest: dict, hashes: dict) -> tuple[bool, str]:
    """INV-6: registry/server(+controls, probe client) hash in gate_impl_digest."""
    covers = _get_covers(manifest)
    filemap = _get_filemap(manifest)
    missing_covers = [c for c in INV6_REQUIRED_COVERS if c not in covers]
    missing_files = [c for c in INV6_REQUIRED_COVERS if c not in filemap]
    mismatched = [
        c for c in INV6_REQUIRED_COVERS
        if c in filemap and c in hashes and str(filemap[c]) != str(hashes[c])
    ]
    bad = []
    if missing_covers:
        bad.append(f"covers missing {missing_covers}")
    if missing_files:
        bad.append(f"manifest files missing {missing_files}")
    if mismatched:
        bad.append(f"hash mismatch {mismatched}")
    return (not bad), "; ".join(bad)


def inv7(orchestrator_perms: list, dispatch_targets: set, orchestrator_targets: list) -> tuple[bool, str]:
    """INV-7: every subagent target the orchestrator routes to is allowed."""
    allowed = {
        _norm_subagent(str(p.get("resource")))
        for p in (orchestrator_perms or [])
        if isinstance(p, dict) and p.get("action") == "subagent" and p.get("effect") == "allow" and str(p.get("resource") or "") != "*"
    }
    routed = set(dispatch_targets or set()) | set(orchestrator_targets or [])
    routed_norm = {_norm_subagent(str(r)) for r in routed if str(r) not in ("", "none")}
    missing = sorted(routed_norm - allowed)
    return (not missing), f"missing subagent allows {missing} allowed={sorted(allowed)}"


def _run_fixtures(fixtures_dir: Path) -> int:
    """Run INV-1..7 against every fixture JSON; exit 0 iff expectations hold."""
    files = sorted(fixtures_dir.glob("*.json"))
    if not files:
        print(f"fixtures: no JSON found in {fixtures_dir}")
        return 1
    all_ok = True
    total = 0
    for fpath in files:
        try:
            state = json.loads(fpath.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL  fixture {fpath.name}: load error {exc}")
            all_ok = False
            continue
        agents = state.get("agents") or {}
        registry = state.get("registry") or {}
        matrix_rows = state.get("matrix_rows") or []
        manifest = state.get("manifest") or {}
        hashes = dict(manifest.get("hashes") or {})
        dispatch = state.get("dispatch") or {}
        d_targets = set()
        for r in (dispatch.get("rules") or []):
            for x in (r.get("dispatch_first") or []):
                d_targets.add(x)
            if r.get("require_before"):
                d_targets.add(r["require_before"])
        orch_perms = ((agents.get("orchestrator") or {}).get("permissions") or []) if isinstance(agents.get("orchestrator"), dict) else []
        o_targets = list(state.get("orchestrator_targets") or [])
        results = {
            "INV-1": inv1(agents),
            "INV-2": inv2(agents),
            "INV-3": inv3(agents),
            "INV-4": inv4(agents),
            "INV-5": inv5(registry, matrix_rows),
            "INV-6": inv6(manifest, hashes),
            "INV-7": inv7(orch_perms, d_targets, o_targets),
        }
        expect = list(state.get("expect_fails") or [])
        total += len(results)
        for inv_id in INV_IDS:
            ok, detail = results[inv_id]
            want_fail = inv_id in expect
            passed = (not ok) if want_fail else ok
            label = f"fixture {fpath.name} {inv_id} {'FAIL' if not ok else 'PASS'}"
            if want_fail:
                label += " (expected FAIL)"
            if passed:
                print(f"PASS  {label}" + (f"  [{detail}]" if (not ok or detail) and not ok else ""))
            else:
                print(f"FAIL  {label}" + (f"  detail=[{detail}] expect_fails={expect}"))
                all_ok = False
        # isolation: each bad fixture must fail exactly its expected INV(s)
        actual_fails = sorted(k for k, (ok, _d) in results.items() if not ok)
        if sorted(expect) != actual_fails:
            print(f"FAIL  fixture {fpath.name} isolation: fails={actual_fails} expected={sorted(expect)}")
            all_ok = False
    print()
    print(f"FIXTURES RESULT: {'PASS' if all_ok else 'FAIL'} ({len(files)} fixtures, {total} INV-evals)")
    return 0 if all_ok else 1


if "--fixtures" in sys.argv:
    _idx = sys.argv.index("--fixtures")
    _dir = Path(sys.argv[_idx + 1]) if (_idx + 1 < len(sys.argv) and not sys.argv[_idx + 1].startswith("-")) else (HARNESS / "phase6" / "out" / "6C-3" / "fixtures")
    raise SystemExit(_run_fixtures(_dir))

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
        # Cutover compatibility (6C-3): post-gen_perms a role's edit policy
        # is explicit via zero edit rules under the blanket deny (all roles
        # except compliance's scoped write). Either an edit allow or the
        # cutover form (blanket deny + zero edit allows) passes.
        _edit_allows = sum(1 for r in rules if isinstance(r, dict) and r.get("action") == "edit" and r.get("effect") == "allow")
        _cutover = first.get("action") == "*" and first.get("resource") == "*" and first.get("effect") == "deny" and _edit_allows == 0
        check(("edit", "allow") in actions or role in ("auditor", "release-engineer") or _cutover,
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
# Cutover compatibility (6C-3): after gen_perms, auditor carries no explicit
# edit/write rules at all; the blanket deny (*,*) plus zero edit/write
# allows is the new proof of "denies edit globally". Either form passes.
_blanket_deny = any(
    rule.get("action") == "*" and rule.get("resource") == "*" and rule.get("effect") == "deny"
    for rule in auditor_rules
)
_explicit_edit_deny = any(
    rule.get("action") == "edit" and rule.get("resource") == "*" and rule.get("effect") == "deny"
    for rule in auditor_rules
)
check(
    _explicit_edit_deny or (_blanket_deny and not edit_allows),
    "auditor denies edit globally",
    f"explicit={_explicit_edit_deny} blanket={_blanket_deny} allows={edit_allows}",
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
# Cutover compatibility (6C-3): once builder carries zero shell rules the
# ask list is vacuous (INV-1 forbids shell). Skip rather than fail so the
# checker stays green both pre- and post-6C-1b; INV-1 remains the guard.
_builder_shell_count = sum(1 for r in builder_rules if r.get("action") == "shell")
for action, resource in BUILDER_ASKS:
    if _builder_shell_count == 0:
        check(True, f"builder asks for {resource}", "skipped: builder has no shell rules (INV-1)")
    else:
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
# Cutover compatibility (6C-3): pre-cutover the lifecycle is shell K1
# scripts; post-cutover it is typed tools k1.up/down/exec/status. Either
# form passes; neither fails.
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
_k1_tools = {r.get("resource") for r in auditor_rules if r.get("action") == "tool" and r.get("effect") == "allow"}
_k1_tool_ok = {"k1.up", "k1.down", "k1.exec", "k1.status"} <= _k1_tools
check(bool(not k1_missing or _k1_tool_ok), "auditor can run K1 lifecycle", ", ".join(k1_missing) + f" tools={sorted(_k1_tools & {'k1.up','k1.down','k1.exec','k1.status'})}")

# --- owner-only policy manifest ----------------------------------------
# The manifest is a full inventory (all policies, agents, twins, skills,
# wrappers, tools, fixtures). No factory agent may read, grep or glob it.
# The harness verifier may. Cutover compatibility (6C-3): gen_perms emits
# read/grep/glob manifest denies only (zero edit/write/shell lines, enforced
# by INV-1/INV-2), so the legacy edit/write/shell manifest denies are no
# longer required. INV-4 below is the canonical form.
for path in sorted(AGENTS.glob("*.md")):
    rules = frontmatter(path).get("permissions") or []
    for action in ("read", "grep", "glob"):
        check(
            any(
                rule.get("action") == action
                and rule.get("resource") == "**/policy-manifest.json"
                and rule.get("effect") == "deny"
                for rule in rules
            ),
            f"{path.stem} denies {action} on policy-manifest.json",
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

# --- INV-1..7 (live, from resolved files) --------------------------------
# Build the synthetic state from live files and call the same pure functions
# used by --fixtures. Live reds here are expected pre-cutover (6C-1b still
# pending for builder/auditor/hacker; 6C-4 pending for INV-6).
_installed = {}
for _p in sorted(AGENTS.glob("*.md")):
    _fm = frontmatter(_p)
    _installed[_p.stem] = _fm if "__parse_error__" in _fm else {"permissions": _fm.get("permissions") or [], "model": _fm.get("model")}
# normalize: agents dict expects per-role {"permissions": [...]} or {"__parse_error__":...}
_inv_agents = {}
for _role, _val in _installed.items():
    if "__parse_error__" in _val:
        _inv_agents[_role] = {"__parse_error__": _val["__parse_error__"]}
    else:
        _inv_agents[_role] = {"permissions": _val.get("permissions") or []}

_ok, _det = inv1(_inv_agents)
check(_ok, "INV-1 no shell action in any agent", _det)
_ok, _det = inv2(_inv_agents)
check(_ok, "INV-2 no edit/write on quality/** outside ledger.append", _det)
_ok, _det = inv3(_inv_agents)
check(_ok, "INV-3 only hacker reaches hacker-scratch via scratch.write", _det)
_ok, _det = inv4(_inv_agents)
check(_ok, "INV-4 manifest grep/glob/read denies on all roles", _det)
try:
    _reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
    with open(MATRIX, encoding="utf-8", newline="") as _f:
        _mat = list(csv.DictReader(_f))
    _ok, _det = inv5(_reg, _mat)
except Exception as exc:  # noqa: BLE001
    _ok, _det = False, f"{type(exc).__name__}: {exc}"
check(_ok, "INV-5 per-role tool list equals matrix", _det)
try:
    _man = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    _hashes = {}
    for _c in INV6_REQUIRED_COVERS:
        _fp = HARNESS / _c
        _hashes[_c] = hashlib.sha256(_fp.read_bytes()).hexdigest() if _fp.is_file() else ""
    _ok, _det = inv6(_man, _hashes)
except Exception as exc:  # noqa: BLE001
    _ok, _det = False, f"{type(exc).__name__}: {exc}"
check(_ok, "INV-6 registry/server hash in gate_impl_digest", _det)
try:
    _orch_txt = (AGENTS / "orchestrator.md").read_text(encoding="utf-8")
    _m = re.search(r'"target"\s*:\s*"([^"]+)"', _orch_txt)
    _o_targets = [x for x in (_m.group(1).split("|") if _m else []) if x and x != "none"]
    _disp = json.loads(DISPATCH_PATH.read_text(encoding="utf-8"))
    _d_targets: set = set()
    for _r in (_disp.get("rules") or []):
        for _x in (_r.get("dispatch_first") or []):
            _d_targets.add(_x)
        if _r.get("require_before"):
            _d_targets.add(_r["require_before"])
    _orch_perms = ((_inv_agents.get("orchestrator") or {}).get("permissions") or [])
    _ok, _det = inv7(_orch_perms, _d_targets, _o_targets)
except Exception as exc:  # noqa: BLE001
    _ok, _det = False, f"{type(exc).__name__}: {exc}"
check(_ok, "INV-7 every subagent target orchestrator routes to is allowed", _det)

print()
if failures:
    print(f"RESULT: FAIL ({len(failures)}/{checks})")
    for item in failures:
        print(f"  - {item}")
    sys.exit(1)
print(f"RESULT: PASS ({checks} checks)")
