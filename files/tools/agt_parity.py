#!/usr/bin/env python3
"""AGT_PARITY -- prove the AGT policy and install pin agree with the contract.

The check compares the resolved AGT policy path, the OpenCode V2 adapter entry,
the workspace npm spec, the lockfile resolution, and the policy body against the
mandated enforce contract. A deliberate deviation is a finding of class
AGT_PARITY_MISMATCH.

`--root <dir>` names the harness root (the directory holding .agt/ and
.opencode/). `--control` runs the two fixture roots and prints the control
envelope used by gate_control.py.

Exit codes: 0 accept, 1 reject, 2 tool error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

TOOL = "agt_parity"
VERSION = "1.1.0"
HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parent.parent
FIXTURES = HERE / "fixtures" / "agt_parity"
POLICY_ENV = "AGT_OPENCODE_POLICY_PATH"
PACKAGE = "@microsoft/agent-governance-opencode"
PIN = "5.0.0"
ADAPTER_FILE = Path(".opencode") / "plugins" / "agt.js"
# The AGT adapter is mandatory; these additional plugins are explicitly
# authorized. Anything else is rejected so the plugin array fails closed.
PLUGINS_DIR = Path(".opencode") / "plugins"
ALLOWED_PLUGINS = ("agt.js", "authz.js")
REQUIRED_ALLOWED_TOOLS = [
    "read",
    "glob",
    "grep",
    "list",
    "edit",
    "write",
    "patch",
    "bash",
    "webfetch",
    "task",
    "shell",
    "execute",
    "agt_policy_status",
    "agt_policy_check_text",
    "subagent",
    "question",
    "skill",
    "websearch",
]
MANDATED_POLICY = {
    "schemaVersion": 1,
    "version": 1,
    "mode": "enforce",
    "denyOnPolicyError": True,
    "toolPolicies": {
        "allowedTools": REQUIRED_ALLOWED_TOOLS,
        "blockedTools": [],
        "defaultEffect": "deny",
        "reviewTools": [],
    },
    "directResourcePolicies": {
        "pathRules": [
            {
                "id": "no-opencode-tree",
                "effect": "deny",
                "operation": "any",
                "pathPatterns": [
                    {"source": r"(^|/)\.opencode(/|$)", "flags": "i"},
                    {"source": r"(^|/)\.config/opencode(/|$)", "flags": "i"},
                    {"source": r"(^|/)\.local/share/opencode(/|$)", "flags": "i"},
                ],
                "reason": "R05-10: the OpenCode control tree is not accessible to agents.",
            },
            {
                "id": "no-fuzz-seed-evidence",
                "effect": "deny",
                "operation": "read",
                "pathPatterns": [
                    {"source": r"(^|/)fuzz-evidence(/|$)", "flags": "i"},
                    {"source": r"(^|/)schema-fuzz-evidence(/|$)", "flags": "i"},
                    {"source": r"(^|/)[^/]*fuzz[^/]*seed[^/]*\.json$", "flags": "i"},
                ],
                "reason": "Fuzz seed evidence is not readable by agents; the per-cycle seed lives in evidence artifacts only.",
            },
            {
                "id": "no-ledger-tree",
                "effect": "deny",
                "operation": "any",
                "pathPatterns": [
                    {"source": r"(^|/)quality/ledger(/|$)", "flags": "i"},
                    {"source": r"(^|/)quality/ledger/findings(/|$)", "flags": "i"},
                    {"source": r"(^|/)quality/ledger/attack-logs(/|$)", "flags": "i"},
                    {"source": r"(^|/)quality/ledger/dispatch(/|$)", "flags": "i"},
                    {"source": r"(^|/)quality/ledger/gate-control(/|$)", "flags": "i"},
                    {"source": r"(^|/)quality/ledger/release(/|$)", "flags": "i"},
                    {"source": r"(^|/)quality/ledger/acceptance(/|$)", "flags": "i"},
                    {"source": r"(^|/)quality/ledger/verdicts(/|$)", "flags": "i"},
                    {"source": r"(^|/)quality/ledger/audit(/|$)", "flags": "i"},
                ],
                "reason": "quality/ledger is not directly readable by agents; records are written only via ledger.append.",
            },
            {
                "id": "no-agt-tree",
                "effect": "deny",
                "operation": "any",
                "pathPatterns": [
                    {"source": r"(^|/)\.agt(/|$)", "flags": "i"},
                ],
                "reason": "The AGT policy tree reveals the allowed-tool list and must not be readable by agents.",
            },
            {
                "id": "no-git-tree",
                "effect": "deny",
                "operation": "any",
                "pathPatterns": [
                    {"source": r"(^|/)\.git(/|$)", "flags": "i"},
                ],
                "reason": "Git metadata is not directly readable by agents; repo reads go through typed MCP tools.",
            },
        ]
    },
}


def finding(locus: str, detail: str) -> dict:
    return {"class": "AGT_PARITY_MISMATCH", "locus": locus, "detail": detail}


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def normalized(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def plugin_target(entry: object) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict) and isinstance(entry.get("package"), str):
        return entry["package"]
    return None


def check(root: Path, env: dict[str, str] | None = None) -> list[dict]:
    env = os.environ if env is None else env
    findings: list[dict] = []

    expected_policy = (root / ".agt" / "policy.json").resolve()
    configured = env.get(POLICY_ENV)
    resolved = Path(configured).expanduser().resolve() if configured else expected_policy
    if normalized(resolved) != normalized(expected_policy):
        findings.append(
            finding(
                "policy-path",
                f"resolved policy path {str(resolved)!r} != {str(expected_policy)!r}",
            )
        )

    config_path = root / "opencode.json"
    try:
        config = load_json(config_path)
    except (OSError, json.JSONDecodeError) as exc:
        findings.append(finding("opencode.json", f"cannot load: {exc}"))
        config = {}
    if not isinstance(config, dict):
        findings.append(finding("opencode.json", "root value is not an object"))
        config = {}
    plugins = config.get("plugins")
    if plugins is None:
        plugins = config.get("plugin")
    if not isinstance(plugins, list):
        findings.append(
            finding("opencode.json:plugins", f"plugins is not an array: {plugins!r}")
        )
    else:
        allowed = {normalized(root / PLUGINS_DIR / name) for name in ALLOWED_PLUGINS}
        present: set[str] = set()
        for index, entry in enumerate(plugins):
            target = plugin_target(entry)
            if target is None:
                findings.append(
                    finding(
                        "opencode.json:plugins",
                        f"entry {index} is not a string or {{package}} object: {entry!r}",
                    )
                )
                continue
            target_path = Path(target)
            if not target_path.is_absolute():
                target_path = root / target_path
            actual = normalized(target_path)
            if actual not in allowed:
                findings.append(
                    finding(
                        "opencode.json:plugins",
                        f"entry {index} {target!r} resolves to "
                        f"{str(target_path.resolve())!r}, not an authorized plugin "
                        f"{sorted(allowed)!r}",
                    )
                )
                continue
            present.add(actual)
        adapter = normalized(root / ADAPTER_FILE)
        if adapter not in present:
            findings.append(
                finding(
                    "opencode.json:plugins",
                    f"mandatory AGT adapter {str((root / ADAPTER_FILE).resolve())!r} "
                    f"is not listed: {plugins!r}",
                )
            )

    package_path = root / ".opencode" / "package.json"
    try:
        package = load_json(package_path)
    except (OSError, json.JSONDecodeError) as exc:
        findings.append(finding(".opencode/package.json", f"cannot load: {exc}"))
        package = {}
    if not isinstance(package, dict):
        findings.append(
            finding(".opencode/package.json", "root value is not an object")
        )
        package = {}
    dependencies = package.get("dependencies")
    spec = dependencies.get(PACKAGE) if isinstance(dependencies, dict) else None
    if spec != PIN:
        findings.append(
            finding(
                ".opencode/package.json:dependencies",
                f"{PACKAGE} spec {spec!r} != {PIN!r}",
            )
        )

    lock_candidates = (
        root / ".opencode" / "package-lock.json",
        root / ".opencode" / "node_modules" / ".package-lock.json",
    )
    lock_path = next((path for path in lock_candidates if path.is_file()), None)
    if lock_path is None:
        findings.append(
            finding(
                ".opencode/package-lock.json",
                "no package-lock.json or node_modules/.package-lock.json found",
            )
        )
    else:
        locus = lock_path.relative_to(root).as_posix()
        try:
            lock = load_json(lock_path)
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(finding(locus, f"cannot load: {exc}"))
            lock = {}
        packages = lock.get("packages") if isinstance(lock, dict) else None
        entry = (
            packages.get(f"node_modules/{PACKAGE}")
            if isinstance(packages, dict)
            else None
        )
        version = entry.get("version") if isinstance(entry, dict) else None
        if version != PIN:
            findings.append(
                finding(
                    f"{locus}:node_modules/{PACKAGE}",
                    f"resolved version {version!r} != {PIN!r}",
                )
            )

    policy_path = root / ".agt" / "policy.json"
    try:
        policy = load_json(policy_path)
    except (OSError, json.JSONDecodeError) as exc:
        findings.append(finding(".agt/policy.json", f"cannot load: {exc}"))
        policy = None
    if not isinstance(policy, dict):
        if policy is not None:
            findings.append(finding(".agt/policy.json", "root value is not an object"))
    else:
        for key in sorted(set(MANDATED_POLICY) | set(policy)):
            expected = MANDATED_POLICY.get(key, "<absent>")
            actual = policy.get(key, "<absent>")
            if actual == expected:
                continue
            if (
                key == "toolPolicies"
                and isinstance(expected, dict)
                and isinstance(actual, dict)
            ):
                for subkey in sorted(set(expected) | set(actual)):
                    sub_expected = expected.get(subkey, "<absent>")
                    sub_actual = actual.get(subkey, "<absent>")
                    if sub_actual != sub_expected:
                        findings.append(
                            finding(
                                f".agt/policy.json:{subkey}",
                                f"expected {sub_expected!r}, found {sub_actual!r}",
                            )
                        )
                continue
            findings.append(
                finding(
                    f".agt/policy.json:{key}",
                    f"expected {expected!r}, found {actual!r}",
                )
            )
    return findings


def outcome(findings: list[dict]) -> str:
    return "FAIL" if findings else "PASS"


def control() -> dict:
    cases = []
    for name in ("good_root", "bad_root"):
        root = FIXTURES / name
        findings = check(root, env={})
        expected = "PASS" if name == "good_root" else "FAIL"
        cases.append(
            {
                "name": f"agt_parity/{name}",
                "expected": expected,
                "actual": {
                    "outcome": outcome(findings),
                    "findings": len(findings),
                    "details": findings,
                },
                "passed": outcome(findings) == expected,
            }
        )
    return {"ran": True, "passed": all(case["passed"] for case in cases), "cases": cases}


def envelope(findings: list[dict], control_doc: dict | None, code: int) -> dict:
    return {
        "schema": "factory-tool/1",
        "tool": TOOL,
        "version": VERSION,
        "interpreter": sys.executable,
        "result_type": "RESULT" if code == 0 else ("CONTROL_FAIL" if control_doc else "REJECT"),
        "exit_code": code,
        "findings": findings,
        "control": control_doc,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="harness root")
    parser.add_argument("--control", action="store_true", help="run fixture roots")
    args = parser.parse_args(argv)

    if args.control:
        try:
            control_doc = control()
        except Exception as exc:  # noqa: BLE001 - CLI boundary
            print(
                json.dumps(
                    {
                        "schema": "factory-tool/1",
                        "tool": TOOL,
                        "version": VERSION,
                        "result_type": "ERROR",
                        "error": f"{type(exc).__name__}: {exc}",
                        "exit_code": 2,
                    },
                    sort_keys=True,
                )
            )
            return 2
        code = 0 if control_doc["passed"] else 1
        print(json.dumps(envelope([], control_doc, code), sort_keys=True))
        return code

    try:
        findings = check(Path(args.root).resolve())
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(
            json.dumps(
                {
                    "schema": "factory-tool/1",
                    "tool": TOOL,
                    "version": VERSION,
                    "result_type": "ERROR",
                    "error": f"{type(exc).__name__}: {exc}",
                    "exit_code": 2,
                },
                sort_keys=True,
            )
        )
        return 2
    code = 1 if findings else 0
    print(json.dumps(envelope(findings, None, code), sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
