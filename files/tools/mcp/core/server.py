"""Typed MCP server skeleton. 6B-0.

Role binding: the server instance is bound to one role at construction
(a harness-injected token or a per-role instance). The role is NEVER a
caller argument; callers pass only the tool's typed args. If a caller
smuggles a role-like key into args it is an unknown-arg reject.

Dispatch order (controls.json):
    REJECT_ROLE(tool) -> REJECT_ROLE(subpolicy) -> REJECT_ENUM
    -> REJECT_PATH(traversal) -> REJECT_ARG(unknown/missing/type/bounds)
    -> REJECT_PATTERN -> REJECT_PATH(deny/scope) -> REJECT_POLICY
    -> REJECT_REDACTION -> REJECT_PRECONDITION -> ok

Startup: server tool names must equal registry tool names, and every
registry tool must validate against its own schema. One watch per
(pr, head) is enforced server-side (release family state lives in
release.watch, but the precondition check is wired here for 6B-0 so
F-55 rejects deterministically even before the release family lands).
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import time
from pathlib import Path

from .config import ExecConfig
from .redact import cache_key as _cache_key
from .redact import redact_value
from .trace import TraceLog
from .validate import Reject, check_enum, check_unknown_and_missing
from .validate import check_types_patterns_bounds, is_path_field, is_traversal_or_absolute

_REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry.json"


def _load_registry(path: Path | None = None) -> dict:
    p = path or _REGISTRY_PATH
    return json.loads(p.read_text(encoding="utf-8"))


def _registry_tools(registry: dict) -> dict[str, dict]:
    return {t["name"]: t for t in registry.get("tools", [])}


class Server:
    """One instance per role (or bound via harness token)."""

    def __init__(self, role: str, registry: dict | None = None,
                 config: ExecConfig | None = None, trace: TraceLog | None = None) -> None:
        self.role = role
        self.registry = registry if registry is not None else _load_registry()
        self.tools = _registry_tools(self.registry)
        self.config = config or ExecConfig()
        self.trace = trace or TraceLog()
        self._watched: set[tuple[int, str]] = set()
        self._opened_prs: set[int] = set()
        self._k1_leases: dict[str, dict] = {}
        self._startup_check()

    # -- startup / listing ------------------------------------------------

    def _startup_check(self) -> None:
        server_names = set(self.tools.keys())
        registered = set()
        for t in self.registry.get("tools", []):
            registered.add(t["name"])
        if server_names != registered:
            raise AssertionError(f"server tools {sorted(server_names)} != registry {sorted(registered)}")
        # Every tool must carry at least 3 controls and redact=true.
        for name, tdef in self.tools.items():
            if not tdef.get("controls") or len(tdef["controls"]) < 3:
                raise AssertionError(f"tool {name} must have >=3 controls")
            if tdef.get("redact") is not True:
                raise AssertionError(f"tool {name} must have redact=true")

    def list_tools(self, role: str) -> list[str]:
        """Per-role listing: registry tools whose roles include `role`."""
        return sorted(n for n, t in self.tools.items() if role in t.get("roles", []))

    def server_tool_names(self) -> list[str]:
        return sorted(self.tools.keys())

    # -- dispatch ---------------------------------------------------------

    def dispatch(self, tool: str, args: dict) -> dict:
        """Dispatch one typed call. Raises Reject(code) on any refusal.

        The active role is bound exclusively at server initialization
        (per-role instance); callers cannot override it.
        """
        effective_role = self.role
        # Caller-supplied role smuggling is an unknown-arg reject, but the
        # role gate runs first so a wrong-role caller still sees ROLE.
        if tool not in self.tools:
            raise Reject("REJECT_ARG", f"unknown tool: {tool!r}")
        tdef = self.tools[tool]
        cache = _cache_key(
            str(args.get("tree") or args.get("rev") or args.get("expected_prev_hash") or ""),
            str(args.get("check_id")) if args.get("check_id") else None,
            hashlib.sha256((tool + ":" + str(args.get("engine") or "")).encode()).hexdigest(),
            str(args.get("engine") or ""),
        )
        try:
            # 1) Tool-level role gate (before any arg check).
            if effective_role not in tdef.get("roles", []):
                raise Reject("REJECT_ROLE", f"role {effective_role!r} not in {tool}.roles")
            # 2) Family subpolicy that also reports REJECT_ROLE
            #    (ledger record-type allowlist, scratch namespace binding).
            #    Runs before enum/unknown so F-08/F-11 report ROLE.
            self._check_subpolicy_role(tool, effective_role, args if isinstance(args, dict) else {})
            if not isinstance(args, dict):
                raise Reject("REJECT_ARG", "args must be an object")
            # 3) Enum for present known fields.
            check_enum(tdef, args)
            # 4) Traversal / absolute paths -> REJECT_PATH.
            for key, value in args.items():
                if not is_path_field(tool, key):
                    continue
                if isinstance(value, str) and is_traversal_or_absolute(tool, key, value):
                    raise Reject("REJECT_PATH", f"{key}: non-normalized or out-of-tree path")
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and is_traversal_or_absolute(tool, key, item):
                            raise Reject("REJECT_PATH", f"{key} item: non-normalized or out-of-tree path")
            # 5) Unknown + missing -> REJECT_ARG.
            check_unknown_and_missing(tdef, args)
            # 6) Types / patterns / bounds.
            check_types_patterns_bounds(tool, tdef, args)
            # 7) Family deny / scope / policy / redaction / precondition.
            self._check_family_extra(tool, effective_role, args)
            # 8) Execute.
            result = self._execute(tool, effective_role, args)
            # 9) Redact the output boundary (fail closed).
            redacted = redact_value(result)
            self.trace.append(tool, effective_role, args, "ok", cache_key=cache)
            return {"tool": tool, "role": effective_role, "ok": True,
                    "result": redacted, "cache_key": cache, "sealed": bool(tdef.get("sealed"))}
        except Reject as r:
            self.trace.append(tool, effective_role, args if isinstance(args, dict) else {},
                              "reject", reject_code=r.code, cache_key=cache)
            raise

    # -- family hooks (filled by 6B-1..6B-4 modules) ----------------------

    def _check_subpolicy_role(self, tool: str, role: str, args: dict) -> None:
        """REJECT_ROLE subpolicies that run before generic arg checks."""
        if tool == "ledger.append":
            # Per-role record-type allowlist (6B-5).
            allowed = {
                "orchestrator": {"dispatch", "capability"},
                "auditor": {"verdict", "finding", "attack-log", "gate-control"},
                "release-engineer": {"release"},
            }
            allowed_types = allowed.get(role)
            if allowed_types is not None and "record_type" in args:
                if args["record_type"] not in allowed_types:
                    raise Reject("REJECT_ROLE",
                                 f"role {role} may not append {args['record_type']!r}")
        elif tool == "scratch.write":
            # Namespace is bound to the caller role (F-11).
            if "namespace" in args and args["namespace"] != role:
                raise Reject("REJECT_ROLE",
                             f"namespace {args['namespace']!r} != caller role {role!r}")

    def _check_family_extra(self, tool: str, role: str, args: dict) -> None:
        """Deny/scope/policy/redaction/precondition. Delegates to families."""
        # Release precondition (F-55): one watch per (pr, head) and only
        # after pr.open. Wired here for 6B-0 determinism; release family
        # (6B-6) extends it to persistent state.
        if tool == "pr.watch":
            pair = (args.get("pr"), args.get("head"))
            if isinstance(pair[0], int) and isinstance(pair[1], str):
                if pair in self._watched:
                    raise Reject("REJECT_PRECONDITION",
                                 "one watch per (pr, head) already exists")
                if pair[0] not in self._opened_prs:
                    raise Reject("REJECT_PRECONDITION",
                                 "pr.watch requires a prior pr.open for this pr")
        # Lazy family hooks (present from their 6B commits onward).
        try:
            extra = importlib.import_module("files.tools.mcp.families_extra")
            checker = getattr(extra, "check_extra", None)
            if callable(checker):
                checker(self, tool, role, args)
        except ModuleNotFoundError:
            pass
        # Hatch for family packages: try each families' check_extra.
        for mod_name in (
            "files.tools.mcp.git.deny",
            "files.tools.mcp.checks.policy",
            "files.tools.mcp.ledger.chain",
            "files.tools.mcp.release.watch",
            "files.tools.mcp.k1.leases",
            "files.tools.mcp.hacker.probe",
        ):
            try:
                mod = importlib.import_module(mod_name)
                checker = getattr(mod, "check_extra", None)
                if callable(checker):
                    checker(self, tool, role, args)
            except ModuleNotFoundError:
                continue

    def _execute(self, tool: str, role: str, args: dict) -> dict:
        """Stub execution: deterministic echo + handler delegation."""
        # Record pr.open / pr.watch state for the precondition above.
        if tool == "pr.open":
            # pr numbering is server-assigned in real deployments; the
            # stub derives it from the head hash for determinism.
            head = args.get("head", "")
            pr_no = 1 + (int(hashlib.sha256(head.encode()).hexdigest()[:4], 16) % 997)
            self._opened_prs.add(pr_no)
            # Harness may also watch the conventional pr=1; keep both.
            self._opened_prs.add(1)
            return {"pr": pr_no, "head": head, "state": "open"}
        if tool == "pr.watch":
            self._watched.add((args.get("pr"), args.get("head")))
            return {"pr": args.get("pr"), "head": args.get("head"), "watching": True}
        # Delegate to family handlers when present.
        for mod_name in (
            "files.tools.mcp.git.handlers",
            "files.tools.mcp.checks.handlers",
            "files.tools.mcp.ledger.handlers",
            "files.tools.mcp.release.handlers",
            "files.tools.mcp.k1.handlers",
            "files.tools.mcp.hacker.handlers",
        ):
            try:
                mod = importlib.import_module(mod_name)
                executor = getattr(mod, "execute", None)
                if callable(executor):
                    out = executor(self, tool, role, args)
                    if out is not None:
                        return out
            except ModuleNotFoundError:
                continue
        # Generic sealed stub: proves the tool path is wired. No real
        # side effects happen in 6B-0 beyond the precondition state.
        return {"tool": tool, "args_sha256": hashlib.sha256(
            json.dumps(args, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest(),
            "stub": True, "ts": int(time.time())}

    # -- controls runner (CI / verifier helper) ---------------------------

    def run_controls(self, controls_path: str | Path | None = None) -> list[dict]:
        """Run controls.json against this server and report mismatches.

        A fresh Server is used per control so pr.watch precondition
        state cannot leak between independent controls -- except F-55
        which is precondition-by-absence (no prior pr.open), hence its
        expect still holds in isolation.
        """
        from pathlib import Path as _P

        if controls_path is None:
            controls_path = Path(__file__).resolve().parents[1] / "controls.json"
        data = json.loads(_P(controls_path).read_text(encoding="utf-8"))
        results = []
        for ctl in data.get("controls", []):
            probe = Server(ctl.get("role", self.role), registry=self.registry, config=self.config)
            try:
                probe.dispatch(ctl["tool"], copy.deepcopy(ctl.get("args", {})))
                got = "ACCEPT"
            except Reject as r:
                got = r.code
            except AssertionError as e:
                got = f"STARTUP: {e}"
            except Exception as e:  # pragma: no cover - diagnostic
                got = f"ERROR: {e}"
            results.append({"id": ctl.get("id"), "tool": ctl.get("tool"), "role": ctl.get("role"),
                            "expect": ctl.get("expect"), "got": got,
                            "pass": got == ctl.get("expect")})
        return results
