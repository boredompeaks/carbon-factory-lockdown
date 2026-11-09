"""Typed MCP server skeleton. 6B-0 + P2 durable dispatch.

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
import importlib.util
import json
import os
import subprocess
import sys
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


def _harness_root() -> Path:
    # server.py -> core -> mcp -> tools -> files -> <harness>
    return Path(__file__).resolve().parents[4]


def _gate_control_script() -> Path:
    # files/tools/gate_control.py (server.py parents[2] is tools/).
    return Path(__file__).resolve().parents[2] / "gate_control.py"


def _ledger_tips_from_disk() -> tuple[dict[str, str], str]:
    """Initialise ledger tips from disk; per-type tips plus legacy tip."""
    try:
        mod = importlib.import_module("files.tools.mcp.ledger.store")
        genesis = "0" * 64
        tips: dict[str, str] = {}
        known = getattr(mod, "KNOWN_RECORD_TYPES", ())
        for rt in known:
            try:
                tips[rt] = mod.tip_for(rt)
            except Exception:
                tips[rt] = genesis
        legacy = genesis
        try:
            legacy = mod.global_tip()
        except Exception:
            legacy = genesis
        return tips, legacy
    except Exception:
        genesis = "0" * 64
        return {}, genesis


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
        # P2 durable ledger: tip(s) initialised from disk at construction.
        # _ledger_prev_hash is a compatibility snapshot only; the durable
        # store (ledger.store) reads the live tip fresh per operation and
        # is never advanced by a per-instance counter.
        self._ledger_tips, self._ledger_prev_hash = _ledger_tips_from_disk()
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
        # Non-object args must fail as REJECT_ARG before any args.get
        # access (cache-key computation) would raise AttributeError.
        if not isinstance(args, dict):
            raise Reject("REJECT_ARG", "args must be an object")
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
        # Fail-closed: a ModuleNotFoundError caused by a missing inner
        # dependency, or by a hook module that exists on disk but fails
        # to import, is a REJECT_PRECONDITION — never a silent pass.
        # The optional families_extra hatch may legitimately be absent;
        # only that exact absence is tolerated.
        try:
            extra = importlib.import_module("files.tools.mcp.families_extra")
            checker = getattr(extra, "check_extra", None)
            if callable(checker):
                checker(self, tool, role, args)
        except ModuleNotFoundError as e:
            if e.name != "files.tools.mcp.families_extra":
                raise Reject(
                    "REJECT_PRECONDITION",
                    f"family hook dependency missing: {e}",
                ) from e
            # Exact absence of the optional hatch is tolerated; any file
            # present on disk that fails to import is fail-closed below
            # via importlib.util.find_spec.
            spec = None
            try:
                spec = importlib.util.find_spec("files.tools.mcp.families_extra")
            except Exception:
                spec = None
            if spec is not None:
                raise Reject(
                    "REJECT_PRECONDITION",
                    "family hook families_extra exists but failed to import",
                ) from e
        # Hatch for family packages: try each families' check_extra.
        # Fail-closed: any ModuleNotFoundError for a required family
        # module rejects instead of silently skipping its deny/policy.
        for mod_name in (
            "files.tools.mcp.git.deny",
            "files.tools.mcp.checks.policy",
            "files.tools.mcp.ledger.chain",
            "files.tools.mcp.ledger.store",
            "files.tools.mcp.release.watch",
            "files.tools.mcp.k1.leases",
            "files.tools.mcp.hacker.probe",
        ):
            try:
                mod = importlib.import_module(mod_name)
                checker = getattr(mod, "check_extra", None)
                if callable(checker):
                    checker(self, tool, role, args)
            except ModuleNotFoundError as e:
                raise Reject(
                    "REJECT_PRECONDITION",
                    f"required family module {mod_name!r} unavailable: {e}",
                ) from e

    def _scrubbed_env(self) -> dict[str, str]:
        try:
            from .config import scrub_environment
            from .config import _ENV_BLOCKLIST

            env = dict(scrub_environment())
        except Exception:
            env = {"PYTHONNOUSERSITE": "1"}
        # Host subprocesses (gate_control.py spawns git via PATH; the
        # docker helper runs powershell.exe) need the Windows shell
        # essentials even though the sealed core uses absolute execs.
        # Restore PATH / SystemRoot / COMSPEC etc. from the parent while
        # keeping every blocklisted secret scrubbed.
        wanted = {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
        }
        try:
            block = set(_ENV_BLOCKLIST) if "_ENV_BLOCKLIST" in locals() else set()
        except NameError:
            block = set()
        for key, val in os.environ.items():
            if key in block:
                continue
            if key.upper() in wanted and key not in env:
                env[key] = val
        env.setdefault("PYTHONNOUSERSITE", "1")
        return env

    def _truncate(self, text: str) -> str:
        cap = getattr(self.config, "output_cap_bytes", 65536)
        if len(text.encode("utf-8", errors="replace")) > cap:
            return text[: max(0, cap // 2)] + "\n[OUTPUT_TRUNCATED]"
        return text

    def _execute_gate_control(self, role: str, args: dict) -> dict:
        harness = _harness_root()
        script = _gate_control_script()
        repo = harness
        mode = str(args.get("mode") or "run")
        target = str(args.get("target") or "gate")
        argv: list[str] = [sys.executable, str(script), "--repo", str(repo)]
        if mode == "verify":
            rec = args.get("rec") or args.get("record") or args.get("path")
            if not isinstance(rec, str) or not rec:
                gate_dir = harness / "files" / "quality" / "ledger" / "gate-control"
                records = sorted(
                    (gate_dir.glob("*.json") if gate_dir.is_dir() else []),
                    key=lambda p: p.name,
                )
                records = [p for p in records if p.name != "verify.json"]
                if not records:
                    return {
                        "tool": "gate.control",
                        "target": target,
                        "mode": mode,
                        "executed": True,
                        "exit_code": 2,
                        "result": "ERROR",
                        "detail": "no gate-control record found to verify",
                        "evidence": {
                            "argv": list(argv),
                            "exit_code": 2,
                            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                        },
                    }
                rec = str(records[-1])
            argv += ["--verify", str(rec)]
        else:
            argv += ["--write"]
        if not script.is_file():
            return {
                "tool": "gate.control",
                "target": target,
                "mode": mode,
                "executed": True,
                "exit_code": 2,
                "result": "ERROR",
                "detail": f"gate_control.py missing at {script}",
                "evidence": {
                    "argv": list(argv),
                    "exit_code": 2,
                    "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                },
            }
        try:
            proc = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=300,
                cwd=str(harness),
                env=self._scrubbed_env(),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "tool": "gate.control",
                "target": target,
                "mode": mode,
                "executed": True,
                "exit_code": 2,
                "result": "ERROR",
                "detail": "gate_control.py timed out after 300s",
                "evidence": {
                    "argv": list(argv),
                    "exit_code": 2,
                    "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                },
            }
        except OSError as exc:
            return {
                "tool": "gate.control",
                "target": target,
                "mode": mode,
                "executed": True,
                "exit_code": 2,
                "result": "ERROR",
                "detail": f"failed to start gate_control.py: {exc}",
                "evidence": {
                    "argv": list(argv),
                    "exit_code": 2,
                    "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                },
            }
        parsed: dict = {}
        try:
            parsed = json.loads(proc.stdout or "")
        except ValueError:
            parsed = {}
        result_name = parsed.get("result") if isinstance(parsed, dict) else None
        out: dict = {
            "tool": "gate.control",
            "target": target,
            "mode": mode,
            "executed": True,
            "exit_code": proc.returncode,
            "stdout": self._truncate(proc.stdout or ""),
            "stderr": self._truncate(proc.stderr or ""),
            "evidence": {
                "argv": list(argv),
                "exit_code": proc.returncode,
                "stdout_sha256": hashlib.sha256((proc.stdout or "").encode("utf-8")).hexdigest(),
                "stderr_sha256": hashlib.sha256((proc.stderr or "").encode("utf-8")).hexdigest(),
            },
        }
        if isinstance(parsed, dict) and parsed:
            out["gate_record"] = parsed
            if result_name is not None:
                out["result"] = result_name
            if "record_hash" in parsed:
                out["record_hash"] = parsed["record_hash"]
            if "record" in parsed:
                out["record"] = parsed["record"]
        else:
            out["result"] = "PASS" if proc.returncode == 0 else "FAIL" if proc.returncode == 1 else "ERROR"
        return out

    def _execute(self, tool: str, role: str, args: dict) -> dict:
        """Host execution: gate subprocess + handler delegation.

        The docker engine tool is owned solely by k1/handlers (real argv
        + evidence shape); the handler loop below reaches it.
        """
        # Real subprocess handlers (argv-only, 300s). A FAIL exit code is a
        # real result, not a dispatch error: the dict always carries
        # executed=True and the child's exit_code.
        if tool == "gate.control":
            return self._execute_gate_control(role, args)
        # Delegate to family handlers when present. Fail-closed: a
        # required handler module that cannot be imported rejects, and
        # a tool with no handler rejects instead of returning a generic
        # stub-ok.
        for mod_name in (
            "files.tools.mcp.git.handlers",
            "files.tools.mcp.checks.handlers",
            "files.tools.mcp.ledger.store",
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
                        if not isinstance(out, dict):
                            out = {"tool": tool, "value": out}
                        if "executed" not in out:
                            out["executed"] = True
                        return out
            except ModuleNotFoundError as e:
                raise Reject(
                    "REJECT_PRECONDITION",
                    f"required handler module {mod_name!r} unavailable: {e}",
                ) from e
        raise Reject(
            "REJECT_PRECONDITION",
            f"no handler for tool {tool!r}; refusing to return generic stub",
        )

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
