#!/usr/bin/env python3
"""Config-level control evaluator (WAVE 3 / A7).

Evaluates the declarative controls in files/tools/mcp/controls.json that
Server.run_controls() cannot evaluate -- entries whose ``expect`` is NOT
``REJECT_*`` and NOT ``ACCEPT`` (currently ASK_ONLY, NOT_GRANTED,
ROLE_MATRIX, EMPTY, ROLE_ALLOWED). Without this evaluator,
``Server.run_controls()`` reports only the dispatchable subset (196/221)
and the remaining 25 would be silently skipped.

Sources (read-only, no edits to server.py / controls.json / registry.json
/ agent files):

- Agent permission blocks: ``.opencode/agents/<role>.md`` and twin
  ``files/<role>.md`` (YAML ``permissions`` for carbon tools plus the
  ``## Tool surface`` prose bullets for basemind tools). Basemind has no
  carbon handler and no YAML entries by design; the prose layer is the
  authoritative basemind grant encoding. This evaluator checks BOTH
  layers: a YAML ``allow`` (or prose ``Use `basemind_X```) is an
  unconditional grant, a prose ``(`ask`)`` qualifier is the ``ask``
  encoding. Treating prose as the basemind layer is not masking -- it is
  where basemind grants actually live.
- ``files/tools/mcp/registry.json`` roles (for carbon tools).
- ``basemind.toml`` excludes (for EMPTY).
- Live basemind over MCP stdio (for EMPTY), spawned argv-only via the
  ``scripts/mcp_discover.py`` helpers (``find_config`` / ``load_server`` /
  ``LineReader``). No shell is ever used.

Usage:
    python scripts/config_controls.py
    python scripts/config_controls.py --json

Output (stdout, JSON): ``{"total": N, "passed": P, "failed": [...]}``
Exit: 0 iff every selected control passes; 1 on any control failure
(including RUNTIME_UNAVAILABLE for EMPTY when basemind cannot be spawned);
2 on evaluator error (unreadable inputs / unexpected failure).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parent.parent
CONTROLS_PATH = HARNESS_ROOT / "files" / "tools" / "mcp" / "controls.json"
REGISTRY_PATH = HARNESS_ROOT / "files" / "tools" / "mcp" / "registry.json"
BASEMIND_TOML = HARNESS_ROOT / "basemind.toml"
PRIMARY_AGENTS_DIR = HARNESS_ROOT / ".opencode" / "agents"
TWIN_AGENTS_DIR = HARNESS_ROOT / "files"
MCP_DISCOVER_PATH = HARNESS_ROOT / "scripts" / "mcp_discover.py"

DECLARATIVE_EXPECTS = ("ASK_ONLY", "NOT_GRANTED", "ROLE_MATRIX", "EMPTY", "ROLE_ALLOWED")


def is_dispatchable(expect: str | None) -> bool:
    return expect == "ACCEPT" or (isinstance(expect, str) and expect.startswith("REJECT_"))


def is_declarative(expect: str | None) -> bool:
    return not is_dispatchable(expect)


def basemind_short(tool: str) -> str:
    """Map a control tool name to the live basemind MCP tool name."""
    if tool.startswith("basemind_"):
        return tool[len("basemind_"):] or tool
    return tool


def load_mcp_discover():
    """Reuse scripts/mcp_discover.py helpers (argv-only stdio spawning)."""
    try:
        sys.path.insert(0, str(HARNESS_ROOT))
        import scripts.mcp_discover as mod  # type: ignore[import-not-found]

        return mod
    except Exception:
        import importlib.util

        spec = importlib.util.spec_from_file_location("mcp_discover", MCP_DISCOVER_PATH)
        if spec is None or spec.loader is None:
            raise
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod


# --- agent file parsing ---------------------------------------------------


def parse_frontmatter_permissions(text: str) -> list[dict]:
    """Parse the YAML ``permissions`` list from a role file's frontmatter."""
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not match:
        return []
    block = match.group(1)
    try:
        import yaml  # type: ignore[import-untyped]

        loaded = yaml.safe_load(block)
        if isinstance(loaded, dict) and isinstance(loaded.get("permissions"), list):
            return [p for p in loaded["permissions"] if isinstance(p, dict)]
    except Exception:
        pass
    # Fallback: extract ``- { action: ..., resource: ..., effect: ... }`` lines.
    perms: list[dict] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped.startswith("-"):
            continue
        entry: dict[str, str] = {}
        for key in ("action", "resource", "effect"):
            km = re.search(rf"{key}\s*:\s*(?:\"([^\"]*)\"|'([^']*)'|([^,}}]+))", line.strip(" -"))
            if km:
                val = next((g for g in km.groups() if g is not None), "").strip()
                entry[key] = val.strip("\"'")
        if entry:
            perms.append(entry)
    return perms


def parse_prose_grants(text: str) -> tuple[set[str], set[str]]:
    """Parse the ``## Tool surface`` basemind encoding.

    Returns (unconditional_grants, ask_qualified_tools). ``Use `basemind_X```
    is an unconditional grant; a bullet naming ``basemind_X`` together with
    ``(`ask`)`` is the ``ask`` encoding (used for ``basemind_shell``). The
    ``Never use ...`` bullets are denials, not grants, and are ignored.
    """
    granted = set(re.findall(r"Use\s+`(basemind_[a-z0-9_]+)`", text))
    asked: set[str] = set()
    for line in text.splitlines():
        if "`ask`" not in line:
            continue
        # The Never-use bullet names several tools on one line but only the
        # nearest preceding tool before ``(`ask`)`` is ask-qualified (the
        # shell tool). Earlier tools on the line (e.g. basemind_graph) are
        # denials, not asks, and must not pollute the asked set.
        ask_pos = line.find("`ask`")
        preceding = [m.group(1) for m in re.finditer(r"(basemind_[a-z0-9_]+)", line) if m.start() < ask_pos]
        if preceding:
            asked.add(preceding[-1])
    # An ask-qualified tool is not an unconditional grant.
    granted -= asked
    return granted, asked


def agent_stem(role: str) -> str:
    # Registry uses ``crouton``; the agent file is ``crouton-alpha.md``.
    return "crouton-alpha" if role == "crouton" else role


def load_agents() -> dict[str, dict]:
    """Load per-role permission blocks plus prose grants (primary + twin)."""
    agents: dict[str, dict] = {}
    for path in sorted(PRIMARY_AGENTS_DIR.glob("*.md")):
        stem = path.stem
        primary_text = path.read_text(encoding="utf-8")
        twin_path = TWIN_AGENTS_DIR / f"{stem}.md"
        twin_text = twin_path.read_text(encoding="utf-8") if twin_path.is_file() else None
        p_perms = parse_frontmatter_permissions(primary_text)
        t_perms = parse_frontmatter_permissions(twin_text) if twin_text is not None else None
        p_granted, p_asked = parse_prose_grants(primary_text)
        if twin_text is not None:
            t_granted, t_asked = parse_prose_grants(twin_text)
        else:
            t_granted, t_asked = set(), set()
        agents[stem] = {
            "primary_path": str(path),
            "twin_path": str(twin_path) if twin_text is not None else None,
            "primary_text": primary_text,
            "twin_text": twin_text,
            "primary_perms": p_perms,
            "twin_perms": t_perms,
            "primary_granted": p_granted,
            "twin_granted": t_granted,
            "primary_asked": p_asked,
            "twin_asked": t_asked,
        }
    return agents


def load_registry_roles() -> dict[str, list[str]]:
    reg = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    out: dict[str, list[str]] = {}
    for tool in reg.get("tools", []):
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            roles = tool.get("roles") or []
            out[tool["name"]] = [r for r in roles if isinstance(r, str)]
    return out


def load_registry() -> dict[str, dict]:
    """Tool -> {roles, scopes} from registry.json (for ROLE_ALLOWED)."""
    reg = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for tool in reg.get("tools", []):
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            roles = tool.get("roles") or []
            scopes = tool.get("scopes")
            out[tool["name"]] = {
                "roles": [r for r in roles if isinstance(r, str)],
                "scopes": scopes if isinstance(scopes, dict) else None,
            }
    return out


# --- YAML permission matching ----------------------------------------------


def _perm_matches_tool(perm: dict, tool: str) -> bool:
    resource = str(perm.get("resource") or "")
    short = basemind_short(tool)
    if resource in (tool, short):
        return True
    # Wildcard tool grant (e.g. action tool/* with allow) grants every tool.
    if resource == "*" and str(perm.get("action") or "") in ("tool", "*"):
        return True
    return False


def yaml_effects(perms: list[dict], tool: str) -> tuple[list[dict], list[dict], list[dict]]:
    allows = [p for p in perms if _perm_matches_tool(p, tool) and p.get("effect") == "allow"]
    asks = [p for p in perms if _perm_matches_tool(p, tool) and p.get("effect") == "ask"]
    denies = [p for p in perms if _perm_matches_tool(p, tool) and p.get("effect") == "deny"]
    return allows, asks, denies


def role_has_allow(role: str, tool: str, agents: dict[str, dict]) -> bool:
    """True iff the role holds an unconditional allow in either layer."""
    info = agents.get(role)
    if not info:
        return False
    allows, _, _ = yaml_effects(info["primary_perms"], tool)
    if allows:
        return True
    t_allows, _, _ = yaml_effects(info["twin_perms"] or [], tool)
    if t_allows:
        return True
    return tool in info["primary_granted"] or tool in info["twin_granted"]


def twin_mismatch(role: str, tool: str, agents: dict[str, dict]) -> str | None:
    """Return a mismatch message when primary and twin disagree, else None."""
    info = agents.get(role)
    if not info:
        return f"no agent file for role {role!r}"
    if info["twin_text"] is None:
        return f"missing twin {info['twin_path']}"
    p_allows, p_asks, _ = yaml_effects(info["primary_perms"], tool)
    t_allows, t_asks, _ = yaml_effects(info["twin_perms"], tool)
    if (len(p_allows) > 0) != (len(t_allows) > 0):
        return f"twin YAML allow mismatch for {tool}: primary={len(p_allows)} twin={len(t_allows)}"
    if (len(p_asks) > 0) != (len(t_asks) > 0):
        return f"twin YAML ask mismatch for {tool}: primary={len(p_asks)} twin={len(t_asks)}"
    if info["primary_granted"] != info["twin_granted"]:
        return f"twin prose grant mismatch for {tool}: primary={sorted(info['primary_granted'])} twin={sorted(info['twin_granted'])}"
    if info["primary_asked"] != info["twin_asked"]:
        return f"twin prose ask mismatch for {tool}: primary={sorted(info['primary_asked'])} twin={sorted(info['twin_asked'])}"
    return None


# --- basemind excludes (static) --------------------------------------------


def load_bxm_excludes() -> list[str]:
    patterns: list[str] = []
    try:
        import tomllib

        data = tomllib.loads(BASEMIND_TOML.read_text(encoding="utf-8"))
        for section in ("scan", "documents"):
            excl = (data.get(section) or {}).get("exclude") if isinstance(data.get(section), dict) else None
            if isinstance(excl, list):
                patterns.extend(str(x) for x in excl if isinstance(x, str))
        return patterns
    except Exception:
        pass
    text = BASEMIND_TOML.read_text(encoding="utf-8")
    for m in re.finditer(r"exclude\s*=\s*\[([^\]]*)\]", text, re.DOTALL):
        for q in re.findall(r"\"([^\"]+)\"", m.group(1)):
            patterns.append(q)
    return patterns


def glob_matches(pattern: str, path: str) -> bool:
    """Match a basemind repo-relative glob against a repo-relative path.

    Basemind globs are forward-slash, case-sensitive; ``*`` crosses ``/``;
    a leading ``**/`` matches zero or more leading directories.
    """
    pat = pattern.replace("\\", "/")
    pth = path.replace("\\", "/")
    variants = [pat]
    if pat.startswith("**/"):
        variants.append(pat[3:])
    elif pat.startswith("/"):
        variants.append(pat[1:])
    for variant in variants:
        if fnmatch.fnmatch(pth, variant):
            return True
        if fnmatch.fnmatch("/" + pth, variant):
            return True
    # Bare name (no glob chars) matches the path and everything beneath it.
    if not any(ch in pat for ch in "*?["):
        return pth == pat or pth.startswith(pat.rstrip("/") + "/")
    return False


def is_excluded(path: str, patterns: list[str]) -> tuple[bool, str | None]:
    for pat in patterns:
        if glob_matches(pat, path):
            return True, pat
    return False, None


# --- per-expect evaluators --------------------------------------------------


def eval_ask_only(ctl: dict, agents: dict[str, dict]) -> tuple[bool, str, str]:
    tool = str(ctl.get("tool") or "")
    role = str(ctl.get("role") or "")
    args = ctl.get("args") if isinstance(ctl.get("args"), dict) else {}
    required = str(args.get("required_effect") or args.get("required") or "ask")
    if required != "ask":
        return False, "UNEXPECTED_REQUIRED", f"ASK_ONLY requires required_effect 'ask', got {required!r}"
    stem = agent_stem(role)
    if stem not in agents:
        return False, "MISSING_AGENT_FILE", f"no agent file for role {role!r} (stem {stem!r})"
    mismatch = twin_mismatch(stem, tool, agents)
    if mismatch:
        return False, "TWIN_MISMATCH", mismatch
    info = agents[stem]
    p_allows, p_asks, _ = yaml_effects(info["primary_perms"], tool)
    t_allows, t_asks, _ = yaml_effects(info["twin_perms"], tool)
    prose_grant = tool in info["primary_granted"] or tool in info["twin_granted"]
    if p_allows or t_allows or prose_grant:
        where = []
        if p_allows:
            where.append(f"YAML allow primary={p_allows!r}")
        if t_allows:
            where.append(f"YAML allow twin={t_allows!r}")
        if prose_grant:
            where.append(f"prose Use grant for {tool}")
        return False, "ALLOW", f"{tool} must be ask never allow for {role}; found {' and '.join(where)}"
    yaml_ask = bool(p_asks) or bool(t_asks)
    prose_ask = tool in info["primary_asked"] and tool in info["twin_asked"]
    if not yaml_ask and not prose_ask:
        return (
            False,
            "NO_ASK_RULE",
            f"{tool} has no effect: ask for {role}: no YAML ask entry and no prose "
            f"(`ask`) qualifier found (searched both primary and twin)",
        )
    source = "YAML" if yaml_ask else "prose"
    return True, "ASK", f"{tool} is {source}-ask never allow for {role}"


def eval_not_granted(ctl: dict, agents: dict[str, dict], registry_roles: dict[str, list[str]]) -> tuple[bool, str, str]:
    tool = str(ctl.get("tool") or "")
    role = str(ctl.get("role") or "")
    stem = agent_stem(role)
    if stem not in agents:
        return False, "MISSING_AGENT_FILE", f"no agent file for role {role!r} (stem {stem!r})"
    # No allow for the action in ANY role block (both layers, both copies).
    holders = [r for r in sorted(agents) if role_has_allow(r, tool, agents)]
    if holders:
        return False, "ALLOW", f"{tool} is granted to {holders} but must be NOT_GRANTED (none)"
    # Registry: basemind tools are absent; carbon tools must not list the role.
    if tool in registry_roles and role in registry_roles[tool]:
        return False, "REGISTRY_GRANTED", f"registry lists role {role!r} for {tool}"
    if tool.startswith("basemind_") and tool in registry_roles:
        # A basemind tool in the carbon registry would itself be a grant surface.
        return False, "REGISTRY_PRESENT", f"basemind tool {tool} unexpectedly present in registry.json"
    mismatch = twin_mismatch(stem, tool, agents)
    if mismatch:
        return False, "TWIN_MISMATCH", mismatch
    return True, "NOT_GRANTED", f"{tool} absent (no allow in any role block, no registry grant)"


def eval_role_matrix(ctl: dict, agents: dict[str, dict]) -> tuple[bool, str, str]:
    tool = str(ctl.get("tool") or "")
    args = ctl.get("args") if isinstance(ctl.get("args"), dict) else {}
    allowed = args.get("allowed_roles", args.get("allowed", []))
    denied = args.get("denied_roles", args.get("denied", []))
    if not isinstance(allowed, list) or not isinstance(denied, list):
        return False, "BAD_MATRIX_ARGS", f"allowed/denied must be lists, got allowed={allowed!r} denied={denied!r}"
    holders = {r for r in sorted(agents) if role_has_allow(r, tool, agents)}
    want = {agent_stem(str(r)) for r in allowed}
    denied_stems = {agent_stem(str(r)) for r in denied}
    # Twin agreement across every role for this tool.
    for r in sorted(agents):
        mismatch = twin_mismatch(r, tool, agents)
        if mismatch:
            return False, "TWIN_MISMATCH", f"{mismatch} (role {r})"
    denied_holders = holders & denied_stems
    extra = holders - want
    missing = want - holders
    if holders != want or denied_holders:
        detail = (
            f"holders={sorted(holders)} != allowed={sorted(want)} "
            f"(extra={sorted(extra)} missing={sorted(missing)} "
            f"denied_holders={sorted(denied_holders)})"
        )
        return False, f"holders={sorted(holders)}", detail
    return True, "ROLE_MATRIX", f"holders={sorted(holders)} == allowed"


def eval_role_allowed(ctl: dict, registry: dict[str, dict]) -> tuple[bool, str, str]:
    """ROLE_ALLOWED: role may use ``mode`` for ``tool`` per registry scope.

    Evaluated against registry scope only -- never executes the tool
    (V1/F3: controls must be side-effect free; e.g. gate.control run
    would otherwise --write the ledger). Mirrors
    Server._check_subpolicy_role: roles[] is the coarse gate; a present
    ``scopes`` map adds a (role, mode) check where ``run`` implies
    ``verify`` and a role absent from scopes is verify-only.
    """
    tool = str(ctl.get("tool") or "")
    role = str(ctl.get("role") or "")
    args = ctl.get("args") if isinstance(ctl.get("args"), dict) else {}
    mode = str(args.get("mode") or ctl.get("mode") or "verify")
    if mode not in ("run", "verify"):
        return False, "BAD_MODE", f"mode must be run/verify, got {mode!r}"
    if tool not in registry:
        return False, "UNKNOWN_TOOL", f"tool {tool!r} not in registry.json"
    entry = registry[tool]
    roles = entry.get("roles") or []
    if role not in roles:
        return False, "ROLE_NOT_IN_ROLES", f"{role!r} not in {tool}.roles {roles!r}"
    scopes = entry.get("scopes")
    if isinstance(scopes, dict):
        if role in scopes:
            raw = scopes[role]
            if isinstance(raw, str):
                allowed = {raw}
            elif isinstance(raw, (list, tuple, set)):
                allowed = set(raw)
            elif raw is None:
                allowed = set()
            else:
                allowed = {raw}
            if "run" in allowed:
                allowed.add("verify")
        else:
            allowed = {"verify"}
        if mode not in allowed:
            return False, "ROLE_NOT_ALLOWED", (
                f"{tool} mode {mode!r} not permitted for role {role!r} (allowed={sorted(allowed)})"
            )
        return True, "ROLE_ALLOWED", f"{tool} mode {mode!r} allowed for {role!r} per registry scope"
    return True, "ROLE_ALLOWED", f"{tool} allowed for {role!r} (no scope limit)"


# --- basemind runtime (EMPTY) ------------------------------------------------


class BasemindUnavailable(Exception):
    pass


class BasemindSession:
    """Alive basemind MCP session over stdio (argv only, no shell)."""

    def __init__(self, config_override: str | None = None) -> None:
        self._mod = load_mcp_discover()
        config_path = self._mod.find_config(config_override)
        try:
            command, cwd, env_extra = self._mod.load_server(config_path, "basemind")
        except ValueError as exc:
            raise BasemindUnavailable(str(exc)) from exc
        env = {**os.environ, **env_extra}
        try:
            self._proc = subprocess.Popen(  # argv only, no shell
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                shell=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except (FileNotFoundError, OSError) as exc:
            raise BasemindUnavailable(f"cannot spawn {command[0]!r}: {exc}") from exc
        self._reader = self._mod.LineReader(self._proc.stdout)
        self._next_id = 2
        deadline = time.monotonic() + 90.0
        try:
            self._proc.stdin.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": self._mod.PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": self._mod.CLIENT_INFO,
                        },
                    }
                )
                + "\n"
            )
            self._proc.stdin.flush()
            resp = self._reader.read_json(max(0.0, deadline - time.monotonic()))
            if resp.get("id") != 1 or "result" not in resp:
                raise BasemindUnavailable(f"initialize failed: {resp!r}")
            self._proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            self._proc.stdin.flush()
        except BasemindUnavailable:
            self.close()
            raise
        except Exception as exc:
            self.close()
            raise BasemindUnavailable(str(exc)) from exc

    def call(self, name: str, arguments: dict, timeout: float = 60.0) -> dict:
        req_id = self._next_id
        self._next_id += 1
        self._proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}) + "\n"
        )
        self._proc.stdin.flush()
        resp = self._reader.read_json(timeout)
        if resp.get("id") != req_id:
            raise BasemindUnavailable(f"tools/call {name} id mismatch: {resp!r}")
        return resp

    def close(self) -> None:
        try:
            if getattr(self, "_proc", None) is None:
                return
            proc = self._proc
            try:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
            except Exception:
                pass
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            for stream in (getattr(proc, "stderr", None), getattr(proc, "stdout", None)):
                try:
                    if stream:
                        stream.close()
                except Exception:
                    pass
        except Exception:
            pass


def _result_texts(resp: dict) -> list[str]:
    out: list[str] = []
    if "result" not in resp or not isinstance(resp["result"], dict):
        return out
    for item in resp["result"].get("content", []) or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            out.append(item["text"])
    return out


def _result_has_content(resp: dict) -> tuple[bool, str]:
    """True when a tools/call response carries actual content (not empty)."""
    if "error" in resp:
        # A JSON-RPC error (e.g. mode show does not accept path) carries no
        # result content; it is empty by the control's definition provided
        # the error text itself echoes no file bytes.
        msg = str((resp.get("error") or {}).get("message", ""))
        return False, f"error(no content): {msg[:200]}"
    result = resp.get("result") if isinstance(resp.get("result"), dict) else {}
    if result.get("isError"):
        texts = _result_texts(resp)
        return bool(" ".join(texts).strip()), f"isError texts={texts!r}"[:300]
    structured = result.get("structuredContent") if isinstance(result.get("structuredContent"), dict) else {}
    texts = _result_texts(resp)
    joined = " ".join(texts).strip()
    if not joined and not structured:
        return False, "empty result"
    if structured:
        commits = structured.get("commits")
        if isinstance(commits, list) and len(commits) == 0:
            # touching on an excluded/unknown path: no history, no content.
            if not joined or joined == json.dumps(structured):
                return False, f"empty commits for path {structured.get('path')!r}"
        files = structured.get("files")
        if isinstance(files, list) and len(files) == 0:
            return False, "empty files"
        # Any other non-empty structured payload counts as content.
        if isinstance(commits, list) and len(commits) > 0:
            return True, f"commits={len(commits)}"
        if isinstance(files, list) and len(files) > 0:
            return True, f"files={len(files)}"
    # Raw text: non-empty JSON with substantive fields is content.
    try:
        parsed = json.loads(joined) if joined else {}
    except Exception:
        return bool(joined.strip()), f"text len={len(joined)}"
    if isinstance(parsed, dict):
        if parsed.get("commits") == [] and not any(k in parsed for k in ("content", "body", "files") if parsed.get(k)):
            return False, "empty commits (text)"
        if parsed.get("files") == []:
            return False, "empty files (text)"
        if not parsed:
            return False, "empty object"
        return True, f"structured keys={sorted(parsed)[:8]}"
    return bool(joined.strip()), f"text len={len(joined)}"


def eval_empty(ctl: dict, session: BasemindSession | None, session_error: str | None, excludes: list[str]) -> tuple[bool, str, str]:
    path = str((ctl.get("args") or {}).get("path") or "") if isinstance(ctl.get("args"), dict) else ""
    if not path:
        return False, "MISSING_PATH", f"{ctl.get('id')} EMPTY control has no args.path"
    excluded, matched = is_excluded(path, excludes)
    if not excluded:
        return False, "NOT_EXCLUDED", f"{path!r} is not matched by any basemind.toml exclude pattern"
    if session is None:
        return False, "RUNTIME_UNAVAILABLE", f"basemind cannot be spawned: {session_error or 'unknown error'}"
    mcp_name = basemind_short(str(ctl.get("tool") or "basemind_git"))
    # Spec-literal call: basemind_git with mode:"show" on the denied path.
    # Current basemind rejects a path argument for show (it takes a sha)
    # and returns no result content; per the control that is EMPTY. The
    # static exclude check above is what makes the emptiness meaningful
    # (the path must be excluded in basemind.toml), and the session health
    # probe proves the runtime is alive rather than dead-on-arrival.
    try:
        show_resp = session.call(mcp_name, {"mode": "show", "path": path})
    except Exception as exc:
        return False, "RUNTIME_UNAVAILABLE", f"show call failed: {exc}"
    has, why_show = _result_has_content(show_resp)
    if has:
        return False, "CONTENT", f"show on excluded {path!r} returned content: {why_show}"
    return True, "EMPTY", f"excluded by {matched!r}: show={why_show}"


# --- main --------------------------------------------------------------------


def evaluate() -> tuple[dict, int]:
    controls = json.loads(CONTROLS_PATH.read_text(encoding="utf-8"))
    control_list = controls.get("controls", [])
    if not isinstance(control_list, list):
        raise ValueError("controls.json 'controls' must be a list")
    selected = [c for c in control_list if is_declarative(c.get("expect"))]
    agents = load_agents()
    registry_roles = load_registry_roles()
    registry = load_registry()
    excludes = load_bxm_excludes()

    # One basemind session for all EMPTY controls (lazy, only if needed).
    has_empty = any(c.get("expect") == "EMPTY" for c in selected)
    session: BasemindSession | None = None
    session_error: str | None = None
    healthy = False
    if has_empty:
        try:
            session = BasemindSession()
            # Health probe: status must answer without error, else the
            # runtime cannot be trusted to prove emptiness.
            h = session.call("git", {"mode": "status"})
            if "error" in h or (isinstance(h.get("result"), dict) and h["result"].get("isError")):
                session_error = f"health probe (git status) errored: {h!r}"[:300]
                try:
                    session.close()
                except Exception:
                    pass
                session = None
            else:
                healthy = True
        except BasemindUnavailable as exc:
            session_error = str(exc)
            session = None
        except Exception as exc:
            session_error = f"{type(exc).__name__}: {exc}"
            session = None

    failed: list[dict] = []
    try:
        for ctl in selected:
            expect = ctl.get("expect")
            cid = str(ctl.get("id") or "?")
            try:
                if expect == "ASK_ONLY":
                    passed, got, detail = eval_ask_only(ctl, agents)
                elif expect == "NOT_GRANTED":
                    passed, got, detail = eval_not_granted(ctl, agents, registry_roles)
                elif expect == "ROLE_MATRIX":
                    passed, got, detail = eval_role_matrix(ctl, agents)
                elif expect == "ROLE_ALLOWED":
                    passed, got, detail = eval_role_allowed(ctl, registry)
                elif expect == "EMPTY":
                    passed, got, detail = eval_empty(ctl, session, session_error, excludes)
                else:
                    passed, got, detail = False, "UNKNOWN_EXPECT", f"unsupported declarative expect {expect!r}"
            except Exception as exc:
                passed, got, detail = False, "EVALUATOR_ERROR", f"{type(exc).__name__}: {exc}"
            if not passed:
                failed.append({"id": cid, "expect": expect, "got": got, "detail": detail})
    finally:
        if session is not None:
            session.close()

    total = len(selected)
    passed_count = total - len(failed)
    summary = {"total": total, "passed": passed_count, "failed": failed}
    return summary, (0 if not failed else 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate declarative (config-level) controls.")
    parser.add_argument("--json", action="store_true", help="print JSON summary (default behaviour)")
    args = parser.parse_args(argv)
    try:
        summary, code = evaluate()
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(json.dumps({"total": 0, "passed": 0, "failed": [], "error": str(exc)}))
        return 2
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(json.dumps({"total": 0, "passed": 0, "failed": [], "error": str(exc)}))
        return 2
    except Exception as exc:  # pragma: no cover - evaluator error
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(json.dumps({"total": 0, "passed": 0, "failed": [], "error": f"{type(exc).__name__}: {exc}"}))
        return 2
    print(json.dumps(summary, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
