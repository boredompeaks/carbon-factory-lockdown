"""Carbon MCP stdio server: one process per role (per-role instance).

MCP stdio over newline-delimited JSON-RPC 2.0: one message per line,
stdout carries only JSON-RPC replies (no logging there, stderr only).

Role is bound from CARBON_ROLE env and never from the caller: when it
is unset or not one of the 7 known roles the process refuses to start
(exit 2) instead of guessing. tools/call handlers shell with
shell=False (this module spawns nothing directly) and are capped at
300s per call (fail closed as isError).

Methods:
  initialize             -> protocolVersion, serverInfo, capabilities.tools
  notifications/initialized (notification, no reply)
  tools/list             -> Server(role).list_tools(role) projection
  tools/call             -> Server(role).dispatch(name, arguments)
  ping                   -> {}
Unknown methods reply JSON-RPC -32601; malformed params reply -32602
when an id is present; malformed JSON lines are logged to stderr and
skipped (no id to reply to). Notifications (no id) never get a reply.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

# Bootstrap so this module also works when loaded as a top-level
# ``stdio`` (run as script) as well as ``files.tools.mcp.stdio``.
# __main__.py inserts the same two entries; doing it here too keeps
# ``python files/tools/mcp/stdio.py`` correct in isolation.
_here = Path(__file__).resolve().parent
_root = _here.parents[2]
for _p in (str(_here), str(_root)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from files.tools.mcp.core import Reject, Server  # noqa: E402

PROTOCOL_VERSION = "2024-11-05"
SERVER_VERSION = "1.0.0"
PER_CALL_TIMEOUT = 300.0

KNOWN_ROLES = frozenset(
    {
        "auditor",
        "builder",
        "compliance",
        "crouton",
        "hacker",
        "orchestrator",
        "release-engineer",
    }
)


def _role() -> str | None:
    role = os.environ.get("CARBON_ROLE")
    if not role or role not in KNOWN_ROLES:
        print(
            "error: CARBON_ROLE must be one of "
            f"{sorted(KNOWN_ROLES)} (got {role!r}); refusing to start",
            file=sys.stderr,
        )
        return None
    return role


def _input_schema(tdef: dict) -> dict:
    args = tdef.get("args", {}) if isinstance(tdef.get("args", {}), dict) else {}
    props: dict = {}
    explicit = args.get("properties", {})
    if isinstance(explicit, dict):
        props.update(explicit)
    for key, schema in args.items():
        if key not in ("type", "properties", "required", "additionalProperties"):
            props.setdefault(key, schema)
    required = args.get("required", [])
    if not isinstance(required, list):
        required = []
    return {
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": False,
    }


def _list_tools(server: Server, role: str) -> list[dict]:
    names = server.list_tools(role)
    return [
        {
            "name": name,
            "description": server.tools[name].get("description", ""),
            "inputSchema": _input_schema(server.tools[name]),
        }
        for name in names
    ]


def _write(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _dispatch_with_cap(server: Server, name: str, arguments: dict):
    """Run dispatch with a 300s cap; TimeoutError when exceeded."""
    box: dict = {}
    box_err: dict = {}

    def _run() -> None:
        try:
            box["result"] = server.dispatch(name, arguments)
        except BaseException as exc:  # noqa: BLE001 - re-raised on caller thread
            box_err["exc"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(PER_CALL_TIMEOUT)
    if thread.is_alive():
        # Fail closed: the stray backend thread keeps running in
        # background but the caller gets a timeout error and cannot
        # observe a result. The next call may interleave with it.
        raise TimeoutError(f"tools/call {name} exceeded 300s cap")
    if "exc" in box_err:
        raise box_err["exc"]
    return box["result"]


def serve() -> int:
    role = _role()
    if role is None:
        return 2
    try:
        server = Server(role)
    except Exception as exc:  # fail closed on startup checks
        print(f"error: carbon stdio startup failed: {exc}", file=sys.stderr)
        return 2
    tools_cache = _list_tools(server, role)
    try:
        for line in sys.stdin:
            text = line.strip()
            if not text:
                continue
            try:
                msg = json.loads(text)
            except json.JSONDecodeError as exc:
                print(f"carbon-stdio: invalid JSON line: {exc}", file=sys.stderr)
                continue
            if not isinstance(msg, dict):
                # Not a single JSON-RPC object (e.g. a batch array);
                # no id to reply to deterministically: skip.
                print("carbon-stdio: expected JSON-RPC object, skipped", file=sys.stderr)
                continue
            method = msg.get("method")
            mid = msg.get("id")
            is_notif = "id" not in msg
            if method == "initialize":
                if is_notif:
                    continue
                _write(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "result": {
                            "protocolVersion": PROTOCOL_VERSION,
                            "capabilities": {"tools": {"listChanged": False}},
                            "serverInfo": {"name": f"carbon-{role}", "version": SERVER_VERSION},
                        },
                    }
                )
            elif method == "tools/list":
                if is_notif:
                    continue
                _write({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools_cache}})
            elif method == "tools/call":
                if is_notif:
                    continue
                params = msg.get("params", {})
                if not isinstance(params, dict):
                    _write(
                        {
                            "jsonrpc": "2.0",
                            "id": mid,
                            "error": {"code": -32602, "message": "invalid params: expected object"},
                        }
                    )
                    continue
                name = params.get("name")
                arguments = params.get("arguments", {})
                if arguments is None:
                    arguments = {}
                if not isinstance(name, str) or not name:
                    _write(
                        {
                            "jsonrpc": "2.0",
                            "id": mid,
                            "error": {"code": -32602, "message": "invalid params: name required"},
                        }
                    )
                    continue
                if not isinstance(arguments, dict):
                    _write(
                        {
                            "jsonrpc": "2.0",
                            "id": mid,
                            "error": {"code": -32602, "message": "invalid params: arguments must be object"},
                        }
                    )
                    continue
                try:
                    out = _dispatch_with_cap(server, name, arguments)
                    _write(
                        {
                            "jsonrpc": "2.0",
                            "id": mid,
                            "result": {
                                "content": [{"type": "text", "text": json.dumps(out)}],
                                "isError": False,
                            },
                        }
                    )
                except Reject as rej:
                    payload = {"code": rej.code, "detail": rej.detail, "tool": name, "role": role}
                    _write(
                        {
                            "jsonrpc": "2.0",
                            "id": mid,
                            "result": {
                                "content": [{"type": "text", "text": json.dumps(payload)}],
                                "isError": True,
                            },
                        }
                    )
                except TimeoutError as exc:
                    payload = {"code": "REJECT_TIMEOUT", "detail": str(exc), "tool": name, "role": role}
                    _write(
                        {
                            "jsonrpc": "2.0",
                            "id": mid,
                            "result": {
                                "content": [{"type": "text", "text": json.dumps(payload)}],
                                "isError": True,
                            },
                        }
                    )
                except Exception as exc:  # fail closed: never bubble up as ok
                    payload = {"code": "ERROR", "detail": str(exc), "tool": name, "role": role}
                    _write(
                        {
                            "jsonrpc": "2.0",
                            "id": mid,
                            "result": {
                                "content": [{"type": "text", "text": json.dumps(payload)}],
                                "isError": True,
                            },
                        }
                    )
            elif method == "ping":
                if is_notif:
                    continue
                _write({"jsonrpc": "2.0", "id": mid, "result": {}})
            elif isinstance(method, str) and method.startswith("notifications/"):
                continue
            elif is_notif:
                continue
            else:
                _write(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32601, "message": f"method not found: {method}"},
                    }
                )
    except BrokenPipeError:
        return 0
    return 0


def main() -> int:
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
