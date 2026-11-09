#!/usr/bin/env python3
"""MCP stdio discovery: spawn a local MCP server from opencode.json and list tools.

Usage:
    python scripts/mcp_discover.py --server carbon
    python scripts/mcp_discover.py --server basemind
    python scripts/mcp_discover.py --server basemind --config opencode.json

Spawns the server's argv exactly as configured (no shell, argv only),
runs MCP ``initialize`` + ``notifications/initialized`` + ``tools/list``
over newline-delimited JSON-RPC on stdio, and prints JSON to stdout::

    {"server": "<name>", "tools": [{"name": "...", "inputSchema": [...keys...],
    "inputSchemaKeys": [...keys...]}], "resources": []}

``resources`` is always ``[]`` by spec (tools discovery only).
Overall deadline is 30s; any failure is fail-closed with exit 2 and a
message on stderr (never a traceback on stdout).

Why there is no top-level ``basemind`` block in opencode.json:
    ``basemind --help`` / ``basemind serve --help`` show no opencode.json
    key; basemind reads ``basemind.toml`` (``[scan] exclude`` /
    ``[documents] exclude``). No invented key is added to opencode.json.
    The current exclude list lives in ``basemind.toml``:

        exclude = ["**/.env*", "**/*.pem", "**/*.key", "**/id_rsa*",
          "**/secrets/**", "**/.opencode/**", "**/.git/**",
          "**/node_modules/**", "**/venv/**", "**/__pycache__/**",
          "**/policy-manifest.json", "**/*.sqlite", "**/db.sqlite3",
          "**/files/**", "**/.agents/**", "**/quality/ledger/**",
          "**/audit-scratch/**", "**/.agt/**", "opencode.json",
          "**/opencode.json", ".opencode/**", ".opencode"]

    BASEMIND_EXCLUDE below mirrors that list so this file is
    self-documenting; ``basemind.toml`` remains authoritative.

Carbon note:
    The configured carbon argv is ``python -m carbon_mcp``. When that
    module is not importable, discovery does NOT pretend it spawned it:
    it spawns this same script in ``--carbon-stdio`` mode (argv only),
    which serves the authoritative ``files/tools/mcp/registry.json``
    (30 tools) over MCP stdio with real initialize/tools-list handling,
    and notes the fallback on stderr. Once ``carbon_mcp`` is installed,
    the configured argv is spawned directly with no fallback.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
from pathlib import Path

DISCOVER_TIMEOUT = 30.0
PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "mcp-discover", "version": "1.0.0"}

# Mirror of basemind.toml [scan]/[documents] exclude (authoritative there).
BASEMIND_EXCLUDE = [
    "**/.env*",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa*",
    "**/secrets/**",
    "**/.opencode/**",
    "**/.git/**",
    "**/node_modules/**",
    "**/venv/**",
    "**/__pycache__/**",
    "**/policy-manifest.json",
    "**/*.sqlite",
    "**/db.sqlite3",
    "**/files/**",
    "**/.agents/**",
    "**/quality/ledger/**",
    "**/audit-scratch/**",
    "**/.agt/**",
    "opencode.json",
    "**/opencode.json",
    ".opencode/**",
    ".opencode",
]


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def resolve_python_argv(command: list[str]) -> list[str]:
    """Map a bare python name that is missing on this host to the stable interpreter.

    Same resolution as ``scripts/gen_opencode_config.py``: ``sys.executable``
    when it is a stable path (absolute and an existing file), otherwise
    ``python3`` on POSIX / ``python`` on Windows. A stale ``opencode.json``
    with bare ``python`` would otherwise fail to spawn on Ubuntu >=22.04,
    where only ``python3`` exists. Bare names that are on PATH are kept
    as-is; absolute or otherwise-pathed argv[0] is never rewritten.
    """
    head = command[0]
    if os.path.sep in head or (os.path.altsep and os.path.altsep in head):
        return command
    name = head.lower()
    if name.endswith((".exe", ".bat", ".cmd")):
        name = name[:-4]
    if name not in ("python", "python3", "py"):
        return command
    if shutil.which(head):
        return command
    exe = sys.executable or ""
    if exe and os.path.isabs(exe) and os.path.isfile(exe):
        replacement = exe
    else:
        replacement = "python" if sys.platform.startswith("win") else "python3"
    if replacement == head:
        return command
    print(f"note: {head!r} not on PATH; using {replacement!r} for server command", file=sys.stderr)
    return [replacement, *command[1:]]


def find_config(override: str | None) -> Path:
    if override:
        return Path(override)
    here = Path(__file__).resolve()
    harness_root = here.parent.parent
    candidates = [harness_root / "opencode.json", Path("opencode.json")]
    for cand in candidates:
        if cand.is_file():
            return cand
    return candidates[0]


def load_server(config_path: Path, name: str) -> tuple[list[str], str, dict[str, str]]:
    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"config not found: {config_path}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {config_path}: {exc}") from exc
    servers = cfg.get("mcp", {}).get("servers", {})
    if name not in servers:
        raise ValueError(f"server {name!r} not in config (have: {sorted(servers)})")
    server = servers[name]
    if not isinstance(server, dict):
        raise ValueError(f"server {name!r} must be an object")
    if server.get("disabled") is True:
        raise ValueError(f"server {name!r} is disabled")
    if server.get("type") != "local":
        raise ValueError(f"server {name!r} is not local stdio (type={server.get('type')!r}); fail closed")
    command = server.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        raise ValueError(f"server {name!r} has no valid command argv")
    command = resolve_python_argv(command)
    cwd_raw = server.get("cwd", ".")
    if not isinstance(cwd_raw, str) or not cwd_raw:
        cwd_raw = "."
    cwd_path = Path(cwd_raw)
    if not cwd_path.is_absolute():
        cwd_path = (config_path.parent / cwd_path).resolve()
    env_extra = server.get("environment", {})
    if not isinstance(env_extra, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in env_extra.items()
    ):
        raise ValueError(f"server {name!r} has invalid environment")
    return command, str(cwd_path), env_extra


class LineReader:
    def __init__(self, stream) -> None:
        self._queue: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._pump, args=(stream,), daemon=True)
        self._thread.start()

    def _pump(self, stream) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                self._queue.put(line)
        except Exception:
            pass
        self._queue.put(None)

    def read_json(self, timeout_left: float):
        if timeout_left <= 0:
            raise TimeoutError("discovery deadline exceeded")
        try:
            raw = self._queue.get(timeout=timeout_left)
        except queue.Empty as exc:
            raise TimeoutError("discovery deadline exceeded") from exc
        if raw is None:
            raise ConnectionError("server closed stdout")
        text = raw.strip()
        if not text:
            return self.read_json(timeout_left)
        return json.loads(text)


def discover(server_name: str, command: list[str], cwd: str, env_extra: dict[str, str]) -> dict:
    import time

    deadline = time.monotonic() + DISCOVER_TIMEOUT
    env = {**os.environ, **env_extra}
    try:
        proc = subprocess.Popen(  # argv only, no shell
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
    except FileNotFoundError as exc:
        raise ValueError(f"cannot spawn {command[0]!r}: {exc}. argv={command}") from exc
    except OSError as exc:
        raise ValueError(f"cannot spawn {command[0]!r}: {exc}") from exc

    reader = LineReader(proc.stdout)
    try:
        # initialize
        proc.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": CLIENT_INFO,
                    },
                }
            )
            + "\n"
        )
        proc.stdin.flush()
        resp = reader.read_json(max(0.0, deadline - __import__("time").monotonic()))
        if resp.get("id") != 1 or "result" not in resp:
            raise ValueError(f"initialize failed: {resp!r}")
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()
        # tools/list
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
        proc.stdin.flush()
        resp = reader.read_json(max(0.0, deadline - __import__("time").monotonic()))
        if resp.get("id") != 2 or "result" not in resp:
            raise ValueError(f"tools/list failed: {resp!r}")
        raw_tools = resp["result"].get("tools")
        if not isinstance(raw_tools, list) or not raw_tools:
            raise ValueError(f"tools/list returned no tools: {resp!r}")
        tools = []
        for item in raw_tools:
            if not isinstance(item, dict) or "name" not in item:
                raise ValueError(f"malformed tool entry: {item!r}")
            schema = item.get("inputSchema", {})
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}
            keys = list(props.keys()) if isinstance(props, dict) else []
            tools.append({"name": item["name"], "inputSchema": keys, "inputSchemaKeys": keys})
        return {"server": server_name, "tools": tools, "resources": []}
    except (TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
        raise ValueError(f"MCP stdio failure for {server_name!r}: {exc}") from exc
    finally:
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
        try:
            if proc.stderr:
                proc.stderr.close()
        except Exception:
            pass
        try:
            if proc.stdout:
                proc.stdout.close()
        except Exception:
            pass


def serve_carbon_stdio() -> int:
    """Serve files/tools/mcp/registry.json as an MCP stdio server (30 tools).

    Used only when ``python -m carbon_mcp`` is not installed; the
    configured argv is preferred whenever the module exists.
    """
    registry_path = Path(__file__).resolve().parent.parent / "files" / "tools" / "mcp" / "registry.json"
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        reg_tools = registry.get("tools", [])
    except Exception as exc:
        print(f"carbon-stdio: cannot load registry {registry_path}: {exc}", file=sys.stderr)
        return 2
    tools = []
    for tdef in reg_tools:
        args = tdef.get("args", {})
        props = args.get("properties", {}) if isinstance(args, dict) else {}
        # Preserve registry arg order in the schema; fall back to empty.
        tools.append(
            {
                "name": tdef["name"],
                "description": tdef.get("description", ""),
                "inputSchema": {
                    "type": "object",
                    "properties": props,
                    "required": args.get("required", []),
                    "additionalProperties": False,
                },
            }
        )
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize":
            sys.stdout.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "result": {
                            "protocolVersion": PROTOCOL_VERSION,
                            "capabilities": {"tools": {"listChanged": False}},
                            "serverInfo": {"name": "carbon (registry)", "version": "1.0.0"},
                        },
                    }
                )
                + "\n"
            )
            sys.stdout.flush()
        elif method == "tools/list":
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}}) + "\n")
            sys.stdout.flush()
        elif method == "notifications/initialized":
            continue
        elif mid is not None:
            sys.stdout.write(
                json.dumps(
                    {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
                )
                + "\n"
            )
            sys.stdout.flush()
    return 0


def main() -> int:
    if "--carbon-stdio" in sys.argv[1:]:
        return serve_carbon_stdio()
    parser = argparse.ArgumentParser(description="MCP stdio tool discovery (fail closed, exit 2).")
    parser.add_argument("--server", required=True, help="Server name under mcp.servers")
    parser.add_argument("--config", default=None, help="opencode.json path (default: harness root)")
    args = parser.parse_args()
    config_path = find_config(args.config)
    try:
        command, cwd, env_extra = load_server(config_path, args.server)
    except ValueError as exc:
        return fail(str(exc))

    # Prefer the configured argv. For carbon, if the module is missing,
    # fall back to the embedded registry server so discovery still works.
    if args.server == "carbon":
        import importlib.util

        if importlib.util.find_spec("carbon_mcp") is None:
            script = Path(__file__).resolve()
            command = [sys.executable, str(script), "--carbon-stdio"]
            cwd = str(config_path.parent)
            env_extra = {}
            print(
                "note: carbon_mcp module not installed; serving files/tools/mcp/registry.json (30 tools) via --carbon-stdio fallback",
                file=sys.stderr,
            )

    try:
        result = discover(args.server, command, cwd, env_extra)
    except ValueError as exc:
        return fail(str(exc))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
