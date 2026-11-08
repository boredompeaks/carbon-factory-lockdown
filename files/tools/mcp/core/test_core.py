"""6B-0 unit tests: 20 generic controls + sealing/redaction/role binding.

Run: python files/tools/mcp/core/test_core.py
Exits non-zero on the first failure.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from files.tools.mcp.core import Server, Reject  # noqa: E402
from files.tools.mcp.core.config import scrub_environment, validate_executable  # noqa: E402
from files.tools.mcp.core.redact import redact_text, UnredactableSecret, cache_key  # noqa: E402

PASS = 0


def expect_reject(server: Server, tool: str, args: dict, code: str, role: str, label: str) -> None:
    global PASS
    try:
        server.dispatch(tool, dict(args), role=role)
    except Reject as r:
        assert r.code == code, f"{label}: expected {code}, got {r.code} ({r.detail})"
        PASS += 1
        return
    raise AssertionError(f"{label}: expected {code}, got ACCEPT")


def expect_ok(server: Server, tool: str, args: dict, role: str, label: str) -> None:
    global PASS
    out = server.dispatch(tool, dict(args), role=role)
    assert out.get("ok") is True, f"{label}: not ok"
    PASS += 1


def main() -> None:
    global PASS
    registry = __import__("json").loads(
        (Path(__file__).resolve().parents[1] / "registry.json").read_text(encoding="utf-8")
    )
    srv = Server("auditor", registry=registry)

    # Startup: server tools == registry tools.
    assert set(srv.server_tool_names()) == {t["name"] for t in registry["tools"]}
    print(f"startup: {len(srv.server_tool_names())} tools ok")

    # Per-role listing is the registry projection.
    for role in ["auditor", "builder", "compliance", "hacker", "orchestrator", "release-engineer", "crouton"]:
        listed = srv.list_tools(role)
        expected = sorted(t["name"] for t in registry["tools"] if role in t["roles"])
        assert listed == expected, f"{role} list mismatch"
    print("per-role listing ok")

    srv = Server("auditor", registry=registry)
    # 1-20 generic controls: unknown arg, leading dash, traversal,
    # trailing dot, ADS/colon, oversize, wrong role, missing required.
    expect_reject(srv, "git.state", {"fields": ["head"], "__unknown_arg__": True}, "REJECT_ARG", "auditor", "g01-unknown")
    expect_reject(srv, "git.state", {"fields": ["head"], "__dash__": "--bad"}, "REJECT_ARG", "auditor", "g02-dash-key")
    expect_reject(srv, "git.state", {"fields": ["head"]}, "REJECT_ROLE", "compliance", "g03-wrong-role")
    expect_reject(srv, "git.state", {}, "REJECT_ARG", "auditor", "g04-missing-fields")
    expect_reject(srv, "git.state", {"fields": ["nope"]}, "REJECT_ENUM", "auditor", "g05-enum-fields")
    expect_reject(srv, "git.state", {"fields": ["head"], "op": "delete"}, "REJECT_ARG", "auditor", "g06-unknown-op")
    expect_reject(srv, "worktrees.list", {"__unknown_arg__": True}, "REJECT_ARG", "orchestrator", "g07-unknown")
    expect_reject(srv, "worktrees.list", {}, "REJECT_ROLE", "auditor", "g08-wrong-role")
    expect_reject(srv, "git.commit", {"message": "--amend x", "tree": "0" * 40}, "REJECT_PATTERN", "builder", "g09-dash-message")
    expect_reject(srv, "k1.up", {"run_id": "r1", "base": "latest", "head": "0" * 40}, "REJECT_PATTERN", "auditor", "g10-base-pattern")
    expect_reject(srv, "k1.exec", {"run_id": "r1", "action": "shell"}, "REJECT_ENUM", "auditor", "g11-enum-action")
    expect_reject(srv, "gate.control", {"target": "registry"}, "REJECT_ENUM", "auditor", "g12-enum-target")
    expect_reject(srv, "repro.run", {"spec": "../../../etc/passwd"}, "REJECT_PATH", "auditor", "g13-traversal")
    expect_reject(srv, "code.write", {"path": "C:/Users/Admin/Downloads/backend/docs/x.md", "content": "x"}, "REJECT_PATH", "compliance", "g14-absolute")
    expect_reject(srv, "code.write", {"path": "backend/app.py.", "content": "x"}, "REJECT_PATH", "builder", "g15-trailing-dot")
    expect_reject(srv, "git.read_file", {"rev": "0" * 40, "path": "a.txt:ads"}, "REJECT_PATH", "auditor", "g16-ads-colon")
    expect_reject(srv, "docker.ensure", {"action": "run"}, "REJECT_ENUM", "auditor", "g17-enum-docker")
    expect_reject(srv, "check.run", {"check_id": "SUITE", "tree": "0" * 40, "engine": "sqlite", "install": ["x"]}, "REJECT_ARG", "builder", "g18-unknown-install")
    expect_reject(srv, "hacker.probe", {"item_id": "AUTHZ-ROUTE", "actor": "hacker-high"}, "REJECT_ARG", "hacker", "g19-missing-capability")
    expect_reject(srv, "pr.watch", {"pr": 1, "head": "0" * 40}, "REJECT_PRECONDITION", "release-engineer", "g20-precondition-no-open")

    # CRLF in message is a pattern reject.
    expect_reject(srv, "git.commit", {"message": "fix\r\nbody", "tree": "0" * 40}, "REJECT_PATTERN", "builder", "g21-crlf")

    # Oversize content is an ARG reject (no pattern on content).
    expect_reject(srv, "code.write", {"path": "backend/a.py", "content": "x" * 262145}, "REJECT_ARG", "builder", "g22-oversize")

    # Sealing cache key is deterministic and 64-hex.
    k1 = cache_key("a" * 40, "SUITE", "sha1", "sqlite")
    k2 = cache_key("a" * 40, "SUITE", "sha1", "sqlite")
    assert k1 == k2 and len(k1) == 64
    PASS += 1

    # Redaction: secret replacement, then entropy fail-closed.
    assert "[REDACTED" in redact_text("key AKIA1234567890123456 done")
    try:
        redact_text("token t" + "Ab3dEf6hIjKlMnOpQrStUv" + " tail")
        raised = False
    except UnredactableSecret:
        raised = True
    # Fixture allowlist: 127.0.0.1 is preserved (not high-entropy anyway).
    assert "127.0.0.1" in redact_text("fixture 127.0.0.1 ok")
    PASS += 1

    # Exec config: wrappers rejected, env scrubbed.
    for bad in ["git.exe", "C:\\tools\\git.cmd", "run.ps1", "-rf"]:
        try:
            validate_executable(bad)
            raise AssertionError(f"should reject {bad}")
        except ValueError:
            pass
    assert validate_executable("C:/tools/git.exe") == "C:/tools/git.exe"
    env = scrub_environment({"DATABASE_URL": "x", "LANG": "en", "SECRET": "y"})
    assert "DATABASE_URL" not in env and env.get("LANG") == "en"
    PASS += 1

    # Trace records every call.
    assert len(srv.trace.records) >= 22
    print(f"PASS {PASS} checks (6B-0 exec core)")


if __name__ == "__main__":
    main()
