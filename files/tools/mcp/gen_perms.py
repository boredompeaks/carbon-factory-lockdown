#!/usr/bin/env python3
"""Permission generator for phase 6C-1a.

Reads the frozen registry (files/tools/mcp/registry.json) and the grant
matrix (phase6/matrix.csv) and emits each role's permission block as
OpenCode ordered rules (last match wins).

Emission contract (spec 6C-1a):
  * blanket deny first: { action: "*", resource: "*", effect: deny }
  * tool allows: one allow per registry tool the role may call (sorted)
  * read allows: read/grep/glob allow on "**" (reads stay broad; denies
    below win on the same actions because they come later)
  * wall denies (read + grep + glob for each):
      - manifest: **/policy-manifest.json, every role
      - .opencode: **/.opencode, **/.opencode/**, .opencode, .opencode/**,
        every role
      - secrets: **/.env*, **/*.pem, **/*.key, **/secrets/** plus the
        root-relative forms, every role
      - ledger wholesale: quality/ledger/** (findings/, attack-logs/,
        dispatch/, gate-control/, release/, acceptance/, verdicts/,
        audit/), every role
      - .agt: **/.agt, **/.agt/**, .agt, .agt/**, every role
      - .git: **/.git, **/.git/**, .git, .git/**, every role
      - home-opencode: **/.config/opencode/**, .config/opencode/**,
        ~/.config/opencode/**, **/.local/share/opencode/**,
        .local/share/opencode/**, ~/.local/share/opencode/**, every role
      - fuzz: **/fuzz-evidence/**, **/schema-fuzz-evidence/**,
        **/*fuzz*seed*.json plus root forms, every role
      - hacker-scratch: every role except hacker (hacker reaches scratch
        only through the scratch.write tool, not through direct paths)
      - audit-scratch: every role except auditor (auditor reaches scratch
        only through scratch.write; native read/grep/glob is denied)
      - attack-catalog: builder only (**/attack-catalog.json)
  * no shell/edit/write rule lines except compliance's scoped write:
      - every other role emits zero lines with action edit or write and
        zero lines with action shell (grepped case-insensitively over the
        rendered output, the count must be 0)
      - compliance additionally emits:
          { action: edit,  resource: "backend/docs/compliance/*", effect: allow }
          { action: write, resource: "backend/docs/compliance/*", effect: allow }
        alongside its code.write tool allow (the tool is the typed path;
        the direct allow preserves the pre-existing single-section scope
        until 6C-1c retires it). The scoped paths are not under quality/**,
        so the ledger invariant (no edit/write on quality/** outside
        ledger.append) still holds.

Per-role tool sets are the intersection-checked union of registry and
matrix: the script refuses to emit when registry.roles and matrix
TOOL: dispositions disagree for any role (6C-3 INV-5). Output is
deterministic: roles sorted, tools sorted, walls in fixed order, LF
line endings, trailing newline, no timestamps. Running the generator
twice yields byte-identical output (idempotent).

Usage:
  python -m files.tools.mcp.gen_perms                # print to stdout
  python files/tools/mcp/gen_perms.py                 # print to stdout
  python files/tools/mcp/gen_perms.py --check         # self-check + idempotent
  python files/tools/mcp/gen_perms.py --out FILE      # write file (LF, utf-8)

Inputs are registry.json + matrix.csv (defaults resolved relative to
this file). controls.json, when present next to the registry, is read
only to assert every emitted tool has at least one negative control;
its absence does not fail generation.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# --- wall patterns (fixed order; order within a category is part of
# --- the idempotent output) -------------------------------------------

MANIFEST_PATTERNS: tuple[str, ...] = ("**/policy-manifest.json",)

OPENCODE_PATTERNS: tuple[str, ...] = (
    "**/.opencode",
    "**/.opencode/**",
    ".opencode",
    ".opencode/**",
)

SECRETS_PATTERNS: tuple[str, ...] = (
    "**/.env*",
    "**/*.pem",
    "**/*.key",
    "**/secrets/**",
    ".env*",
    "*.pem",
    "*.key",
    "secrets/**",
)

HACKER_SCRATCH_PATTERNS: tuple[str, ...] = (
    "hacker-scratch/**",
    "**/hacker-scratch/**",
)

ATTACK_CATALOG_PATTERNS: tuple[str, ...] = ("**/attack-catalog.json",)

LEDGER_PATTERNS: tuple[str, ...] = (
    "quality/ledger/**",
    "**/quality/ledger/**",
    "quality/ledger",
    "**/quality/ledger",
    "quality/ledger/findings/**",
    "quality/ledger/attack-logs/**",
    "quality/ledger/dispatch/**",
    "quality/ledger/gate-control/**",
    "quality/ledger/release/**",
    "quality/ledger/acceptance/**",
    "quality/ledger/verdicts/**",
    "quality/ledger/audit/**",
    "**/quality/ledger/findings/**",
    "**/quality/ledger/attack-logs/**",
    "**/quality/ledger/dispatch/**",
    "**/quality/ledger/gate-control/**",
    "**/quality/ledger/release/**",
    "**/quality/ledger/acceptance/**",
    "**/quality/ledger/verdicts/**",
    "**/quality/ledger/audit/**",
)

AGT_PATTERNS: tuple[str, ...] = (
    "**/.agt",
    "**/.agt/**",
    ".agt",
    ".agt/**",
)

GIT_PATTERNS: tuple[str, ...] = (
    "**/.git",
    "**/.git/**",
    ".git",
    ".git/**",
)

AUDIT_SCRATCH_PATTERNS: tuple[str, ...] = (
    "audit-scratch/**",
    "**/audit-scratch/**",
    "audit-scratch",
    "**/audit-scratch",
)

HOME_OPENCODE_PATTERNS: tuple[str, ...] = (
    "**/.config/opencode/**",
    ".config/opencode/**",
    "**/.config/opencode",
    ".config/opencode",
    "**/.local/share/opencode/**",
    ".local/share/opencode/**",
    "**/.local/share/opencode",
    ".local/share/opencode",
    "~/.config/opencode/**",
    "~/.local/share/opencode/**",
    "~/.config/opencode",
    "~/.local/share/opencode",
)

FUZZ_PATTERNS: tuple[str, ...] = (
    "**/fuzz-evidence/**",
    "**/schema-fuzz-evidence/**",
    "**/*fuzz*seed*.json",
    "**/fuzz-evidence",
    "**/schema-fuzz-evidence",
    "fuzz-evidence/**",
    "schema-fuzz-evidence/**",
    "*fuzz*seed*.json",
)

READ_ALLOW_PATTERNS: tuple[str, ...] = ("**",)  # read/grep/glob each

COMPLIANCE_SCOPED_WRITE = "backend/docs/compliance/*"

# Wall actions emitted for every pattern (read + grep + glob).
WALL_ACTIONS: tuple[str, ...] = ("read", "grep", "glob")


# --- loading ------------------------------------------------------------


def _default_registry() -> Path:
    return Path(__file__).resolve().parent / "registry.json"


def _default_matrix() -> Path:
    here = Path(__file__).resolve()
    # files/tools/mcp/gen_perms.py -> parents[3] is the harness root.
    candidates = [
        here.parents[3] / "phase6" / "matrix.csv",
        Path.cwd() / "phase6" / "matrix.csv",
        here.parent / ".." / ".." / ".." / "phase6" / "matrix.csv",
    ]
    for c in candidates:
        try:
            if c.resolve().exists():
                return c.resolve()
        except OSError:
            continue
    return candidates[0].resolve()


def load_registry(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_matrix_rows(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_controls_tools(path: Path) -> set[str] | None:
    """Return the set of tool names that have >=1 control, or None if absent."""
    if not Path(path).exists():
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {c.get("tool", "") for c in data.get("controls", []) if c.get("tool")}


# --- role/tool projection ----------------------------------------------


def registry_tools_by_role(registry: dict) -> dict[str, set[str]]:
    by_role: dict[str, set[str]] = {}
    for tool in registry.get("tools", []):
        name = tool["name"]
        for role in tool.get("roles", []):
            by_role.setdefault(role, set()).add(name)
    return by_role


def matrix_tools_by_role(rows: list[dict]) -> dict[str, set[str]]:
    by_role: dict[str, set[str]] = {}
    for row in rows:
        disp = (row.get("disposition") or "").strip()
        if disp.startswith("TOOL:"):
            role = (row.get("role") or "").strip()
            tool = disp[len("TOOL:"):]
            by_role.setdefault(role, set()).add(tool)
    return by_role


def checked_tools_by_role(
    registry: dict, rows: list[dict], controls_tools: set[str] | None
) -> dict[str, set[str]]:
    reg = registry_tools_by_role(registry)
    mat = matrix_tools_by_role(rows)
    roles = sorted(set(reg) | set(mat))
    # 'ci' appears only in check_runners; it is never a tool role. Guard anyway.
    roles = [r for r in roles if r != "ci"]
    mismatches: list[str] = []
    for role in roles:
        r = reg.get(role, set())
        m = mat.get(role, set())
        if r != m:
            mismatches.append(
                f"  {role}: registry={sorted(r)} matrix={sorted(m)} "
                f"(only-registry={sorted(r - m)} only-matrix={sorted(m - r)})"
            )
    if mismatches:
        raise SystemExit(
            "gen_perms: per-role tool list != matrix (INV-5)\n" + "\n".join(mismatches)
        )
    if controls_tools is not None:
        known = set(controls_tools)
        for role in roles:
            for tool in sorted(reg.get(role, set())):
                if tool not in known:
                    raise SystemExit(
                        f"gen_perms: tool {tool!r} (role {role}) has no "
                        "control in controls.json"
                    )
    return {role: set(reg.get(role, set())) for role in roles}


# --- rendering ----------------------------------------------------------


def render_role(role: str, tools: set[str]) -> list[str]:
    lines: list[str] = []
    lines.append(f"# role: {role}")
    lines.append("permissions:")
    # 1. blanket deny
    lines.append('  - { action: "*", resource: "*", effect: deny }')
    # 2. tool allows (sorted)
    for tool in sorted(tools):
        lines.append(f'  - {{ action: tool, resource: "{tool}", effect: allow }}')
    # 3. read allows (broad; walls below win)
    for action in ("read", "grep", "glob"):
        for pat in READ_ALLOW_PATTERNS:
            lines.append(f'  - {{ action: {action}, resource: "{pat}", effect: allow }}')
    # 4. wall denies (read/grep/glob each, last match wins)
    wall_groups: list[tuple[str, tuple[str, ...]]] = [
        ("manifest", MANIFEST_PATTERNS),
        (".opencode", OPENCODE_PATTERNS),
        ("secrets", SECRETS_PATTERNS),
        ("ledger", LEDGER_PATTERNS),
        (".agt", AGT_PATTERNS),
        (".git", GIT_PATTERNS),
        ("home-opencode", HOME_OPENCODE_PATTERNS),
        ("fuzz", FUZZ_PATTERNS),
    ]
    if role != "hacker":
        wall_groups.append(("hacker-scratch", HACKER_SCRATCH_PATTERNS))
    if role != "auditor":
        wall_groups.append(("audit-scratch", AUDIT_SCRATCH_PATTERNS))
    if role == "builder":
        wall_groups.append(("attack-catalog", ATTACK_CATALOG_PATTERNS))
    for _group, patterns in wall_groups:
        for pat in patterns:
            for action in WALL_ACTIONS:
                lines.append(
                    f'  - {{ action: {action}, resource: "{pat}", effect: deny }}'
                )
    # 5. the single scoped edit/write exception
    if role == "compliance":
        lines.append(
            f'  - {{ action: edit, resource: "{COMPLIANCE_SCOPED_WRITE}", '
            "effect: allow }"
        )
        lines.append(
            f'  - {{ action: write, resource: "{COMPLIANCE_SCOPED_WRITE}", '
            "effect: allow }"
        )
    return lines


def render_all(roles: list[str], tools_by_role: dict[str, set[str]]) -> str:
    blocks: list[str] = []
    for role in roles:
        blocks.append("\n".join(render_role(role, tools_by_role.get(role, set()))))
    return "\n\n".join(blocks) + "\n"


# --- validation ---------------------------------------------------------


def _rule_has_action(line: str, action: str) -> bool:
    # Matches the emitted shape: "{ action: <action>," (quoted only for "*").
    return f"action: {action}," in line


def validate(text: str, roles: list[str], tools_by_role: dict[str, set[str]]) -> None:
    problems: list[str] = []
    # Zero shell lines: no emitted rule line may carry this action, and the
    # rendered text must not contain the word at all (guards comments too).
    if "shell" in text.lower():
        problems.append("output contains the word shell (must be 0 lines)")
    # Per-role structural checks.
    lines = text.splitlines()
    # Re-split into blocks by header.
    blocks: dict[str, list[str]] = {}
    cur: str | None = None
    for ln in lines:
        if ln.startswith("# role: "):
            cur = ln[len("# role: "):].strip()
            blocks[cur] = []
        elif cur is not None:
            blocks[cur].append(ln)
    if sorted(blocks) != sorted(roles):
        problems.append(f"roles in output {sorted(blocks)} != expected {sorted(roles)}")
    for role in roles:
        blk = blocks.get(role, [])
        # blanket deny exactly once, first rule
        blanket = [ln for ln in blk if _rule_has_action(ln, '"*"') and "deny" in ln]
        if len(blanket) != 1:
            problems.append(f"{role}: blanket deny count={len(blanket)} (want 1)")
        # tool allows == projection
        tools_out = sorted(
            ln.split('resource: "')[1].split('"')[0]
            for ln in blk
            if _rule_has_action(ln, "tool") and "allow" in ln
        )
        if tools_out != sorted(tools_by_role.get(role, set())):
            problems.append(
                f"{role}: tool allows {tools_out} != projection "
                f"{sorted(tools_by_role.get(role, set()))}"
            )
        # read allow broad
        if not any(_rule_has_action(ln, "read") and '"**"' in ln and "allow" in ln for ln in blk):
            problems.append(f"{role}: missing read ** allow")
        # manifest read/grep/glob denies (INV-4)
        for pat in MANIFEST_PATTERNS:
            for action in WALL_ACTIONS:
                if not any(
                    _rule_has_action(ln, action)
                    and f'"{pat}"' in ln
                    and "deny" in ln
                    for ln in blk
                ):
                    problems.append(f"{role}: missing {action} deny for {pat}")
        # .opencode read/grep/glob denies (at least one pattern per action)
        for action in WALL_ACTIONS:
            if not any(
                _rule_has_action(ln, action)
                and (".opencode" in ln)
                and "deny" in ln
                for ln in blk
            ):
                problems.append(f"{role}: missing {action} deny for .opencode")
        # secrets read/grep/glob denies
        for action in WALL_ACTIONS:
            if not any(
                _rule_has_action(ln, action)
                and (".env" in ln or "*.pem" in ln or "*.key" in ln or "secrets/" in ln)
                and "deny" in ln
                for ln in blk
            ):
                problems.append(f"{role}: missing {action} deny for secrets")
        # hacker-scratch denies for non-hackers
        if role != "hacker":
            for action in WALL_ACTIONS:
                if not any(
                    _rule_has_action(ln, action)
                    and "hacker-scratch" in ln
                    and "deny" in ln
                    for ln in blk
                ):
                    problems.append(f"{role}: missing {action} deny for hacker-scratch")
        else:
            # hacker itself must not carry a hacker-scratch deny wall (its
            # scratch access is the scratch.write tool only).
            if any("hacker-scratch" in ln and "deny" in ln for ln in blk):
                problems.append("hacker: must not deny hacker-scratch (tool-only)")
        # attack-catalog deny for builder only
        if role == "builder":
            for action in WALL_ACTIONS:
                if not any(
                    _rule_has_action(ln, action)
                    and "attack-catalog" in ln
                    and "deny" in ln
                    for ln in blk
                ):
                    problems.append(f"{role}: missing {action} deny for attack-catalog")
        # ledger wholesale read/grep/glob denies (all roles)
        for pat in LEDGER_PATTERNS:
            for action in WALL_ACTIONS:
                if not any(
                    _rule_has_action(ln, action)
                    and f'"{pat}"' in ln
                    and "deny" in ln
                    for ln in blk
                ):
                    problems.append(f"{role}: missing {action} deny for {pat}")
        # .agt read/grep/glob denies (all roles)
        for pat in AGT_PATTERNS:
            for action in WALL_ACTIONS:
                if not any(
                    _rule_has_action(ln, action)
                    and f'"{pat}"' in ln
                    and "deny" in ln
                    for ln in blk
                ):
                    problems.append(f"{role}: missing {action} deny for {pat}")
        # .git read/grep/glob denies (all roles)
        for pat in GIT_PATTERNS:
            for action in WALL_ACTIONS:
                if not any(
                    _rule_has_action(ln, action)
                    and f'"{pat}"' in ln
                    and "deny" in ln
                    for ln in blk
                ):
                    problems.append(f"{role}: missing {action} deny for {pat}")
        # home-opencode tree read/grep/glob denies (all roles)
        for pat in HOME_OPENCODE_PATTERNS:
            for action in WALL_ACTIONS:
                if not any(
                    _rule_has_action(ln, action)
                    and f'"{pat}"' in ln
                    and "deny" in ln
                    for ln in blk
                ):
                    problems.append(f"{role}: missing {action} deny for {pat}")
        # fuzz-evidence read/grep/glob denies (all roles)
        for pat in FUZZ_PATTERNS:
            for action in WALL_ACTIONS:
                if not any(
                    _rule_has_action(ln, action)
                    and f'"{pat}"' in ln
                    and "deny" in ln
                    for ln in blk
                ):
                    problems.append(f"{role}: missing {action} deny for {pat}")
        # audit-scratch denies for non-auditors (native read hole)
        if role != "auditor":
            for action in WALL_ACTIONS:
                if not any(
                    _rule_has_action(ln, action)
                    and "audit-scratch" in ln
                    and "deny" in ln
                    for ln in blk
                ):
                    problems.append(f"{role}: missing {action} deny for audit-scratch")
        else:
            # auditor itself must not carry an audit-scratch deny wall (its
            # scratch access is the scratch.write tool only; native read is
            # the auditor's verification path).
            if any("audit-scratch" in ln and "deny" in ln for ln in blk):
                problems.append("auditor: must not deny audit-scratch (tool-only)")
        # no edit/write lines except compliance scoped write
        edit_write = [
            ln for ln in blk
            if _rule_has_action(ln, "edit") or _rule_has_action(ln, "write")
        ]
        if role == "compliance":
            if len(edit_write) != 2 or not all(
                COMPLIANCE_SCOPED_WRITE in ln and "allow" in ln for ln in edit_write
            ):
                problems.append(
                    f"compliance: scoped write lines={len(edit_write)} (want 2 "
                    f"for {COMPLIANCE_SCOPED_WRITE})"
                )
            # no edit/write on quality/** (ledger invariant)
            if any("quality/" in ln for ln in edit_write):
                problems.append("compliance: edit/write on quality/** forbidden")
        else:
            if edit_write:
                problems.append(
                    f"{role}: edit/write lines present ({len(edit_write)}), "
                    "only compliance may carry them"
                )
    if problems:
        raise SystemExit("gen_perms: validation failed:\n" + "\n".join(problems))


# --- main ---------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Emit per-role permission blocks (6C-1a).")
    ap.add_argument("--registry", type=Path, default=_default_registry())
    ap.add_argument("--matrix", type=Path, default=_default_matrix())
    ap.add_argument(
        "--controls",
        type=Path,
        default=Path(__file__).resolve().parent / "controls.json",
    )
    ap.add_argument("--out", type=Path, default=None, help="write output to FILE")
    ap.add_argument(
        "--check",
        action="store_true",
        help="self-check: render twice, assert byte-identical, validate",
    )
    args = ap.parse_args(argv)

    registry = load_registry(args.registry)
    rows = load_matrix_rows(args.matrix)
    controls_tools = load_controls_tools(args.controls)
    tools_by_role = checked_tools_by_role(registry, rows, controls_tools)
    roles = sorted(tools_by_role)

    text = render_all(roles, tools_by_role)
    validate(text, roles, tools_by_role)

    if args.check:
        again = render_all(roles, tools_by_role)
        if again != text:
            print("gen_perms: NOT idempotent (second render differs)", file=sys.stderr)
            return 1
        print(
            f"gen_perms: idempotent OK ({len(roles)} roles, "
            f"{sum(len(v) for v in tools_by_role.values())} tool grants)"
        )

    if args.out is not None:
        args.out.write_text(text, encoding="utf-8", newline="\n")
        if args.check:
            # Re-read to prove the file bytes match the print bytes.
            on_disk = args.out.read_text(encoding="utf-8")
            if on_disk != text:
                print("gen_perms: written file differs from render", file=sys.stderr)
                return 1
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
