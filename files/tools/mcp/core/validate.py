"""Schema validation from registry.json + generic path normalization. 6B-0.

Only typed args exist: unknown keys are rejected, every string is
checked against its anchored regex, arrays/items are checked against
their enum, and paths are normalized (relative, no traversal, no
trailing dot/space, no colon, no leading dash).

The server (`server.py`) enforces the reject-code ordering that
controls.json expects:

    REJECT_ROLE -> REJECT_ENUM -> REJECT_PATH(traversal/absolute)
    -> REJECT_ARG(unknown/missing/type) -> REJECT_PATTERN
    -> REJECT_PATH(deny/scope) -> REJECT_POLICY -> REJECT_REDACTION
    -> REJECT_PRECONDITION

This module implements the generic steps that do not need a family
module. Family modules add deny-glob / scope / policy / redaction /
precondition checks in the later steps.
"""
from __future__ import annotations

import re


class Reject(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# Args that carry filesystem paths or ledger spec references.
_PATH_FIELDS = frozenset({"path", "spec", "paths"})
# endpoint is a URL path (leading '/' is legitimate there).
_ENDPOINT_TOOL = "hacker.probe"


def is_path_field(tool: str, field: str) -> bool:
    return field in _PATH_FIELDS


def is_traversal_or_absolute(tool: str, field: str, value: str) -> bool:
    """True if a path value escapes the repo root or is absolute.

    Checked BEFORE regex validation so out-of-tree absolute paths and
    traversals report REJECT_PATH (F-34, F-37, F-48) rather than
    REJECT_PATTERN.
    """
    if not isinstance(value, str):
        return False
    # Windows drive absolute: C:/... or C:\\...
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    # UNC or leading backslash
    if value.startswith("\\\\") or value.startswith("\\"):
        return True
    # Leading '/' is absolute except the probe endpoint where it is required.
    if value.startswith("/") and not (tool == _ENDPOINT_TOOL and field == "endpoint"):
        return True
    # Colon in a path (drive letter or ADS like file:stream).
    if ":" in value:
        return True
    # Traversal segments via '/' or '\\'.
    parts = re.split(r"[/\\]+", value)
    if any(p == ".." for p in parts):
        return True
    # Trailing dot or space in any segment (Windows normalization).
    for part in parts:
        if part.endswith(".") or part.endswith(" "):
            return True
        if part != part.strip(" ") and part.strip(" ") != "":
            # interior leading/trailing spaces already covered by the loop.
            return True
    # Bare backslash separators are non-normalized.
    if "\\" in value:
        return True
    return False


def check_enum(tool_def: dict, args: dict) -> None:
    """Raise REJECT_ENUM for any present value outside its enum.

    Runs before unknown-key checks so F-16 (bad enum + unknown `command`)
    reports ENUM as controls.json specifies.
    """
    props = tool_def.get("args", {}).get("properties", {})
    # Registry flattens arg schemas as siblings of `properties` (see 6A-3):
    # args = {type, properties:{}, required, additionalProperties, <field>: schema}
    arg_schema = tool_def.get("args", {})
    for key, value in args.items():
        schema = None
        if key in props:
            schema = props[key]
        elif key in arg_schema:
            schema = arg_schema[key]
        if not isinstance(schema, dict):
            continue
        if "enum" in schema and value not in schema["enum"]:
            raise Reject("REJECT_ENUM", f"{key}={value!r} not in enum")
        # Array-of-enum, e.g. git.state.fields[].enum
        if isinstance(value, list) and isinstance(schema.get("items"), dict):
            item_enum = schema["items"].get("enum")
            if item_enum is not None:
                for item in value:
                    if item not in item_enum:
                        raise Reject("REJECT_ENUM", f"{key} item {item!r} not in enum")


def check_unknown_and_missing(tool_def: dict, args: dict) -> None:
    arg_schema = tool_def.get("args", {})
    props = arg_schema.get("properties", {}) or {}
    known = set(props.keys())
    # Sibling keys that are not `properties`/`required`/meta are field schemas.
    for key in arg_schema.keys():
        if key not in ("type", "properties", "required", "additionalProperties"):
            known.add(key)
    for key in args.keys():
        if key not in known:
            raise Reject("REJECT_ARG", f"unknown argument: {key!r}")
    for required in arg_schema.get("required", []):
        # A required arg whose value is None counts as missing (check.run base/head defaults).
        if required not in args or args[required] is None:
            raise Reject("REJECT_ARG", f"missing required argument: {required!r}")


_TYPE_CHECKS = {
    "string": str,
    "integer": int,
    "boolean": bool,
    "array": list,
    "object": dict,
}


def _matches_type(value, t: str) -> bool:
    if t == "integer":
        # bool is a subclass of int in Python; reject it explicitly.
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "boolean":
        return isinstance(value, bool)
    py = _TYPE_CHECKS.get(t)
    return py is not None and isinstance(value, py)


def check_types_patterns_bounds(tool: str, tool_def: dict, args: dict) -> None:
    """Validate types, anchored patterns, and numeric/length bounds.

    Pattern failures raise REJECT_PATTERN (F-01, F-13, F-36, F-69);
    pure bound failures (content size, integer ranges, item counts)
    raise REJECT_ARG.
    """
    arg_schema = tool_def.get("args", {})
    props = arg_schema.get("properties", {}) or {}
    for key, value in args.items():
        if value is None:
            continue
        schema = None
        if key in props:
            schema = props[key]
        elif key in arg_schema:
            schema = arg_schema[key]
        if not isinstance(schema, dict):
            continue
        # --- type ---
        t = schema.get("type")
        if t is not None and not _matches_type(value, t):
            raise Reject("REJECT_ARG", f"{key}: expected type {t}, got {type(value).__name__}")
        # --- pattern ---
        pattern = schema.get("pattern")
        if pattern is not None and isinstance(value, str):
            try:
                if not re.fullmatch(pattern, value):
                    raise Reject("REJECT_PATTERN", f"{key} does not match {pattern!r}")
            except re.error:
                # A broken registry pattern must fail closed as ARG.
                raise Reject("REJECT_ARG", f"{key}: invalid registry pattern")
        # --- leading dash on any string value (belt-and-braces) ---
        if isinstance(value, str) and value.startswith("-"):
            raise Reject("REJECT_PATTERN", f"{key} must not start with a dash")
        # --- numeric bounds ---
        if isinstance(value, int) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                raise Reject("REJECT_ARG", f"{key} below minimum")
            if "maximum" in schema and value > schema["maximum"]:
                raise Reject("REJECT_ARG", f"{key} above maximum")
        # --- string length bounds (when no pattern covered them) ---
        if isinstance(value, str):
            if pattern is None:
                if "minLength" in schema and len(value) < schema["minLength"]:
                    raise Reject("REJECT_ARG", f"{key} shorter than minLength")
                if "maxLength" in schema and len(value) > schema["maxLength"]:
                    raise Reject("REJECT_ARG", f"{key} longer than maxLength")
            elif "maxLength" in schema or "minLength" in schema:
                # Pattern already encodes its own bounds; a divergent
                # recorded bound mismatch is treated as ARG.
                if "maxLength" in schema and len(value) > schema["maxLength"]:
                    raise Reject("REJECT_ARG", f"{key} longer than maxLength")
                if "minLength" in schema and len(value) < schema["minLength"]:
                    raise Reject("REJECT_ARG", f"{key} shorter than minLength")
        # --- array bounds ---
        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                raise Reject("REJECT_ARG", f"{key} fewer than minItems")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                raise Reject("REJECT_ARG", f"{key} more than maxItems")
            # Array item patterns (e.g. git.commit.paths[]).
            item_schema = schema.get("items")
            if isinstance(item_schema, dict) and isinstance(item_schema.get("pattern"), str):
                for item in value:
                    if isinstance(item, str) and not re.fullmatch(item_schema["pattern"], item):
                        raise Reject("REJECT_PATTERN", f"{key} item does not match pattern")
        # --- object size cap (ledger.record) ---
        if isinstance(value, dict) and key == "record":
            import json

            if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > 262144:
                raise Reject("REJECT_ARG", "record exceeds 262144 bytes")


def validate_args(tool: str, tool_def: dict, args: dict) -> None:
    """Generic validation steps in controls-compatible order."""
    if not isinstance(args, dict):
        raise Reject("REJECT_ARG", "args must be an object")
    # 1) enum for present known fields
    check_enum(tool_def, args)
    # 2) traversal / absolute paths (before unknown/pattern)
    props = tool_def.get("args", {}).get("properties", {}) or {}
    arg_schema = tool_def.get("args", {})
    for key, value in args.items():
        if not is_path_field(tool, key):
            continue
        if isinstance(value, str) and is_traversal_or_absolute(tool, key, value):
            raise Reject("REJECT_PATH", f"{key}: non-normalized or out-of-tree path")
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and is_traversal_or_absolute(tool, key, item):
                    raise Reject("REJECT_PATH", f"{key} item: non-normalized or out-of-tree path")
    # 3) unknown + missing
    check_unknown_and_missing(tool_def, args)
    # 4) types / patterns / bounds
    check_types_patterns_bounds(tool, tool_def, args)
