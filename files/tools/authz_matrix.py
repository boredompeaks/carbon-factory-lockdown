#!/usr/bin/env python
"""Enumerate the authorization surface of a Django project.

The tool walks Django's URL resolver (including DRF router-generated patterns
already exposed by the resolver), derives the permission classes in effect for
every route + HTTP method, and emits a stable matrix row per (route, method).

Exit codes
----------
0   Matrix complete: every row has a derivation other than UNKNOWN and every
    --require-route route is present.
1   At least one row is missing/UNKNOWN, or a --require-route route is absent.
2   Tool error (Django import/setup, settings, resolver, roles file, output).

Row shape (stable keys)
-----------------------
route, name, view, module, methods, permission_classes, gate, derivation, roles,
expected, missing_row, source

`methods` is `[method]` for a per-method row, or `["*"]` when the view exposes
no derivable method.  `expected` maps every role name to "allow"/"deny".
`gate` lists decorator or helper symbols that carry a gate the DRF permission
classes do not express (for example `staff_only` or `require_admin_session`).

Derivation enum
---------------
PUBLIC | AUTHENTICATED | STAFF | CAPABILITY | OWNER | UNKNOWN
"""

from __future__ import annotations

import argparse
import fnmatch
import inspect
import json
import os
import re
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

TOOL = "authz_matrix"
VERSION = "1.0.0"
SCHEMA = "factory-tool/1"
HERE = Path(__file__).resolve().parent

HTTP_METHODS = ("get", "post", "put", "patch", "delete")
DERIVATIONS = ("PUBLIC", "AUTHENTICATED", "STAFF", "CAPABILITY", "OWNER", "UNKNOWN")
DERIVATION_RANK = {
    "UNKNOWN": 0,
    "PUBLIC": 1,
    "AUTHENTICATED": 2,
    "STAFF": 3,
    "OWNER": 4,
    "CAPABILITY": 5,
}
ROUTER_CRUD_ACTIONS = {
    "list",
    "create",
    "retrieve",
    "update",
    "partial_update",
    "destroy",
}
DEFAULT_EXCLUDES = ("admin/**", "__debug__/**", "media/**", "static/**")

# Permission classes whose name alone does not follow the HasX convention but
# whose semantics are known in this codebase.  Capability-bearing classes are
# discovered from their `capability`/`write_capability` attributes first.
KNOWN_PERMISSIONS = {
    "IsPrivilegedRole": ("CAPABILITY", "staff.manage"),
    "IsAuthenticatedOrSubmittedEmail": ("AUTHENTICATED", None),
}

# Function decorators and in-body gate helpers.  DRF permission classes are
# read from the view; these carry gates that never appear there: a plain
# Django function view wrapped in @staff_only, or a view that calls an
# admin-session helper before touching the request.  Symbol matching is
# deliberately narrow (call syntax or decorator syntax) so a docstring that
# mentions the helper is not treated as a gate.
GATE_SYMBOLS = {
    "STAFF": (
        "staff_only",
        "staff_member_required",
        "require_admin_session",
        "viewable_model_admin",
        "has_view_permission",
        "user.is_staff",
    ),
    "CAPABILITY": (
        "permission_required",
        "capability_required",
        "user_has_capability",
        "has_capability",
    ),
    "AUTHENTICATED": (
        "login_required",
        "user.is_authenticated",
    ),
}
GATE_RANK = {"AUTHENTICATED": 1, "STAFF": 2, "CAPABILITY": 3}


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def discover_git_root(start: Path | None = None) -> Path | None:
    """Discover the enclosing git top-level, or None.

    Tries ``git rev-parse --show-toplevel`` from ``start`` (default cwd)
    first, then walks parents of ``start``/``__file__``/cwd looking for a
    ``.git`` entry, so a bare ``--repo`` default elsewhere cannot mask a
    missing path.
    """
    base = (start or Path.cwd()).expanduser().resolve()
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(base),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            candidate = Path(proc.stdout.strip())
            if candidate.is_dir():
                return candidate
    except (OSError, subprocess.TimeoutExpired):
        pass
    for anchor in (base, Path(__file__).resolve().parent, Path.cwd().resolve()):
        current = anchor
        while True:
            if (current / ".git").exists():
                return current
            if current.parent == current:
                break
            current = current.parent
    return None


def resolve_repo(value: str | None) -> Path | None:
    """Resolve --repo or fall back to git-root discovery. None if neither."""
    if value:
        return Path(value).expanduser().resolve()
    return discover_git_root()


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def bootstrap_django(repo: Path) -> dict:
    """Put Django on the path and configure settings.

    Real project layout: <repo>/backend/manage.py + <repo>/backend/config.
    Control-fixture layout: a package (with __init__.py) containing urls.py;
    a minimal in-memory settings object is configured for it.
    """
    backend = repo / "backend"
    if (backend / "manage.py").is_file():
        sys.path.insert(0, str(backend))
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
        os.environ.setdefault("DJANGO_DEBUG", "true")
        # config.settings resolves .env relative to the process cwd.
        os.chdir(backend)
        return {
            "mode": "repo",
            "root": str(backend),
            "settings": os.environ["DJANGO_SETTINGS_MODULE"],
        }

    if not (repo / "urls.py").is_file():
        raise RuntimeError(
            f"{repo} is neither a Django repo (backend/manage.py) nor a "
            "control fixture (urls.py)"
        )

    parent = repo.parent
    if not (repo / "__init__.py").is_file():
        raise RuntimeError(
            f"control fixture {repo} needs __init__.py so ROOT_URLCONF can be "
            "imported as a package"
        )
    sys.path.insert(0, str(parent))
    root_urlconf = f"{repo.name}.urls"

    from django.conf import settings as django_settings

    if not django_settings.configured:
        django_settings.configure(
            DEBUG=True,
            SECRET_KEY="authz-matrix-control-fixture",
            ROOT_URLCONF=root_urlconf,
            INSTALLED_APPS=[
                "django.contrib.contenttypes",
                "django.contrib.auth",
                "rest_framework",
            ],
            DATABASES={
                "default": {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": ":memory:",
                }
            },
            USE_TZ=True,
            DEFAULT_AUTO_FIELD="django.db.models.AutoField",
        )
    return {
        "mode": "fixture",
        "root": str(repo),
        "settings": root_urlconf,
    }


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


def _capability_values(value: object) -> list[str]:
    if isinstance(value, dict):
        value = value.get("roles", [])
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(item) for item in value]
    return []


def load_roles(roles_file: str | None) -> tuple[list[str], dict[str, set[str]], str]:
    if roles_file:
        data = json.loads(Path(roles_file).read_text(encoding="utf-8"))
        roles = [str(role) for role in data.get("roles", [])]
        capabilities = {
            str(name): set(_capability_values(value))
            for name, value in (data.get("capabilities") or {}).items()
        }
        if not roles:
            raise RuntimeError(f"roles file {roles_file} has no 'roles' list")
        return list(dict.fromkeys(roles)), capabilities, "roles-file"

    import common.roles as role_module

    roles: list[str] = []
    staff_roles = getattr(role_module, "STAFF_ROLES", ())
    for role in staff_roles:
        if isinstance(role, str) and role not in roles:
            roles.append(role)
    for key, value in vars(role_module).items():
        if key.startswith("ROLE_") and isinstance(value, str) and value not in roles:
            roles.append(value)
    if not roles:
        raise RuntimeError("common.roles exposes no ROLE_* constants")

    capabilities = {
        str(name): set(_capability_values(value))
        for name, value in getattr(role_module, "CAPABILITY_ROLES", {}).items()
    }
    return roles, capabilities, "common.roles"


# ---------------------------------------------------------------------------
# URL walking
# ---------------------------------------------------------------------------


def pattern_fragment(pattern: object) -> str:
    route = getattr(pattern, "_route", None)
    if route is not None:
        return str(route)
    regex = getattr(pattern, "regex", None)
    if regex is not None:
        value = regex.pattern
        value = value.removeprefix("^")
        if value.endswith("$"):
            value = value[:-1]
        return value
    return str(pattern)


def concat_route(prefix: str, fragment: str) -> str:
    fragment = fragment or ""
    if not prefix:
        return fragment
    if not fragment:
        return prefix
    return prefix.rstrip("/") + "/" + fragment.lstrip("/")


def full_route(prefix: str, fragment: str) -> str:
    route = concat_route(prefix, fragment).lstrip("/")
    return "/" + route if route else "/"


def safe_getattr(obj: object, name: str, default: object = None) -> object:
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def wrapped_chain(callable_obj: object):
    seen: set[int] = set()
    current = callable_obj
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = safe_getattr(current, "__wrapped__")


def class_for(callback: object):
    return safe_getattr(callback, "view_class") or safe_getattr(callback, "cls")


def is_wrapped_api_view(cls: object) -> bool:
    qualname = str(safe_getattr(cls, "__qualname__", ""))
    return qualname == "WrappedAPIView" or qualname.endswith(".WrappedAPIView")


def callable_name(callback: object, cls: object) -> tuple[str, str]:
    """Return (dotted view, module)."""
    # DRF's @api_view creates a WrappedAPIView whose __name__ is the original
    # function but whose __qualname__ is the generic "WrappedAPIView".
    if cls is not None:
        cls_name = str(safe_getattr(cls, "__name__", "view"))
        if not is_wrapped_api_view(cls):
            cls_name = str(safe_getattr(cls, "__qualname__", cls_name))
        module = str(safe_getattr(cls, "__module__", "?"))
        return f"{module}.{cls_name}", module
    module = str(safe_getattr(callback, "__module__", "?"))
    qualname = str(safe_getattr(callback, "__qualname__", safe_getattr(callback, "__name__", "view")))
    return f"{module}.{qualname}", module


def permission_classes_for(callback: object, cls: object) -> list:
    classes: list = []
    for candidate in wrapped_chain(callback):
        value = safe_getattr(candidate, "permission_classes", None)
        if value:
            classes.extend(value if isinstance(value, (list, tuple)) else [value])

    if cls is not None:
        raw = safe_getattr(cls, "permission_classes", None)
        # Only instantiate when the class resolves permissions dynamically or
        # has no static list to read.
        if "get_permissions" in getattr(cls, "__dict__", {}) or raw is None:
            if hasattr(cls, "get_permissions"):
                try:
                    instance = cls()
                    resolved = instance.get_permissions()
                    if resolved is not None:
                        raw = resolved
                except Exception:
                    pass
        if raw:
            classes = list(raw)

    # De-duplicate while keeping declaration order.
    result: list = []
    for permission in classes:
        if permission not in result:
            result.append(permission)
    return result


def permission_name(permission: object) -> str:
    if inspect.isclass(permission):
        return permission.__name__
    return type(permission).__name__


def _function_source(callable_obj: object) -> str:
    try:
        return inspect.getsource(callable_obj)
    except (OSError, TypeError):
        return ""


def _gate_hits(source: str) -> list[str]:
    return [
        symbol
        for symbols in GATE_SYMBOLS.values()
        for symbol in symbols
        if symbol in source
    ]


def detect_gate(callback: object) -> tuple[str | None, list[str]]:
    """Resolve gates carried by decorators or in-body helper calls.

    DRF views expose permission classes; plain Django views and the
    before-the-admin helpers do not.  A wrapper's qualname names the
    decorator (`staff_only.<locals>.guarded`), and the source of the view
    body names the helper it calls (`require_admin_session`, ...).  Both are
    evidence of a gate the permission list cannot see.
    """
    symbols: list[str] = []

    def remember(values: list[str]) -> None:
        for value in values:
            if value not in symbols:
                symbols.append(value)

    for candidate in wrapped_chain(callback):
        qualname = str(safe_getattr(candidate, "__qualname__", ""))
        if ".<locals>." in qualname:
            remember([qualname.split(".<locals>.", 1)[0].rsplit(".", 1)[-1]])
        remember(_gate_hits(_function_source(candidate)))
        try:
            closure = inspect.getclosurevars(candidate)
        except Exception:
            continue
        for value in closure.nonlocals.values():
            if callable(value):
                remember(_gate_hits(_function_source(value)))

    best: str | None = None
    for derivation, needles in GATE_SYMBOLS.items():
        if any(needle in symbols for needle in needles):
            if best is None or GATE_RANK[derivation] > GATE_RANK[best]:
                best = derivation
    return best, symbols


def apply_gate(derivation: str, gate: str | None) -> str:
    """A resolved gate may raise a PUBLIC/UNKNOWN/AUTHENTICATED row, never lower it."""
    if gate is None:
        return derivation
    if derivation in {"PUBLIC", "UNKNOWN", "AUTHENTICATED"}:
        return gate
    return derivation


def _closure_capabilities(callback: object) -> list[str]:
    found: list[str] = []
    for candidate in wrapped_chain(callback):
        for attr in ("capability", "capabilities"):
            value = safe_getattr(candidate, attr, None)
            if isinstance(value, str):
                found.append(value)
            elif isinstance(value, (list, tuple, set)):
                found.extend(str(item) for item in value)
        try:
            closure = inspect.getclosurevars(candidate)
        except Exception:
            continue
        for name in ("capability", "capabilities"):
            value = closure.nonlocals.get(name)
            if isinstance(value, str):
                found.append(value)
            elif isinstance(value, (list, tuple, set)):
                found.extend(str(item) for item in value)
    return list(dict.fromkeys(found))


def _function_methods(callback: object) -> list[str]:
    for candidate in wrapped_chain(callback):
        value = safe_getattr(candidate, "require_http_methods", None)
        if isinstance(value, (list, tuple, set)):
            methods = [str(item).lower() for item in value]
            methods = [m for m in methods if m in HTTP_METHODS]
            if methods:
                return methods
        try:
            closure = inspect.getclosurevars(candidate)
        except Exception:
            continue
        value = closure.nonlocals.get("request_method_list")
        if isinstance(value, (list, tuple, set)):
            methods = [str(item).lower() for item in value]
            methods = [m for m in methods if m in HTTP_METHODS]
            if methods:
                return methods
    return []


def methods_for(callback: object, cls: object, action_method: str | None = None) -> list[str]:
    if action_method:
        method = action_method.lower()
        return [method] if method in HTTP_METHODS else ["*"]

    if cls is not None:
        allowed = set(str(m).lower() for m in safe_getattr(cls, "http_method_names", HTTP_METHODS) or HTTP_METHODS)
        methods = [
            method
            for method in HTTP_METHODS
            if method in allowed and callable(safe_getattr(cls, method, None))
        ]
        if methods:
            return methods

    methods = _function_methods(callback)
    return methods or ["*"]


def view_capabilities(callback: object, cls: object, action: str | None) -> list[str]:
    found: list[str] = []
    for source in (cls, callback):
        if source is None:
            continue
        mapping = safe_getattr(source, "capability_map", None)
        if isinstance(mapping, dict) and action:
            for key in (action, action.replace("_", "-")):
                value = mapping.get(key)
                if isinstance(value, str):
                    found.append(value)
                elif isinstance(value, (list, tuple, set)):
                    found.extend(str(item) for item in value)
        value = safe_getattr(source, "capability", None)
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, (list, tuple, set)):
            found.extend(str(item) for item in value)
    found.extend(_closure_capabilities(callback))
    return list(dict.fromkeys(found))


def capability_from_class_name(name: str) -> str | None:
    """HasWidgetWrite -> widget.write; HasProductsWriteOrReadOnly -> products.write."""
    if not name.startswith("Has"):
        return None
    base = name[3:]
    for suffix in ("OrReadOnly", "Permission"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    if not base:
        return None
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", base).lower()
    return snake.replace("_", ".", 1)


def classify_permission(
    permission: object, method: str, capabilities: dict[str, set[str]]
) -> tuple[str, list[str], bool]:
    """Return (derivation, capabilities required, missing capability mapping)."""
    name = permission_name(permission)
    capability = safe_getattr(permission, "capability", None)
    if isinstance(capability, str) and capability:
        return "CAPABILITY", [capability], capability not in capabilities

    write_capability = safe_getattr(permission, "write_capability", None)
    if write_capability is not None:
        # SAFE_METHODS are public for this permission shape; writes need the
        # pinned capability.
        if method == "get":
            return "PUBLIC", [], False
        if isinstance(write_capability, str) and write_capability:
            return (
                "CAPABILITY",
                [write_capability],
                write_capability not in capabilities,
            )

    if name in KNOWN_PERMISSIONS:
        derivation, known_capability = KNOWN_PERMISSIONS[name]
        caps = [known_capability] if known_capability else []
        return derivation, caps, bool(known_capability and known_capability not in capabilities)

    if name == "AllowAny":
        return "PUBLIC", [], False

    if "Owner" in name or "Object" in name:
        return "OWNER", [], False

    mapped = capability_from_class_name(name)
    if mapped:
        return "CAPABILITY", [mapped], mapped not in capabilities

    if name in {"IsAdminUser", "IsStaff"} or "Staff" in name or "Admin" in name:
        return "STAFF", [], False

    if name == "IsAuthenticated" or "Authenticated" in name:
        return "AUTHENTICATED", [], False

    return "UNKNOWN", [], False


def derive(
    permissions: list,
    method: str,
    view_caps: list[str],
    capabilities: dict[str, set[str]],
) -> tuple[str, list[str], bool]:
    if view_caps:
        missing = any(cap not in capabilities for cap in view_caps)
        return "CAPABILITY", view_caps, missing
    if not permissions:
        return "PUBLIC", [], False

    best = "PUBLIC"
    caps: list[str] = []
    missing = False
    for permission in permissions:
        derivation, required, lacks = classify_permission(permission, method, capabilities)
        missing = missing or lacks
        if derivation == "UNKNOWN":
            # An unclassifiable permission class means the row cannot be
            # trusted, regardless of what its siblings say.
            return "UNKNOWN", [], True
        if required:
            caps.extend(required)
        if DERIVATION_RANK[derivation] > DERIVATION_RANK[best]:
            best = derivation
    caps = list(dict.fromkeys(caps))
    return best, caps, missing


def expected_for(
    derivation: str,
    capabilities_required: list[str],
    roles: list[str],
    capabilities: dict[str, set[str]],
) -> tuple[dict[str, str], bool]:
    if not roles:
        return {}, True

    if derivation in {"PUBLIC", "AUTHENTICATED", "STAFF", "OWNER"}:
        return {role: "allow" for role in roles}, False

    if derivation == "CAPABILITY":
        if not capabilities_required:
            return {role: "deny" for role in roles}, True
        allowed = set(roles)
        missing = False
        for cap in capabilities_required:
            if cap not in capabilities:
                missing = True
                allowed = set()
                continue
            allowed &= set(capabilities[cap])
        return {
            role: "allow" if role in allowed else "deny" for role in roles
        }, missing

    return {role: "deny" for role in roles}, True


def admin_derive(route: str, derivation: str, admin_boundary: bool) -> str:
    """Apply the admin boundary carried by the resolver recursion.

    Django admin views have no DRF permission_classes, so the generic
    derivation sees an empty list and calls them PUBLIC. The boundary is known
    from the mount, not from the callback: everything under /admin/ is STAFF
    except the login and password-reset pages (PUBLIC) and logout
    (AUTHENTICATED). A CAPABILITY derivation already carries stronger
    information and is left alone.
    """
    if not admin_boundary:
        return derivation
    path = "/" + route.strip("/")
    public = (
        "/admin/login",
        "/admin/password_reset",
        "/admin/password_reset/done",
        "/admin/reset",
        "/admin/reset/done",
    )
    if path in public or path.startswith("/admin/password_reset/"):
        return "PUBLIC"
    if path == "/admin/logout":
        return "AUTHENTICATED"
    if derivation in {"PUBLIC", "AUTHENTICATED", "UNKNOWN"}:
        return "STAFF"
    return derivation


def build_rows(
    route: str,
    name: str | None,
    callback: object,
    roles: list[str],
    capabilities: dict[str, set[str]],
    admin_boundary: bool = False,
) -> list[dict]:
    cls = class_for(callback)
    actions = safe_getattr(callback, "actions", None)
    if not actions:
        initkwargs = safe_getattr(callback, "initkwargs", None)
        if isinstance(initkwargs, dict):
            actions = initkwargs.get("actions")
    permissions = permission_classes_for(callback, cls)
    declared = [permission_name(permission) for permission in permissions]
    gate, gate_symbols = detect_gate(callback)
    view_name, module = callable_name(callback, cls)

    if actions:
        rows: list[dict] = []
        for method, action in actions.items():
            method = str(method).lower()
            if method not in HTTP_METHODS:
                continue
            action = str(action)
            row_view = f"{view_name}.{action}"
            # A custom @action may pin its own permission_classes and may
            # carry its own decorator gate.
            action_permissions = permissions
            action_obj = safe_getattr(cls, action, None) if cls is not None else None
            action_gate, action_gate_symbols = (
                detect_gate(action_obj) if action_obj is not None else (gate, gate_symbols)
            )
            kwargs = safe_getattr(action_obj, "kwargs", None)
            if isinstance(kwargs, dict) and kwargs.get("permission_classes"):
                action_permissions = list(kwargs["permission_classes"])
            action_declared = [permission_name(permission) for permission in action_permissions]
            caps = view_capabilities(callback, cls, action)
            derivation, required, missing = derive(
                action_permissions, method, caps, capabilities
            )
            derivation = apply_gate(derivation, action_gate)
            derivation = admin_derive(route, derivation, admin_boundary)
            expected, missing_roles = expected_for(
                derivation, required, roles, capabilities
            )
            source = (
                "router"
                if action in ROUTER_CRUD_ACTIONS
                else "viewset_action"
            )
            rows.append(
                {
                    "route": route,
                    "name": name,
                    "view": row_view,
                    "module": module,
                    "methods": [method],
                    "permission_classes": action_declared,
                    "gate": action_gate_symbols,
                    "derivation": derivation,
                    "roles": list(roles),
                    "expected": expected,
                    "missing_row": bool(missing or missing_roles),
                    "source": source,
                }
            )
        if rows:
            return rows

    methods = methods_for(callback, cls)
    caps = view_capabilities(callback, cls, None)
    if methods == ["*"]:
        derivation, required, missing = derive(permissions, "get", caps, capabilities)
        derivation = apply_gate(derivation, gate)
        derivation = admin_derive(route, derivation, admin_boundary)
        expected, missing_roles = expected_for(
            derivation, required, roles, capabilities
        )
        return [
            {
                "route": route,
                "name": name,
                "view": view_name,
                "module": module,
                "methods": ["*"],
                "permission_classes": declared,
                "gate": gate_symbols,
                "derivation": derivation,
                "roles": list(roles),
                "expected": expected,
                "missing_row": bool(missing or missing_roles),
                "source": "function"
                if cls is None or is_wrapped_api_view(cls)
                else "resolver",
            }
        ]

    rows = []
    for method in methods:
        derivation, required, missing = derive(permissions, method, caps, capabilities)
        derivation = apply_gate(derivation, gate)
        derivation = admin_derive(route, derivation, admin_boundary)
        expected, missing_roles = expected_for(
            derivation, required, roles, capabilities
        )
        rows.append(
            {
                "route": route,
                "name": name,
                "view": view_name,
                "module": module,
                "methods": [method],
                "permission_classes": declared,
                "gate": gate_symbols,
                "derivation": derivation,
                "roles": list(roles),
                "expected": expected,
                "missing_row": bool(missing or missing_roles),
                "source": "function"
                if cls is None or is_wrapped_api_view(cls)
                else "resolver",
            }
        )
    return rows


def collect_rows(roles: list[str], capabilities: dict[str, set[str]]) -> tuple[list[dict], dict]:
    from django.urls import URLPattern, URLResolver, get_resolver

    resolved = get_resolver()
    rows: list[dict] = []
    route_strings: set[str] = set()
    resolver_errors: list[str] = []

    def add_rows(route: str, name: str | None, callback: object, admin_boundary: bool = False) -> None:
        new_rows = build_rows(route, name, callback, roles, capabilities, admin_boundary)
        if not new_rows:
            return
        route_strings.add(route)
        for row in new_rows:
            key = (row["route"], row["name"], row["view"], row["methods"][0])
            if any(
                (existing["route"], existing["name"], existing["view"], existing["methods"][0])
                == key
                for existing in rows
            ):
                continue
            rows.append(row)

    def walk(resolver, prefix: str = "", namespace: str = "", admin_boundary: bool = False) -> None:
        try:
            patterns = resolver.url_patterns
        except Exception as exc:  # noqa: BLE001 - surfaced as tool error
            resolver_errors.append(f"{resolver!r}: {exc}")
            return
        for entry in patterns:
            if isinstance(entry, URLResolver):
                fragment = pattern_fragment(entry.pattern)
                child_namespace = namespace
                if entry.namespace:
                    child_namespace += f"{entry.namespace}:"
                child_admin = admin_boundary or fragment.strip("/") == "admin"
                walk(entry, concat_route(prefix, fragment), child_namespace, child_admin)
                continue
            if isinstance(entry, URLPattern):
                route = full_route(prefix, pattern_fragment(entry.pattern))
                name = f"{namespace}{entry.name}" if entry.name else None
                add_rows(route, name, entry.callback, admin_boundary)
                continue

            # Some resolver implementations expose a router-shaped object
            # rather than plain URLResolver/URLPattern entries.
            nested = safe_getattr(entry, "urls", None)
            if nested is not None:
                for child in nested:
                    fragment = pattern_fragment(safe_getattr(child, "pattern", ""))
                    route = full_route(prefix, fragment)
                    name = safe_getattr(child, "name", None)
                    callback = safe_getattr(child, "callback", None)
                    if callback is not None:
                        add_rows(route, name, callback)
                continue

            resolver_errors.append(
                f"unrecognised resolver entry {entry!r} at {prefix or '/'}"
            )

    walk(resolved)
    if resolver_errors:
        raise RuntimeError("resolver walk failed: " + "; ".join(resolver_errors))
    return rows, {"routes": len(route_strings)}


# ---------------------------------------------------------------------------
# Filters / output
# ---------------------------------------------------------------------------


def matches_any(route: str, module: str, patterns: list[str]) -> bool:
    targets = [
        route,
        route.lstrip("/"),
        "/" + route.lstrip("/"),
        module,
        module.replace(".", "/"),
    ]
    for pattern in patterns:
        pattern = pattern.strip()
        if not pattern:
            continue
        for target in targets:
            if fnmatch.fnmatchcase(target, pattern) or fnmatch.fnmatchcase(
                "/" + target.lstrip("/"), pattern
            ):
                return True
    return False


def filter_rows(
    rows: list[dict], include: list[str], exclude: list[str]
) -> tuple[list[dict], int]:
    kept: list[dict] = []
    excluded_routes: set[str] = set()
    for row in rows:
        if include and not matches_any(row["route"], row["module"], include):
            excluded_routes.add(row["route"])
            continue
        if matches_any(row["route"], row["module"], exclude):
            excluded_routes.add(row["route"])
            continue
        kept.append(row)
    return kept, len(excluded_routes)


def normalise_required_route(value: str) -> str:
    value = value.strip()
    if not value:
        return "/"
    return "/" + value.strip("/") + "/"


def summarise(rows: list[dict], routes: int, required_missing: list[str]) -> dict:
    derivations = {name: 0 for name in DERIVATIONS}
    sources = {"resolver": 0, "router": 0, "viewset_action": 0, "function": 0}
    for row in rows:
        derivations[row["derivation"]] = derivations.get(row["derivation"], 0) + 1
        sources[row["source"]] = sources.get(row["source"], 0) + 1
    return {
        "routes": routes,
        "rows": len(rows),
        "missing_rows": sum(1 for row in rows if row["missing_row"]),
        "derivations": derivations,
        "sources": sources,
        "required_routes_missing": required_missing,
    }


def print_summary(summary: dict) -> None:
    eprint(
        "authz_matrix: "
        f"routes={summary['routes']} rows={summary['rows']} "
        f"missing={summary['missing_rows']}"
    )
    eprint(
        "  derivations: "
        + " ".join(
            f"{name}={count}" for name, count in summary["derivations"].items()
        )
    )
    eprint(
        "  sources: "
        + " ".join(f"{name}={count}" for name, count in summary["sources"].items())
    )
    if summary["required_routes_missing"]:
        eprint(
            "  required routes missing: "
            + ", ".join(summary["required_routes_missing"])
        )
    if summary.get("required_derivations_missing"):
        eprint(
            "  required derivations missing: "
            + ", ".join(summary["required_derivations_missing"])
        )


# ---------------------------------------------------------------------------
# Control (multi-role, read-only)
# ---------------------------------------------------------------------------


def envelope(result_type: str, findings: list, control_doc: dict, exit_code: int, extras: dict) -> dict:
    doc = {
        "schema": SCHEMA,
        "tool": TOOL,
        "version": VERSION,
        "interpreter": sys.executable,
        "result_type": result_type,
        "findings": findings,
        "control": control_doc,
        "exit_code": exit_code,
    }
    doc.update(extras)
    return doc


def control() -> dict:
    """Multi-role control over OWNER, UNKNOWN and unmapped capabilities.

    Read-only: bootstraps the ``authz_multi`` fixture in-process, collects
    rows with three roles (admin/editor/viewer) and asserts per-case JSON
    (route, method, derivation, per-role expected map, missing_row, roles),
    not just an exit code.
    """
    fixtures = HERE / "fixtures" / "authz_multi"
    roles_file = fixtures / "roles.json"
    bootstrap_django(fixtures)
    import django

    try:
        from django.apps import apps

        if not apps.ready:
            django.setup()
    except Exception:
        try:
            django.setup()
        except Exception:
            pass
    roles, capabilities, _roles_source = load_roles(str(roles_file))
    rows, _walk_info = collect_rows(roles, capabilities)
    rows, _excluded = filter_rows(rows, [], list(DEFAULT_EXCLUDES))
    by_key = {(row["route"], row["methods"][0]): row for row in rows}
    roles_list = list(roles)
    expectations = [
        {
            "name": "authz_multi/owner",
            "route": "/owner/",
            "method": "get",
            "derivation": "OWNER",
            "expected": {role: "allow" for role in roles_list},
            "missing_row": False,
        },
        {
            "name": "authz_multi/unknown",
            "route": "/unknown/",
            "method": "get",
            "derivation": "UNKNOWN",
            "expected": {role: "deny" for role in roles_list},
            "missing_row": True,
        },
        {
            "name": "authz_multi/unmapped",
            "route": "/unmapped/",
            "method": "get",
            "derivation": "CAPABILITY",
            "expected": {role: "deny" for role in roles_list},
            "missing_row": True,
        },
        {
            "name": "authz_multi/cap",
            "route": "/cap/",
            "method": "get",
            "derivation": "CAPABILITY",
            "expected": {"admin": "allow", "editor": "allow", "viewer": "deny"},
            "missing_row": False,
        },
    ]
    cases: list[dict] = []
    for spec in expectations:
        row = by_key.get((spec["route"], spec["method"]))
        expected_view = {
            "route": spec["route"],
            "method": spec["method"],
            "derivation": spec["derivation"],
            "expected": spec["expected"],
            "missing_row": spec["missing_row"],
            "roles": roles_list,
        }
        if row is None:
            cases.append(
                {
                    "name": spec["name"],
                    "passed": False,
                    "expected": expected_view,
                    "actual": None,
                }
            )
            continue
        actual_view = {
            "route": row["route"],
            "method": row["methods"][0],
            "view": row["view"],
            "permission_classes": list(row["permission_classes"]),
            "derivation": row["derivation"],
            "expected": dict(row["expected"]),
            "missing_row": row["missing_row"],
            "roles": list(row["roles"]),
        }
        passed = (
            actual_view["derivation"] == spec["derivation"]
            and actual_view["expected"] == spec["expected"]
            and actual_view["missing_row"] is spec["missing_row"]
            and actual_view["roles"] == roles_list
        )
        cases.append(
            {
                "name": spec["name"],
                "passed": bool(passed),
                "expected": expected_view,
                "actual": actual_view,
            }
        )
    return {"ran": True, "passed": all(case["passed"] for case in cases), "cases": cases}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build an authorization matrix for a Django/DRF project.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes: 0 complete, 1 missing/UNKNOWN row or missing required "
            "route, 2 tool error.\n"
            "Rows are emitted per (route, method); methods is [method] or ['*']."
        ),
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="repo root (required for matrix mode; defaults to the discovered git top-level)",
    )
    parser.add_argument("--control", action="store_true", help="run the read-only multi-role control")
    parser.add_argument(
        "--out",
        default=None,
        help="write JSON here (default: stdout)",
    )
    parser.add_argument("--summary", action="store_true", help="print counts to stderr")
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="GLOB",
        help="only keep routes/modules matching this glob (repeatable)",
    )
    parser.add_argument(
        "--route",
        action="append",
        default=[],
        metavar="GLOB",
        help="only keep routes matching this glob; overrides the default excludes (repeatable)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="drop routes/modules matching this glob (repeatable)",
    )
    parser.add_argument(
        "--roles-file",
        default=None,
        metavar="JSON",
        help='override roles: {"roles": [...], "capabilities": {...}}',
    )
    parser.add_argument(
        "--require-route",
        action="append",
        default=[],
        metavar="ROUTE",
        help="exit 1 if this route is absent from the emitted matrix (repeatable)",
    )
    parser.add_argument(
        "--require-derivation",
        action="append",
        default=[],
        metavar="ROUTE=DERIVATION",
        help="exit 1 if the route's rows do not all carry this derivation (repeatable)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.control:
        try:
            control_doc = control()
        except Exception as exc:  # noqa: BLE001 - surfaced as control failure
            control_doc = {
                "ran": True,
                "passed": False,
                "cases": [],
                "error": f"{type(exc).__name__}: {exc}",
            }
        result_type = "RESULT" if control_doc["passed"] else "CONTROL_FAIL"
        code = 0 if control_doc["passed"] else 1
        doc = envelope(result_type, [], control_doc, code, {})
        sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
        return code
    repo = resolve_repo(args.repo)
    if repo is None:
        eprint("authz_matrix: --repo is required (no git top-level discovered)")
        return 2
    if not repo.is_dir():
        eprint(f"authz_matrix: repo not found: {repo}")
        return 2

    out_path = Path(args.out).expanduser().resolve() if args.out else None
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    roles_path = (
        Path(args.roles_file).expanduser().resolve() if args.roles_file else None
    )

    try:
        bootstrap = bootstrap_django(repo)
        import django

        django.setup()

        roles, capabilities, roles_source = load_roles(
            str(roles_path) if roles_path is not None else None
        )
        rows, walk_info = collect_rows(roles, capabilities)

        excludes = list(DEFAULT_EXCLUDES) + list(args.exclude)
        includes = list(args.include) + list(args.route)
        if args.route:
            # An explicit route filter is authoritative: the default admin/
            # exclusion must not hide the thing the caller asked to inspect.
            excludes = list(args.exclude)
        rows, excluded_routes = filter_rows(rows, includes, excludes)

        emitted_routes = {row["route"] for row in rows}
        required_missing: list[str] = []
        for required in args.require_route:
            expected_route = normalise_required_route(required)
            if expected_route not in emitted_routes:
                required_missing.append(expected_route)

        required_derivation_missing: list[str] = []
        for spec in args.require_derivation:
            route_part, separator, derivation_part = spec.partition("=")
            if not separator or not derivation_part:
                raise RuntimeError(
                    f"--require-derivation expects ROUTE=DERIVATION, got {spec!r}"
                )
            expected_route = normalise_required_route(route_part)
            matched = [row for row in rows if row["route"] == expected_route]
            if not matched or any(
                row["derivation"] != derivation_part for row in matched
            ):
                required_derivation_missing.append(
                    f"{expected_route}={derivation_part}"
                )

        summary = summarise(rows, len(emitted_routes), required_missing)
        summary["required_derivations_missing"] = required_derivation_missing
        summary["excluded_routes"] = excluded_routes
        summary["roles_source"] = roles_source
        summary["all_routes_before_filters"] = walk_info["routes"]

        matrix = {
            "tool": "authz_matrix",
            "repo": str(repo),
            "settings": bootstrap["settings"],
            "mode": bootstrap["mode"],
            "django_version": django.get_version(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "filters": {
                "include": list(args.include),
                "exclude": excludes,
            },
            "summary": summary,
            "rows": rows,
        }

        encoded = json.dumps(matrix, indent=2, ensure_ascii=False)
        if out_path is not None:
            out_path.write_text(encoded + "\n", encoding="utf-8")
        else:
            sys.stdout.write(encoded + "\n")

        if args.summary:
            print_summary(summary)

        if summary["missing_rows"] or required_missing or required_derivation_missing:
            return 1
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        eprint(f"authz_matrix: tool error: {type(exc).__name__}: {exc}")
        if os.environ.get("AUTHZ_MATRIX_TRACEBACK"):
            traceback.print_exc()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
