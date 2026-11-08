#!/usr/bin/env python3
"""Redaction runner implementing the runner-patch steps of
files/policies/redaction.json (stdlib only).

Policy contract (redaction.json, "high_entropy_fallback.note" + on_match_fail_variant):
  1. Compile secret_patterns first, then pii_patterns ("ordering"),
     honoring each pattern's "flags" field ('i'/'m'/'s'/'x').
  2. Replace matched spans with each pattern's "replacement".
     Matches are computed on the ORIGINAL text and resolved
     longest-span-first, so a replacement placeholder is never
     re-scanned by a later pattern. Every overlapping match that is
     skipped is recorded in the result (overlap diagnostics).
  3. Scan the residue (with placeholder spans masked out) with the
     regex_probe ([A-Za-z0-9+/=_-]{20,}) and a Shannon entropy
     threshold (default 4.5 bits/char), excluding allowlisted
     UUID / commit-SHA shapes. Pure-hex tokens can never reach
     4.5 bits/char, so SHAs are also naturally below threshold.
  4. If any residue hit fires and fail_on_unredactable is true,
     raise UnredactableSecret and suppress artifact output
     (the runner writes nothing for that artifact - no partial write).
  5. Also raise when on_match_fail_variant fires: after replacement,
     a re-scan of the placeholder-masked output still finds a named
     secret/PII pattern (overlapping match / malformed replacement
     left residue).

CLI:
  --input FILE --output FILE   redact a file (written atomically)
  --input FILE --check         check only: report, write nothing;
                               exit 0 clean, 1 unredactable
  --selftest                   run inline fixture tests

Exit codes: 0 ok / clean; 1 unredactable secret; 2 usage or I/O error.
Diagnostics never print the matched secret bytes - only pattern name,
span offsets, lengths, and entropy values.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

TOOL = "redaction_runner"
VERSION = "1.0.0"
SCHEMA = "factory-tool/1"

HERE = Path(__file__).resolve().parent
DEFAULT_POLICY = HERE.parent / "policies" / "redaction.json"

# Allowlist shapes excluded from the high-entropy probe scan.
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")  # full git commit SHA
# sha256 (64 hex): below the 4.5 bits/char ceiling anyway, allowlisted for clarity
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class UnredactableSecret(Exception):
    """A secret/PII pattern left residue, or the high-entropy fallback fired."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


@dataclass
class RedactionResult:
    redacted: str
    # applied replacements: {"name": ..., "kind": "secret"|"pii", "start": int, "end": int}
    redactions: list = field(default_factory=list)
    # overlapping matches skipped during resolution
    overlaps: list = field(default_factory=list)
    # probe hits that fired (only reported; never include the token bytes)
    probe_hits: list = field(default_factory=list)
    # named-pattern re-scan hits after replacement (fail-variant trigger)
    residue_hits: list = field(default_factory=list)


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char over the token's own alphabet."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _compile_flag(flagstr: str) -> int:
    flagmap = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL, "x": re.VERBOSE}
    flags = 0
    for ch in (flagstr or ""):
        flags |= flagmap.get(ch, 0)
    return flags


def load_policy(path: Path | str = DEFAULT_POLICY) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_patterns(policy: dict) -> list:
    """Return ordered [{'name','kind','regex','replacement','order'}].

    Secret patterns come first (order 0..), then PII, per the policy's
    "ordering": "secret_patterns_then_pii_patterns".
    """
    patterns = []
    order = 0
    for kind in ("secret_patterns", "pii_patterns"):
        for spec in policy.get(kind, []):
            patterns.append(
                {
                    "name": spec["name"],
                    "kind": "secret" if kind.startswith("secret") else "pii",
                    "regex": re.compile(spec["regex"], _compile_flag(spec.get("flags", ""))),
                    "replacement": spec["replacement"],
                    "order": order,
                }
            )
            order += 1
    return patterns


def _mask_spans(text: str, spans: list) -> str:
    """Blank out [start, end) spans with spaces (length-preserving)."""
    if not spans:
        return text
    chars = list(text)
    for s, e in spans:
        for i in range(s, e):
            chars[i] = " "
    return "".join(chars)


def _resolve_matches(text: str, patterns: list) -> tuple[list, list]:
    """All named matches on the original text, overlap-resolved longest-first."""
    found = []
    for pat in patterns:
        for m in pat["regex"].finditer(text):
            if m.end() > m.start():  # skip zero-width matches
                found.append(
                    {
                        "name": pat["name"],
                        "kind": pat["kind"],
                        "replacement": pat["replacement"],
                        "order": pat["order"],
                        "start": m.start(),
                        "end": m.end(),
                    }
                )
    # Longest span wins so an outer/complete match consumes a nested
    # secret (e.g. bearer over jwt); ties by pattern order, then start.
    found.sort(key=lambda x: (-(x["end"] - x["start"]), x["order"], x["start"]))
    accepted, overlaps = [], []
    for cand in found:
        clash = next(
            (a for a in accepted if cand["start"] < a["end"] and a["start"] < cand["end"]),
            None,
        )
        if clash:
            overlaps.append({**cand, "overlaps": clash["name"]})
        else:
            accepted.append(cand)
    accepted.sort(key=lambda x: x["start"])
    return accepted, overlaps


def _probe_residue(masked: str, policy: dict) -> list:
    """High-entropy probe hits in residue text (token bytes excluded)."""
    fb = policy.get("high_entropy_fallback", {})
    if not fb.get("enabled", False):
        return []
    probe = re.compile(fb["regex_probe"])
    threshold = float(fb.get("shannon_threshold_bits_per_char", 4.5))
    min_len = int(fb.get("min_length", 20))
    hits = []
    for m in probe.finditer(masked):
        token = m.group(0)
        if len(token) < min_len:
            continue
        if UUID_RE.match(token) or SHA_RE.match(token) or SHA256_RE.match(token):
            continue
        ent = shannon_entropy(token)
        if ent >= threshold:
            hits.append(
                {"start": m.start(), "end": m.end(), "length": len(token), "entropy": round(ent, 3)}
            )
    return hits


def redact_text(
    text: str,
    policy: dict | None = None,
    policy_path: Path | str = DEFAULT_POLICY,
    fail_on_unredactable: bool | None = None,
) -> RedactionResult:
    """Redact text per policy. Raises UnredactableSecret on failure paths."""
    policy = policy if policy is not None else load_policy(policy_path)
    if fail_on_unredactable is None:
        fail_on_unredactable = bool(policy.get("fail_on_unredactable", True))
    patterns = build_patterns(policy)

    accepted, overlaps = _resolve_matches(text, patterns)

    # Splice accepted replacements into the original text.
    parts, pos = [], 0
    placeholder_spans = []  # spans in the redacted output
    for a in accepted:
        parts.append(text[pos : a["start"]])
        repl = a["replacement"]
        parts.append(repl)
        placeholder_spans.append((sum(len(p) for p in parts) - len(repl), sum(len(p) for p in parts)))
        pos = a["end"]
    parts.append(text[pos:])
    redacted = "".join(parts)

    masked = _mask_spans(redacted, placeholder_spans)

    # Fail-variant re-scan: any named pattern still matching the masked
    # output means replacement left residue (overlap / multi-line token /
    # malformed replacement).
    residue_hits = []
    for pat in patterns:
        for m in pat["regex"].finditer(masked):
            if m.end() > m.start():
                residue_hits.append(
                    {"name": pat["name"], "kind": pat["kind"], "start": m.start(), "end": m.end()}
                )

    probe_hits = _probe_residue(masked, policy)

    result = RedactionResult(
        redacted=redacted,
        redactions=[
            {"name": a["name"], "kind": a["kind"], "start": a["start"], "end": a["end"]} for a in accepted
        ],
        overlaps=overlaps,
        probe_hits=probe_hits,
        residue_hits=residue_hits,
    )

    # Suppression rule: raise, caller must emit NO redacted output.
    if fail_on_unredactable and (probe_hits or residue_hits):
        raise UnredactableSecret(
            "unredactable secret material: "
            f"{len(probe_hits)} high-entropy residue hit(s), "
            f"{len(residue_hits)} named-pattern residue hit(s)",
            details={
                "probe_hits": probe_hits,
                "residue_hits": residue_hits,
                "overlaps": overlaps,
            },
        )
    return result


def summary(result: RedactionResult) -> dict:
    return {
        "redactions": result.redactions,
        "overlaps": result.overlaps,
        "probe_hits": result.probe_hits,
        "residue_hits": result.residue_hits,
        "unredactable": bool(result.probe_hits or result.residue_hits),
    }


# ---------------------------------------------------------------- selftest

def run_selftest() -> int:
    policy = load_policy()
    passed = failed = 0

    def check(label, cond, extra=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"PASS {label}")
        else:
            failed += 1
            print(f"FAIL {label} {extra}")

    def redacted(**kw):
        return redact_text(kw["text"], policy=policy).redacted

    # --- Named secret patterns -------------------------------------------
    out = redacted(text="key AKIAIOSFODNN7EXAMPLE end")
    check("aws_access_key_id AKIA", "[REDACTED:SECRET:aws_access_key_id]" in out and "AKIA" not in out)
    out = redacted(text="key ASIAIOSFODNN7EXAMPLE end")
    check("aws_access_key_id ASIA", "[REDACTED:SECRET:aws_access_key_id]" in out and "ASIA" not in out)
    out = redacted(text="aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    check("aws_secret_access_key", out == "[REDACTED:SECRET:aws_secret_access_key]")
    out = redacted(
        text="x -----BEGIN RSA PRIVATE KEY-----\nAB\n-----END RSA PRIVATE KEY----- y"
    )
    check("private_key_block multiline", "[REDACTED:SECRET:private_key_block]" in out and "END RSA" not in out)
    out = redacted(
        text="t eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    check("jwt", "[REDACTED:SECRET:jwt]" in out and "eyJ" not in out)
    out = redacted(text="Bearer abc123tokVALUE")
    check("bearer bare", out == "[REDACTED:SECRET:bearer_token]")
    out = redacted(text="Authorization: Bearer abc123tokVALUE")
    check("bearer Authorization: form", out == "[REDACTED:SECRET:bearer_token]")
    out = redacted(text="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigPartHere99")
    check("bearer+jwt overlap consumes all", "eyJ" not in out and "sigPartHere99" not in out)
    out = redacted(text="api_key = ABC123xyzValue99")
    check("generic api_key", out == "[REDACTED:SECRET:generic_secret_assignment]")
    out = redacted(text="password: hunter2value99")
    check("generic password", out == "[REDACTED:SECRET:generic_secret_assignment]")
    out = redacted(text="ghp_1234567890abcdefghij1234ABCD")
    check("github_token", out == "[REDACTED:SECRET:github_token]")
    out = redacted(text="xoxb-123456789012-abcdefghijklMNOP")
    check("slack_token", out == "[REDACTED:SECRET:slack_token]")

    # --- PII patterns ------------------------------------------------------
    out = redacted(text="mail user@example.com here")
    check("email", out == "mail [REDACTED:PII:email] here")
    out = redacted(text="tel +14155552671")
    check("phone E.164", out == "tel [REDACTED:PII:phone_e164]")
    # NOTE: policy regex `\b(\(?\d{3}...` cannot anchor at '(' (no word
    # boundary before a non-word char), so it matches from the first digit
    # and leaves the leading parenthesis. Assert on content, not exact text.
    out = redacted(text="tel (555) 867-5309")
    check("phone NANP (555)", "867-5309" not in out and "[REDACTED:PII:phone_nanp]" in out, repr(out))
    out = redacted(text="tel 555.867.5309")
    check("phone NANP dotted", out == "tel [REDACTED:PII:phone_nanp]")
    out = redacted(text="ssn 123-45-6789")
    check("us_ssn", out == "ssn [REDACTED:PII:us_ssn]")
    out = redacted(text="card 4111111111111111")
    check("credit_card", out == "card [REDACTED:PII:credit_card]")
    out = redacted(text="host 192.168.1.10 up")
    check("ipv4", out == "host [REDACTED:PII:ipv4_address] up")
    out = redacted(text="addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 end")
    check("ipv6 full form", out == "addr [REDACTED:PII:ipv6_address] end")
    out = redacted(text="addr fe80::1 end")
    check("ipv6 compressed", out == "addr [REDACTED:PII:ipv6_address] end")
    out = redacted(text="at 123 Main Street now")
    check("street_address", out == "at [REDACTED:PII:street_address] now")

    # --- High-entropy fallback ---------------------------------------------
    raw = "x7K9pQ2mZ8vB4nL6rT0yW3sD5fG1hJ9"  # 31 chars, no named pattern
    ent = shannon_entropy(raw)
    check("fixture entropy >= 4.5", ent >= 4.5, f"entropy={ent:.3f}")
    try:
        redact_text(f"raw {raw} end", policy=policy)
        check("high-entropy unredactable raises", False, "(no exception)")
    except UnredactableSecret as exc:
        check(
            "high-entropy unredactable raises",
            bool(exc.details.get("probe_hits")) and raw not in str(exc.details),
        )
    try:
        redact_text(f"Bearer={raw}", policy=policy)
        check("Bearer= (no space) fallback fires", False, "(no exception)")
    except UnredactableSecret:
        check("Bearer= (no space) fallback fires", True)
    # Named pattern wins over the probe: token inside Bearer is replaced,
    # so the fallback does not fire on the placeholder residue.
    try:
        res = redact_text(f"Bearer {raw}", policy=policy)
        check("bearer bare high-entropy redacts, no fallback", raw not in res.redacted and not res.probe_hits)
    except UnredactableSecret:
        check("bearer bare high-entropy redacts, no fallback", False, "(raised)")

    # --- Allowlist -----------------------------------------------------------
    res = redact_text("id 550e8400-e29b-41d4-a716-446655440000 fine", policy=policy)
    check("UUID allowlisted", res.redacted == "id 550e8400-e29b-41d4-a716-446655440000 fine")
    res = redact_text("sha e3b0c44298fc1c149afbf4c8996fb92427ae41e4 fine", policy=policy)
    check("commit SHA allowlisted", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4" in res.redacted)
    res = redact_text("sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 fine", policy=policy)
    check("sha256 allowlisted", "9f86d081884c7d659a2feaa0c55ad015" in res.redacted)

    # --- Clean text passes through -------------------------------------------
    res = redact_text("hello world, nothing sensitive here.", policy=policy)
    check("clean text unchanged", res.redacted == "hello world, nothing sensitive here." and not res.redactions)

    # --- fail_on_unredactable override ---------------------------------------
    res = redact_text(f"raw {raw}", policy=policy, fail_on_unredactable=False)
    check("fail_on_unredactable=False returns", raw in res.redacted and bool(res.probe_hits))

    print(f"selftest: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


# ------------------------------------------------------------------- CLI

def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog=TOOL, description=__doc__.splitlines()[0])
    ap.add_argument("--input", metavar="FILE", help="input file (required unless --selftest)")
    ap.add_argument("--output", metavar="FILE", help="output file (required unless --check/--selftest)")
    ap.add_argument("--check", action="store_true", help="check only: report, write nothing")
    ap.add_argument("--selftest", action="store_true", help="run inline fixture tests")
    ap.add_argument("--policy", metavar="FILE", default=str(DEFAULT_POLICY), help="redaction policy JSON")
    ap.add_argument("--kind", metavar="KIND", help="artifact kind; validated against policy apply_to")
    ap.add_argument("--fail-on-unredactable", dest="fail", action="store_true", default=None)
    ap.add_argument("--no-fail-on-unredactable", dest="fail", action="store_false")
    args = ap.parse_args(argv)

    if args.selftest:
        return run_selftest()

    if not args.input:
        ap.error("--input is required (or use --selftest)")
    if not args.check and not args.output:
        ap.error("--output is required (or use --check)")

    policy_path = Path(args.policy)
    if not policy_path.is_file():
        print(f"error: policy not found: {policy_path}", file=sys.stderr)
        return 2
    try:
        policy = load_policy(policy_path)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot load policy: {exc}", file=sys.stderr)
        return 2

    if args.kind and args.kind not in policy.get("apply_to", []):
        print(f"error: kind '{args.kind}' not in policy apply_to {policy.get('apply_to', [])}", file=sys.stderr)
        return 2

    in_path = Path(args.input)
    if not in_path.is_file():
        print(f"error: input not found: {in_path}", file=sys.stderr)
        return 2
    try:
        text = in_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2

    fail = args.fail
    try:
        result = redact_text(text, policy=policy, fail_on_unredactable=fail)
    except UnredactableSecret as exc:
        # Suppression: no output file is written for this artifact.
        print(json.dumps({"tool": TOOL, "status": "unredactable", **exc.details}, indent=2))
        return 1

    report = {"tool": TOOL, "status": "ok", **summary(result)}
    if args.check:
        print(json.dumps(report, indent=2))
        return 0

    out_path = Path(args.output)
    tmp_path = out_path.with_name(out_path.name + ".tmp")
    try:
        # Atomic write: a partial redacted artifact is never visible.
        tmp_path.write_text(result.redacted, encoding="utf-8")
        tmp_path.replace(out_path)
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
