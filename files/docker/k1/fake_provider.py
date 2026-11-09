#!/usr/bin/env python3
"""Deterministic fake payment provider for K1 sandboxes (stdlib only).

Listens on 127.0.0.1:8081 inside the app container. Responses depend only on
the request path and body (sha256 of the raw body), so repeated runs produce
identical ids. Payment/refund calls are appended as JSON lines to
/work/provider-calls.jsonl; /health is not logged.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = int(os.environ.get("FAKE_PROVIDER_PORT", "8081"))
LOG_PATH = os.environ.get("FAKE_PROVIDER_LOG", "/work/provider-calls.jsonl")
MAX_BODY = 64 * 1024

_LOG_LOCK = threading.Lock()


def _digest(raw: bytes, prefix: str) -> str:
    return prefix + hashlib.sha256(raw or b"{}").hexdigest()[:16]


def _json_body(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _create(raw: bytes) -> dict:
    body = _json_body(raw)
    return {
        "id": _digest(raw, "pay_"),
        "object": "payment",
        "amount": body.get("amount", 0),
        "currency": body.get("currency", "usd"),
        "status": "succeeded",
    }


def _refund(raw: bytes) -> dict:
    body = _json_body(raw)
    payment_id = body.get("payment_id") or body.get("paymentId") or body.get("id")
    if not isinstance(payment_id, str) or not payment_id:
        payment_id = _digest(raw, "pay_")
    return {
        "id": _digest(raw, "ref_"),
        "object": "refund",
        "payment_id": payment_id,
        "amount": body.get("amount", 0),
        "currency": body.get("currency", "usd"),
        "status": "succeeded",
    }


def _append_call(record: dict) -> None:
    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        directory = os.path.dirname(LOG_PATH)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with _LOG_LOCK:
            with open(LOG_PATH, "a", encoding="utf-8") as handle:
                handle.write(line)
    except OSError as exc:  # read-only or missing /work: never break the caller
        print(f"fake-provider: cannot append {LOG_PATH}: {exc}", file=sys.stderr, flush=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "k1-fake-provider/1.0"
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _path(self) -> str:
        return urlsplit(self.path).path

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self._path() == "/health":
            self._send(200, {"status": "ok", "provider": "k1-fake"})
            return
        self._send(404, {"error": "not_found", "path": self._path()})

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        length = max(0, min(length, MAX_BODY))
        raw = self.rfile.read(length) if length else b""
        path = self._path()

        if "refund" in path:
            response, status = _refund(raw), 200
        elif "payment" in path or "create" in path or "charge" in path:
            response, status = _create(raw), 200
        else:
            response, status = {"error": "not_found", "path": path}, 404

        _append_call(
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "method": "POST",
                "path": path,
                "body": raw.decode("utf-8", "replace"),
                "status": status,
                "response": response,
            }
        )
        self._send(status, response)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"fake-provider: {self.address_string()} {fmt % args}", file=sys.stderr, flush=True)


def main() -> int:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print(f"fake-provider: listening on http://{HOST}:{PORT}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
