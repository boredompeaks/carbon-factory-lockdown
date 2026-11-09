#!/usr/bin/env python3
"""Idempotent, PII-free fixture seeder for K1 (SQLite or Postgres).

Usage:
    python seed.py                                  # /work/sqlite/k1.sqlite3
    python seed.py --sqlite /work/sqlite/k1.sqlite3
    python seed.py --database-url postgresql://...

Postgres needs psycopg (or psycopg2) available in the image; the default
stdlib-only image seeds SQLite. Fixtures are generic names, no personal data.
Re-running only inserts missing rows (unique name).
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys

DEFAULT_SQLITE = "/work/sqlite/k1.sqlite3"

ROWS = (
    ("fixture-alpha", 100, 1),
    ("fixture-bravo", 250, 1),
    ("fixture-charlie", 0, 0),
)


def seed_sqlite(path: str) -> int:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS k1_fixture (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                amount INTEGER NOT NULL,
                active INTEGER NOT NULL
            )
            """
        )
        for name, amount, active in ROWS:
            connection.execute(
                "INSERT OR IGNORE INTO k1_fixture (name, amount, active) VALUES (?, ?, ?)",
                (name, amount, active),
            )
        connection.commit()
        return int(connection.execute("SELECT COUNT(*) FROM k1_fixture").fetchone()[0])
    finally:
        connection.close()


def seed_postgres(url: str) -> int:
    try:
        import psycopg  # type: ignore
    except ImportError:
        try:
            import psycopg2 as psycopg  # type: ignore
        except ImportError:
            print(
                "seed: Postgres requested but neither psycopg nor psycopg2 is installed; "
                "use --sqlite or add the driver to requirements.txt",
                file=sys.stderr,
            )
            raise SystemExit(2)

    connection = psycopg.connect(url)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS k1_fixture (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    amount INTEGER NOT NULL,
                    active BOOLEAN NOT NULL
                )
                """
            )
            for name, amount, active in ROWS:
                cursor.execute(
                    "INSERT INTO k1_fixture (name, amount, active) VALUES (%s, %s, %s) "
                    "ON CONFLICT (name) DO NOTHING",
                    (name, amount, bool(active)),
                )
            connection.commit()
            cursor.execute("SELECT COUNT(*) FROM k1_fixture")
            return int(cursor.fetchone()[0])
    finally:
        connection.close()


def sqlite_path_from_url(url: str) -> str:
    if "///" in url:
        path = url.split("///", 1)[1]
        return path or DEFAULT_SQLITE
    return DEFAULT_SQLITE


def main() -> int:
    parser = argparse.ArgumentParser(description="Idempotent K1 fixture seeder")
    parser.add_argument("--sqlite", default=None, help=f"SQLite file (default {DEFAULT_SQLITE})")
    parser.add_argument("--database-url", default=None, help="Postgres or sqlite DATABASE_URL")
    args = parser.parse_args()

    url = args.database_url or os.environ.get("DATABASE_URL", "")

    if args.sqlite:
        path = args.sqlite
        rows = seed_sqlite(path)
        print(f"seed: sqlite {path} rows={rows}")
        return 0

    if url.startswith(("postgres://", "postgresql://")):
        rows = seed_postgres(url)
        print(f"seed: postgres rows={rows}")
        return 0

    if url.startswith("sqlite"):
        path = sqlite_path_from_url(url)
        rows = seed_sqlite(path)
        print(f"seed: sqlite {path} rows={rows}")
        return 0

    if url:
        print(f"seed: unsupported DATABASE_URL scheme: {url.split(':', 1)[0]}", file=sys.stderr)
        return 2

    rows = seed_sqlite(DEFAULT_SQLITE)
    print(f"seed: sqlite {DEFAULT_SQLITE} rows={rows}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
