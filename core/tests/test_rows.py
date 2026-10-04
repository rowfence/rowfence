#!/usr/bin/env python3
"""test_rows: the rows of a policy test run, for suites that check them one by one.

    python3 tests/test_rows.py "dbname=authz_devx" tests/a.authz [more.authz ...]

Runs the policy in force's tests and the named tests in these files (keyed by file name, as
`rowstile test` does) through authzlib.database, in a transaction that is rolled back. Prints one
row per check: test, line, ok (t or f), detail, separated by tabs; newlines in detail become " | ".
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "cli"), ROOT]
import pgwire  # noqa: E402
from authzlib import database  # noqa: E402
from rowstile_cli import transaction  # noqa: E402


def main(dsn: str, paths: list[str]) -> None:
    tests: dict[str, str] = {}
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            tests[os.path.basename(p)] = fh.read()
    conn = pgwire.connect(**pgwire.parse_dsn(dsn))
    try:
        rows = transaction(conn, lambda db: database.test(db, tests), keep=False)
    except (database.Error, pgwire.PgError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    for test, line, ok, detail in rows:
        print("\t".join([test, line or "", "t" if ok else "f", (detail or "").replace("\n", " | ")]))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
