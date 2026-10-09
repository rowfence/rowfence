#!/usr/bin/env python3
"""confidence_test: rowstile prove, test --coverage, snapshot, indexes, plans and bench, on the docs example.

PGHOST=... PGUSER=... python3 tests/confidence_test.py [--db authz_confidence]
"""

import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from typing import TypeVar
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import pgwire  # noqa: E402
import rowstile_cli  # noqa: E402
from authzlib import database, perf  # noqa: E402
from authzlib.connection import Db  # noqa: E402

T = TypeVar("T")

fails = 0

TESTS = """test "an owner edits their folder, a stranger doesn't"
  given ann  = {INSERT INTO app.users (id, name) VALUES (901, 'ann') RETURNING id}
  given bo   = {INSERT INTO app.users (id, name) VALUES (902, 'bo') RETURNING id}
  given acme = {INSERT INTO app.orgs (id, name) VALUES (901, 'Acme') RETURNING id}
  given f    = {INSERT INTO app.folders (org_id, owner_id, name) VALUES ($acme, $ann, 'F') RETURNING id}
  user $ann can edit folder $f
  user $bo cannot view folder $f
"""

# a deny inside inheritance: view is compiled as a hidden permission (its `or` part) and the deny on it
DENY_SCHEMA = """CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY);
CREATE TABLE app.folders (id bigint PRIMARY KEY, parent_id bigint REFERENCES app.folders, owner_id bigint, viewer_id bigint,
                          blocked boolean NOT NULL DEFAULT false);
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
"""
DENY_POLICY = """app role app_user
type user = app.users
type folder = app.folders
  parent : folder = parent_id
  owner  : user   = owner_id
  viewer : user   = viewer_id
  can hidden = {blocked} or parent.hidden
  can view   = (owner or viewer or parent.view) and not hidden
  can see    = signed_in
"""
# a table that holds only its key and its owner
TAGS_SCHEMA = """CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY);
CREATE TABLE app.tags (id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users);
CREATE INDEX ON app.tags (owner_id);
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT, UPDATE ON ALL TABLES IN SCHEMA app TO app_user;
INSERT INTO app.users VALUES (1), (2);
INSERT INTO app.tags VALUES (1, 1), (2, 2);
"""
TAGS_POLICY = """app role app_user
type user = app.users
type tag = app.tags
  owner : user = owner_id
  can edit = owner
rules app.tags
  select : edit
  update : edit
  update owner_id : nobody
"""
DENY_TESTS = """test "the owner"
  given u = {INSERT INTO app.users VALUES (1) RETURNING id}
  given f = {INSERT INTO app.folders (id, owner_id) VALUES (1, $u) RETURNING id}
  given g = {INSERT INTO app.folders (id, parent_id) VALUES (2, $f) RETURNING id}
  user $u can view folder $f
"""


def check(label: str, ok: object, detail: object = "") -> None:
    global fails
    if ok:
        print(f"ok    {label}")
    else:
        fails += 1
        print(f"FAIL  {label}{': ' + str(detail)[:800] if detail else ''}")


def cli(db: str | None, *args: str, cwd: str | None = None) -> tuple[int, str]:
    r = subprocess.run(
        [
            sys.executable,
            os.path.join(ROOT, "cli", "rowstile_cli.py"),
            *(["--db", f"dbname={db}"] if db else []),
            *args,
        ],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    return r.returncode, r.stdout + r.stderr


def main() -> None:
    db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_confidence"
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", os.path.join(ROOT, "example", "app_schema.sql")],
        check=True,
        capture_output=True,
    )
    policy = os.path.join(ROOT, "example", "docs.authz")
    # the policy without its test section (it needs the scenario's data): coverage counts this file's tests only
    with open(policy, encoding="utf-8") as fh:
        bare = re.sub(r"\ntest\n(  .*\n)+", "\n", fh.read())
    tmp_policy = os.path.join(tempfile.mkdtemp(), "docs.authz")
    with open(tmp_policy, "w", encoding="utf-8") as fh:
        fh.write(bare)
    rc, out = cli(db, "apply", tmp_policy)
    if rc:
        raise SystemExit(out)
    conn = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))

    def work(fn: Callable[[Db], T], keep: bool = False) -> T:
        return rowstile_cli.transaction(conn, fn, keep=keep)

    print("-- rowstile prove")
    rc, out = cli(None, "prove", policy)
    check(
        "an invariant the policy doesn't guarantee: exit 1, and the smallest counterexample",
        rc == 1 and "no   user 1 holds it on folder 1" in out and "folder.owner: folder 1 -> user 1" in out,
        out,
    )
    with tempfile.TemporaryDirectory() as tmp:
        ok = os.path.join(tmp, "p.authz")
        with open(policy, encoding="utf-8") as fh:
            text = fh.read()
        with open(ok, "w", encoding="utf-8") as fh:
            fh.write(text.replace("never folder: share and not org.member", "never folder: edit and not view"))
        rc, out = cli(None, "prove", ok, "--worlds", "60")
        # the 60 drawn, and the corners (each condition true on every row or none) 3 times at each of the 4 sizes
        tried = re.search(r"ok   holds in every world tried \((\d+) worlds", out)
        check("one it does: exit 0", rc == 0 and tried is not None and (int(tried.group(1)) - 60) % 12 == 0, out)
        with open(ok, "w", encoding="utf-8") as fh:
            fh.write(
                text.replace(
                    "can view  = edit or viewer or (parent.view and {inherit})",
                    "can view  = edit or viewer or (parnt.view and {inherit})",
                )
            )
        rc, out = cli(None, "prove", ok)
        check(
            "a policy check refuses: its message, line and code, no traceback",
            rc == 1 and "[AZ" in out and "line " in out and "Traceback" not in out,
            out,
        )
        rc, out = cli(None, "prove", ok, "--worlds", "abc")
        check(
            "--worlds that isn't a number: a usage error",
            rc == 2 and "--worlds needs a whole number" in out and "Traceback" not in out,
            out,
        )

    print("-- coverage")
    rows, report = work(lambda d: database.coverage(d, {"t.authz": TESTS}))
    check("the tests pass", rows and all(r[2] for r in rows), rows)
    missing = {(name, item) for _, name, item in report["missing"]}
    check(
        "the branches a passing check made true are covered",
        ("folder.edit", "share") not in missing and ("folder.share", "owner") not in missing,
        report,
    )
    check(
        "... and those none did are named, with their lines",
        ("folder.edit", "editor") in missing and all(line.startswith("line ") for line, _, _ in report["missing"]),
        report,
    )
    check("a check that someone cannot adds nothing", ("folder.view", "viewer") in missing, report)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "t.authz")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(TESTS)
        rc, out = cli(db, "test", "--coverage", path)
        check(
            "rowstile test --coverage",
            rc == 0 and "coverage: " in out and 'branches made true by a test; no "can" check reaches:' in out,
            out,
        )

    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["dropdb", "--if-exists", db + "_deny"], capture_output=True)
        subprocess.run(["createdb", db + "_deny"], check=True)
        subprocess.run(
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db + "_deny", "-c", DENY_SCHEMA],
            check=True,
            capture_output=True,
        )
        pol, tests = os.path.join(tmp, "p.authz"), os.path.join(tmp, "t.authz")
        for path, text in ((pol, DENY_POLICY), (tests, DENY_TESTS)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        rc, out = cli(db + "_deny", "apply", pol)
        rc, out = cli(db + "_deny", "test", "--coverage", tests) if rc == 0 else (rc, out)
        check(
            "a deny inside inheritance: the branches are those of its `or` part, in the policy's words",
            rc == 0
            and "coverage: 1 of 6 branches" in out
            and "folder.view: owner" not in out
            and all(x in out for x in ("folder.view: viewer", "folder.view: parent.view", "folder.see: signed_in")),
            out,
        )
        with open(tests, "a", encoding="utf-8") as fh:
            fh.write("  user $u can view folder $g\n")
        rc, out = cli(db + "_deny", "test", "--coverage", tests)
        check(
            "... and the inherited one is covered by a check on what is below",
            rc == 0 and "coverage: 2 of 6 branches" in out and "folder.view: parent.view" not in out,
            out,
        )
        # a policy without rules, on tables without rows: plans has no app role to read as; bench lists, as
        # nobody signed in, and checks nothing on a type that has no row
        rc, out = cli(db + "_deny", "plans")
        check(
            "rowstile plans with no rules applied: no app role to read as, exit 1",
            rc == 1 and out == "no policy with rules is applied, so there is no app role to read as\n",
            out,
        )
        rc, out = cli(db + "_deny", "bench", "--people", "1", "--rounds", "1")
        check(
            "rowstile bench with no rows: lists only, as nobody signed in",
            rc == 0
            and out.startswith("1 rounds as 1 people")
            and "  authz.list folder view " in out
            and "authz.can" not in out
            and "read " not in out,
            out,
        )
        subprocess.run(["dropdb", "--if-exists", db + "_deny"], capture_output=True)

    print("-- snapshot")
    lines = work(database.snapshot)
    check(
        "who holds what, one sorted line per object and permission",
        lines and all(": " in x for x in lines) and any(x.startswith("folder 1 view: ") for x in lines),
        lines[:5],
    )
    try:
        work(lambda d: database.snapshot(d, limit=3))
        refused = ""
    except database.Error as e:
        refused = str(e)
    check(
        "more people in the data than a snapshot is for: refused, saying how many",
        re.fullmatch(r"\d+ people and principals: a snapshot is for small review data \(at most 3\)", refused),
        refused,
    )
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "access.snapshot")
        rc, out = cli(db, "snapshot", "--out", snap)
        rc2, out2 = cli(db, "snapshot", "--check", "--out", snap)
        check(
            "rowstile snapshot writes it, and --check finds it up to date",
            rc == 0 and rc2 == 0 and "up to date" in out2,
            out + out2,
        )
        subprocess.run(
            [
                "psql",
                "-X",
                "-q",
                "-d",
                db,
                "-c",
                "BEGIN; SELECT authz.act_as('user', '5'); SELECT authz.share('folder', '2', 'editor', 'user', '6'); COMMIT",
            ],
            capture_output=True,
            check=True,
        )
        rc, out = cli(db, "snapshot", "--check", "--out", snap)
        check(
            "... a change of access makes it out of date, and says what changed",
            rc == 1 and "+ folder 2 edit: 5, 6" in out,
            out,
        )

    print("-- indexes")
    check(
        "the example's tables have every index the policy needs",
        work(lambda d: perf.missing_indexes(d, database.policy_compiler(*database.applied(d)))) == [],
    )

    def without(d: Db) -> list[perf.Missing]:
        d.script("DROP INDEX app.team_members_user_id_idx")
        return perf.missing_indexes(d, database.policy_compiler(*database.applied(d)))

    missing = work(without)
    check(
        "a dropped index is named, with why",
        [(m[0], m[1]) for m in missing] == [("app.team_members", ("user_id",))] and "team.member" in missing[0][2],
        missing,
    )
    check(
        "... and the line to add, for the app's tool",
        perf.advice("app.team_members", ("user_id",), "prisma").startswith("@@index([user_id])")
        and perf.advice("app.team_members", ("user_id",), "sql").startswith("CREATE INDEX CONCURRENTLY"),
    )

    def behind_an_expression(d: Db) -> list[perf.Missing]:
        d.script(
            "DROP INDEX app.team_members_user_id_idx; "
            "CREATE INDEX team_members_expr ON app.team_members ((team_id + 0), user_id)"
        )
        return perf.missing_indexes(d, database.policy_compiler(*database.applied(d)))

    check(
        "an index that starts with an expression serves no lookup by its later columns",
        [(m[0], m[1]) for m in work(behind_an_expression)] == [("app.team_members", ("user_id",))],
    )

    def capitals(d: Db) -> list[tuple[str, ...]]:
        # names with capital letters, as Prisma writes them: the table is looked up by its quoted name
        d.script(
            'CREATE TABLE app."TeamMember" ("teamId" bigint, "userId" bigint, PRIMARY KEY ("teamId", "userId")); '
            'CREATE INDEX ON app."TeamMember" ("userId")'
        )
        return sorted(perf.table_indexes(d, "app.TeamMember"))

    check(
        "a table whose name has capital letters: its indexes are found",
        work(capitals) == [("teamId", "userId"), ("userId",)],
    )

    def through_a_view(d: Db) -> list[perf.Missing]:
        # team members read through a view, and the folders' owner index gone: a view can't have an index (the
        # tables under it answer its lookups), so only the table is named
        d.script(
            "CREATE VIEW app.team_members_v AS SELECT team_id, user_id FROM app.team_members; "
            "DROP INDEX app.folders_owner_id_idx"
        )
        text, files = database.applied(d)
        policy = text.replace("app.team_members(team_id -> user_id)", "app.team_members_v(team_id -> user_id)")
        return perf.missing_indexes(d, database.policy_compiler(policy, files))

    found = work(through_a_view)
    check(
        "a relation read from a view: no index asked of the view, the table's still named",
        [(m[0], m[1]) for m in found] == [("app.folders", ("owner_id",))],
        found,
    )

    def partitioned(d: Db) -> tuple[str, str, list[perf.Missing]]:
        # a governed table may be partitioned: Postgres makes no index on it concurrently, so the line to add says
        # CREATE INDEX alone there; made, it serves the lookup
        d.script(
            "CREATE TABLE app.events (id bigint, owner_id bigint, at date NOT NULL) PARTITION BY RANGE (at); "
            "CREATE TABLE app.events_2026 PARTITION OF app.events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')"
        )
        text, files = database.applied(d)
        c = database.policy_compiler(
            text + "\ntype event = app.events\n  owner : user = owner_id\n  can view = owner\n", files
        )
        said = perf.describe_missing(perf.missing_indexes(d, c), "sql")
        refused = ""
        try:
            with database.savepoint(d, "authz_index"):
                d.script(said.partition("\n  add: ")[2])
        except d.errors as e:
            refused = str(getattr(e, "message", e))
        return said, refused, perf.missing_indexes(d, c)

    said, refused, after = work(partitioned)
    check(
        "a partitioned table: the index to add without CONCURRENTLY, which Postgres refuses there; made, it serves",
        re.fullmatch(
            r"app\.events has no index on \(owner_id\): finding the events by their event\.owner \(lists, select "
            r'rules\) \(line \d+\)\n  add: CREATE INDEX "events_owner_id_idx" ON "app"\."events" \("owner_id"\);',
            said,
        )
        is not None
        and (refused, after) == ("", []),
        (said, refused, after),
    )
    # the line to add in the words of the tool rowstile.toml names, and --check exits 1 while a lookup has no index
    subprocess.run(["psql", "-X", "-q", "-d", db, "-c", "DROP INDEX app.team_members_user_id_idx"], check=True)
    with tempfile.TemporaryDirectory() as tmp:
        for tool, line in (
            ("drizzle", "index('team_members_user_id_idx').on(t.user_id) in the table for app.team_members"),
            (
                "alembic",
                "Index('team_members_user_id_idx', 'user_id') in app.team_members's model (or index=True on the "
                "column), then alembic revision --autogenerate",
            ),
        ):
            with open(os.path.join(tmp, "rowstile.toml"), "w", encoding="utf-8") as fh:
                fh.write(f'[migrations]\ntool = "{tool}"\n')
            rc, out = cli(db, "indexes", "--check", cwd=tmp)
            check(
                f"rowstile indexes --check: the lookup with no index, the line to add for {tool}, exit 1",
                rc == 1
                and out.startswith("app.team_members has no index on (user_id): finding the teams by their team.member")
                and f"\n  add: {line}\n" in out,
                out,
            )
    subprocess.run(
        ["psql", "-X", "-q", "-d", db, "-c", "CREATE INDEX team_members_user_id_idx ON app.team_members (user_id)"],
        check=True,
    )

    print("-- plans and bench")
    p = work(lambda d: perf.plans(d, database.policy_compiler(*database.applied(d)), ("user", "1")))
    tables = {t["table"]: t for t in p["tables"]}
    check(
        "each governed table read as someone, with its time",
        set(tables) == {"app.folders", "app.files"}
        and all(t["ms"] is not None and t["ms"] >= 0 for t in tables.values()),
        p,
    )
    rc, out = cli(db, "plans", "--as", "user:1")
    check("rowstile plans", rc == 0 and "as user:1:" in out and "app.folders:" in out, out)
    check("no warning on the example's few rows", all(t["warnings"] == [] for t in tables.values()), p)
    rc, out = cli(db, "plans")
    check("without --as, as the first user in the data", rc == 0 and out.startswith("as user:1:\n"), out)

    def nobody(d: Db) -> perf.Plans:
        d.script("TRUNCATE app.users CASCADE")
        return perf.plans(d, database.policy_compiler(*database.applied(d)))

    alone = work(nobody)
    check("... and as anyone when there is no user", alone["as"] == "anyone" and len(alone["tables"]) == 2, alone)

    def unreadable(d: Db) -> perf.Plans:
        d.script("REVOKE SELECT ON app.files FROM app_user")
        return perf.plans(d, database.policy_compiler(*database.applied(d)), ("user", "1"))

    failed = {t["table"]: (t["ms"], t["rows"], t["warnings"]) for t in work(unreadable)["tables"]}
    check(
        "a table the app role may not read: the read failed, and why; the others are read",
        failed.get("app.files") == (None, None, ["failed: permission denied for table files"])
        and failed.get("app.folders", (None, None, []))[0] is not None,
        failed,
    )
    with mock.patch.object(perf, "SLOW_MS", -1):  # every read is slower than that
        slower = work(lambda d: perf.plans(d, database.policy_compiler(*database.applied(d)), ("user", "1")))
    check(
        "a read slower than the limit: its time is the first warning",
        all(t["warnings"] and re.fullmatch(r"took \d+(\.\d+)? ms", t["warnings"][0]) for t in slower["tables"]),
        slower,
    )

    def grown(d: Db) -> perf.Plans:
        # a link table grown past what a scan should read, and the index its lookup needs gone
        d.script(
            "INSERT INTO app.users (id, name) SELECT i, 'u' || i FROM generate_series(1000, 13000) i; "
            "INSERT INTO app.org_members SELECT 2, i, 'member' FROM generate_series(1000, 13000) i; "
            "DROP INDEX app.org_members_user_id_idx; ALTER TABLE app.org_members DROP CONSTRAINT org_members_pkey; "
            "ANALYZE app.org_members"
        )  # the key too: Postgres 18 can skip through (org_id, user_id)
        return perf.plans(d, database.policy_compiler(*database.applied(d)), ("user", "7"))

    slow = work(grown)
    check(
        "a scan that reads a big table and keeps little is named (a missing index)",
        any("reads all of app.org_members" in w for t in slow["tables"] for w in t["warnings"]),
        slow,
    )
    count: Callable[[], str] = lambda: subprocess.run(
        ["psql", "-X", "-At", "-d", db, "-c", "SELECT count(*), sum(length(name)) FROM app.folders"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    before = count()
    b = work(lambda d: perf.bench(d, database.policy_compiler(*database.applied(d)), people=3, rounds=3))
    paths = {x["path"]: x for x in b["paths"]}
    check(
        "bench: reads, lists, checks and updates, p50 and p95",
        {"read app.folders", "authz.list folder view", "authz.can folder edit", "update app.folders"} <= set(paths)
        and all(x["p50"] is not None for x in paths.values()),
        b,
    )
    rc, out = cli(db, "bench", "--rounds", "2", "--people", "2")
    check("rowstile bench", rc == 0 and "p50" in out and "read app.files" in out, out)
    check("... and nothing it did stays", count() == before, (before, count()))
    # a table whose columns are all its key and what its relations read: nothing to write back unchanged, so no
    # update is timed
    subprocess.run(["dropdb", "--if-exists", db + "_tags"], capture_output=True)
    subprocess.run(["createdb", db + "_tags"], check=True)
    subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db + "_tags", "-c", TAGS_SCHEMA], check=True)
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "p.authz"), "w", encoding="utf-8") as fh:
            fh.write(TAGS_POLICY)
        rc, out = cli(db + "_tags", "apply", os.path.join(tmp, "p.authz"))
        rc, out = cli(db + "_tags", "bench", "--people", "1", "--rounds", "1") if rc == 0 else (rc, out)
        check(
            "bench: no update timed on a table with no column to write back unchanged",
            rc == 0 and "  read app.tags " in out and "  authz.can tag edit " in out and "update" not in out,
            out,
        )
    subprocess.run(["dropdb", "--if-exists", db + "_tags"], capture_output=True)

    def bench_unreadable(d: Db) -> perf.Bench:
        d.script("REVOKE SELECT ON app.files FROM app_user")
        return perf.bench(d, database.policy_compiler(*database.applied(d)), people=1, rounds=1)

    b = work(bench_unreadable)
    ran = {x["path"]: (x["n"], x["p50"], x["failed"]) for x in b["paths"]}
    said = perf.describe_bench(b)
    check(
        "bench: a path that fails is there with why, not left out",
        ran.get("read app.files") == ran.get("update app.files") == (0, None, "permission denied for table files")
        and ran.get("read app.folders", (0, None, "missing"))[::2] == (1, None)
        and re.search(r"\n  read app\.files +- +-  <- failed: permission denied for table files\n", said) is not None,
        said,
    )

    conn.close()
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    print("confidence: all passed" if not fails else f"confidence: {fails} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
