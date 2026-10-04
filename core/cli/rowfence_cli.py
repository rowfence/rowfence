#!/usr/bin/env python3
"""rowfence: compile policies and apply them to a database, from a terminal, CI or a migration.

    rowfence dev     [--once] [--no-studio] [--studio-port N]
                                                   on each save: check, diff, push, test, write the clients;
                                                   Studio on http://localhost:4983 beside it
    rowfence studio  [--port N] [--write]          Studio: the tables as anyone, why and how to grant, the graph,
                                                   the access diff, shares and requests (read-only unless --write)
    rowfence migrate [POLICY.authz] [--name NAME] [--check] [--tool T] [--dir D] [--one-phase]
                                                   write the policy's changes since the lock file as a migration
                                                   for the app's migration tool (no database needed); two when
                                                   inheritance trees are built beside the ones in use first
                                                   (--one-phase: one); --check: exit 1 if there are changes no
                                                   migration has (for CI)
    rowfence review  [--base REF] [--markdown|--json|--annotations] [--db DSN]
                                                   what the change since REF (default main) does: meaning,
                                                   access (with --db: a database at REF with review data),
                                                   risk, tests, deploy; the pull request comment with --markdown
                                                   (exit 0 whatever it finds: test and migrate --check gate)
    rowfence fmt     [--check] [FILE.authz ...]     write policies and test files one way (--check: exit 1 if
                                                   one isn't; for CI); line endings stay the file's own
    rowfence push    [POLICY.authz] [--development]
                                                   bring a development database to the policy with the same
                                                   migration (never production: that takes migrations); a
                                                   database with a policy must be marked as one first, once:
                                                   --development (the first push to one with none marks it)
    rowfence apply   [POLICY.authz] [--force]      apply it whole (and the files it includes), unless it is in force;
                                                   --force: in any case, and every inheritance table computed again
                                                   (after authz.verify() said false)
                                                   (apply, push and migrate refuse a database or lock file a newer
                                                   rowfence wrote; --downgrade goes back on purpose)
    rowfence check   [POLICY.authz]                report its first mistake, as 'file: line N: message'
    rowfence prove   [POLICY.authz] [--worlds N]   every invariant in many small worlds (no database): the
                                                   smallest counterexample, or that none was found
    rowfence diff    [POLICY.authz] [--users 1,2] [--limit N]
                                                   who would gain and lose what; changes nothing
    rowfence test    [TESTS.authz ...] [--coverage]
                                                   the policy's tests, these named tests, and the invariants;
                                                   --coverage: the branches of each permission no test makes true
    rowfence graph   [POLICY.authz]                Mermaid diagram (of the current policy if none given)
    rowfence lint                                  the ways around row-level security the database leaves open
                                                   (authz.lint()); exit 1 if there are errors or warnings
    rowfence indexes [--check]                     the lookups the policy makes into the app's tables that no
                                                   index serves, and the line to add for the migration tool
    rowfence plans   [--as WHO]                    each governed table read as someone (EXPLAIN ANALYZE): the
                                                   time, and full scans or per-row subplans that would be slow
    rowfence bench   [--people N] [--rounds N]     p50 and p95 of reads, lists, checks and updates (undone), as
                                                   people in the data
    rowfence snapshot [--check] [--out FILE]      who holds what on this database's data, one sorted line per
                                                   object and permission (for review data: commit it, and a
                                                   pull request that changes access changes it); --check: exit 1
                                                   if it is out of date
    rowfence client  [py|ts] [POLICY.authz]        typed helpers for app code; with neither, writes the
                                                   clients rowfence.toml names
    rowfence init    [--schema app,...] [--users app.users] [--role app_user] [--out db]
                                                   a first policy from the database's tables, and rowfence.toml
    rowfence lsp                                   the language server, for editors (stdin and stdout)
    rowfence mcp                                   the MCP server, for coding agents (stdin and stdout): check,
                                                   prove, review, test, why, lint, and push to a development database
    rowfence --version                             the version, and the Python it runs on
    rowfence help AZ201                            what a mistake's code means, and how to fix it (help errors: all)

  asking the database as someone (--as user:42, bot:7, or anyone):
    rowfence can     --as WHO TYPE ID PERM         yes or no
    rowfence explain --as WHO TYPE ID PERM         why, or what is missing
    rowfence perms   --as WHO TYPE ID              every permission WHO holds on it
    rowfence list    --as WHO TYPE PERM            every id WHO holds PERM on
    rowfence who     TYPE ID PERM                  everyone who holds PERM on it
    rowfence why     --as WHO TYPE ID PERM         yes and why; or no, why not, and the smallest changes that
                                                   would grant it (each tried and undone)
    rowfence explain-rule --as WHO TABLE insert|update|delete [ID] [--row JSON]
                                                   why a write is (or would be) refused
    rowfence sql     --as WHO "SELECT ..."         a statement as the app role signed in as WHO; rolled back

    rowfence reapply [--force]                     apply the policy in force again (after upgrading rowfence);
                                                   --force: and compute every inheritance table again
    rowfence remove  --yes                         remove everything the current policy made

The database is --db DSN (host=... port=... user=... password=... dbname=..., or a postgresql:// URL), else
rowfence.toml's `database` (in this folder or a folder above it), else DATABASE_URL, else the PG* environment variables.
rowfence.toml:

    policy   = "db/policy.authz"
    tests    = ["db/tests/*.authz"]
    database = "env:DATABASE_URL"          # a DSN or URL, or env:NAME for an environment variable holding one
    [clients]
    py = "backend/app/authz_client.py"
    ts = "frontend/src/authz.ts"
    [migrations]
    tool = "alembic"                       # alembic, prisma, drizzle, sql, goose, dbmate or flyway
    dir  = "alembic/versions"              # where the tool keeps them (each tool has a default)
    lock = "db/policy.lock"                # what the migrations made so far (default: next to the policy)
    write_after = 300                      # rowfence dev writes the migration this long after the last save
                                           # (seconds; 0: never, run rowfence migrate yourself)

The compiler runs here: the database only runs the SQL it writes, and the authz.* functions
apps call. Applying, previewing and testing each run in one transaction on the database.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from typing import NoReturn, TypeVar

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(1, os.path.dirname(HERE))
import pgwire  # noqa: E402
from authzlib import database  # noqa: E402
from authzlib.connection import Row, Value  # noqa: E402
from authzlib.parse import collect_includes, disk_reader, within  # noqa: E402

T = TypeVar("T")

CONFIG = "rowfence.toml"
EXPLAIN_SHOWN = 12          # lines of a failing check's explanation shown


def read_text(path: str) -> str:
    """A policy or test file's text. A file that isn't UTF-8 is an OSError that says so (callers print strerror)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError as e:
        raise OSError(0, f"not UTF-8 (the byte at {e.start}): save it as UTF-8") from None


def read_policy(path: str) -> tuple[str, dict[str, str]]:
    """The policy's text, and every file it includes (by name relative to the policy's folder, never outside it)."""
    text = read_text(path)
    folder = os.path.dirname(os.path.abspath(path))
    disk = disk_reader(folder)

    def read(name: str) -> str | None:
        got = disk(name)
        full = os.path.join(folder, *name.split("/"))
        if got is None and os.path.isfile(full):
            try:
                read_text(full)         # there, and not read: not UTF-8 (or a link out of the folder: the compiler says)
            except OSError as e:
                raise OSError(0, f"the file it includes, {name}, is {e.strerror}") from None
        return got
    return text, collect_includes(text, read)


def fail(msg: str | None, code: int = 1) -> NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(code)


class Db:
    """The connection authzlib.database works with (authzlib.connection.Db)."""
    errors = pgwire.PgError

    def __init__(self, conn: pgwire.Connection) -> None:
        self.conn = conn

    def rows(self, sql: str, args: Sequence[Value] = ()) -> list[Row]:
        rows, cols = self.conn.query_described(sql, list(args))
        return [dict(zip(cols, r, strict=True)) for r in rows]

    def script(self, sql: str) -> None:
        self.conn.script(sql)

    def warn(self, message: str, detail: str | None = None, hint: str | None = None) -> None:
        if self.conn.on_notice:
            self.conn.on_notice({"S": "WARNING", "V": "WARNING", "M": message,
                                 **({"D": detail} if detail else {}), **({"H": hint} if hint else {})})


def transaction(conn: pgwire.Connection, work: Callable[[Db], T], keep: bool = True) -> T:
    """work(Db) in one transaction: committed if keep, else rolled back."""
    conn.execute("BEGIN")
    try:
        out = work(Db(conn))
    except BaseException:
        try:
            if conn.busy:
                conn.cancel()       # stopped in the middle of a statement (Ctrl-C): end it on the server too
            else:
                conn.execute("ROLLBACK")
        except (pgwire.PgError, pgwire.ProtocolError, OSError):
            pass
        raise
    conn.execute("COMMIT" if keep else "ROLLBACK")
    return out


def in_force(db: Db) -> bool:
    """Whether a policy is applied (so there is something to compare with)."""
    try:
        database.applied(db)
    except database.Error:
        return False
    return True


def table(rows: Sequence[Sequence[object]], cols: list[str]) -> str:
    cells = [["" if v is None else str(v) for v in r] for r in rows]
    width = [max([len(c)] + [len(r[i]) for r in cells]) for i, c in enumerate(cols)]
    line: Callable[[list[str]], str] = lambda r: "  ".join(v.ljust(w) for v, w in zip(r, width, strict=True)).rstrip()
    return "\n".join([line(cols), line(["-" * w for w in width])] + [line(r) for r in cells])


# --- rowfence.toml -----------------------------------------------------------------------------
class Config:
    """rowfence.toml, read with a typed accessor per setting."""

    def __init__(self, path: str | None = None, data: Mapping[str, object] | None = None) -> None:
        self.path = path
        self.data: dict[str, object] = dict(data or {})
        self.dir = os.path.dirname(path) if path else os.getcwd()

    def file(self, name: str) -> str:
        return os.path.normpath(os.path.join(self.dir, name))

    def inside(self, name: str, what: str) -> str:
        """A file rowfence.toml names to be read (the policy, the tests, the lock): in rowfence.toml's folder, also
        through links. The file may be a pull request's, read by CI: it must not name the runner's own files."""
        path = self.file(name)
        top = os.path.realpath(self.dir)
        if os.path.isabs(name) or not within(top, os.path.realpath(path)):
            fail(f"{self.path}: {what} = \"{name}\" is outside the folder {CONFIG} is in (or a link out of it): "
                 f"the files it names stay in that folder", 2)
        return path

    def section(self, name: str) -> dict[str, object]:
        """A [table] of the file (empty if it isn't there, or isn't a table)."""
        value = self.data.get(name)
        return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}

    def setting(self, section: str | None, key: str) -> str | None:
        """A text setting, top-level or in a [section]; None if it isn't text."""
        value = (self.section(section) if section else self.data).get(key)
        return value if isinstance(value, str) and value else None

    @property
    def policy(self) -> str | None:
        p = self.setting(None, "policy")
        return self.inside(p, "policy") if p else None

    def test_globs(self) -> list[str]:
        value = self.data.get("tests", [])
        return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []

    def tests(self) -> list[str]:
        """The test files its globs name, sorted."""
        out: list[str] = []
        for pattern in self.test_globs():
            self.inside(pattern.split("*")[0].split("?")[0].split("[")[0] or ".", "tests")
            out += sorted(f for f in glob.glob(self.file(pattern)) if self.inside(os.path.relpath(f, self.dir), "tests"))
        return list(dict.fromkeys(out))

    @property
    def clients(self) -> dict[str, str]:
        """{language: path}; the TypeScript one is only the policy's names when the app uses the SDK
        (a dependency on @rowfence/* in its package.json): the SDK has the rest."""
        out: dict[str, str] = {}
        for lang, p in self.section("clients").items():
            if isinstance(p, str):
                out["ts-sdk" if lang in ("ts", "typescript") and self.uses_ts_sdk() else lang] = self.file(p)
        return out

    @property
    def tool(self) -> str | None:
        """[migrations] tool: the app's migration tool."""
        return self.setting("migrations", "tool")

    @property
    def write_after(self) -> float:
        """[migrations] write_after: seconds after the last save that rowfence dev writes the migration (0: never)."""
        if "migrations" not in self.data:
            return 0
        value = self.section("migrations").get("write_after", 300)
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 300

    def uses_ts_sdk(self) -> bool:
        d = self.dir
        while True:
            try:
                with open(os.path.join(d, "package.json"), encoding="utf-8") as fh:
                    import stack
                    deps = stack.dependencies(json.load(fh))
                return any(name.startswith("@rowfence/") for name in deps)
            except (OSError, ValueError):
                pass
            parent = os.path.dirname(d)
            if parent == d:
                return False
            d = parent

    @property
    def database(self) -> str | None:
        db = self.setting(None, "database")
        if db and db.startswith("env:"):
            value = os.environ.get(db[4:])
            if value is None:
                fail(f"{self.path}: database = \"{db}\", but {db[4:]} is not set", 2)
            return value
        return db


# what rowfence.toml may hold: {setting: its type in words}, top-level and per [table]
SETTINGS: dict[str, dict[str, str]] = {
    "": {"policy": "text", "tests": "a list of patterns", "database": "text"},
    "clients": {"py": "text", "python": "text", "ts": "text", "typescript": "text", "ts-sdk": "text"},
    "migrations": {"tool": "text", "dir": "text", "lock": "text", "write_after": "a number"},
    "review": {"snapshot": "text"},
}


def check_settings(path: str, data: Mapping[str, object]) -> None:
    """Refuses a setting rowfence doesn't know, or one of the wrong type: left alone, `tests = "..."` runs no test."""
    def right(value: object, kind: str) -> bool:
        if kind == "text":
            return isinstance(value, str)
        if kind == "a number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        return isinstance(value, list) and all(isinstance(x, str) for x in value)

    def check(table: str, values: Mapping[str, object]) -> None:
        for key, value in values.items():
            name = f"[{table}] {key}" if table else key
            if table == "" and key in SETTINGS and key != "":
                if not isinstance(value, dict):
                    fail(f"{path}: [{key}] is a table of settings", 2)
                check(key, {str(k): v for k, v in value.items()})
            elif key not in SETTINGS[table]:
                known = ", ".join(SETTINGS[table]) + (", and the tables [clients], [migrations], [review]" if not table else "")
                fail(f"{path}: {name} is not a setting rowfence knows ({known})", 2)
            elif not right(value, SETTINGS[table][key]):
                example = 'tests = ["db/tests/*.authz"]' if key == "tests" else f"{key} = ..."
                fail(f"{path}: {name} is {SETTINGS[table][key]}: {example}", 2)
    check("", data)


def load_config() -> Config:
    d = os.getcwd()
    while True:
        path = os.path.join(d, CONFIG)
        if os.path.exists(path):
            try:
                import tomllib
            except ImportError:
                fail(f"{path}: reading it needs Python 3.11 or newer (tomllib)", 2)
            try:
                with open(path, "rb") as fh:
                    data = tomllib.loads(fh.read().decode("utf-8-sig"))     # a byte order mark is skipped
            except (OSError, ValueError) as e:
                fail(f"{path}: {e}", 2)
            check_settings(path, data)
            return Config(path, data)
        parent = os.path.dirname(d)
        if parent == d:
            return Config()
        d = parent


def relative(path: str) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:
        return path


# --- asking as someone ---------------------------------------------------------------------------
def principal(who: str) -> tuple[str, str]:
    """'user:42' -> ('user', '42'); 'anyone' -> ('user', '')."""
    if who in ("anyone", "nobody", ""):
        return "user", ""
    kind, sep, ident = who.partition(":")
    if not sep or not ident:
        fail(f"--as {who}: write it as user:42, bot:7 or anyone", 2)
    return kind, ident


Query = Callable[..., list[tuple[Value, ...]]]


def sign_in(q: Query, who: str) -> None:
    kind, ident = principal(who)
    q("SELECT authz.act_as($1, $2)", [kind, ident or None])


def app_role(q: Query) -> str:
    rows = q("SELECT DISTINCT r.rolname FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_description d ON d.objoid = p.oid "
             "AND d.classoid = 'pg_catalog.pg_policy'::regclass AND d.description = 'rowfence' "
             "CROSS JOIN unnest(p.polroles) ro JOIN pg_catalog.pg_roles r ON r.oid = ro")
    if not rows:
        fail("no policy with rules is applied, so there is no app role to run as", 1)
    return str(rows[0][0])


# --- tests ---------------------------------------------------------------------------------------
def read_tests(paths: list[str]) -> dict[str, str]:
    tests: dict[str, str] = {}
    for path in paths:
        try:
            tests[relative(path).replace(os.sep, "/")] = read_text(path)
        except OSError as e:
            raise Unreadable(f"{path}: {e.strerror}") from None
    return tests


class Unreadable(Exception):
    """A file that is missing or can't be read: 'path: why'."""


def write_clients(cfg: Config, text: str, files: dict[str, str]) -> list[str]:
    """Writes the clients rowfence.toml names; returns the files that changed. Every client is made before any
    file is opened: a mistake in the policy, or a language rowfence doesn't know, leaves the files as they were."""
    made = {path: database.client(lang, text, files) for lang, path in cfg.clients.items()}
    written: list[str] = []
    for path, code in made.items():
        try:
            if read_text(path) == code:
                continue
        except OSError:
            pass
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code)
        written.append(path)
    return written


def report_tests(rows: list[database.TestRow], out: Callable[[str], None] = print, verbose: bool = True) -> int:
    """Prints the results by test; returns the number that failed."""
    failed = 0
    current: str | None = None
    for test, line, ok, detail in rows:
        first, *rest = (detail or "").split("\n")
        if not ok:
            failed += 1
        if not verbose and ok:
            continue
        if test != current:
            out(test)
            current = test
        if ok:
            out(f"  ok    {first}")
        else:
            out(f"  FAIL  {line + ': ' if line else ''}{first}")
            for r in rest[:EXPLAIN_SHOWN]:
                out(f"          {r}")
            if len(rest) > EXPLAIN_SHOWN:
                out(f"          ... {len(rest) - EXPLAIN_SHOWN} more lines (rowfence explain --as ... shows them all)")
    return failed


# --- dev: the edit loop --------------------------------------------------------------------------
def watched(cfg: Config, policy_path: str) -> list[str]:
    files = [policy_path]
    try:
        _, inc = read_policy(policy_path)
        base = os.path.dirname(os.path.abspath(policy_path))
        files += [os.path.join(base, *k.split("/")) for k in inc]
    except OSError:
        pass
    return files + cfg.tests()


def stamp(files: list[str]) -> dict[str, int | None]:
    out: dict[str, int | None] = {}
    for f in files:
        try:
            out[f] = os.stat(f).st_mtime_ns
        except OSError:
            out[f] = None
    return out


class Dev:
    def __init__(self, cfg: Config, dsn: str | None, policy_path: str) -> None:
        self.cfg, self.dsn, self.policy = cfg, dsn, policy_path
        self.conn: pgwire.Connection | None = None
        self.notices: list[pgwire.Fields] = []
        self.lint: set[str] | None = None
        self.studio_port: int | None = None     # rowfence dev starts Studio on it (None: not)

    def connect(self) -> pgwire.Connection:
        if self.conn is None:
            conn = pgwire.connect(**pgwire.parse_dsn(self.dsn))
            conn.on_notice = self.notices.append
            conn.query("SELECT set_config('client_min_messages', 'warning', false)")
            self.conn = conn
        return self.conn

    def index_warnings(self) -> None:
        """The lookups the policy makes into the app's tables that no index serves (rowfence indexes), once."""
        from authzlib import perf
        try:
            missing = transaction(self.connect(), lambda db: perf.missing_indexes(
                db, database.policy_compiler(*database.applied(db))), keep=False)
        except (database.Error, pgwire.PgError, OSError):
            return
        if missing:
            self.say("!", perf.describe_missing(missing, self.cfg.tool or "sql"))

    def say(self, mark: str, text: str) -> None:
        lines = text.split("\n")
        print(f"  {mark:<4} {lines[0]}")
        for line in lines[1:]:
            print(f"       {line}")

    def cycle(self, why: str) -> bool:
        """One pass; True if everything passed."""
        print(f"{time.strftime('%H:%M:%S')} {why}")
        try:
            text, files = read_policy(self.policy)
        except OSError as e:
            self.say("x", f"{relative(self.policy)}: {e.strerror}")
            return False
        msg = database.check(text, files)
        if msg:
            where = msg.removeprefix("policy ")
            line = re.match(r"(?:(\S+) )?line (\d+):", where)
            source = ""
            if line:
                name = line.group(1)
                body = files.get(name, text) if name else text
                lines = body.split("\n")
                n = int(line.group(2))
                if 0 < n <= len(lines):
                    source = "\n  " + lines[n - 1].strip()
            self.say("x", f"{relative(self.policy)}: {where}{source}\nnothing applied: the database keeps the policy in force")
            return False
        self.say("ok", "compiles")
        try:
            conn = self.connect()
        except (ValueError, OSError, pgwire.PgError, pgwire.ProtocolError) as e:
            self.say("x", f"can't connect: {e}")
            self.conn = None
            return False
        try:
            self.diff(conn, text, files)
            self.notices.clear()
            started = time.monotonic()
            state = transaction(conn, lambda db: database.push(db, text, files))
            took = time.monotonic() - started
            self.say("ok", "unchanged: already in force" if state == "unchanged" else
                     f"applied in {took:.2f} s" + (" (the whole policy)" if state == "applied" else ""))
            warnings = [n.get("M", "") + (f"\n{n['D']}" if n.get("D") else "") + (f"\n{n['H']}" if n.get("H") else "")
                        for n in self.notices]
            for w in warnings:
                if w not in (self.lint or ()):
                    self.say("!", w)
            old = sum(1 for w in warnings if w in (self.lint or ()))
            if old:
                self.say("!", f"and {old} warning(s) shown before")
            if state != "unchanged":
                self.lint = set(warnings)
            passed = self.tests(conn)
            for path in write_clients(self.cfg, text, files):
                self.say("ok", f"wrote {relative(path)}")
            return passed
        except Unreadable as e:
            self.say("x", str(e))
            return False
        except database.Error as e:
            self.say("x", str(e) + (f"\n{e.hint}" if e.hint else "") + "\nnothing applied")
            return False
        except pgwire.PgError as e:
            detail = e.fields.get("D")
            self.say("x", e.message + (f"\n{detail}" if detail else "") + "\nnothing applied")
            return False
        except (OSError, pgwire.ProtocolError) as e:
            self.say("x", f"lost the database: {e}")
            self.conn = None
            return False

    def diff(self, conn: pgwire.Connection, text: str, files: dict[str, str]) -> None:
        def changes(db: Db) -> list[database.DiffRow] | None:
            return database.diff(db, text, files) if in_force(db) else None
        found = transaction(conn, changes, keep=False)
        if found is None:
            return
        groups: dict[tuple[str, str, str], tuple[set[str | None], set[str]]] = {}
        for r in found:
            users, objs = groups.setdefault((r["change"], r["type"], r["what"]), (set(), set()))
            users.add(r["user_id"])
            objs.add(r["id"])
        rows = [(c, t, w, len(u), len(o)) for (c, t, w), (u, o) in sorted(groups.items())]
        if not rows:
            self.say("~", "access: nobody gains or loses anything")
            return
        parts = [f"{users} user(s) {change.rstrip('s')} {what} on {objs} of {type_}"
                 for change, type_, what, users, objs in rows[:8]]
        more = f"\n... and {len(rows) - 8} more (rowfence diff)" if len(rows) > 8 else ""
        self.say("~", "access:\n" + "\n".join(parts) + more)

    def tests(self, conn: pgwire.Connection) -> bool:
        from authzlib import coverage
        tests = read_tests(self.cfg.tests())
        rows, report = transaction(conn, lambda db: database.coverage(db, tests), keep=False)
        failed = report_tests(rows, out=lambda s: None)
        if not rows:
            self.say("ok", "no tests yet (rowfence.toml: tests = [\"db/tests/*.authz\"])")
            return True
        if not failed:
            missing = coverage.summary(report)
            self.say("ok", f"{len(rows)} check(s) pass" + (f"; {missing}" if missing else ""))
            return True
        out: list[str] = []
        report_tests(rows, out=out.append, verbose=False)
        self.say("x", f"{failed} of {len(rows)} checks fail\n" + "\n".join(out))
        return False

    def run(self, once: bool) -> bool:
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(line_buffering=True)     # a line as it happens, even into a pipe or a log
        target = pgwire.parse_dsn(self.dsn)
        print(f"rowfence dev: {relative(self.policy)} -> {target['database']} on {target['host']}:{target['port']}")
        passed = self.cycle("start")
        if passed:
            self.index_warnings()
        if once:
            return passed
        if self.studio_port is not None:
            # Studio beside the loop, able to write: this is a development database
            import studio
            try:
                url = studio.Studio(self.dsn, self.cfg, self.policy, writable=True, port=self.studio_port,
                                    read_policy=read_policy).start(background=True)
                print(f"Studio on {url}")
            except OSError as e:
                print(f"Studio didn't start ({e}): rowfence dev --studio-port N for another port")
        files = watched(self.cfg, self.policy)
        seen = stamp(files)
        # with [migrations] in rowfence.toml, the migration is written once you stop editing (write_after
        # seconds after the last save that passed; 0: never, run rowfence migrate yourself)
        after = self.cfg.write_after
        pending: float | None = None
        print(f"watching {len(files)} file(s); Ctrl-C to stop")
        try:
            while True:
                time.sleep(0.4)
                files = watched(self.cfg, self.policy)
                now = stamp(files)
                if now != seen:
                    changed = [relative(f) for f in files if now.get(f) != seen.get(f)]
                    time.sleep(0.1)                     # editors write in steps
                    seen = stamp(files)
                    pending = time.monotonic() if self.cycle(", ".join(changed[:3]) + " saved") and after else None
                if pending is not None and time.monotonic() - pending >= after:
                    pending = None
                    self.write_migration()
        except KeyboardInterrupt:
            return True

    def write_migration(self) -> None:
        """'stopped editing': the migration for what changed, if the lock file is behind the policy."""
        try:
            text, files = read_policy(self.policy)
        except OSError:
            return
        print(f"{time.strftime('%H:%M:%S')} stopped editing")
        try:
            migrate_cmd(self.cfg, self.policy, text, files, {}, False)
        except SystemExit:
            pass


# --- main ----------------------------------------------------------------------------------------
# each command, and how many arguments it takes at most (None: any number)
ARGUMENTS: dict[str, int | None] = {
    "dev": 1, "studio": 0, "migrate": 1, "review": 1, "fmt": None, "push": 1, "apply": 1, "check": 1, "prove": 1,
    "diff": 1, "test": None, "graph": 1, "lint": 0, "indexes": 0, "plans": 0, "bench": 0, "snapshot": 0, "client": 2,
    "init": 0, "lsp": 0, "mcp": 0, "can": 3, "explain": 3, "perms": 2, "list": 2, "who": 3, "why": 3,
    "explain-rule": 3, "sql": 1, "reapply": 0, "remove": 0,
}


def main(argv: list[str]) -> None:
    dsn: str | None = None
    opts: dict[str, str] = {}
    # options are read wherever they are on the line: `rowfence --db URL lint` and `rowfence lint --db URL`
    # (for `sql`, not in its last argument: that is the statement, which may hold anything)
    def options() -> list[str]:
        return argv[:-1] if "sql" in argv else argv

    for flag in ("--db", "-d", "--users", "--limit", "--as", "--row", "--schema", "--role", "--out", "--name", "--tool",
                 "--dir", "--base", "--port", "--studio-port", "--worlds", "--people", "--rounds"):
        if flag in options():
            i = argv.index(flag)
            if i + 1 >= len(argv):
                fail(f"{flag} needs a value", 2)
            opts[flag] = argv[i + 1]
            del argv[i:i + 2]
            if flag in options():
                fail(f"{flag} is given twice", 2)
    if "--db" in opts or "-d" in opts:
        dsn = opts.pop("--db", None) or opts.pop("-d")
    for flag in ("--limit", "--port", "--studio-port", "--worlds", "--people", "--rounds"):
        if flag in opts and not (opts[flag].isdigit() and int(opts[flag]) > 0):
            fail(f"{flag} needs a whole number above 0, not {opts[flag]!r}", 2)
    flags = {a for a in argv if a in ("--yes", "--force", "--once", "--check", "--one-phase", "--markdown", "--json",
                                      "--annotations", "--write", "--no-studio", "--coverage", "--development", "--downgrade")}
    argv = [a for a in argv if a not in flags]
    if argv[:1] == ["help"] and argv[1:]:
        from authzlib import errors
        code = argv[1].upper()
        if code in errors.CODES:
            print(errors.page(code))
        elif code in ("ERRORS", "CODES"):
            sys.stdout.write(errors.index())
        else:
            fail(f"rowfence help: no code {argv[1]} (rowfence help errors lists them)", 2)
        return
    if not argv or argv[0] in ("-h", "--help", "help") or "--help" in argv:
        fail(__doc__, 0 if argv else 2)
    if argv[0] in ("--version", "version"):
        from authzlib import __version__
        print(f"rowfence {__version__} (Python {sys.version.split()[0]})")
        return
    cmd, args = argv[0], argv[1:]
    if cmd not in ARGUMENTS:
        fail(f"unknown command '{cmd}'\n\n{__doc__}", 2)
    most = ARGUMENTS[cmd]
    unknown = [a for a in args if a.startswith("--")] if cmd != "sql" else []
    if unknown:
        fail(f"rowfence {cmd}: {unknown[0]} is not an option it has (rowfence --help)", 2)
    if most is not None and len(args) > most:
        fail(f"rowfence {cmd} takes {most or 'no'} argument{'' if most == 1 else 's'}: what is "
             f"{' '.join(args[most:])}? (rowfence --help)", 2)
    cfg = load_config()

    if cmd == "lsp":
        from lsp import serve
        serve(cfg)
        return
    if cmd == "mcp":
        import mcp
        mcp.serve(dsn)
        return

    def policy_arg() -> tuple[str, str, dict[str, str]]:
        path = args[-1] if args else cfg.policy
        if not path:
            fail(f"rowfence {cmd}: which policy file? (or name it in {CONFIG}: policy = \"db/policy.authz\")", 2)
        try:
            text, files = read_policy(path)
        except OSError as e:
            fail(f"{path}: {e.strerror}", 2)
        return path, text, files

    # without a database: the compiler alone
    try:
        if cmd == "check":
            path, text, files = policy_arg()
            msg = database.check(text, files)
            if msg:
                fail(f"{path}: {msg.removeprefix('policy ')}")
            print(f"{path}: ok")
            return
        if cmd == "graph" and (args or cfg.policy):
            _, text, files = policy_arg()
            sys.stdout.write(database.graph(text, files))
            return
        if cmd == "client" and args[1:]:
            if args[0] not in ("py", "ts"):
                fail("rowfence client: which language, py or ts?", 2)
            _, text, files = policy_arg()
            sys.stdout.write(database.client(args[0], text, files))
            return
        if cmd == "prove":
            from authzlib import parse_policy, prove
            path, text, files = policy_arg()
            # the policy as `rowfence check` sees it: one the compiler refuses has nothing to prove
            msg = database.check(text, files)
            if msg:
                fail(f"{relative(path)}: {msg.removeprefix('policy ')}")
            try:
                pol = parse_policy(text, None, files=files)
            except database.PolicyError as e:
                fail(f"{relative(path)}: {e}")
            if not pol.invariants:
                print(f"{relative(path)}: no invariants to prove (write them under 'invariants': never TYPE: ...)")
                return
            results = prove.prove(pol, worlds=int(opts.get("--worlds", prove.WORLDS)))
            print(prove.describe(results))
            sys.exit(0 if all(r["holds"] for r in results) else 1)
        if cmd == "fmt":
            sys.exit(fmt_cmd(cfg, args, "--check" in flags))
        if cmd == "review":
            sys.exit(review_cmd(cfg, args, opts, flags, dsn))
        if cmd == "migrate":
            path, text, files = policy_arg()
            sys.exit(migrate_cmd(cfg, path, text, files, opts, "--check" in flags, "--one-phase" in flags, "--downgrade" in flags))
        if cmd == "client" and not args and cfg.clients and cfg.policy:
            _, text, files = policy_arg()
            write_clients(cfg, text, files)
            for path in cfg.clients.values():
                print(f"wrote {relative(path)}")
            return
    except database.Error as e:
        fail(str(e) + (f"\nHINT: {e.hint}" if e.hint else ""))
    except Unreadable as e:
        fail(str(e), 2)
    except RecursionError:
        fail(f"rowfence {cmd}: an expression in the policy is nested too deep to read", 1)

    dsn = dsn if dsn is not None else (cfg.database or os.environ.get("DATABASE_URL"))
    if cmd == "dev":
        path = args[0] if args else cfg.policy
        if not path:
            fail(f"rowfence dev: which policy file? (or name it in {CONFIG}: policy = \"db/policy.authz\")", 2)
        dev = Dev(cfg, dsn, path)
        dev.studio_port = None if "--no-studio" in flags else int(opts.get("--studio-port", "4983"))
        sys.exit(0 if dev.run("--once" in flags) else 1)
    if cmd == "studio":
        import studio
        target = dsn if dsn is not None else (cfg.database or os.environ.get("DATABASE_URL") or "")
        studio.serve(target, cfg, cfg.policy, "--write" in flags, int(opts.get("--port", "4983")), read_policy)
        return

    try:
        conn = pgwire.connect(**pgwire.parse_dsn(dsn))
    except (ValueError, OSError, pgwire.PgError, pgwire.ProtocolError) as e:
        fail(f"can't connect: {e}", 2)
    conn.on_notice = lambda f: print(f"{f.get('V', f.get('S', 'NOTICE'))}: {f.get('M', '')}"
                                     + (f"\nDETAIL: {f['D']}" if f.get("D") else "")
                                     + (f"\nHINT: {f['H']}" if f.get("H") else ""), file=sys.stderr)
    q = conn.query
    q("SELECT set_config('client_min_messages', 'warning', false)")
    try:
        if cmd == "apply":
            path, text, files = policy_arg()
            state = transaction(conn, lambda db: database.apply(db, text, files, "--force" not in flags, "--downgrade" in flags,
                                                                   rebuild="--force" in flags))
            print(f"{path}: {state}")
        elif cmd == "push":
            path, text, files = policy_arg()
            state = transaction(conn, lambda db: database.push(db, text, files, mark="--development" in flags,
                                                                  downgrade="--downgrade" in flags))
            print(f"{path}: {state}" + (" (the whole policy)" if state == "applied" else ""))
        elif cmd == "diff":
            path, text, files = policy_arg()
            users = [u for u in opts.get("--users", "").split(",") if u] or None
            cols = ["change", "user_id", "type", "what", "id"]
            rows = [(r["change"], r["user_id"] if r["user_id"] is not None else "(nobody signed in)", r["type"], r["what"], r["id"])
                    for r in transaction(conn, lambda db: database.diff(db, text, files, users), keep=False)]
            counts: dict[tuple[str, str, str], int] = {}
            for change, _, type_, what, _ in rows:
                counts[(type_, what, change)] = counts.get((type_, what, change), 0) + 1
            print(f"{path}: {len(rows)} changes" + ("" if rows else " (nobody gains or loses anything)"))
            if rows:
                print(table([(t, w, c, n) for (t, w, c), n in sorted(counts.items())], ["type", "what", "change", "pairs"]))
                limit = int(opts.get("--limit", 200))
                print()
                print(table(rows[:limit], cols))
                if len(rows) > limit:
                    print(f"... and {len(rows) - limit} more (--limit)")
        elif cmd == "test":
            from authzlib import coverage
            if not args and cfg.test_globs() and not cfg.tests():
                print(f"{cfg.path}: tests = {cfg.test_globs()} matches no file", file=sys.stderr)
            tests = read_tests(args or cfg.tests())
            report: coverage.Report | None = None
            if "--coverage" in flags:
                rows, report = transaction(conn, lambda db: database.coverage(db, tests), keep=False)
            else:
                rows = transaction(conn, lambda db: database.test(db, tests), keep=False)
            failed = report_tests(rows)
            if failed:
                print(f"{failed} policy test(s) failed")      # after the results, on the same stream
                sys.exit(1)
            print(f"policy tests passed ({len(rows)} checks)")
            if report is not None:
                print(coverage.describe(report))
        elif cmd == "snapshot":
            snapshot_cmd(conn, cfg, opts, "--check" in flags)
        elif cmd == "lint":
            found = transaction(conn, database.lint, keep=False)
            if not found:
                print("authz.lint(): nothing found")
            else:
                print(table([(r["severity"], r["object"], r["problem"]) for r in found], ["severity", "object", "problem"]))
            if any(r["severity"] in ("error", "warning") for r in found):
                sys.exit(1)
        elif cmd in ("indexes", "plans", "bench"):
            from authzlib import perf

            def compiled(db: Db) -> database.Compiler:
                return database.policy_compiler(*database.applied(db))

            if cmd == "indexes":
                out = transaction(conn, lambda db: perf.missing_indexes(db, compiled(db)), keep=False)
                if out:
                    print(perf.describe_missing(out, cfg.tool or "sql"))
                else:
                    print("every lookup the policy makes into the app's tables has an index")
                if out and "--check" in flags:
                    sys.exit(1)
            elif cmd == "plans":
                who = principal(opts["--as"]) if opts.get("--as") else None
                print(perf.describe_plans(transaction(conn, lambda db: perf.plans(db, compiled(db), who), keep=False)))
            else:
                people, rounds = int(opts.get("--people", "10")), int(opts.get("--rounds", "20"))
                print(perf.describe_bench(transaction(
                    conn, lambda db: perf.bench(db, compiled(db), people=people, rounds=rounds), keep=False)))
        elif cmd == "graph":
            text, files = transaction(conn, database.applied, keep=False)
            sys.stdout.write(database.graph(text, files))
        elif cmd == "client":
            text, files = transaction(conn, database.applied, keep=False)
            if not args and cfg.clients:
                write_clients(cfg, text, files)
                for path in cfg.clients.values():
                    print(f"wrote {relative(path)}")
                return
            if not args or args[0] not in ("py", "ts"):
                fail("rowfence client: which language, py or ts?", 2)
            sys.stdout.write(database.client(args[0], text, files))
        elif cmd == "why":
            if len(args) != 3 or not opts.get("--as"):
                fail("rowfence why --as user:42 TYPE ID PERM", 2)
            from authzlib import grant
            kind, ident = principal(opts["--as"])
            type_name, oid, perm = args
            answer = transaction(conn, lambda db: database.why(db, kind, ident, type_name, oid, perm), keep=False)
            print(grant.describe(answer, opts["--as"], type_name, oid, perm))
        elif cmd in ("can", "explain", "perms", "list", "who", "explain-rule", "sql"):
            ask(conn, cmd, args, opts)
        elif cmd == "init":
            from init import init
            schemas = [s for s in opts.get("--schema", "").split(",") if s] or None
            policy = transaction(conn, lambda db: database.draft(db, schemas, opts.get("--users"),
                                                                 opts.get("--role", "app_user")), keep=False)
            init(policy, opts, cfg)
        elif cmd == "reapply":
            transaction(conn, lambda db: database.reapply(db, rebuild="--force" in flags))
            print("applied again")
        elif cmd == "remove":
            if "--yes" not in flags:
                fail("rowfence remove drops every view, trigger and row-level security policy the current policy made "
                     "(shares and history stay). Run it again with --yes.", 2)
            transaction(conn, database.remove)
            print("removed")
        else:
            fail(f"unknown command '{cmd}'\n\n{__doc__}", 2)
    except database.Error as e:
        fail(str(e) + (f"\nHINT: {e.hint}" if e.hint else ""))
    except pgwire.PgError as e:
        if (e.code == "3F000" and 'schema "authz"' in e.message) or (e.code == "42883" and "function authz." in e.message):
            fail("no policy is applied [AZ609]\nHINT: rowfence apply db/policy.authz")     # as the other commands say it
        if e.fields.get("S") in ("FATAL", "PANIC"):
            fail(f"lost the database: {e.message}", 2)
        detail = e.fields.get("D")
        hint = e.fields.get("H")
        fail(e.message + (f"\nDETAIL: {detail}" if detail else "") + (f"\nHINT: {hint}" if hint else ""))
    except (OSError, pgwire.ProtocolError) as e:
        fail(f"lost the database: {e}", 2)
    except Unreadable as e:
        fail(str(e), 2)
    except RecursionError:
        fail(f"rowfence {cmd}: an expression in the policy is nested too deep to read", 1)
    except KeyboardInterrupt:
        fail("stopped: nothing was kept", 130)
    finally:
        conn.close()


# --- review and fmt ------------------------------------------------------------------------------
def git(*args: str) -> str | None:
    import subprocess
    try:
        p = subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8")
    except FileNotFoundError:
        fail("rowfence: git is not installed (the review reads the base branch with it)", 2)
    return p.stdout if p.returncode == 0 else None


def at_base(ref: str, path: str) -> str | None:
    """A file's text at a commit (None if it isn't there), for a path relative to here."""
    rel = os.path.relpath(path).replace(os.sep, "/")
    return git("show", f"{ref}:./{rel}" if not rel.startswith("..") else f"{ref}:{rel}")


def base_policy(ref: str, path: str) -> tuple[str | None, dict[str, str]]:
    """The policy at a commit, and the files it includes (read from git, as read_policy reads the disk)."""
    text = at_base(ref, path)
    if text is None:
        return None, {}
    base = os.path.dirname(os.path.abspath(path))
    return text, collect_includes(text, lambda key: at_base(ref, os.path.join(base, *key.split("/"))))


def base_tests(cfg: Config, ref: str) -> dict[str, str]:
    """The test files rowfence.toml names, as they were at a commit."""
    import fnmatch
    root = git("rev-parse", "--show-toplevel")
    listed = git("ls-tree", "-r", "--name-only", "--full-tree", ref)   # from the top folder, wherever this runs
    if root is None or listed is None:
        return {}
    root = root.strip()
    out: dict[str, str] = {}
    for pattern in cfg.test_globs():
        full = os.path.normpath(cfg.file(pattern))
        rel_pattern = os.path.relpath(full, root).replace(os.sep, "/")
        for name in listed.split("\n"):
            if name and fnmatch.fnmatch(name, rel_pattern):
                text = git("show", f"{ref}:{name}")
                if text is not None:
                    out[relative(os.path.join(root, name)).replace(os.sep, "/")] = text
    return out


def default_base() -> str:
    for ref in ("origin/main", "main", "origin/master", "master"):
        if git("rev-parse", "--verify", "--quiet", ref) is not None:
            return ref
    fail("rowfence review: which commit to compare with? --base main (or a commit)", 2)


def review_cmd(cfg: Config, args: list[str], opts: dict[str, str], flags: set[str], dsn: str | None) -> int:
    """What the change since --base does, as text, --markdown (the pull request comment), --json
    or --annotations (GitHub workflow commands). Access and the tests' results need --db: a database at the
    base's state (its migrations, then the review data), which the review changes nothing in."""
    from authzlib import review
    path = args[-1] if args else cfg.policy
    if not path:
        fail(f"rowfence review: which policy file? (or name it in {CONFIG}: policy = \"db/policy.authz\")", 2)
    ref = opts.get("--base") or default_base()
    # a commit git doesn't know would read as "no policy there": the whole policy reviewed as new
    if ref.startswith("-") or git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}") is None:
        fail(f"rowfence review: git doesn't know the commit to compare with, {ref} (a shallow checkout? fetch the "
             "base branch: fetch-depth: 0 with actions/checkout)", 2)
    try:
        head_text, head_files = read_policy(path)
    except OSError as e:
        fail(f"{path}: {e.strerror}", 2)
    base_text, base_files = base_policy(ref, path)
    if base_text is None:
        base_text, base_files = "app role app_user\ntype user = app.users\n", {}
    lock = lock_path(cfg, path)
    base_lock = at_base(ref, lock)
    try:
        with open(lock, encoding="utf-8") as fh:
            head_lock = fh.read()
    except FileNotFoundError:
        head_lock = None
    head_tests = read_tests(cfg.tests())
    conn: pgwire.Connection | None = None
    db: Db | None = None
    if dsn is not None:
        try:
            conn = pgwire.connect(**pgwire.parse_dsn(dsn))
        except (ValueError, OSError, pgwire.PgError, pgwire.ProtocolError) as e:
            fail(f"can't connect: {e}", 2)
        conn.on_notice = lambda f: None
        conn.execute("BEGIN")
        db = Db(conn)
    try:
        r = review.review((base_text, base_files, base_tests(cfg, ref)), (head_text, head_files, head_tests),
                          base_lock, head_lock, db)
    except database.Error as e:
        fail(str(e))
    except review.PolicyError as e:
        fail(f"{path}: {e}")
    except review.BaseMistake as e:
        fail(f"{path} at {ref}: {e}")
    finally:
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except pgwire.PgError:
                pass
            conn.close()
    if "--json" in flags:
        sys.stdout.write(review.as_json(r))
    elif "--markdown" in flags:
        sys.stdout.write(review.markdown(r))
    elif "--annotations" in flags:
        # GitHub finds the file from the repository's top folder, wherever in it the review runs
        top = (git("rev-parse", "--show-toplevel") or "").strip() or os.getcwd()
        sys.stdout.write(review.annotations(r, os.path.relpath(os.path.abspath(path), top).replace(os.sep, "/")))
    else:
        sys.stdout.write(review.text(r))
    return 0


def line_ending(path: str) -> str:
    """How the file's lines end: as its first line does (a Windows checkout's CRLF stays CRLF)."""
    with open(path, "rb") as fh:
        return "\r\n" if fh.readline().endswith(b"\r\n") else "\n"


def fmt_cmd(cfg: Config, args: list[str], check: bool) -> int:
    """Formats the policy and its test files (or the files named) one way; --check: only says which aren't.
    Line endings are the file's own: read either way, written back as found."""
    from authzlib.fmt import FormatError, format
    paths = args or ([cfg.policy] if cfg.policy else []) + cfg.tests()
    if not paths:
        fail(f"rowfence fmt: which files? (or name the policy in {CONFIG})", 2)
    bad = 0
    for path in paths:
        try:
            text, files = read_policy(path)         # with the files it includes: the format must say the same
        except OSError as e:
            fail(f"{path}: {e.strerror}", 2)
        try:
            done = format(text, files)
        except FormatError as e:
            print(f"{relative(path)}: {e}", file=sys.stderr)
            bad += 1
            continue
        if done == text:
            continue
        if check:
            print(f"{relative(path)}: not formatted (rowfence fmt)")
            bad += 1
        else:
            with open(path, "w", encoding="utf-8", newline=line_ending(path)) as fh:
                fh.write(done)
            print(f"formatted {relative(path)}")
    return 1 if bad else 0


# --- migrations ----------------------------------------------------------------------------------
def lock_path(cfg: Config, policy_path: str) -> str:
    lock = cfg.setting("migrations", "lock")
    return cfg.inside(lock, "[migrations] lock") if lock else os.path.splitext(policy_path)[0] + ".lock"


def migration_name(summary: list[str]) -> str:
    """A name from what changed: the one line that changed, else 'policy'."""
    if len(summary) == 1 and summary[0][:2] in ("+ ", "- "):
        words = re.sub(r"[^A-Za-z0-9]+", " ", summary[0][2:]).split()
        drop = {"type", "can", "rules", "user", "shared", "and", "or", "not"}
        return "_".join([w for w in words if w.lower() not in drop][:5]).lower() or "policy"
    return "policy"


def migrate_cmd(cfg: Config, path: str, text: str, files: dict[str, str], opts: dict[str, str], check: bool,
                one_phase: bool = False, downgrade: bool = False) -> int:
    """Writes the migration from the lock file to this policy, for the tool rowfence.toml names (two, when
    inheritance trees are built beside the ones in use first); with --check, only says whether there is one
    to write (exit 1 if so). Needs no database."""
    import migrations
    tool = opts.get("--tool") or cfg.tool or "sql"
    if tool not in migrations.TOOLS:
        fail(f"rowfence migrate: unknown tool '{tool}' (use one of {', '.join(migrations.TOOLS)})", 2)
    folder = cfg.file(opts.get("--dir") or cfg.setting("migrations", "dir") or migrations.DEFAULT_DIRS[tool])
    lock = lock_path(cfg, path)
    try:
        with open(lock, encoding="utf-8") as fh:
            old = fh.read()
    except FileNotFoundError:
        old = ""
    try:
        ms = database.migrations(text, files, old, opts.get("--name") or "policy", not one_phase, downgrade)
    except database.Error as e:
        fail(f"{path}: {str(e).removeprefix('policy ')}")
    if all(m.empty for m in ms):
        print(f"nothing to migrate: {relative(lock)} is up to date with {relative(path)}")
        return 0
    summary = ms[-1].summary
    if check:
        print(f"{relative(path)} has changes no migration has: run rowfence migrate")
        for line in summary[:20]:
            print(f"  {line}")
        return 1
    name = opts.get("--name") or migration_name(summary)
    ms = database.migrations(text, files, old, name, not one_phase, downgrade)
    written: list[str] = []
    now = time.time()
    try:
        for i, m in enumerate(ms):
            written += migrations.write_migration(tool, folder, f"build_{name}" if i < len(ms) - 1 else name, m.sql,
                                                  now=now + i)
    except migrations.Error as e:
        fail(f"rowfence migrate: {e}", 2)
    os.makedirs(os.path.dirname(lock) or ".", exist_ok=True)
    with open(lock, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(ms[-1].lock)
    for line in summary[:20]:
        print(f"  {line}")
    if len(summary) > 20:
        print(f"  ... and {len(summary) - 20} more")
    if len(ms) == 2:
        print(f"builds {', '.join(ms[0].rebuilt)} beside the ones in use (the app keeps working), then swaps "
              f"{'them' if len(ms[0].rebuilt) > 1 else 'it'} in: two migrations")
    rebuilt = [t for t in ms[-1].rebuilt if len(ms) == 1 or t not in ms[0].rebuilt]
    if rebuilt:
        print(f"rebuilds {', '.join(rebuilt)} (the app's tables they follow are locked while it runs)")
    for f in written:
        print(f"wrote {relative(f)}")
    print(f"wrote {relative(lock)}")
    rel: Callable[[str], str] = lambda p: os.path.relpath(p, cfg.dir).replace(os.sep, "/")
    marked = migrations.mark_generated(cfg.dir, migrations.generated_patterns(tool, rel(folder), rel(lock))) \
        if cfg.path else None
    if marked:
        print(f"wrote {relative(marked)} (reviews show the generated files collapsed)")
    return 0


def take_app_role(conn: pgwire.Connection) -> None:
    """The rest of the transaction as the app role; if this connection may not switch to it, what to grant."""
    role = app_role(conn.query)
    try:
        database.may_take(Db(conn), role)
    except database.Error as e:
        fail(str(e) + (f"\nHINT: {e.hint}" if e.hint else ""))
    conn.query(f"SET LOCAL ROLE {quote_ident(role)}")


def ask(conn: pgwire.Connection, cmd: str, args: list[str], opts: dict[str, str]) -> None:
    """One question to the database, as someone, in a transaction that is rolled back."""
    q = conn.query
    need = {"can": 3, "explain": 3, "perms": 2, "list": 2, "who": 3, "sql": 1}
    if cmd in need and len(args) != need[cmd]:
        fail(f"rowfence {cmd}: see rowfence --help", 2)
    who = opts.get("--as")
    if who is None and cmd not in ("who",):
        fail(f"rowfence {cmd}: as whom? --as user:42 (or bot:7, or anyone)", 2)
    q("BEGIN")
    try:
        if who is not None:
            sign_in(q, who)
        if cmd == "can":
            (ok,), = q("SELECT authz.can($1, $2, $3)", args)
            print("yes" if ok else "no")
        elif cmd == "explain":
            for (line,) in q("SELECT l FROM authz.explain($1, $2, $3) l", args):
                print(line)
        elif cmd == "perms":
            (perms,), = q("SELECT authz.perms($1, $2)", args)
            print("\n".join(str(p) for p in perms) if isinstance(perms, list) and perms else "(none)")
        elif cmd == "list":
            for (x,) in q("SELECT x FROM authz.list($1, $2) x", args):
                print(x)
        elif cmd == "who":
            for (x,) in q("SELECT x FROM authz.who($1, $2, $3) x", args):
                print(x)
        elif cmd == "explain-rule":
            if len(args) not in (2, 3):
                fail("rowfence explain-rule --as WHO TABLE insert|update|delete [ID] [--row JSON]", 2)
            row = opts.get("--row")
            if row is not None:
                try:
                    if not isinstance(json.loads(row), dict):
                        fail("--row: the row as a JSON object, {\"column\": value}", 2)
                except ValueError as e:
                    fail(f"--row: {e}", 2)
            take_app_role(conn)
            (lines,), = q("SELECT authz.explain_rule($1, $2, $3, $4::jsonb)",
                          [args[0], args[1], args[2] if len(args) > 2 else None, row])
            print("\n".join(str(x) for x in lines) if isinstance(lines, list) else f"not found: {args[0]} {args[2] if len(args) > 2 else ''} "
                                                              f"isn't there, or {who} can't see it")
        elif cmd == "sql":
            take_app_role(conn)
            rows, cols = conn.query_described(args[0])
            if cols:
                print(table(rows, cols))
                print(f"({len(rows)} row{'s' if len(rows) != 1 else ''}, as {who}; rolled back)")
            else:
                print(f"done, as {who}; rolled back")
    finally:
        try:
            q("ROLLBACK")
        except (pgwire.PgError, pgwire.ProtocolError, OSError):
            pass


def snapshot_path(cfg: Config, opts: dict[str, str]) -> str:
    """--out, else [review] snapshot in rowfence.toml, else access.snapshot next to the policy."""
    if opts.get("--out"):
        return opts["--out"]
    snapshot = cfg.setting("review", "snapshot")
    if snapshot:
        return cfg.file(snapshot)
    base = os.path.dirname(cfg.policy) if cfg.policy else "."
    return os.path.join(base, "access.snapshot")


def snapshot_cmd(conn: pgwire.Connection, cfg: Config, opts: dict[str, str], check: bool) -> None:
    path = snapshot_path(cfg, opts)
    lines = transaction(conn, database.snapshot, keep=False)
    text = database.SNAPSHOT_HEAD + "".join(x + "\n" for x in lines)
    try:
        with open(path, encoding="utf-8") as fh:
            old = fh.read()
    except OSError:
        old = None
    if check:
        if old == text:
            print(f"{relative(path)} is up to date ({len(lines)} lines)")
            return
        before = {x for x in (old or "").split("\n") if x and not x.startswith("#")}
        after = set(lines)
        print(f"{relative(path)} is out of date: rowfence snapshot writes it" if old is not None
              else f"{relative(path)} is missing: rowfence snapshot writes it")
        for x in sorted(after - before)[:20]:
            print(f"  + {x}")
        for x in sorted(before - after)[:20]:
            print(f"  - {x}")
        sys.exit(1)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"wrote {relative(path)} ({len(lines)} lines)")


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


if __name__ == "__main__":
    main(sys.argv[1:])
