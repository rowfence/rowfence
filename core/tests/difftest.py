#!/usr/bin/env python3
"""difftest: check the compiled policy against an independent evaluator.

    python3 tests/difftest.py --db authz_difftest --gen docs --steps 150 --seed 1

Builds a random data set for the policy, applies the compiled policy, then
repeatedly changes the data at random (moves, links, team nesting, shares,
expiry, inheritance flags, deletes, id changes, TRUNCATE, several changes in
one transaction) and after every change compares, for every user:

  - authz.list() for every permission of every type
  - authz.can() for every object and permission, plus ids that don't exist
  - the rows each RLS policy lets the app role read
  - every policy expression (USING and WITH CHECK) evaluated on every row
  - every column rule's condition (a trigger's), evaluated on every row
  - both again as the app role, on the rows it may select (where the app role
    checks them: a condition must read with the policy's rights there too)
  - for one of them, again with a scope: lists, checks and policies
  - authz.verify(): the closure tables match a rebuild

against a reference evaluator written directly from the language's meaning:
relations and permissions are sets of object ids, computed together as the
least fixpoint of the policy. It shares only the parser with the compiler.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import re
import subprocess
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any, ClassVar

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import compile_policy  # noqa: E402
from authzlib import evaluate  # noqa: E402
from authzlib.parse import Caveat, Cols, Rule, Type  # noqa: E402

# the database's answers, read back as JSON: their shape is what the checks compare
Answer = Any
Snapshot = dict[tuple[str, ...], Answer]
Ids = dict[str, list[str]]  # the ids of each type's rows, as text


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


REFUSE = re.compile(r'authz_gen\."[^"]*:refuse"\(')
# a column rule's trigger function: the row it checks, and the function that says whether the rule holds for it
COLUMN_CHECK = re.compile(r"v_row := (OLD|NEW);.*?IF NOT (authz_gen\.\"[^\"]+:holds\")\(v_row\) THEN", re.S)

# a share's end in the past, far enough that a clock set back (Docker Desktop's VM resyncing its clock, seconds at a
# time) doesn't make it live again half way through a check, which reads the data and the answers at different times
EXPIRED = "now() - interval '1 hour'"

# How many sessions answer a snapshot's questions, side by side (DIFFTEST_SESSIONS=1: one after the other). The
# questions are the same either way, each user's in one session from first to last: what it saves is the wait.
SESSIONS = int(os.environ.get("DIFFTEST_SESSIONS") or min(4, os.cpu_count() or 1))


def without_refusals(expr: str) -> str:
    """A WITH CHECK is `check OR <refuse>(row)`, and the refuse function raises (with the reason) when it runs:
    evaluated on every row here, the call becomes false, leaving the check itself."""
    while True:
        m = REFUSE.search(expr)
        if not m:
            return expr
        depth, i = 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(expr[i], 0)
            i += 1
        expr = expr[: m.start()] + "false" + expr[i:]


# ----------------------------------------------------------------------
# psql
# ----------------------------------------------------------------------
class DB:
    def __init__(self, name: str) -> None:
        self.name = name

    def run(self, sql: str, check: bool = True) -> tuple[int, str, str]:
        p = subprocess.run(
            ["psql", "-X", "-q", "-At", "-F", "\t", "-v", "ON_ERROR_STOP=1", "-d", self.name],
            input="SET client_min_messages = warning;\n" + sql,
            capture_output=True,
            text=True,
        )
        if check and p.returncode != 0:
            raise RuntimeError(f"psql failed:\n{p.stderr}\n--- sql ---\n{sql[:3000]}")
        return p.returncode, p.stdout, p.stderr

    def rows(self, sql: str) -> list[list[str]]:
        return [line.split("\t") for line in self.run(sql)[1].splitlines() if line]

    def rows_together(self, scripts: Sequence[str]) -> list[list[str]]:
        """The rows of scripts that change nothing, each in a session of its own, all at the same time."""
        if len(scripts) == 1:
            return self.rows(scripts[0])
        with ThreadPoolExecutor(len(scripts)) as pool:
            return [row for rows in pool.map(self.rows, scripts) for row in rows]

    def recreate(self) -> None:
        for cmd in (["dropdb", "--if-exists", self.name], ["createdb", self.name]):
            subprocess.run(cmd, check=True, capture_output=True)
        # JIT off, as the docs tell apps: a check is many small subplans, whose estimated cost passes Postgres's
        # thresholds, and it then compiles for seconds to read a handful of rows (4.7 s for 7 rows, 41 ms without)
        self.run(f'ALTER DATABASE "{self.name}" SET jit = off;')


def lit(s: object) -> str:
    return "'" + str(s).replace("'", "''") + "'"


# ----------------------------------------------------------------------
# The reference evaluator
# ----------------------------------------------------------------------
def caveat_case(caveats: dict[str, Caveat], alias: str = "g") -> str:
    """A share's caveat as SQL (written separately from the compiler's version)."""
    if not caveats:
        return f"{alias}.caveat IS NULL"
    whens = []
    for c in caveats.values():
        sql = re.sub(r"\barg\s*\(\s*'([^']*)'\s*\)", lambda m: f"({alias}.caveat_args ->> '{m.group(1)}')", c.sql)
        whens.append(f"WHEN {lit(c.name)} THEN coalesce(({sql}), false)")
    return f"({alias}.caveat IS NULL OR CASE {alias}.caveat {' '.join(whens)} ELSE false END)"


def idsql(t: Type, a: str | None = None, columns: Cols | None = None) -> str:
    """The text id of t's row a, or of the t that columns point at: the key column, or for a
    composite key the text Postgres prints for the row (what rowstile's ids are)."""
    p = f"{a}." if a else ""
    cols = [columns] if isinstance(columns, str) else list(columns or [c for c, _ in t.key])
    if len(t.key) == 1:
        return f"{p}{cols[0]}::text"
    return "ROW(" + ", ".join(f"{p}{c}::{ty}" for c, (_, ty) in zip(cols, t.key, strict=True)) + ")::text"


def notnull(a: str, columns: Cols | None) -> str:
    cols = [columns] if isinstance(columns, str) else list(columns or ())
    return " AND ".join(f"{a}.{c} IS NOT NULL" for c in cols)


class Reference(evaluate.Reference):
    """The reference evaluator (authzlib/evaluate.py: relations and permissions as sets of ids, computed as a
    least fixpoint, straight from what the policy says), with the queries that read its data from a database."""

    def live(self) -> str:
        return (
            "(g.expires_at IS NULL OR g.expires_at > now()) AND (g.starts_at IS NULL OR g.starts_at <= now()) "
            f"AND {caveat_case(self.pol.caveats)}"
        )

    def data_queries(self) -> list[tuple[tuple[str | int, ...], str]]:
        """(key, sql returning a json array) for everything the evaluator reads."""
        out: list[tuple[tuple[str | int, ...], str]] = []
        for t in self.types.values():
            out.append((("ids", t.name), f"SELECT coalesce(json_agg({idsql(t, 'r')}), '[]') FROM {t.table} r"))
            # a condition's row is the table aliased `this`: `this.id` and a bare column mean what SQL makes of
            # them, with nothing of the compiler's (sqlutil.on_row) between
            where = f"coalesce(({t.where}), false)" if t.where else "true"
            out.append(
                (
                    ("valid", t.name),
                    f"SELECT coalesce(json_agg({idsql(t, 'this')}), '[]') FROM {t.table} this WHERE {where}",
                )
            )
            for r in t.relations.values():
                for i, src in enumerate(r.sources):
                    for st, sr in src.subjects:
                        key = ("pairs", t.name, r.name, i, st, sr or "")
                        if src.kind == "column":
                            poly = f" AND r.{src.type_col} = {lit(st)}" if src.type_col else ""
                            sql = (
                                f"SELECT coalesce(json_agg(json_build_array({idsql(t, 'r')}, "
                                f"{idsql(self.types[st], 'r', src.column)})), '[]') "
                                f"FROM {t.table} r WHERE {notnull('r', src.column)}{poly}"
                            )
                        elif src.kind == "table":
                            where = f" AND coalesce(({src.where}), false)" if src.where else ""
                            poly = f" AND this.{src.type_col} = {lit(st)}" if src.type_col else ""
                            sql = (
                                f"SELECT coalesce(json_agg(json_build_array({idsql(t, 'this', src.obj_col)}, "
                                f"{idsql(self.types[st], 'this', src.subj_col)})), '[]') "
                                f"FROM {src.table} this WHERE {notnull('this', src.obj_col)} "
                                f"AND {notnull('this', src.subj_col)}{where}{poly}"
                            )
                        else:
                            stype = st
                            srel = "" if sr in (None, "*") else sr
                            # a principal type's shares: to one (bot 2), or to every one signed in (bot:*)
                            one = sr is None and st in self.types and self.types[st].principal
                            sid = (
                                " AND g.subject_id = '*'" if sr == "*" else (" AND g.subject_id <> '*'" if one else "")
                            )
                            sql = (
                                "SELECT coalesce(json_agg(json_build_array(g.object_id, g.subject_id)), '[]') "
                                f"FROM authz.shares g WHERE g.object_type = {lit(t.name)} "
                                f"AND g.relation = {lit(r.name)} AND g.subject_type = {lit(stype)} "
                                f"AND g.subject_relation = {lit(srel)}{sid} AND {self.live()}"
                            )
                        out.append((key, sql))
            if t.roles:
                subjects, perms, _ = t.roles
                # the role's owner, when it is of the type `from rel` names ('' otherwise: it never counts)
                owner = (
                    f"CASE WHEN ro.owner_type = {lit(self.role_owner_type(t))} THEN ro.owner_id ELSE '' END"
                    if t.roles_from
                    else "''"
                )
                for p in perms:
                    for st, sr in subjects:
                        out.append(
                            (
                                ("rolepairs", t.name, p, st, sr or ""),
                                f"SELECT coalesce(json_agg(json_build_array(g.object_id, g.subject_id, {owner})), '[]') "
                                f"FROM authz.shares g JOIN authz.roles ro ON g.relation = 'role:' || ro.id "
                                f"JOIN authz.role_permissions rp ON rp.role_id = ro.id "
                                f"WHERE g.object_type = {lit(t.name)} AND ro.object_type = {lit(t.name)} "
                                f"AND rp.permission = {lit(p)} "
                                f"AND g.subject_type = {lit(st)} AND g.subject_relation = {lit(sr or '')} AND {self.live()}",
                            )
                        )
        for tname, cond in self.conditions():
            t = self.types[tname]
            out.append(
                (
                    ("cond", tname, cond),
                    f"SELECT coalesce(json_agg({idsql(t, 'this')}), '[]') FROM {t.table} this WHERE coalesce(({cond}), false)",
                )
            )
        return out


# ----------------------------------------------------------------------
# Comparing
# ----------------------------------------------------------------------
class Checker:
    def __init__(self, db: DB, policy_path: str, gen: Gen) -> None:
        self.db, self.gen = db, gen
        # everyone who signs in, and nobody ('': signed out, what `anyone` and links are for)
        self.users, self.role = [*gen.users, ""], gen.role
        self.pol = compile_policy.parse_policy(read(policy_path), policy_path)
        self.types, self.rules = self.pol.types, self.pol.rules
        self.ref = Reference(self.pol)
        self._nocontext: dict[tuple[str, str, str], set[str]] | None = None
        self.policies: list[list[str]] = json.loads(
            self.db.run(
                "SELECT coalesce(json_agg(json_build_array(schemaname || '.' || tablename, policyname, "
                "coalesce(qual, ''), coalesce(with_check, '')) ORDER BY tablename, policyname), '[]') "
                "FROM pg_policies WHERE policyname LIKE 'authz\\_%'"
            )[1]
        )
        # Column rules (`update owner_id : share`) are triggers, numbered in the compiler's order: each one's
        # condition is read back from its function, to be evaluated on every row as the policies' are.
        triggers: dict[str, str] = dict(
            json.loads(
                self.db.run(
                    "SELECT coalesce(json_agg(json_build_array(tg.tgname, pg_get_functiondef(tg.tgfoid))), '[]') "
                    "FROM pg_trigger tg WHERE tg.tgname LIKE 'authz\\_update\\_%' AND NOT tg.tgisinternal"
                )[1]
            )
        )
        by_table: dict[str, list[Rule]] = {}
        for r in self.rules:
            by_table.setdefault(r.table, []).append(r)
        ruled = [r for rules in by_table.values() for r in rules if r.columns and r.command != "mask"]
        if len(triggers) != len(ruled):
            raise SystemExit(
                f"{len(ruled)} column rules in the policy, {len(triggers)} triggers for them: {sorted(triggers)}"
            )
        self.column_rules: list[tuple[Rule, str]] = []
        for n, r in enumerate(ruled, 1):
            m = COLUMN_CHECK.search(triggers[f"authz_update_{n}"])
            if not m or (m.group(1) == "NEW") != (r.command == "update check"):
                raise SystemExit(
                    f"{r.table}, the rule on {', '.join(r.columns)}: its trigger authz_update_{n} doesn't "
                    f"check the row {'after' if r.command == 'update check' else 'before'} the change"
                )
            self.column_rules.append((r, f"{m.group(2)}(the_row)"))  # asked of each row, FROM <table> the_row
        self.checks = 0  # how many snapshots so far: who is asked with a scope, and which
        self.scoped: tuple[str, str] = ("", "read")

    def context(self, u: str) -> dict[str, str]:
        return self.gen.context(u)

    def scope_allows(self, scope: str, kind: str, qual: str, word: str) -> bool:
        """Whether a transaction limited to this scope may run a command on a table (kind 'cmd') or use a
        permission of a type ('perm'). `read` is built in unless the policy defines it."""
        sc = self.pol.scopes.get(scope)
        items = sc.items if sc else [("cmd", None, "select"), ("perm", None, "*")]
        return any(
            k == kind and (w == word or (kind == "perm" and w == "*")) and (q is None or q == qual) for k, q, w in items
        )

    def snapshot(self) -> Snapshot:
        """The evaluator's inputs and the database's answers, per user. Each user's questions are a block that
        leaves its session as it found it, so the blocks can be asked in any order, in a few sessions side by
        side (SESSIONS). A session still answers for several users, one after the other: what it keeps from one
        (cached plans, settings) must not show in the next one's answers, and which users share a session, and
        in what order, changes with each snapshot."""
        blocks: list[list[str]] = []
        lines: list[str] = []

        def emit(key: list[str | int], sql: str) -> None:
            lines.append(f"SELECT {lit(json.dumps(key))}, ({sql});")

        self.db.run("\n".join(self.as_app_functions()))
        for u in self.users:
            lines = []
            blocks.append(lines)
            kind, pid = evaluate.principal_of(u, self.types)
            lines.append(f"SET authz.user_id = {lit(pid)};")
            lines.append(f"SET authz.principal_type = {lit('' if kind == 'user' else kind)};")
            for k, v in self.context(u).items():
                lines.append(f"SET authz_ctx.{k} = {lit(v)};")
            for key, sql in self.ref.data_queries():
                emit([u, "data", *key], sql)
            # the database's answers, as the app role
            lines.append(f"SET ROLE {self.role};")
            for t in self.types.values():
                for p in t.perms:
                    emit(
                        [u, "list", t.name, p],
                        f"SELECT coalesce(json_agg(x ORDER BY x), '[]') FROM authz.list({lit(t.name)}, {lit(p)}) x",
                    )
                    emit(
                        [u, "can", t.name, p],
                        f"SELECT coalesce(json_agg(json_build_array(i, authz.can({lit(t.name)}, i, {lit(p)}))), '[]') "
                        f"FROM (SELECT {idsql(t)} AS i FROM {t.table} TABLESAMPLE BERNOULLI (30) "
                        f"UNION SELECT '999999') ids",
                    )
            for table in dict.fromkeys(r.table for r in self.rules if r.command == "select"):
                t = self.ref.type_of_table(table)
                emit([u, "rls", table], f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {table}")
            for table, view in self.pol.views.items():
                t = self.ref.type_of_table(table)
                emit([u, "view", table], f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {view}")
                for r in self.rules:
                    if r.table == table and r.command == "mask":
                        for c in r.columns:
                            emit(
                                [u, "mask", table, c],
                                f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {view} WHERE {c} IS NOT NULL",
                            )
            # the policy expressions and column rules again, as the app role checks them (on the rows it may
            # select): a condition run with the app role's rights instead of the policy's shows here only
            for key, fn in self.as_app_keys():
                emit([u, *key], f"SELECT {fn}()")
            lines.append("RESET ROLE;")
            # authz.explain's verdict, as an administrator asking about this user
            for t in self.types.values():
                for p in t.perms:
                    asked = lit(u) if kind == "user" and u else "NULL"  # other principals, nobody: as themselves
                    emit(
                        [u, "explain", t.name, p],
                        f"SELECT coalesce(json_agg(json_build_array(i, (SELECT e FROM authz.explain({lit(t.name)}, i, "
                        f"{lit(p)}, {asked}) e LIMIT 1))), '[]') FROM (SELECT {idsql(t)} AS i FROM {t.table} "
                        f"ORDER BY md5({idsql(t)}) LIMIT 2) s",
                    )
            # every policy expression on every row (as the owner, so RLS does not filter)
            for table, name, qual, check in self.policies:
                t = self.ref.type_of_table(table)
                for part, expr in (("using", qual), ("check", without_refusals(check))):
                    if expr:
                        emit(
                            [u, "policy", table, name, part],
                            f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {table} WHERE ({expr})",
                        )
            for n, (r, cond) in enumerate(self.column_rules):
                emit(
                    [u, "column", str(n)],
                    f"SELECT coalesce(json_agg({idsql(self.ref.type_of_table(r.table))}), '[]') "
                    f"FROM {r.table} the_row WHERE coalesce(({cond}), false)",
                )
            for k in self.context(u):
                lines.append(f"RESET authz_ctx.{k};")
            lines += ["RESET authz.user_id;", "RESET authz.principal_type;"]
        # One of them again with a scope (what a token limited to it may do), another pair each time
        scopes = sorted({"read", *self.pol.scopes})
        u, scope = self.users[self.checks % len(self.users)], scopes[self.checks // len(self.users) % len(scopes)]
        self.scoped, self.checks = (u, scope), self.checks + 1
        kind, pid = evaluate.principal_of(u, self.types)
        lines = []
        blocks.append(lines)
        lines += [
            f"SET authz.user_id = {lit(pid)};",
            f"SET authz.principal_type = {lit('' if kind == 'user' else kind)};",
            *[f"SET authz_ctx.{k} = {lit(v)};" for k, v in self.context(u).items()],
            f"SET authz.scopes = {lit(scope)};",
            f"SET ROLE {self.role};",
        ]
        for t in self.types.values():
            for p in t.perms:
                emit(
                    ["scoped", "list", t.name, p],
                    f"SELECT coalesce(json_agg(x ORDER BY x), '[]') FROM authz.list({lit(t.name)}, {lit(p)}) x",
                )
                emit(
                    ["scoped", "can", t.name, p],
                    f"SELECT coalesce(json_agg(json_build_array(i, authz.can({lit(t.name)}, i, {lit(p)}))), '[]') "
                    f"FROM (SELECT {idsql(t)} AS i FROM {t.table} TABLESAMPLE BERNOULLI (30)) ids",
                )
        lines.append("RESET ROLE;")
        for table, name, qual, check in self.policies:
            t = self.ref.type_of_table(table)
            for part, expr in (("using", qual), ("check", without_refusals(check))):
                if expr:
                    emit(
                        ["scoped", "policy", table, name, part],
                        f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {table} WHERE ({expr})",
                    )
        lines += ["RESET authz.scopes;", *[f"RESET authz_ctx.{k};" for k in self.context(u)]]
        lines.append("RESET authz.user_id;")
        lines.append("RESET authz.principal_type;")
        # authz.who for a few objects of each type (as an administrator)
        lines = []
        blocks.append(lines)
        for t in self.types.values():
            for p in t.perms:
                emit(
                    ["who", t.name, p],
                    f"SELECT coalesce(json_agg(json_build_array(i, (SELECT coalesce(json_agg(x ORDER BY x), '[]') "
                    f"FROM authz.who({lit(t.name)}, i, {lit(p)}) x))), '[]') FROM (SELECT {idsql(t)} AS i "
                    f"FROM {t.table} ORDER BY md5({idsql(t)} || 'w') LIMIT 6) s",
                )
        lines.append("SELECT '[\"verify\"]', to_json(authz.verify());")
        # two blocks or more to a session, where there are enough
        random.Random(self.checks).shuffle(blocks)
        n = max(1, min(SESSIONS, len(blocks) // 2))
        scripts = ["\n".join(line for block in blocks[i::n] for line in block) for i in range(n)]
        out: Snapshot = {}
        for key, val in self.db.rows_together(scripts):
            out[tuple(json.loads(key))] = json.loads(val)
        return out

    def as_app(self, table: str) -> bool:
        """Whether the app role can evaluate a table's rules on its rows: it may select some of them (a select
        rule), and it may name every column (a table with masked columns is read through its view)."""
        return table not in self.pol.views and any(
            r.table == table and r.command == "select" and not r.columns for r in self.rules
        )

    def as_app_queries(self) -> list[tuple[list[str], str]]:
        """Each policy expression and column rule the app role can evaluate: (key, the query of the rows it holds
        for)."""
        out: list[tuple[list[str], str]] = []
        for table, name, qual, check in self.policies:
            if self.as_app(table):
                t = self.ref.type_of_table(table)
                for part, expr in (("using", qual), ("check", without_refusals(check))):
                    if expr:
                        out.append(
                            (
                                ["policy as app", table, name, part],
                                f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {table} WHERE ({expr})",
                            )
                        )
        for n, (r, cond) in enumerate(self.column_rules):
            if self.as_app(r.table):
                out.append(
                    (
                        ["column as app", str(n)],
                        f"SELECT coalesce(json_agg({idsql(self.ref.type_of_table(r.table))}), "
                        f"'[]') FROM {r.table} the_row WHERE coalesce(({cond}), false)",
                    )
                )
        return out

    def as_app_keys(self) -> list[tuple[list[str], str]]:
        return [(key, f"difftest_app.q{n}") for n, (key, _) in enumerate(self.as_app_queries())]

    def as_app_functions(self) -> list[str]:
        """The queries above as functions the owner makes, BEGIN ATOMIC: parsed once, as row-level security's
        expressions are, so the app role runs them (as itself, through the rules) without looking up names it may
        not (authz_int). Made again for each snapshot: applying again would drop them with what they name."""
        lines = ["CREATE SCHEMA IF NOT EXISTS difftest_app;", f"GRANT USAGE ON SCHEMA difftest_app TO {self.role};"]
        for n, (_, sql) in enumerate(self.as_app_queries()):
            lines.append(
                f"CREATE OR REPLACE FUNCTION difftest_app.q{n}() RETURNS json LANGUAGE sql STABLE "
                f"BEGIN ATOMIC {sql}; END;"
            )
        return lines

    def expected_rule(self, state: evaluate.State, table: str, command: str) -> set[str]:
        t = self.ref.type_of_table(table)
        rule = next((r for r in self.rules if r.table == table and r.command == command and not r.columns), None)
        if not rule:
            raise LookupError(f"{table}: no {command} rule")
        return self.ref.eval_expr(state, t, rule.expr) & self.ref.ids(t) & self.ref.valid(t)

    def links_of(self, u: str) -> set[str]:
        tokens = [x.strip() for x in self.context(u).get("links", "").split(",") if x.strip()]
        return {hashlib.sha256(x.encode()).hexdigest() for x in tokens}

    def check(self) -> list[str]:
        self._nocontext = None
        snap = self.snapshot()
        problems: list[str] = []
        if snap[("verify",)] is not True:
            problems.append("authz.verify() is false: a closure table is stale")
        holders: dict[tuple[str, str, str], set[str]] = {}
        for u in self.users:
            data = evaluate.Data.of({tuple(k[2:]): v for k, v in snap.items() if k[0] == u and k[1] == "data"})
            state = self.ref.evaluate(data, u, self.links_of(u))
            for t in self.types.values():
                for p in t.perms:
                    for i in state[(t.name, p)] & self.ref.ids(t):
                        if self.listed(u):
                            holders.setdefault((t.name, p, i), set()).add(u)
                    for i, line in snap[(u, "explain", t.name, p)]:
                        want = i in state[(t.name, p)] & self.ref.ids(t)
                        if not line or line.startswith("yes") != want:
                            problems.append(
                                f"user {u}: authz.explain('{t.name}', {i}, '{p}') says "
                                f"{line!r}, expected {'yes' if want else 'no'}"
                            )
            for t in self.types.values():
                ids = self.ref.ids(t)
                for p in t.perms:
                    want = state[(t.name, p)] & ids
                    got = set(snap[(u, "list", t.name, p)])
                    if got != want:
                        problems.append(
                            f"user {u}: authz.list('{t.name}', '{p}') "
                            f"extra {sorted(got - want)} missing {sorted(want - got)}"
                        )
                    for i, ok in snap[(u, "can", t.name, p)]:
                        if bool(ok) != (i in want):
                            problems.append(f"user {u}: authz.can('{t.name}', {i}, '{p}') = {ok}, expected {i in want}")
            for table in dict.fromkeys(r.table for r in self.rules if r.command == "select"):
                want = self.expected_rule(state, table, "select")
                got = set(snap[(u, "rls", table)])
                if got != want:
                    problems.append(
                        f"user {u}: SELECT from {table} extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
            for table in self.pol.views:
                want = self.expected_rule(state, table, "select")
                got = set(snap[(u, "view", table)])
                if got != want:
                    problems.append(
                        f"user {u}: the view of {table} extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
                t = self.ref.type_of_table(table)
                for r in self.rules:
                    if r.table == table and r.command == "mask":
                        shown = want & self.ref.eval_expr(state, t, r.expr)
                        for c in r.columns:
                            got = set(snap[(u, "mask", table, c)])
                            if got != shown:
                                problems.append(
                                    f"user {u}: {table}.{c} shown in the view: extra {sorted(got - shown)} "
                                    f"missing {sorted(shown - got)}"
                                )
            for table, name, qual, check in self.policies:
                command = name[len("authz_") :]
                for part, expr in (("using", qual), ("check", check)):
                    if not expr:
                        continue
                    # an update's check is its 'after' rule if it has one, otherwise the update rule again
                    after = any(r.table == table and r.command == "update check" and not r.columns for r in self.rules)
                    cmd = "update check" if command == "update" and part == "check" and after else command
                    want = self.expected_rule(state, table, cmd)
                    got = set(snap[(u, "policy", table, name, part)])
                    if got != want:
                        problems.append(
                            f"user {u}: policy {name} ({part}) on {table} "
                            f"extra {sorted(got - want)} missing {sorted(want - got)}"
                        )
                    if self.as_app(table):
                        mine = want & self.expected_rule(state, table, "select")
                        got = set(snap[(u, "policy as app", table, name, part)])
                        if got != mine:
                            problems.append(
                                f"user {u}: policy {name} ({part}) on {table}, as the app role "
                                f"extra {sorted(got - mine)} missing {sorted(mine - got)}"
                            )
            for n, (r, _) in enumerate(self.column_rules):
                t = self.ref.type_of_table(r.table)
                want = self.ref.eval_expr(state, t, r.expr) & self.ref.ids(t) & self.ref.valid(t)
                got = set(snap[(u, "column", str(n))])
                if got != want:
                    problems.append(
                        f"user {u}: the rule on {', '.join(r.columns)} of {r.table} ({r.src}) "
                        f"extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
                if self.as_app(r.table):
                    mine = want & self.expected_rule(state, r.table, "select")
                    got = set(snap[(u, "column as app", str(n))])
                    if got != mine:
                        problems.append(
                            f"user {u}: the rule on {', '.join(r.columns)} of {r.table} ({r.src}), as the "
                            f"app role extra {sorted(got - mine)} missing {sorted(mine - got)}"
                        )
            if u == self.scoped[0]:
                problems += self.check_scoped(snap, state)
        for t in self.types.values():
            for p in t.perms:
                for i, got in snap[("who", t.name, p)]:
                    # who() lists users; context-dependent shares (caveats, links) are judged
                    # in the administrator's context, where no link or context is set
                    want = (
                        set(holders.get((t.name, p, i), set()))
                        if not self.has_context()
                        else self.who_reference(t, p, i)
                    )
                    if set(got) != want:
                        problems.append(
                            f"authz.who('{t.name}', {i}, '{p}') extra {sorted(set(got) - want)} "
                            f"missing {sorted(want - set(got))}"
                        )
        return problems

    def check_scoped(self, snap: Snapshot, state: evaluate.State) -> list[str]:
        """The same user limited to a scope: what the scope names is as without it, the rest is refused."""
        u, scope = self.scoped
        who = f"user {u} with scope {scope}"
        problems: list[str] = []
        for t in self.types.values():
            for p in t.perms:
                want = state[(t.name, p)] & self.ref.ids(t) if self.scope_allows(scope, "perm", t.name, p) else set()
                got = set(snap[("scoped", "list", t.name, p)])
                if got != want:
                    problems.append(
                        f"{who}: authz.list('{t.name}', '{p}') extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
                for i, ok in snap[("scoped", "can", t.name, p)]:
                    if bool(ok) != (i in want):
                        problems.append(f"{who}: authz.can('{t.name}', {i}, '{p}') = {ok}, expected {i in want}")
        for table, name, qual, check in self.policies:
            command = name[len("authz_") :]
            for part, expr in (("using", qual), ("check", check)):
                if not expr:
                    continue
                after = any(r.table == table and r.command == "update check" and not r.columns for r in self.rules)
                cmd = "update check" if command == "update" and part == "check" and after else command
                want = (
                    self.expected_rule(state, table, cmd) if self.scope_allows(scope, "cmd", table, command) else set()
                )
                got = set(snap[("scoped", "policy", table, name, part)])
                if got != want:
                    problems.append(
                        f"{who}: policy {name} ({part}) on {table} extra {sorted(got - want)} missing {sorted(want - got)}"
                    )
        return problems

    def has_context(self) -> bool:
        return any(self.context(u) for u in self.users)

    def listed(self, u: str) -> bool:
        """Whether authz.who can list u: it lists the user table's rows (also one failing the type's where, who
        holds what nobody holds), not other principals, and not an id signed in that the table doesn't have."""
        return bool(u) and evaluate.principal_of(u, self.types)[0] == "user" and u in self.ref.ids(self.types["user"])

    def who_reference(self, t: Type, p: str, i: str) -> set[str]:
        """Holders of p on i when evaluated without any request context (what who() sees)."""
        if self._nocontext is None:
            snap = self.snapshot_data_only()  # sets no context
            out: dict[tuple[str, str, str], set[str]] = {}
            for u in self.users:
                data = evaluate.Data.of({tuple(k[2:]): v for k, v in snap.items() if k[0] == u and k[1] == "data"})
                state = self.ref.evaluate(data, u, set())
                for tt in self.types.values():
                    for pp in tt.perms:
                        for ii in state[(tt.name, pp)] & self.ref.ids(tt):
                            if self.listed(u):
                                out.setdefault((tt.name, pp, ii), set()).add(u)
            self._nocontext = out
        return self._nocontext.get((t.name, p, i), set())

    def snapshot_data_only(self) -> Snapshot:
        lines: list[str] = []
        for u in self.users:
            kind, pid = evaluate.principal_of(u, self.types)
            lines.append(f"SET authz.user_id = {lit(pid)};")
            lines.append(f"SET authz.principal_type = {lit('' if kind == 'user' else kind)};")
            for key, sql in self.ref.data_queries():
                lines.append(f"SELECT {lit(json.dumps([u, 'data', *key]))}, ({sql});")
        lines.append("RESET authz.user_id;")
        lines.append("RESET authz.principal_type;")
        return {tuple(json.loads(k)): json.loads(v) for k, v in self.db.rows("\n".join(lines))}


# ----------------------------------------------------------------------
# Random data and changes
# ----------------------------------------------------------------------
class Gen:
    """A policy's test data: its schema, who signs in, and the SQL for the first data, the first shares and each
    random change."""

    policy: ClassVar[str]
    schema: ClassVar[str]
    users: ClassVar[list[str]]
    role: ClassVar[str] = "app_user"
    expected_errors: ClassVar[tuple[str, ...]] = (
        "cannot be moved inside itself",
        "violates foreign key constraint",
        "duplicate key value",
        "violates unique constraint",
    )

    def __init__(self, rnd: random.Random) -> None:
        self.r = rnd

    def context(self, u: str) -> dict[str, str]:
        """The request context (authz_ctx.*) the user's session sets."""
        return {}

    def initial(self) -> str:
        raise NotImplementedError

    def grants(self) -> str:
        raise NotImplementedError

    def change(self, ids: Ids) -> str:
        """One random change, as SQL. ids: current ids by type."""
        raise NotImplementedError


def ints(ids: Ids | None, name: str) -> list[int]:
    return [int(x) for x in (ids or {}).get(name, [])]


class DocsGen(Gen):
    """The example app (example/app_schema.sql)."""

    policy = "example/docs.authz"
    schema = "example/app_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 9)]

    def initial(self) -> str:
        r = self.r
        s = [
            "TRUNCATE app.folder_links, app.folder_team_access, app.files, app.folders, app.team_members, "
            "app.teams, app.org_members, app.orgs, app.users CASCADE;"
        ]
        s.append("INSERT INTO app.users SELECT i, 'u' || i FROM generate_series(1, 8) i;")
        s.append("INSERT INTO app.orgs VALUES (1, 'o1'), (2, 'o2');")
        for u in self.users:
            for o in (1, 2):
                if r.random() < 0.45:
                    s.append(
                        f"INSERT INTO app.org_members VALUES ({o}, {u}, '{r.choice(['admin', 'member', 'member'])}');"
                    )
        for i in range(10, 16):
            parent = r.choice([None, None] + list(range(10, i)))
            s.append(f"INSERT INTO app.teams VALUES ({i}, {r.choice([1, 2])}, {parent or 'NULL'}, 't{i}');")
        for u in self.users:
            for t in r.sample(range(10, 16), r.choice([0, 1, 1, 2])):
                s.append(f"INSERT INTO app.team_members VALUES ({t}, {u});")
        for i in range(1, 26):
            parent = r.choice([None] + list(range(1, i)) * 3) if i > 1 else None
            s.append(
                f"INSERT INTO app.folders (id, org_id, parent_id, owner_id, name, inherit) VALUES "
                f"({i}, {r.choice([1, 2])}, {parent or 'NULL'}, {r.choice(self.users)}, 'f{i}', "
                f"{'false' if r.random() < 0.15 else 'true'});"
            )
        for i in range(1, 51):
            s.append(
                f"INSERT INTO app.files (id, folder_id, owner_id, name, confidential) VALUES "
                f"({i}, {r.randint(1, 25)}, {r.choice(self.users)}, 'x{i}', {'true' if r.random() < 0.15 else 'false'});"
            )
        for _ in range(8):
            s.append(
                f"INSERT INTO app.folder_team_access VALUES ({r.randint(1, 25)}, {r.randint(10, 15)}, "
                f"'{r.choice(['view', 'edit'])}') ON CONFLICT DO NOTHING;"
            )
        for _ in range(5):
            a, b = r.randint(1, 25), r.randint(1, 25)
            if a != b:
                s.append(f"INSERT INTO app.folder_links VALUES ({a}, {b}) ON CONFLICT DO NOTHING;")
        s.append("SELECT setval(pg_get_serial_sequence('app.folders', 'id'), 100);")
        s.append("SELECT setval(pg_get_serial_sequence('app.files', 'id'), 100);")
        return "\n".join(s)

    def grants(self) -> str:
        return "\n".join(self.grant() for _ in range(25))

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        folders = ints(ids, "folder") or list(range(1, 26))
        files = ints(ids, "file") or list(range(1, 51))
        expires = r.choice(["NULL", "NULL", "NULL", "now() - interval '1 hour'", "now() + interval '1 day'"])
        kind = r.random()
        if kind < 0.6:
            obj, oid, rel = "folder", r.choice(folders), r.choice(["viewer", "editor"])
            st, sid, sr = r.choice(
                [
                    ("user", r.choice(self.users), ""),
                    ("team", r.randint(10, 15), "member"),
                    ("org", r.choice([1, 2]), "member"),
                ]
            )
            if rel == "editor" and st == "org":
                st, sid, sr = "user", r.choice(self.users), ""
        else:
            obj, oid, rel = "file", r.choice(files), "viewer"
            st, sid, sr = r.choice([("user", r.choice(self.users), ""), ("team", r.randint(10, 15), "member")])
        return (
            f"INSERT INTO authz.shares VALUES ('{obj}', {oid}, '{rel}', '{st}', {sid}, '{sr}', {expires}) "
            "ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        folders = ints(ids, "folder") or [1]
        files = ints(ids, "file") or [1]
        teams = ints(ids, "team") or [10]
        f, g = r.choice(folders), r.choice(folders)
        ops = [
            lambda: f"UPDATE app.folders SET parent_id = {r.choice([g, g, 'NULL'])} WHERE id = {f};",
            lambda: f"UPDATE app.folders SET parent_id = {g} WHERE id IN ({f}, {r.choice(folders)});",
            lambda: f"UPDATE app.folders SET inherit = NOT inherit WHERE id = {f};",
            lambda: f"UPDATE app.folders SET inherit = random() < 0.5 WHERE id % 3 = {r.randint(0, 2)};",
            lambda: (
                f"UPDATE app.folders SET org_id = {r.choice([1, 2])}, owner_id = {r.choice(self.users)} WHERE id = {f};"
            ),
            lambda: (
                f"INSERT INTO app.folders (org_id, parent_id, owner_id, name, inherit) VALUES "
                f"({r.choice([1, 2])}, {r.choice([f, 'NULL'])}, {r.choice(self.users)}, 'n', {r.choice(['true', 'false'])});"
            ),
            lambda: (
                f"INSERT INTO app.folders (org_id, parent_id, owner_id, name) "
                f"SELECT 1, {f}, {r.choice(self.users)}, 'bulk' FROM generate_series(1, 3);"
            ),
            lambda: f"DELETE FROM app.files WHERE folder_id = {f}; DELETE FROM app.folders WHERE id = {f};",
            lambda: f"UPDATE app.folders SET id = {max(folders) + r.randint(1, 50)} WHERE id = {f};",
            lambda: f"INSERT INTO app.folder_links VALUES ({f}, {g}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM app.folder_links WHERE folder_id = {f} OR parent_id = {f};",
            lambda: f"UPDATE app.folder_links SET parent_id = {g} WHERE folder_id = {f};",
            lambda: "TRUNCATE app.folder_links;",
            lambda: (
                f"INSERT INTO app.folder_team_access VALUES ({f}, {r.choice(teams)}, '{r.choice(['view', 'edit'])}') "
                "ON CONFLICT (folder_id, team_id) DO UPDATE SET access = EXCLUDED.access;"
            ),
            lambda: f"DELETE FROM app.folder_team_access WHERE folder_id = {f};",
            lambda: (
                f"INSERT INTO app.team_members VALUES ({r.choice(teams)}, {r.choice(self.users)}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM app.team_members WHERE user_id = {r.choice(self.users)};",
            lambda: (
                f"UPDATE app.teams SET parent_id = {r.choice(teams + [None, None]) or 'NULL'} WHERE id = {r.choice(teams)};"
            ),
            lambda: (
                f"INSERT INTO app.org_members VALUES ({r.choice([1, 2])}, {r.choice(self.users)}, "
                f"'{r.choice(['admin', 'member'])}') ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role;"
            ),
            lambda: f"DELETE FROM app.org_members WHERE user_id = {r.choice(self.users)};",
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: f"DELETE FROM authz.shares WHERE object_id = '{r.choice(folders)}';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE random() < 0.2;",
            lambda: f"UPDATE app.files SET folder_id = {g} WHERE id = {r.choice(files)};",
            lambda: (
                f"UPDATE app.files SET confidential = NOT confidential, owner_id = {r.choice(self.users)} WHERE id = {r.choice(files)};"
            ),
            lambda: f"DELETE FROM app.files WHERE id = {r.choice(files)};",
            lambda: f"INSERT INTO app.files (folder_id, owner_id, name) VALUES ({f}, {r.choice(self.users)}, 'new');",
            lambda: f"UPDATE app.files SET id = {max(files) + r.randint(1, 50)} WHERE id = {r.choice(files)};",
        ]
        if r.random() < 0.15:  # several changes in one transaction
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


class AltGen(Gen):
    """tests/alt.authz: non-id keys, NULL columns under `not`, groups of groups by
    sharing, inheritance through shares and through conditions that read another
    table, relations with several sources pointing at another type, a deny that
    inherits, and custom roles granting a permission with a deny and one with a condition."""

    policy = "tests/alt.authz"
    schema = "tests/alt_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 8)]

    def maybe(self, xs: Sequence[str | int], p: float = 0.5) -> str | int:
        return self.r.choice(xs) if self.r.random() < p else "NULL"

    def initial(self) -> str:
        r = self.r
        s = ["INSERT INTO alt.users SELECT i FROM generate_series(1, 7) i;"]
        for g in range(1, 6):
            s.append(f"INSERT INTO alt.groups VALUES ({g}, {r.choice(self.users)});")
        for u in self.users:
            for g in r.sample(range(1, 6), r.choice([0, 1, 1, 2])):
                s.append(f"INSERT INTO alt.group_members VALUES ({g}, {u}, {r.random() < 0.8});")
        for pj in range(1, 4):
            s.append(f"INSERT INTO alt.projects VALUES ({pj}, {r.choice(self.users)});")
            for g in r.sample(range(1, 6), r.choice([0, 1, 2])):
                s.append(f"INSERT INTO alt.project_groups VALUES ({pj}, {g});")
        for d in range(1, 31):
            up = r.choice([None] + list(range(1, d)) * 2) if d > 1 else None
            s.append(
                f"INSERT INTO alt.docs VALUES ({d}, {r.choice(self.users)}, {self.maybe(self.users, 0.2)}, "
                f"{up or 'NULL'}, {self.maybe([1, 2, 3], 0.3)}, {r.random() < 0.15});"
            )
        for _ in range(6):
            a, b = r.randint(1, 30), r.randint(1, 30)
            if a != b:
                s.append(f"INSERT INTO alt.doc_links VALUES ({a}, {b}) ON CONFLICT DO NOTHING;")
        for _ in range(4):
            s.append(
                f"INSERT INTO alt.doc_projects VALUES ({r.randint(1, 30)}, {r.randint(1, 3)}) ON CONFLICT DO NOTHING;"
            )
        for _ in range(3):
            s.append(f"INSERT INTO alt.holds VALUES ({r.randint(1, 30)}) ON CONFLICT DO NOTHING;")
        return "\n".join(s)

    def grants(self) -> str:
        roles = [
            "INSERT INTO authz.roles (id, owner_type, owner_id, object_type, name) VALUES "
            "(1, 'user', '1', 'doc', 'reader'), (2, 'user', '1', 'doc', 'publisher');",
            "INSERT INTO authz.role_permissions VALUES (1, 'view'), (2, 'view'), (2, 'publish');",
            "SELECT setval(pg_get_serial_sequence('authz.roles', 'id'), 10);",
        ]
        return "\n".join(roles + [self.grant() for _ in range(25)])

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        docs = ints(ids, "doc") or list(range(1, 31))
        groups = ints(ids, "grp") or list(range(1, 6))
        k = r.random()
        if k < 0.12:  # a custom role: inside view's deny and publish's condition
            row = (
                "doc",
                r.choice(docs),
                f"role:{r.choice([1, 2])}",
                *r.choice([("user", r.choice(self.users), ""), ("grp", r.choice(groups), "member")]),
            )
        elif k < 0.3:
            row = (
                "doc",
                r.choice(docs),
                "reader",
                *r.choice([("user", r.choice(self.users), ""), ("grp", r.choice(groups), "member")]),
            )
        elif k < 0.45:
            row = ("doc", r.choice(docs), "writer", "user", r.choice(self.users), "")
        elif k < 0.55:  # a deny: view is taken away here and below
            row = (
                "doc",
                r.choice(docs),
                "banned",
                *r.choice([("user", r.choice(self.users), ""), ("grp", r.choice(groups), "member")]),
            )
        elif k < 0.75:
            row = ("doc", r.choice(docs), "shortcut", "doc", r.choice(docs), "")
        else:
            row = ("grp", r.choice(groups), "member", "grp", r.choice(groups), "member")
        expires = "NULL"
        if row[2] != "shortcut" and r.random() < 0.25:
            expires = r.choice(["now() - interval '1 hour'", "now() + interval '1 day'"])
        vals = ", ".join(lit(x) if isinstance(x, str) else str(x) for x in row)
        return f"INSERT INTO authz.shares VALUES ({vals}, {expires}) ON CONFLICT DO NOTHING;"

    def change(self, ids: Ids) -> str:
        r = self.r
        docs = ints(ids, "doc") or [1]
        groups = ints(ids, "grp") or [1]
        d, e = r.choice(docs), r.choice(docs)
        ops = [
            lambda: f"UPDATE alt.docs SET up = {r.choice([e, e, 'NULL'])} WHERE doc_no = {d};",
            lambda: f"UPDATE alt.docs SET locked = NOT locked WHERE doc_no = {d};",
            lambda: f"UPDATE alt.docs SET blocked_id = {self.maybe(self.users)} WHERE doc_no = {d};",
            lambda: (
                f"UPDATE alt.docs SET owner_id = {r.choice(self.users)}, project_id = {self.maybe([1, 2, 3])} WHERE doc_no = {d};"
            ),
            lambda: (
                f"INSERT INTO alt.docs VALUES ({max(docs) + 1}, {r.choice(self.users)}, NULL, {r.choice([d, 'NULL'])}, NULL, false);"
            ),
            lambda: f"DELETE FROM alt.docs WHERE doc_no = {d};",
            lambda: f"UPDATE alt.docs SET doc_no = {max(docs) + r.randint(1, 20)} WHERE doc_no = {d};",
            lambda: f"INSERT INTO alt.doc_links VALUES ({d}, {e}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM alt.doc_links WHERE child = {d} OR parent = {d};",
            lambda: "TRUNCATE alt.doc_links;",
            lambda: f"INSERT INTO alt.holds VALUES ({d}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM alt.holds WHERE target = {r.choice(docs)};",
            lambda: f"UPDATE alt.holds SET target = {e} WHERE target = {d};",
            lambda: "TRUNCATE alt.holds;",
            lambda: f"INSERT INTO alt.doc_projects VALUES ({d}, {r.randint(1, 3)}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM alt.doc_projects WHERE doc_no = {d};",
            lambda: f"UPDATE alt.group_members SET active = NOT active WHERE user_id = {r.choice(self.users)};",
            lambda: (
                f"INSERT INTO alt.group_members VALUES ({r.choice(groups)}, {r.choice(self.users)}, true) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM alt.group_members WHERE group_id = {r.choice(groups)};",
            lambda: (
                f"INSERT INTO alt.project_groups VALUES ({r.randint(1, 3)}, {r.choice(groups)}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"UPDATE alt.projects SET lead_id = {r.choice(self.users)} WHERE id = {r.randint(1, 3)};",
            lambda: f"DELETE FROM alt.groups WHERE gid = {r.choice(groups)};",
            lambda: f"INSERT INTO alt.groups VALUES ({max(groups) + 1}, {r.choice(self.users)});",
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: f"DELETE FROM authz.shares WHERE object_id = '{d}' OR subject_id = '{d}';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE relation <> 'shortcut' AND random() < 0.2;",
            lambda: (
                f"INSERT INTO authz.role_permissions VALUES (1, {lit(r.choice(['view', 'publish']))}) ON CONFLICT DO NOTHING;"
            ),
            lambda: "DELETE FROM authz.role_permissions WHERE role_id = 1 AND permission = 'publish';",
        ]
        if r.random() < 0.15:
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


def uid(i: int, prefix: str = "00000000-0000-4000-8000-") -> str:
    return f"{prefix}{i:012d}"


class MultiGen(Gen):
    """tests/multi.authz: UUID keys, suspended users and orgs, archived folders,
    folders and projects nested in each other (inheritance across types),
    documents in either, user:*, anyone, link tokens, shares that start later or
    carry a caveat, and custom roles."""

    policy = "tests/multi.authz"
    schema = "tests/multi_schema.sql"
    users: ClassVar[list[str]] = [uid(i) for i in range(1, 8)]
    tokens: ClassVar[list[str]] = ["tok-a", "tok-b", "tok-c"]

    def context(self, u: str) -> dict[str, str]:
        i = self.users.index(u) if u else len(self.users)  # nobody: signed out, holding a link or not
        ctx = {"mode": "business" if i % 2 == 0 else "night", "ip": f"10.0.0.{i % 3}"}
        ctx["links"] = ",".join(t for j, t in enumerate(self.tokens) if (i + j) % 3 == 0)
        return ctx

    def u(self) -> str:
        return lit(self.r.choice(self.users))

    def maybe_user(self) -> str:
        return self.u() if self.r.random() < 0.8 else "NULL"

    def initial(self) -> str:
        r = self.r
        s = [f"INSERT INTO mt.users VALUES ({lit(u)}, {str(i != 6).lower()});" for i, u in enumerate(self.users)]
        s.append("INSERT INTO mt.orgs VALUES (1, false), (2, false);")
        for u in self.users:
            for o in (1, 2):
                if r.random() < 0.4:
                    s.append(
                        f"INSERT INTO mt.org_members VALUES ({o}, {lit(u)}, '{r.choice(['admin', 'member', 'member'])}');"
                    )
        s.append("INSERT INTO mt.teams SELECT i FROM generate_series(1, 4) i;")
        for u in self.users:
            for t in r.sample(range(1, 5), r.choice([0, 1, 1, 2])):
                s.append(f"INSERT INTO mt.team_members VALUES ({t}, {lit(u)});")
        for i in range(1, 11):
            parent = r.choice([None] + list(range(1, i))) if i > 1 else None
            s.append(
                f"INSERT INTO mt.folders VALUES ({i}, {lit('folder') if parent else 'NULL'}, {parent or 'NULL'}, "
                f"{self.maybe_user()}, {str(r.random() < 0.15).lower()}, {str(r.random() < 0.1).lower()});"
            )
        for p in range(1, 7):
            s.append(
                f"INSERT INTO mt.projects VALUES ({p}, {r.choice([1, 2])}, {r.choice([None] + list(range(1, 11))) or 'NULL'}, "
                f"{self.maybe_user()});"
            )
        for i in range(11, 21):
            kind = r.choice(["folder", "project", None])
            parent = r.randint(1, i - 1) if kind == "folder" else r.randint(1, 6) if kind == "project" else None
            s.append(
                f"INSERT INTO mt.folders VALUES ({i}, {lit(kind) if kind else 'NULL'}, {parent or 'NULL'}, "
                f"{self.maybe_user()}, {str(r.random() < 0.15).lower()}, {str(r.random() < 0.1).lower()});"
            )
        for d in range(1, 31):
            kind = r.choice(["folder", "folder", "project"])
            cid = r.randint(1, 20) if kind == "folder" else r.randint(1, 6)
            s.append(
                f"INSERT INTO mt.docs VALUES ({lit(uid(d, '10000000-0000-4000-8000-'))}, {lit(kind)}, {cid}, {self.maybe_user()});"
            )
        s.append("UPDATE mt.folders SET org_id = (ARRAY[1, 2, NULL])[1 + id % 3];")  # whose roles count there
        return "\n".join(s)

    def grants(self) -> str:
        roles = [
            # org 2's role too, from the start: shared on a folder of org 1 (or of none), as only a direct
            # insert or a folder moved to another org makes it, it must give nothing
            "INSERT INTO authz.roles (id, owner_type, owner_id, object_type, name) VALUES "
            "(1, 'org', '1', 'folder', 'reader'), (2, 'org', '1', 'folder', 'writer'), (3, 'org', '2', 'folder', 'editor3');",
            "INSERT INTO authz.role_permissions VALUES (1, 'view'), (2, 'view'), (2, 'edit'), (3, 'edit');",
            "SELECT setval(pg_get_serial_sequence('authz.roles', 'id'), 10);",
        ]
        # ... and a few such from the start: folders 3, 6, 9 are org 1's, 1 and 4 org 2's, 2 nobody's (initial)
        cross = [
            "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation) "
            f"VALUES ('folder', '{f}', 'role:{role}', 'user', {self.u()}, '') ON CONFLICT DO NOTHING;"
            for f, role in ((3, 3), (6, 3), (9, 3), (1, 1), (4, 2), (2, 2))
        ]
        return "\n".join(roles + cross + [self.grant() for _ in range(30)])

    def subject(self, allowed: list[str]) -> tuple[str, str, str]:
        r = self.r
        kind = r.choice(allowed)
        if kind == "user":
            return ("user", r.choice(self.users), "")
        if kind == "team":
            return ("team", str(r.randint(1, 4)), "member")
        if kind == "user:*":
            return ("user", "*", "")
        if kind == "anyone":
            return ("anyone", "*", "")
        return ("link", f"encode(sha256(convert_to({lit(r.choice(self.tokens))}, 'UTF8')), 'hex')", "")

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        folders = ints(ids, "folder") or list(range(1, 21))
        projects = ints(ids, "project") or list(range(1, 7))
        k = r.random()
        if k < 0.3:
            obj, oid, rel = "project", r.choice(projects), "viewer"
            st, sid, sr = self.subject(["user", "team", "user:*", "anyone", "link"])
        elif k < 0.5:
            obj, oid, rel = "folder", r.choice(folders), "viewer"
            st, sid, sr = self.subject(["user", "team", "user:*", "link"])
        elif k < 0.6:
            obj, oid, rel = "folder", r.choice(folders), "editor"
            st, sid, sr = self.subject(["user", "team"])
        elif k < 0.85:
            obj, oid, rel = "folder", r.choice(folders), f"role:{r.choice([1, 2, 3])}"
            st, sid, sr = self.subject(["user", "team"])
        else:
            obj, oid, rel = "team", r.randint(1, 4), "member"
            st, sid, sr = "team", str(r.randint(1, 4)), "member"
        sid_sql = sid if sid.startswith("encode(") else lit(sid)
        expires = r.choice(["NULL"] * 4 + ["now() - interval '1 hour'", "now() + interval '1 day'"])
        starts = r.choice(["NULL"] * 4 + ["now() + interval '1 hour'", "now() - interval '1 day'"])
        caveat, args = r.choice(
            [("NULL", "NULL")] * 4
            + [
                ("'business_hours'", "NULL"),
                ("'from_ip'", f'\'{{"ip": "10.0.0.{r.randint(0, 2)}"}}\''),
                ("'nonexistent'", "NULL"),
            ]
        )
        return (
            f"INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation, "
            f"expires_at, starts_at, caveat, caveat_args) VALUES ('{obj}', '{oid}', '{rel}', '{st}', {sid_sql}, '{sr}', "
            f"{expires}, {starts}, {caveat}, {args}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        folders = ints(ids, "folder") or [1]
        projects = ints(ids, "project") or [1]
        docs = ids.get("doc") or [uid(1, "10000000-0000-4000-8000-")]
        f, g, p = r.choice(folders), r.choice(folders), r.choice(projects)
        newdoc = uid(r.randint(100, 999), "10000000-0000-4000-8000-")
        ops = [
            lambda: f"UPDATE mt.folders SET parent_type = 'folder', parent_id = {g} WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET parent_type = 'project', parent_id = {p} WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET parent_type = NULL, parent_id = NULL WHERE id = {f};",
            lambda: f"UPDATE mt.projects SET folder_id = {r.choice([f, 'NULL'])} WHERE id = {p};",
            lambda: f"UPDATE mt.folders SET locked = NOT locked WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET archived = NOT archived WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET owner_id = {self.maybe_user()} WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET org_id = {r.choice(['1', '2', 'NULL'])} WHERE id = {f};",
            lambda: f"UPDATE mt.orgs SET suspended = NOT suspended WHERE id = {r.choice([1, 2])};",
            lambda: f"UPDATE mt.users SET active = NOT active WHERE id = {self.u()};",
            lambda: (
                f"UPDATE mt.projects SET lead_id = {self.maybe_user()}, org_id = {r.choice([1, 2])} WHERE id = {p};"
            ),
            lambda: (
                f"INSERT INTO mt.org_members VALUES ({r.choice([1, 2])}, {self.u()}, '{r.choice(['admin', 'member'])}') "
                "ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role;"
            ),
            lambda: f"DELETE FROM mt.org_members WHERE user_id = {self.u()};",
            lambda: f"INSERT INTO mt.team_members VALUES ({r.randint(1, 4)}, {self.u()}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM mt.team_members WHERE team_id = {r.randint(1, 4)};",
            lambda: (
                f"INSERT INTO mt.folders VALUES ({max(folders) + 1}, {r.choice([chr(39) + 'folder' + chr(39), 'NULL'])}, "
                f"{f}, {self.maybe_user()}, false, false);"
            ),
            lambda: f"DELETE FROM mt.folders WHERE id = {f};",
            lambda: f"UPDATE mt.folders SET id = {max(folders) + r.randint(1, 20)} WHERE id = {f};",
            lambda: f"DELETE FROM mt.projects WHERE id = {p};",
            lambda: (
                f"INSERT INTO mt.docs VALUES ({lit(newdoc)}, {lit(r.choice(['folder', 'project']))}, "
                f"{r.choice([f, p])}, {self.maybe_user()}) ON CONFLICT DO NOTHING;"
            ),
            lambda: (
                f"UPDATE mt.docs SET container_type = 'project', container_id = {p} WHERE id = {lit(r.choice(docs))};"
            ),
            lambda: (
                f"UPDATE mt.docs SET container_type = 'folder', container_id = {f} WHERE id = {lit(r.choice(docs))};"
            ),
            lambda: f"UPDATE mt.docs SET id = {lit(newdoc)} WHERE id = {lit(r.choice(docs))};",
            lambda: f"DELETE FROM mt.docs WHERE id = {lit(r.choice(docs))};",
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: f"DELETE FROM authz.shares WHERE object_id = '{r.choice([f, p])}';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE random() < 0.2;",
            lambda: "UPDATE authz.shares SET starts_at = now() + interval '1 hour' WHERE random() < 0.1;",
            lambda: (
                f"INSERT INTO authz.role_permissions VALUES ({r.choice([1, 2, 3])}, 'edit') ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM authz.role_permissions WHERE role_id = {r.choice([1, 2])} AND permission = 'edit';",
            lambda: (
                "INSERT INTO authz.roles (id, owner_type, owner_id, object_type, name) VALUES "
                "(3, 'org', '2', 'folder', 'editor3') ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM authz.roles WHERE id = {r.choice([1, 2, 3])};",
        ]
        if r.random() < 0.15:
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


def row_of(text: str) -> list[str]:
    """'(1,"a b")' -> ['1', 'a b']: the fields of a row's text (Postgres quotes and doubles quotes)."""
    return next(csv.reader([text[1:-1]]))


class CompositeGen(Gen):
    """tests/composite.authz: tables keyed (org_id, id) and (org_id, slug text); keys with commas
    and quotes; keys renumbered and renamed; inheritance through composite columns, link tables and
    polymorphic pairs, across folders and projects; nested teams; shares with ids written loosely."""

    policy = "tests/composite.authz"
    schema = "tests/composite_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 7)] + [
        "bot:1",
        "bot:2",
        "bot:3",
    ]  # bots sign in as themselves
    people: ClassVar[list[str]] = [str(i) for i in range(1, 7)]
    slugs: ClassVar[list[str]] = ["a b", 'x,y "q"', "plain", "Ünï", "(p)"]

    def maybe_user(self) -> str:
        return self.r.choice(self.people + ["NULL"])

    def initial(self) -> str:
        r = self.r
        s = ["INSERT INTO cx.users SELECT generate_series(1, 6);", "INSERT INTO cx.orgs VALUES (1), (2);"]
        for u in range(2, 7):
            if r.random() < 0.7:
                s.append(f"UPDATE cx.users SET manager_id = {r.randint(1, u - 1)} WHERE id = {u};")
        for b in (1, 2, 3):
            s.append(f"INSERT INTO cx.bots VALUES ({b}, {r.choice(self.people)}, {str(r.random() < 0.8).lower()});")
        for o in (1, 2):
            for u in r.sample(self.people, 1):
                s.append(f"INSERT INTO cx.org_admins VALUES ({o}, {u});")
            slugs = r.sample(self.slugs, 4)
            for i, slug in enumerate(slugs):
                parent = r.choice([None] + slugs[:i]) if i else None
                s.append(
                    f"INSERT INTO cx.teams VALUES ({o}, {lit(slug)}, {self.maybe_user()}, "
                    f"{lit(parent) if parent else 'NULL'});"
                )
                for u in r.sample(self.people, r.choice([0, 1, 2])):
                    s.append(f"INSERT INTO cx.team_members VALUES ({o}, {lit(slug)}, {u});")
                if r.random() < 0.3:
                    s.append(f"INSERT INTO cx.team_bots VALUES ({o}, {lit(slug)}, {r.randint(1, 3)});")
            for i in range(1, 11):
                kind = r.choice(["folder", "folder", "project", None]) if i > 1 else None
                parent = r.randint(1, i - 1) if kind == "folder" else r.randint(1, 3) if kind == "project" else None
                s.append(
                    f"INSERT INTO cx.folders VALUES ({o}, {i}, {self.maybe_user()}, "
                    f"{lit(kind) if kind else 'NULL'}, {parent or 'NULL'});"
                )
            for pj in range(1, 4):
                s.append(
                    f"INSERT INTO cx.projects VALUES ({o}, {pj}, {self.maybe_user()}, "
                    f"{r.choice([None, 1, 2, 3, 4, 5]) or 'NULL'});"
                )
            for _ in range(3):
                s.append(
                    f"INSERT INTO cx.folder_links VALUES ({o}, {r.randint(2, 10)}, {r.randint(1, 10)}) "
                    f"ON CONFLICT DO NOTHING;"
                )
            for _ in range(3):
                s.append(
                    f"INSERT INTO cx.folder_teams VALUES ({o}, {r.randint(1, 10)}, {lit(r.choice(slugs))}) "
                    f"ON CONFLICT DO NOTHING;"
                )
            for i in range(1, 13):
                s.append(
                    f"INSERT INTO cx.files VALUES ({o}, {i}, {r.randint(1, 10)}, {self.maybe_user()}, "
                    f"{r.choice([1, 2, 3, 'NULL', 'NULL'])});"
                )
        return "\n".join(s)

    def grants(self) -> str:
        return "\n".join(self.grant() for _ in range(20))

    def team(self, ids: Ids | None = None) -> tuple[int, str]:
        teams = [row_of(x) for x in (ids or {}).get("team", [])] or [["1", "a b"]]
        o, slug = self.r.choice(teams)
        return int(o), slug

    def id_text(self, o: int, i: int) -> str:
        """A folder's id as a caller might write it: canonical or with spaces."""
        return self.r.choice([f"({o},{i})", f"( {o}, {i} )"])

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        folders = [tuple(map(int, row_of(x))) for x in (ids or {}).get("folder", [])] or [(1, 1)]
        o, f = r.choice(folders)
        if r.random() < 0.25:  # a team inside a team, by sharing
            (o1, s1), (o2, s2) = self.team(ids), self.team(ids)
            return (
                f"INSERT INTO authz.shares VALUES ('team', ROW({o1}, {lit(s1)})::text, 'member', 'team', "
                f"ROW({o2}, {lit(s2)})::text, 'member', NULL) ON CONFLICT DO NOTHING;"
            )
        k = r.random()
        if k < 0.1:
            subj, sid = ("bot", None, ""), "'*'"  # any signed-in bot
        elif k < 0.25:
            subj, sid = ("bot", None, ""), lit(str(r.randint(1, 3)))
        elif k < 0.55:
            subj = ("user", r.choice(self.people), "")
            sid = lit(subj[1])
        else:
            to, ts = self.team(ids)
            subj = ("team", None, "member")
            sid = f"ROW({to}, {lit(ts)})::text"
        expires = r.choice(["NULL", "NULL", "now() - interval '1 hour'", "now() + interval '1 day'"])
        return (
            f"INSERT INTO authz.shares VALUES ('folder', {lit(self.id_text(o, f))}, 'viewer', {lit(subj[0])}, "
            f"{sid}, {lit(subj[2])}, {expires}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        folders = [tuple(map(int, row_of(x))) for x in ids.get("folder", [])] or [(1, 1)]
        projects = [tuple(map(int, row_of(x))) for x in ids.get("project", [])] or [(1, 1)]
        files = [tuple(map(int, row_of(x))) for x in ids.get("file", [])] or [(1, 1)]
        o, f = r.choice(folders)
        g = r.choice([x for x in folders if x[0] == o] or [(o, 1)])[1]
        p = r.choice([x for x in projects if x[0] == o] or [(o, 1)])[1]
        fo, fi = r.choice(files)
        to, ts = self.team(ids)
        ts2 = r.choice([s for oo, s in [row_of(x) for x in ids.get("team", [])] if int(oo) == to] or [ts])
        top = max(i for _, i in folders)
        here = f"(org_id, id) = ({o}, {f})"
        ops = [
            lambda: f"UPDATE cx.folders SET parent_type = 'folder', parent_id = {g} WHERE {here};",
            lambda: f"UPDATE cx.folders SET parent_type = 'project', parent_id = {p} WHERE {here};",
            lambda: f"UPDATE cx.folders SET parent_type = NULL, parent_id = NULL WHERE {here};",
            lambda: f"UPDATE cx.projects SET folder_id = {r.choice([f, 'NULL'])} WHERE (org_id, id) = ({o}, {p});",
            lambda: f"UPDATE cx.folders SET owner_id = {self.maybe_user()} WHERE {here};",
            lambda: f"UPDATE cx.projects SET lead_id = {self.maybe_user()} WHERE (org_id, id) = ({o}, {p});",
            lambda: f"INSERT INTO cx.folders VALUES ({o}, {top + 1}, {self.maybe_user()}, 'folder', {f});",
            lambda: f"DELETE FROM cx.folders WHERE {here};",
            lambda: f"UPDATE cx.folders SET id = {top + r.randint(1, 9)} WHERE {here};",  # renumbered
            lambda: (
                f"UPDATE cx.folders SET org_id = {3 - o} WHERE {here} AND NOT EXISTS "
                f"(SELECT 1 FROM cx.folders x WHERE (x.org_id, x.id) = ({3 - o}, {f}));"
            ),  # half the key changes
            lambda: f"INSERT INTO cx.folder_links VALUES ({o}, {f}, {g}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.folder_links WHERE org_id = {o} AND (child_id = {f} OR parent_id = {f});",
            lambda: f"INSERT INTO cx.folder_teams VALUES ({to}, {f}, {lit(ts)}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.folder_teams WHERE org_id = {o} AND folder_id = {f};",
            lambda: (
                f"UPDATE cx.teams SET parent_slug = {r.choice([lit(ts2), 'NULL'])} WHERE (org_id, slug) = ({to}, {lit(ts)});"
            ),
            lambda: f"UPDATE cx.teams SET slug = {lit(ts + '!')} WHERE (org_id, slug) = ({to}, {lit(ts)});",  # renamed
            lambda: f"UPDATE cx.teams SET disbanded = NOT disbanded WHERE (org_id, slug) = ({to}, {lit(ts)});",
            lambda: (
                f"UPDATE cx.team_members SET team_slug = {lit(ts2)} WHERE org_id = {to} AND team_slug = {lit(ts)} "
                f"AND user_id = {r.choice(self.people)} AND NOT EXISTS (SELECT 1 FROM cx.team_members m "
                f"WHERE m.org_id = {to} AND m.team_slug = {lit(ts2)} AND m.user_id = team_members.user_id);"
            ),
            lambda: (
                f"INSERT INTO cx.team_members VALUES ({to}, {lit(ts)}, {r.choice(self.people)}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM cx.team_members WHERE org_id = {to} AND team_slug = {lit(ts)};",
            lambda: f"DELETE FROM cx.teams WHERE (org_id, slug) = ({to}, {lit(ts)});",
            lambda: (
                f"INSERT INTO cx.org_admins VALUES ({r.choice([1, 2])}, {r.choice(self.people)}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM cx.org_admins WHERE user_id = {r.choice(self.people)};",
            lambda: f"UPDATE cx.files SET folder_id = {g} WHERE (org_id, id) = ({fo}, {fi});",
            lambda: f"UPDATE cx.files SET owner_id = {self.maybe_user()} WHERE (org_id, id) = ({fo}, {fi});",
            lambda: f"DELETE FROM cx.files WHERE (org_id, id) = ({fo}, {fi});",
            lambda: (
                f"UPDATE cx.files SET uploaded_by = {r.choice([1, 2, 3, 'NULL'])} WHERE (org_id, id) = ({fo}, {fi});"
            ),
            lambda: f"UPDATE cx.bots SET active = NOT active WHERE id = {r.randint(1, 3)};",
            lambda: (
                f"UPDATE cx.users SET manager_id = {r.choice(self.people + ['NULL'])} WHERE id = {r.choice(self.people)};"
            ),
            lambda: f"INSERT INTO cx.team_bots VALUES ({to}, {lit(ts)}, {r.randint(1, 3)}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.team_bots WHERE bot_id = {r.randint(1, 3)};",
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: f"DELETE FROM authz.shares WHERE object_type = 'folder' AND object_id = '({o},{f})';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE random() < 0.2;",
        ]
        if r.random() < 0.15:
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


class LoopGen(Gen):
    """tests/loop.authz: inheritance round a loop of foreign keys through four types, two of which have no
    starting point of their own (their edit is only what the loop brings round), and a condition that stops it
    (an address not verified); links re-pointed, cut (NULL) and their rows deleted, so the loop opens, closes and
    runs through rows that are gone."""

    policy = "tests/loop.authz"
    schema = "tests/loop_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 7)]
    tables: ClassVar[dict[str, tuple[str, str, str]]] = {  # type: (table, the link column, the type it names)
        "org": ("lp.orgs", "settings_id", "setting"),
        "setting": ("lp.settings", "email_id", "email"),
        "email": ("lp.emails", "domain_id", "domain"),
        "domain": ("lp.domains", "org_id", "org"),
    }

    def maybe(self, ids: list[int]) -> str:
        return str(self.r.choice(ids)) if ids and self.r.random() < 0.8 else "NULL"

    def initial(self) -> str:
        r = self.r
        s = ["INSERT INTO lp.users SELECT i, 'u' || i FROM generate_series(1, 6) i;"]
        for table, _, _ in self.tables.values():
            s.append(f"INSERT INTO {table} (id) SELECT generate_series(1, 6);")
        for i in range(1, 7):
            s.append(
                f"UPDATE lp.orgs SET owner_id = {r.choice(self.users) if r.random() < 0.6 else 'NULL'} WHERE id = {i};"
            )
            for table, col, _ in self.tables.values():
                s.append(f"UPDATE {table} SET {col} = {self.maybe(list(range(1, 7)))} WHERE id = {i};")
            s.append(f"UPDATE lp.emails SET verified = {str(r.random() < 0.75).lower()} WHERE id = {i};")
        s += [f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), 100);" for table, _, _ in self.tables.values()]
        return "\n".join(s)

    def grants(self) -> str:
        return "\n".join(self.grant() for _ in range(4))

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        expires = r.choice(["NULL", "NULL", "now() - interval '1 hour'", "now() + interval '1 day'"])
        sid = r.choice(ints(ids, "setting") or list(range(1, 7)))
        return (
            f"INSERT INTO authz.shares VALUES ('setting', {sid}, 'admin', 'user', {r.choice(self.users)}, '', "
            f"{expires}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        t = r.choice(list(self.tables))
        table, col, target = self.tables[t]
        mine, theirs = ints(ids, t) or [1], ints(ids, target)
        ops = [
            lambda: f"UPDATE {table} SET {col} = {self.maybe(theirs)} WHERE id = {r.choice(mine)};",
            lambda: f"UPDATE {table} SET {col} = {self.maybe(theirs)} WHERE id % 2 = {r.randint(0, 1)};",
            lambda: f"INSERT INTO {table} ({col}) VALUES ({self.maybe(theirs)});",
            lambda: f"DELETE FROM {table} WHERE id = {r.choice(mine)};",
            lambda: f"UPDATE {table} SET id = {max(mine) + r.randint(1, 50)} WHERE id = {r.choice(mine)};",
            lambda: (
                f"UPDATE lp.orgs SET owner_id = {r.choice(self.users + ['NULL'])} WHERE id = {r.choice(ints(ids, 'org') or [1])};"
            ),
            lambda: f"UPDATE lp.emails SET verified = NOT verified WHERE id = {r.choice(ints(ids, 'email') or [1])};",
            lambda: self.grant(ids),
            lambda: "DELETE FROM authz.shares WHERE object_type = 'setting' AND random() < 0.4;",
        ]
        if r.random() < 0.15:  # several changes in one transaction
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


class CrossGen(Gen):
    """tests/cross.authz: inheritance through two types at once, by every kind of link: a folder's column pair
    naming a folder or a project, a table placing projects in folders (whose rows stop counting when not active),
    and shares of a project with a folder. A condition that reads another table (cx.frozen) stops what editors pass
    down: rows put in it, taken out and truncated must change the inheritance at once. Loops close through the
    placements and the shares, which may loop; through the columns they are refused. Regions and sites hold each
    other through tables only, whose where is the only thing that stops them (and a relation with two sources,
    each naming another type)."""

    policy = "tests/cross.authz"
    schema = "tests/cross_schema.sql"
    users: ClassVar[list[str]] = [str(i) for i in range(1, 7)]
    expected_errors: ClassVar[tuple[str, ...]] = (
        *Gen.expected_errors,
        "cannot expire, start later or have a caveat",  # a share that is a link: refused, as the docs say
    )

    def maybe_user(self) -> str:
        return self.r.choice([*self.users, "NULL"])

    def initial(self) -> str:
        r = self.r
        s = ["INSERT INTO cx.users SELECT i, 'u' || i FROM generate_series(1, 6) i;"]
        s += [f"INSERT INTO cx.projects (id, lead_id) VALUES ({p}, {self.maybe_user()});" for p in range(1, 5)]
        for i in range(1, 11):
            # a folder sits in an earlier folder or in a project: no loop through the columns to begin with
            kind = r.choice(["folder", "project", None]) if i > 1 else r.choice(["project", None])
            parent = r.randint(1, i - 1) if kind == "folder" else r.randint(1, 4) if kind == "project" else None
            s.append(
                f"INSERT INTO cx.folders (id, parent_type, parent_id, owner_id, archived) VALUES ({i}, "
                f"{lit(kind) if kind else 'NULL'}, {parent or 'NULL'}, {self.maybe_user()}, {str(r.random() < 0.1).lower()});"
            )
        for _ in range(5):
            s.append(
                f"INSERT INTO cx.placements VALUES ({r.randint(1, 4)}, {r.randint(1, 10)}, "
                f"{str(r.random() < 0.8).lower()}) ON CONFLICT DO NOTHING;"
            )
        s += [f"INSERT INTO cx.frozen VALUES ({f}) ON CONFLICT DO NOTHING;" for f in r.sample(range(1, 11), 2)]
        s += [f"INSERT INTO cx.regions (id, chief_id) VALUES ({i}, {self.maybe_user()});" for i in range(1, 5)]
        s.append("INSERT INTO cx.sites (id) SELECT generate_series(1, 4);")
        for _ in range(4):
            for table in ("site_links", "site_regions"):
                s.append(
                    f"INSERT INTO cx.{table} VALUES ({r.randint(1, 4)}, {r.randint(1, 4)}, "
                    f"{str(r.random() < 0.8).lower()}) ON CONFLICT DO NOTHING;"
                )
        s += [
            f"INSERT INTO cx.region_links VALUES ({r.randint(1, 4)}, {r.randint(1, 4)}) ON CONFLICT DO NOTHING;"
            for _ in range(2)
        ]
        s += [
            f"SELECT setval(pg_get_serial_sequence('cx.{t}', 'id'), 100);"
            for t in ("folders", "projects", "regions", "sites")
        ]
        return "\n".join(s)

    def grants(self) -> str:
        return "\n".join(self.grant() for _ in range(10))

    def grant(self, ids: Ids | None = None) -> str:
        r = self.r
        folders, projects = ints(ids, "folder") or list(range(1, 11)), ints(ids, "project") or list(range(1, 5))
        if r.random() < 0.5:  # a project shared with a folder: a link, which never expires
            return (
                f"INSERT INTO authz.shares VALUES ('project', {r.choice(projects)}, 'host', 'folder', "
                f"{r.choice(folders)}, '', NULL) ON CONFLICT DO NOTHING;"
            )
        expires = r.choice(["NULL", "NULL", EXPIRED, "now() + interval '1 day'"])
        return (
            f"INSERT INTO authz.shares VALUES ('folder', {r.choice(folders)}, 'viewer', 'user', "
            f"{r.choice(self.users)}, '', {expires}) ON CONFLICT DO NOTHING;"
        )

    def change(self, ids: Ids) -> str:
        r = self.r
        folders, projects = ints(ids, "folder") or [1], ints(ids, "project") or [1]
        f, g, p = r.choice(folders), r.choice(folders), r.choice(projects)
        parent = r.choice([f"'folder', {f}", f"'project', {p}", "NULL, NULL"])  # a new folder's (type, id)
        regions, sites = ints(ids, "region") or [1], ints(ids, "site") or [1]
        a, b, site = r.choice(regions), r.choice(regions), r.choice(sites)
        ops = [
            lambda: f"UPDATE cx.folders SET parent_type = 'folder', parent_id = {g} WHERE id = {f};",
            lambda: f"UPDATE cx.folders SET parent_type = 'project', parent_id = {p} WHERE id = {f};",
            lambda: f"UPDATE cx.folders SET parent_type = NULL, parent_id = NULL WHERE id = {f};",
            lambda: (
                f"UPDATE cx.folders SET parent_type = 'folder', parent_id = {g} WHERE id IN ({f}, {r.choice(folders)});"
            ),
            lambda: f"UPDATE cx.folders SET archived = NOT archived WHERE id = {f};",
            lambda: f"UPDATE cx.folders SET owner_id = {self.maybe_user()} WHERE id = {f};",
            lambda: f"UPDATE cx.projects SET lead_id = {self.maybe_user()} WHERE id = {p};",
            lambda: (
                f"INSERT INTO cx.folders (parent_type, parent_id, owner_id) VALUES ({parent}, {self.maybe_user()});"
            ),
            lambda: f"INSERT INTO cx.projects (lead_id) VALUES ({self.maybe_user()});",
            lambda: f"DELETE FROM cx.folders WHERE id = {f};",
            lambda: f"DELETE FROM cx.projects WHERE id = {p};",
            lambda: f"UPDATE cx.folders SET id = {max(folders) + r.randint(1, 50)} WHERE id = {f};",
            lambda: f"UPDATE cx.projects SET id = {max(projects) + r.randint(1, 50)} WHERE id = {p};",
            # the placements: a link table with a where
            lambda: (
                f"INSERT INTO cx.placements VALUES ({p}, {f}, {r.choice(['true', 'true', 'false'])}) ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM cx.placements WHERE project_id = {p} OR folder_id = {f};",
            lambda: f"UPDATE cx.placements SET active = NOT active WHERE project_id = {p};",
            lambda: f"UPDATE cx.placements SET folder_id = {g} WHERE project_id = {p} AND folder_id = {f};",
            lambda: "TRUNCATE cx.placements;",
            # the table the condition reads
            lambda: f"INSERT INTO cx.frozen VALUES ({f}) ON CONFLICT DO NOTHING;",
            lambda: (
                f"INSERT INTO cx.frozen SELECT id FROM cx.folders WHERE id % 3 = {r.randint(0, 2)} ON CONFLICT DO NOTHING;"
            ),
            lambda: f"DELETE FROM cx.frozen WHERE folder_id = {r.choice(folders)};",
            lambda: f"UPDATE cx.frozen SET folder_id = {g} WHERE folder_id = {f};",
            lambda: "TRUNCATE cx.frozen;",
            # shares: links (project into folder), and viewers
            lambda: self.grant(ids),
            lambda: self.grant(ids),
            lambda: "DELETE FROM authz.shares WHERE relation = 'host' AND random() < 0.4;",
            lambda: f"DELETE FROM authz.shares WHERE object_type = 'folder' AND object_id = '{f}';",
            lambda: f"UPDATE authz.shares SET expires_at = {EXPIRED} WHERE relation = 'viewer' AND random() < 0.3;",
            lambda: (
                f"INSERT INTO authz.shares VALUES ('project', {p}, 'host', 'folder', {f}, '', "
                "now() + interval '1 day');"
            ),
            # regions and sites, through tables only
            lambda: (
                f"INSERT INTO cx.site_links VALUES ({a}, {site}, {r.choice(['true', 'false'])}) "
                "ON CONFLICT (region_id, site_id) DO UPDATE SET active = NOT cx.site_links.active;"
            ),
            lambda: f"INSERT INTO cx.site_regions VALUES ({site}, {a}, true) ON CONFLICT DO NOTHING;",
            lambda: f"UPDATE cx.site_regions SET active = NOT active WHERE site_id = {site};",
            lambda: f"INSERT INTO cx.region_links VALUES ({a}, {b}) ON CONFLICT DO NOTHING;",
            lambda: f"DELETE FROM cx.region_links WHERE region_id = {a} OR parent_id = {a};",
            lambda: (
                f"DELETE FROM cx.site_links WHERE site_id = {site}; DELETE FROM cx.site_regions WHERE region_id = {a};"
            ),
            lambda: f"UPDATE cx.regions SET chief_id = {self.maybe_user()} WHERE id = {a};",
            lambda: f"DELETE FROM cx.regions WHERE id = {a};",
            lambda: f"UPDATE cx.sites SET id = {max(sites) + r.randint(1, 50)} WHERE id = {site};",
            lambda: "INSERT INTO cx.sites DEFAULT VALUES;",
        ]
        if r.random() < 0.15:  # several changes in one transaction
            return "BEGIN;\n" + "\n".join(r.choice(ops)() for _ in range(r.randint(2, 4))) + "\nCOMMIT;"
        return r.choice(ops)()


GENERATORS: dict[str, type[Gen]] = {
    "docs": DocsGen,
    "alt": AltGen,
    "multi": MultiGen,
    "composite": CompositeGen,
    "loop": LoopGen,
    "cross": CrossGen,
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="authz_difftest")
    ap.add_argument("--gen", default="docs", choices=sorted(GENERATORS))
    ap.add_argument("--steps", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    os.chdir(os.path.dirname(HERE))

    rnd = random.Random(args.seed)
    gen = GENERATORS[args.gen](rnd)
    db = DB(args.db)
    db.recreate()
    db.run(read(gen.schema))
    db.run(gen.initial())
    compiled = subprocess.run(
        [sys.executable, "compile_policy.py", gen.policy], capture_output=True, text=True, check=True
    ).stdout
    db.run(compiled)
    db.run(gen.grants())
    checker = Checker(db, gen.policy, gen)

    failures, refused = 0, 0
    for step in range(args.steps + 1):
        problems = checker.check()
        if problems:
            failures += 1
            print(f"step {step}: {len(problems)} mismatch(es)")
            for p in problems[:12]:
                print("   ", p)
            if failures >= 3:
                break
        if step == args.steps:
            break
        ids: Ids = {
            t.name: [x[0] for x in db.rows(f"SELECT {idsql(t)} FROM {t.table} ORDER BY 1")]
            for t in checker.types.values()
        }
        sql = gen.change(ids)
        code, _, err = db.run(sql, check=False)
        if code != 0:
            if any(e in err for e in gen.expected_errors):
                refused += 1
            else:
                print(f"step {step + 1}: unexpected error\n  {sql}\n  {err.strip()}")
                failures += 1
        if not args.quiet:
            print(f"step {step + 1}: {'refused' if code else 'ok'}  {sql.splitlines()[0][:110]}")
    print(
        f"{args.gen} seed {args.seed}: {args.steps} changes ({refused} refused as expected), "
        f"{'no mismatches' if not failures else f'{failures} failing step(s)'}"
    )
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
