#!/usr/bin/env python3
"""unit_test: fast checks that need no database: the generated SQL against golden files, included
files, what the rowstile command runs against a database, its file reading, and the version.

    python3 tests/unit_test.py            # a few seconds; runs anywhere Python 3.9+ does
    python3 tests/unit_test.py --update   # after an intended change to the generated SQL: rewrite
                                          # tests/golden/*.sql, then read the diff before committing
"""

import fnmatch
import glob
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
import types
import unittest
from collections.abc import Callable, Sequence
from typing import ClassVar, cast
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import authzlib  # noqa: E402
import rowstile_cli  # noqa: E402
from authzlib import (  # noqa: E402
    Compiler,
    PolicyError,
    database,
    draft,
    evaluate,
    parse_policy,
    statements,
)
from authzlib.conditions import Scalar  # noqa: E402
from authzlib.connection import Row, Value  # noqa: E402
from authzlib.review import Review  # noqa: E402

GOLDEN = os.path.join(ROOT, "tests", "golden")
UPDATE = "--update" in sys.argv
POLICIES = {
    "docs": "example/docs.authz",
    "alt": "tests/alt.authz",
    "multi": "tests/multi.authz",
    "composite": "tests/composite.authz",
    "loop": "tests/loop.authz",
    "cross": "tests/cross.authz",
}


def read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def errors_prelude() -> str:
    """`app role` and the user type: what a small policy in a test starts with."""
    from authzlib.errors import PRELUDE

    return PRELUDE


def compiled(name: str, transaction: bool = True) -> str:
    return Compiler(parse_policy(read(POLICIES[name]), POLICIES[name])).compile(POLICIES[name], transaction)


def search(pattern: str, text: str, flags: int = 0) -> re.Match[str]:
    m = re.search(pattern, text, flags)
    assert m is not None, f"{pattern!r} is not in the text"
    return m


class ThisRow(unittest.TestCase):
    """`this.` in a condition is the alias its row has where the condition is placed: views, row checks, row-level
    security, triggers, trees and the migrations that build them beside. None is left in the SQL."""

    @staticmethod
    def code(sql: str) -> str:
        """The SQL without comments, string literals and quoted names (function bodies stay: they are code)."""
        out: list[str] = []
        i, n = 0, len(sql)
        while i < n:
            if sql.startswith("--", i):
                j = sql.find("\n", i)
                i = n if j < 0 else j
            elif sql.startswith("/*", i):
                j = sql.find("*/", i + 2)
                i = n if j < 0 else j + 2
            elif sql[i] == "'":
                escapes, j = i > 0 and sql[i - 1] in "eE", i + 1
                while j < n and not (sql[j] == "'" and sql[j + 1 : j + 2] != "'"):
                    j += 2 if (escapes and sql[j] == "\\") or sql[j : j + 2] == "''" else 1
                out.append(" ")
                i = j + 1
            elif sql[i] == '"':
                j = sql.find('"', i + 1)
                out.append(" ")
                i = n if j < 0 else j + 1
            else:
                out.append(sql[i])
                i += 1
        return "".join(out)

    def left(self, sql: str) -> list[str]:
        from authzlib.sqlutil import THIS

        text = self.code(sql)
        return [text[max(0, m.start() - 60) : m.end() + 20] for m in THIS.finditer(text)]

    def test_no_this_is_left_in_the_sql(self) -> None:
        for name in ("alt", "multi", "composite"):
            text = read(POLICIES[name])
            self.assertIn("this.", text, name)
            c = Compiler(parse_policy(text, POLICIES[name]))
            sql = c.compile(POLICIES[name]) + c.tests_function_sql()
            sql += "".join(n["build"] + n["catch_up"] for n in c.tree_next.values())
            self.assertEqual(self.left(sql), [], name)

    def test_the_rewrite(self) -> None:
        from authzlib.sqlutil import names_this, on_row, this_alone

        self.assertEqual(
            on_row("exists (select 1 from app.m m where m.p = this.id and 'this.x' = m.y)", "r"),
            "exists (select 1 from app.m m where m.p = r.id and 'this.x' = m.y)",
        )
        self.assertEqual(
            on_row("this.\"Name\" = $$this.x$$ /* this.y */ and E'a\\'s this.z' = THIS . w", '"files"'),
            '"files"."Name" = $$this.x$$ /* this.y */ and E\'a\\\'s this.z\' = "files".w',
        )
        self.assertEqual(on_row("t.this.x = xthis.y", "r"), "t.this.x = xthis.y")
        self.assertTrue(names_this("this.a = 1") and not names_this("'this.a' = x"))
        self.assertTrue(this_alone("exists (select 1 from app.t this where this.x)") and not this_alone("this.x"))

    def test_what_reads_more_than_its_row(self) -> None:
        """A condition that may read other rows runs with the policy's rights where the app role checks it: a
        function of the app's, however its name is written or as an operator, reads more; built-ins don't."""
        from authzlib.sqlutil import operators, reads_more

        for sql in (
            "app.member(this.id)",
            'app."Member"(this.id)',
            '"app".member(this.id)',
            '"member"(this.id)',
            'app . "Member" /* c */ (this.id)',
            "member /* c */ (id)",
            "exists (select 1 from app.t)",
            "lower(name) = app.f('x')",
            "=!= this.id",
            "id OPERATOR(app.===) 3",
            "a <=> b",
            "a ||- 1",
        ):
            self.assertTrue(reads_more(sql), sql)
        for sql in (
            "not archived",
            "lower(name) = 'f(x)'",
            "authz.uid() = owner_id",
            '"Owner" = authz.uid()',
            "coalesce(n, 0) > 1 /* f(x) */",
            "id in (1, 2)",
            "$$g(x)$$ = name",
            "n<>-1 and n*-2<=+3",
            "tags @> array['a'] and data->>'k' ~* '^x' and name || 'a' !~~ 'b%'",
            "'=!=' = name",
        ):
            self.assertFalse(reads_more(sql), sql)
        self.assertEqual(operators("a=-1 and b<=+-2 and c@-3"), ["=", "-", "<=", "+", "-", "@-"])


class Golden(unittest.TestCase):
    """The generated SQL is what it was; after an intended change, run with --update and read the diff."""

    def check(self, name: str, sql: str) -> None:
        path = os.path.join(GOLDEN, name)
        if UPDATE:
            os.makedirs(GOLDEN, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(sql)
            return
        with open(path, encoding="utf-8") as fh:
            want = fh.read()
        if sql != want:
            a, b = sql.split("\n"), want.split("\n")
            line = next((i for i, (x, y) in enumerate(zip(a, b, strict=False)) if x != y), min(len(a), len(b)))
            self.fail(
                f"{name} differs from line {line + 1}:\n  now:    {a[line] if line < len(a) else '(end)'}\n"
                f"  golden: {b[line] if line < len(b) else '(end)'}\n(intended? python3 tests/unit_test.py --update)"
            )

    def test_psql_scripts(self) -> None:
        for name in POLICIES:
            self.check(f"{name}.sql", compiled(name))

    def test_diff_script(self) -> None:
        c = Compiler(parse_policy(read(POLICIES["multi"]), POLICIES["multi"]))
        self.check("multi.diff.sql", c.compile_diff(POLICIES["multi"], ["1", "2"]))


class Walks(unittest.TestCase):
    def test_walks_look_up_each_source(self) -> None:
        """Tree walks must not join the sources' UNION ALL view: the planner can't use indexes through it,
        so every step would scan every row (measured with bench/)."""
        for name in POLICIES:
            sql = compiled(name)
            self.assertIsNone(re.search(r'JOIN authz_int\."[^"]+_(links|parents)"', sql), name)
            self.assertIn("CROSS JOIN LATERAL", sql)


class Loops(unittest.TestCase):
    LOOP = (
        "type org = app.orgs\n  owner : user = owner_id\n  settings : setting = settings_id\n  can edit = {start}settings.edit\n"
        "type setting = app.settings\n  email : email = email_id\n  can edit = email.edit\n"
        "type email = app.emails\n  domain : domain = domain_id\n  can edit = domain.edit\n"
        "type domain = app.domains\n  org : org = org_id\n  can edit = org.edit\n"
    )

    def test_a_loop_through_types_needs_one_starting_point(self) -> None:
        """Inheritance round a loop of types: one starting point anywhere in it is enough (an org's owner edits its
        domain, and so on round); none at all is the mistake AZ303 names. Its meaning is checked against the
        reference evaluator by difftest --gen loop."""
        sql = Compiler(parse_policy(errors_prelude() + self.LOOP.format(start="owner or "))).compile("the policy")
        self.assertIn('authz_int."domain__edit__start"', sql)
        self.assertIn("SELECT NULL::bigint AS id WHERE false", sql)  # domain's own start: none
        with self.assertRaisesRegex(
            PolicyError, r"line \d+: \w+\.edit needs a starting point besides inheritance \[AZ303\]"
        ):
            Compiler(
                parse_policy(errors_prelude() + self.LOOP.format(start="").replace("  owner : user = owner_id\n", ""))
            ).compile("the policy")


class LockRoom(unittest.TestCase):
    """GitLab's draft, applied whole, stopped after 150 s with Postgres's 'out of shared memory': one lock per
    object made, more than the lock table holds. apply says so before it starts."""

    class Small:
        """A database whose lock table holds 10 locks (1 per connection, 10 connections)."""

        def __init__(self) -> None:
            self.warnings: list[tuple[str, str | None]] = []

        @property
        def errors(self) -> type[Exception]:
            return Exception

        def rows(self, sql: str, args: Sequence[Value] = ()) -> list[Row]:
            return [{"per": 1, "slots": 10}]

        def script(self, sql: str) -> None:
            pass

        def warn(self, message: str, detail: str | None = None, hint: str | None = None) -> None:
            self.warnings.append((message, hint))

    def test_more_objects_than_locks_is_said_first(self) -> None:
        db = self.Small()
        database.lock_room(db, "".join(f"CREATE VIEW v{i} AS SELECT 1;\n" for i in range(20)))
        self.assertEqual(len(db.warnings), 1)
        self.assertIn("about 20 objects in one transaction", db.warnings[0][0])
        self.assertEqual(
            db.warnings[0][1], "raise max_locks_per_transaction to 4 (a restart; on managed Postgres, a parameter)"
        )
        db = self.Small()
        database.lock_room(db, "CREATE VIEW v AS SELECT 1;\n")
        self.assertEqual(db.warnings, [])


class PointChecks(unittest.TestCase):
    def policy(self, sql: str, table: str, command: str) -> str:
        return search(
            rf'CREATE POLICY "authz_{command}" ON {re.escape(table)} FOR {command.upper()}.*?;\n', sql, re.S
        ).group(0)

    def test_writes_check_one_object_and_selects_keep_the_views(self) -> None:
        """Write rules and authz.can check one object at a time (__has functions); select rules may read many
        rows, so they must keep the views (a function call per row would make lists slow)."""
        sql = compiled("docs")
        self.assertIn('authz_gen."folder__edit__has"', self.policy(sql, '"app"."folders"', "insert"))
        self.assertNotIn("__has", self.policy(sql, '"app"."folders"', "select"))
        self.assertNotIn("__has", self.policy(sql, '"app"."files"', "select"))
        can = sql[sql.index("CREATE OR REPLACE FUNCTION authz.can(p_type text, p_id text") :]
        self.assertIn("__has", can[: can.index("END $f$;")])
        lst = sql[sql.index("CREATE OR REPLACE FUNCTION authz.list(p_type text") :]
        self.assertNotIn("__has", lst[: lst.index("END $f$;")])

    def test_own_columns_first(self) -> None:
        """Reads check a recursive permission against what the object's own columns give (owner, org admin)
        before its view, and each check lists its cheapest items first."""
        sql = compiled("docs")
        files = self.policy(sql, '"app"."files"', "select")
        self.assertLess(
            files.index('"folder__share__direct" v WHERE v.id = "files"."folder_id"'),
            files.index('"folder__edit" v WHERE v.id = "files"."folder_id"'),
        )
        self.assertLess(files.index('"file__viewer"'), files.index('"folder__edit"'))
        folders = self.policy(sql, '"app"."folders"', "select")
        self.assertLess(folders.index("coalesce((inherit), false)"), folders.index('"folder__view" v'))


class ColumnRules(unittest.TestCase):
    def test_before_is_the_default(self) -> None:
        """`update cols before : ...` is `update cols : ...` spelt out; `after` checks the row after the change."""
        text = read(POLICIES["docs"])
        spelt = text.replace("update id, owner_id, org_id, inherit :", "update id, owner_id, org_id, inherit before :")
        self.assertNotEqual(text, spelt)
        compile_ = lambda t: Compiler(parse_policy(t)).compile("x")
        self.assertEqual(compile_(text), compile_(spelt))
        self.assertIn("checked on the row after the change", compile_(text))

    # a function whose body is a string, without SECURITY DEFINER: Postgres reads the body when it runs, as the caller
    AS_CALLER = re.compile(
        r"CREATE (?:OR REPLACE )?FUNCTION ((?:authz|authz_gen|authz_int)\.(?:\"[^\"]+\"|\w+))\(.*?\)(.*?)AS \$(\w*)\$(.*?)\$\3\$;",
        re.S,
    )

    def test_what_runs_as_the_app_role_names_nothing_in_authz_int(self) -> None:
        # The app role may not use authz_int by name. A policy or a BEGIN ATOMIC body names it once, when the owner
        # makes it; a body in a string is read each time, as whoever runs it. A rule on a column is checked by
        # a trigger that runs as the app role: where the rule names a service (authz_int."bot__me"), the rule
        # is behind a BEGIN ATOMIC function, or every update of the column fails for want of the schema
        ruled = read(POLICIES["composite"]).replace(
            "  update folder_id after : folder.edit\n",
            "  update folder_id after : folder.edit\n  update name : uploader\n",
        )
        self.assertNotEqual(ruled, read(POLICIES["composite"]))
        # (these two run as the owner whoever calls: their callers are definer functions)
        owners = {"authz_int.session_ok", "authz_int.shares_canon"}
        for sql in [Compiler(parse_policy(ruled)).compile("x"), *(compiled(name) for name in POLICIES)]:
            for m in self.AS_CALLER.finditer(sql):
                name, head, body = m.group(1), m.group(2), m.group(4)
                if "SECURITY DEFINER" in head or name in owners:
                    continue
                self.assertNotRegex(body, r"\bauthz_int\.", f"{name} runs as its caller and names authz_int")
        sql = Compiler(parse_policy(ruled)).compile("x")
        holds = re.findall(r'CREATE FUNCTION authz_gen\."cx\.\w+:column_\d+:holds".*?END;', sql, re.S)
        self.assertEqual(
            len(holds), len(re.findall(r'IF NOT authz_gen\."cx\.\w+:column_\d+:holds"\(v_row\) THEN', sql))
        )
        self.assertTrue(any('"bot__me"' in fn for fn in holds), "the rule that names the bot is behind no function")


class SlowPlans(unittest.TestCase):
    """Each time a permission is named, Postgres writes its view out again when it plans a read. An operand
    named twice is written once; a select rule that still makes it write out many is a lint warning."""

    TEAMS = (
        "app role app_user\ntype user = app.users\ntype team = app.teams\n"
        "  member : user = app.team_members(team_id -> user_id)\n"
    )
    DOCS = "type doc = app.docs\n  team : team = team_id\n  can view = team.p{n}\nrules app.docs\n  select : view\n"

    def test_an_operand_named_twice_is_written_once(self) -> None:
        # in an or, p0 is written out in place (its relation, once); in an and, it is named, once
        for twice, p0, member in (("p0", 0, 1), ("p0 or p0", 0, 1), ("p0 and p0", 1, 0), ("p0 and p0 and p0", 1, 0)):
            text = self.TEAMS + f"  can p0 = member\n  can p1 = {twice}\n" + self.DOCS.format(n=1)
            sql = Compiler(parse_policy(text)).compile("x")
            body = search(r'CREATE VIEW authz_int\."?team__p1"? AS\n(.*?);\n', sql, re.S).group(1)
            self.assertEqual(
                (len(re.findall(r"team__p0\b", body)), len(re.findall(r"team__member\b", body))), (p0, member), twice
            )

    def heavy(self, levels: int) -> str:
        perms = "  can p0 = member\n" + "".join(
            f"  can p{n} = (p{n - 1} and {{a}}) or (p{n - 1} and {{b}})\n" for n in range(1, levels + 1)
        )
        return self.TEAMS + perms + self.DOCS.format(n=levels)

    def test_many_expansions_are_a_lint_warning(self) -> None:
        # p6 names p5 twice, which names p4 twice, ... down to p0 and its relation: 191 views for one read of app.docs
        c = Compiler(parse_policy(self.heavy(6)))
        sql = c.compile("x")
        self.assertRegex(
            sql,
            r"object := to_regclass\('\"app\".\"docs\"'\)::text;\n  problem := 'its select rule .* "
            r"\d+ view definitions to plan before a row is read",
        )
        doc = c.types["doc"]
        rule = next(r for r in c.rules if r.command == "select")
        self.assertEqual(c.expansions(c.rule_sql(doc, "t", rule)), 3 * 2**6 - 1)
        # two levels are few, and the policies here say nothing
        for text in (self.heavy(2), read(POLICIES["docs"]), read(POLICIES["multi"])):
            self.assertNotIn("view definitions to plan", Compiler(parse_policy(text)).compile("x"))

    @staticmethod
    def chain(levels: int) -> str:
        """Types in a chain (an org, its workspaces, their projects, ...): each row is inside one of the type
        above, and manage, edit and view each include the one before and inherit from the row above."""
        text = (
            "app role app_user\ntype user = app.users\ntype t0 = app.t0\n"
            "  member : user = app.t0_members(t0_id -> user_id)\n"
            "  admin  : user = app.t0_admins(t0_id -> user_id)\n"
            "  can manage = admin\n  can edit = manage\n  can view = edit or member\n"
        )
        for n in range(1, levels + 1):
            text += (
                f"type t{n} = app.t{n}\n  parent : t{n - 1} = parent_id\n  owner  : user = owner_id\n"
                f"  editor : user = app.t{n}_editors(t{n}_id -> user_id)\n"
                f"  viewer : user = app.t{n}_viewers(t{n}_id -> user_id)\n"
                "  can manage = owner or parent.manage\n  can edit = manage or editor or parent.edit\n"
                "  can view = edit or viewer or parent.view\n"
            )
        return text + f"rules app.t{levels}\n  select : view\n"

    def test_tiers_that_include_each_other_are_looked_up_once(self) -> None:
        # view names parent.view, and through edit and manage parent.edit and parent.manage, which parent.view
        # includes: only parent.view is looked up, so each level adds the same few views (it was 7, 21, 46, 85, 141)
        counts = []
        for levels in range(1, 6):
            c = Compiler(parse_policy(self.chain(levels)))
            sql = c.compile("x")
            rule = next(r for r in c.rules if r.command == "select")
            counts.append(c.expansions(c.rule_sql(c.types[f"t{levels}"], "t", rule)))
        self.assertEqual(len({b - a for a, b in itertools.pairwise(counts[1:])}), 1, counts)
        self.assertLess(counts[3], 30, counts)
        self.assertNotIn("view definitions to plan", sql)
        # the view of view: what its own relations give and the parent's view, not the parent's edit or manage
        body = search(r'CREATE VIEW authz_int\."?t5__view"? AS\n(.*?);\n', sql, re.S).group(1)
        self.assertIn("parent__view", body)
        self.assertNotRegex(body, r"parent__(edit|manage)\b|t5__(edit|manage)\b")
        # edit still includes manage's people, written out: the owner, and the parent's edit alone
        body = search(r'CREATE VIEW authz_int\."?t5__edit"? AS\n(.*?);\n', sql, re.S).group(1)
        self.assertIn("parent__edit", body)
        self.assertIn("owner", body)
        self.assertNotRegex(body, r"parent__manage\b|t5__manage\b")

    def test_a_lookup_is_dropped_only_where_every_type_the_relation_names_covers_it(self) -> None:
        # up names a folder or a drive. A folder's view includes its edit; where a drive's doesn't, up.view
        # doesn't cover up.edit (a drive's owner would lose the notes on it), and both lookups stay
        def see(drive_view: str) -> str:
            policy = (
                "app role app_user\ntype user = app.users\n"
                "type folder = app.folders\n  owner : user = owner_id\n"
                "  viewer : user = app.folder_viewers(folder_id -> user_id)\n"
                "  can edit = owner\n  can view = edit or viewer\n"
                "type drive = app.drives\n  owner : user = owner_id\n"
                "  viewer : user = app.drive_viewers(drive_id -> user_id)\n"
                f"  can edit = owner\n  can view = {drive_view}\n"
                "type note = app.notes\n  up : folder, drive = (up_type, up_id)\n  can see = up.view or up.edit\n"
                "rules app.notes\n  select : see\n"
            )
            sql = Compiler(parse_policy(policy)).compile("x")
            return search(r'CREATE VIEW authz_int\."?note__see"? AS\n(.*?);\n', sql, re.S).group(1)

        self.assertRegex(see("viewer"), r"note__up__view\b")
        self.assertRegex(see("viewer"), r"note__up__edit\b")
        # ... and where the drive's view includes its edit too, one lookup says it all
        self.assertRegex(see("edit or viewer"), r"note__up__view\b")
        self.assertNotRegex(see("edit or viewer"), r"note__up__edit\b")


class LanguageForms(unittest.TestCase):
    def test_named_columns_mean_the_arrow(self) -> None:
        text = read(POLICIES["docs"])
        named = text.replace("app.teams(parent_id -> id)", "app.teams(subject: id, object: parent_id)")
        self.assertNotEqual(text, named)
        compile_ = lambda t: Compiler(parse_policy(t)).compile("x")
        self.assertEqual(compile_(text), compile_(named))

    def test_words_for_conditions(self) -> None:
        text = read(POLICIES["docs"]).replace(
            "  can break_glass = org.member", "  can break_glass = org.member and signed_in"
        )
        sql = Compiler(parse_policy(text)).compile("x")
        self.assertIn("authz.uid()) IS NOT NULL", sql)
        for word, written in (("anyone", "true"), ("nobody", "false")):
            pol = parse_policy(
                read(POLICIES["docs"]).replace("  can break_glass = org.member", f"  can break_glass = {word}")
            )
            self.assertEqual(pol.types["folder"].perms["break_glass"].expr, authzlib.parse.Cond("cond", written))
        # the word `anyone` replaced: refused, saying which to write
        with self.assertRaises(PolicyError) as e:
            parse_policy(
                read(POLICIES["docs"]).replace("  can break_glass = org.member", "  can break_glass = everyone")
            )
        self.assertIn("write `anyone` instead of `everyone`", str(e.exception))
        self.assertEqual(e.exception.code, "AZ102")

    def test_sql_comments_in_a_condition_end_at_the_line(self) -> None:
        # the lines of a condition are joined into one: a comment left in would swallow the lines after it
        text = read(POLICIES["docs"])
        commented = text.replace("on a.org_id = b.org_id\n", "on a.org_id = b.org_id -- don't drop the next line\n")
        self.assertNotEqual(text, commented)
        compile_ = lambda t: Compiler(parse_policy(t)).compile("x")
        self.assertEqual(compile_(text), compile_(commented))

    def test_quotes_in_include_names_and_test_ids(self) -> None:
        pol = parse_policy('include "a--b.authz"  -- the rest\n', files={"a--b.authz": read(POLICIES["docs"])})
        self.assertIn("folder", pol.types)
        pol = parse_policy(read(POLICIES["docs"]) + "test\n  user 'it''s' cannot view file 'o''k'\n")
        self.assertEqual((pol.tests[-1].who, pol.tests[-1].obj), ("it's", "o'k"))

    def test_the_test_section_signs_in_as_the_principal_it_names(self) -> None:
        text = (
            errors_prelude() + "type service = app.services principal\n  owner : user = owner_id\n"
            "  can manage_keys = owner\ntest\n  service 1 can manage_keys service 1\n  anyone cannot manage_keys service 1\n"
        )
        sql = Compiler(parse_policy(text)).tests_function_sql()
        self.assertIn(
            "set_config('authz.user_id', coalesce('1', ''), true), set_config('authz.principal_type', 'service', true)",
            sql,
        )
        self.assertIn(
            "set_config('authz.user_id', coalesce('', ''), true), set_config('authz.principal_type', '', true)", sql
        )

    def test_lint_notes_relations_named_like_types(self) -> None:
        text = (
            read(POLICIES["docs"])
            .replace("  owner  : user   = owner_id\n", "  owner  : user   = owner_id\n  user   : user   = owner_id\n")
            .replace("  can share = owner or folder.share", "  can share = owner or user or folder.share")
        )
        sql = Compiler(parse_policy(text)).compile("x")
        self.assertIn("('file', 'user',", sql)
        # ...when the type signs in: `user` alone in a rule reads like any user. `folder : folder = folder_id` (what
        # init drafts and the guide writes) is only ever followed, `folder.view`, which reads as what it means
        self.assertIn("  folder : folder = folder_id\n", text)
        self.assertNotIn("('file', 'folder',", sql)

    def test_lint_knows_the_commands_the_rules_ask_for(self) -> None:
        # a rule for a command the app role has no privilege for never applies, and the statement fails with
        # Postgres's own message: lint is given each table's commands that have a rule. `nobody` asks for none; a
        # column's rule, or `after`, is an update's
        def rows(rules: str) -> list[str]:
            text = errors_prelude() + "  boss : user = boss_id\n  can edit = boss\nrules app.users\n" + rules
            sql = Compiler(parse_policy(text)).compile("x")
            return re.findall(r"""\('"app"\."users"', '(\w+)'\)""", search(r"v\(tbl, cmd\)", sql).string)

        self.assertEqual(rows("  select : edit\n  update : edit\n  delete : nobody\n"), ["select", "update"])
        self.assertEqual(
            rows("  select : edit\n  update : edit\n  update boss_id after : edit\n"), ["select", "update"]
        )
        self.assertEqual(rows("  select : edit\n  update : nobody\n  insert : nobody\n"), ["select"])

    def test_your_own_row_is_not_a_move(self) -> None:
        # a relation from the row's own key to its type (`self : user = id`) is "this row": lint doesn't ask for an
        # 'after' rule on the key, as it does for a parent's column
        text = errors_prelude() + (
            "  self : user = id\n  boss : user = boss_id\n  can edit = self or boss\n"
            "rules app.users\n  select : edit\n  update : edit\n"
        )
        sql = Compiler(parse_policy(text)).compile("x")
        self.assertNotIn("('\"app\".\"users\"', 'id', 'self',", sql)
        self.assertIn("('\"app\".\"users\"', 'boss_id', 'boss',", sql)

    def test_a_column_nobody_may_update_needs_no_rule_of_its_own(self) -> None:
        # lint asks for a rule on a column a relation reads when the plain `update` rule lets someone change the row.
        # `update : nobody` lets no one; and the rule lint suggests names `share` only where the type has it (a
        # suggestion that doesn't compile helps no one)
        def sql(perms: str, update: str) -> str:
            text = (
                errors_prelude()
                + f"  boss : user = boss_id\n{perms}rules app.users\n  select : edit\n  update : {update}\n"
            )
            return Compiler(parse_policy(text)).compile("x")

        row = "('\"app\".\"users\"', 'boss_id', 'user.boss', '[^']*', '%s')"
        self.assertRegex(
            sql("  can edit = boss\n", "edit"), re.escape(row % "nobody").replace(re.escape("[^']*"), "[^']*")
        )
        self.assertRegex(
            sql("  can edit = boss\n  can share = boss\n", "edit"),
            re.escape(row % "share").replace(re.escape("[^']*"), "[^']*"),
        )
        self.assertNotIn("'boss_id', 'user.boss',", sql("  can edit = boss\n", "nobody"))


class Denies(unittest.TestCase):
    def test_hidden_base(self) -> None:
        c = Compiler(parse_policy(read(POLICIES["alt"])))
        sql = c.compile("x")
        self.assertIn('CREATE VIEW authz_int."doc__view__base"', sql)
        self.assertRegex(sql, r"\('doc', 'view'\)[,;]")
        self.assertNotIn("'view__base'", sql)  # not in the catalog, authz.can/list/perms, who or explain
        self.assertNotIn("view__base", c.client("py", "x") + c.client("ts", "x"))
        # sharing into a deny takes away: it needs the share permission, not the deny itself
        self.assertIn("('doc', 'banned', 'user', 'share', ARRAY[]::text[]", sql)

    def test_conditions_go_on_every_item(self) -> None:
        text = read(POLICIES["docs"])
        line = "  can share = owner or org.admin or (parent.share and {inherit})"
        joined = text.replace(line, "  can share = (owner or org.admin or parent.share) and {inherit}")
        spread = text.replace(
            line, "  can share = (owner and {inherit}) or (org.admin and {inherit}) or (parent.share and {inherit})"
        )
        self.assertNotEqual(joined, text)
        strip = lambda t: [ln for ln in Compiler(parse_policy(t)).compile("x").splitlines() if "{inherit}" not in ln]
        self.assertEqual(strip(joined), strip(spread))


class CompositeKeys(unittest.TestCase):
    def test_brackets(self) -> None:
        pol = parse_policy(read(POLICIES["composite"]))
        folder = pol.types["folder"]
        self.assertEqual(folder.key, [("org_id", "bigint"), ("id", "bigint")])
        self.assertEqual(pol.types["team"].key, [("org_id", "bigint"), ("slug", "text")])
        parent = folder.relations["parent"].sources
        self.assertEqual((parent[0].type_col, parent[0].column), ("parent_type", ("org_id", "parent_id")))
        self.assertEqual((parent[1].obj_col, parent[1].subj_col), (("org_id", "child_id"), ("org_id", "parent_id")))

    def test_lookups_by_key_go_column_by_column(self) -> None:
        """A composite id compared as a whole can't use the table's index: lookups into app tables go
        column by column."""
        sql = compiled("composite")
        self.assertIn('(c."org_id", c."id") = (((up._a)::authz_gen."folder__key")."org_id"', sql)
        self.assertNotRegex(sql, r'ROW\(c\."org_id"[^)]*\)::text = up\._a')

    def test_user_key_is_one_column(self) -> None:
        text = read(POLICIES["composite"]).replace("type user = cx.users", "type user = cx.users (org_id, id)")
        with self.assertRaisesRegex(PolicyError, "the user type signs in, so it needs a key of one column"):
            Compiler(parse_policy(text))

    def test_client_formats_rows(self) -> None:
        c = Compiler(parse_policy(read(POLICIES["composite"])))
        ns = {}
        exec(c.client("py", "x"), ns)
        self.assertEqual(ns["_id"]((1, 'x,y "q"')), '("1","x,y \\"q\\"")')
        self.assertEqual(ns["_id"](7), "7")


class Principals(unittest.TestCase):
    def test_principal_types(self) -> None:
        pol = parse_policy(read(POLICIES["composite"]))
        self.assertTrue(pol.types["bot"].principal and pol.types["user"].principal)
        self.assertFalse(pol.types["folder"].principal)
        self.assertIn(("bot", "*"), pol.types["folder"].relations["viewer"].sources[0].subjects)

    def test_holding_compares_with_the_signed_in_principal(self) -> None:
        sql = compiled("composite")
        self.assertIn(
            "g.subject_type = 'bot' AND g.subject_relation = '' AND g.subject_id = (SELECT authz_int.\"bot__me\"()::text)",
            sql,
        )
        self.assertIn('coalesce("files"."uploaded_by" = (SELECT authz_int."bot__me"()), false)', sql)

    def test_lint_notes_principals_without_keys(self) -> None:
        text = read(POLICIES["composite"]).replace("  can manage_keys = owner\n", "  can see = owner\n")
        self.assertIn("nobody can make API keys for it", Compiler(parse_policy(text)).compile("x"))


class CommandMode(unittest.TestCase):
    """What the rowstile command runs inside its own transaction."""

    def test_no_transaction_control_but_base_tables(self) -> None:
        psql, cmd = compiled("docs"), compiled("docs", transaction=False)
        self.assertIn("\nBEGIN;\n", psql)
        for text in ("\nBEGIN;\n", "\nCOMMIT;\n"):
            self.assertNotIn(text, cmd)
        for sql in (psql, cmd):
            self.assertIn("CREATE TABLE IF NOT EXISTS authz.shares", sql)
            self.assertIn("CREATE TABLE IF NOT EXISTS authz.policy_versions", sql)
            self.assertNotIn("plpython3u", sql)
            self.assertNotIn("pg_extension", sql)

    def test_diff_parts(self) -> None:
        c = Compiler(parse_policy(read(POLICIES["docs"])))
        parts = c.diff_parts("x", ["3"])
        self.assertEqual(list(parts), ["setup", "before", "body", "after"])
        self.assertNotIn("ROLLBACK", "".join(parts.values()))
        self.assertNotIn("\nBEGIN;\n", parts["body"])
        self.assertIn("'3'", parts["before"])

    def test_files_argument(self) -> None:
        make = lambda c: c.compile("x", transaction=False)
        database.build('include "a.authz"', {"a.authz": read(POLICIES["docs"])}, make)
        database.build('include "a.authz"', '{"a.authz": ' + repr_json(read(POLICIES["docs"])) + "}", make)
        with self.assertRaisesRegex(PolicyError, "files must be a map"):
            database.build("app role app_user", '["a.authz"]', make)
        with self.assertRaisesRegex(PolicyError, "files must be a map"):
            database.build("app role app_user", '{"a.authz": 1}', make)

    def test_check_needs_no_database(self) -> None:
        self.assertIsNone(database.check(read(POLICIES["docs"])))
        self.assertRegex(
            database.check("app role app_user\ntype x = app.x") or "", r"^policy line 1: declare the user type"
        )

    def test_remove_drops_what_apply_makes(self) -> None:
        for text in (
            "DROP SCHEMA IF EXISTS authz_gen, authz_int CASCADE",
            "DROP POLICY",
            "GRANT SELECT ON %s TO %I",
            "shares\\_obj\\_%",
            "NOT IN ('ctx', 'link_hashes')",
        ):
            self.assertIn(text, database.REMOVE_SQL)


def repr_json(s: object) -> str:
    import json

    return json.dumps(s)


class Includes(unittest.TestCase):
    """Included files passed as a map (tests/policy_errors.py has the mistakes)."""

    def test_nested_include_is_relative(self) -> None:
        pol = parse_policy(
            'include "sub/a.authz"', files={"sub/a.authz": 'include "b.authz"', "sub/b.authz": read(POLICIES["docs"])}
        )
        self.assertIn("file", pol.types)

    def test_locations_name_the_included_file(self) -> None:
        with self.assertRaises(PolicyError) as e:
            parse_policy('include "x/y.authz"', files={"x/y.authz": "app role app_user\nnot valid"})
        self.assertTrue(str(e.exception).startswith("x/y.authz line 2:"), str(e.exception))

    def test_disk_includes_still_work_for_the_file_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "part.authz"), "w", encoding="utf-8") as fh:
                fh.write(read(POLICIES["docs"]))
            pol = parse_policy('include "part.authz"', os.path.join(d, "main.authz"))
            self.assertIn("folder", pol.types)

    def test_the_file_compiler_reads_nothing_above_the_policy(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "p"))
            with open(os.path.join(d, "secret.authz"), "w", encoding="utf-8") as fh:
                fh.write("SECRET=1\n")
            with self.assertRaises(PolicyError) as e:
                parse_policy('include "../secret.authz"', os.path.join(d, "p", "main.authz"))
            self.assertIn("an included file is in the policy's folder", str(e.exception))
            self.assertNotIn("SECRET", str(e.exception))

    def test_a_byte_order_mark_is_not_part_of_the_policy(self) -> None:
        pol = parse_policy("﻿" + read(POLICIES["docs"]), files={"sub/a.authz": "﻿app role app_user\n"})
        self.assertIn("folder", pol.types)
        self.assertIn(
            "folder",
            parse_policy(
                'include "sub/a.authz"\n' + read(POLICIES["docs"]),
                files={"sub/a.authz": "﻿caveat mfa = {authz.ctx('mfa') = 'yes'}\n"},
            ).types,
        )


class Command(unittest.TestCase):
    def test_reads_included_files(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "sub"))
            files = {
                "main.authz": 'include "sub/a.authz"  -- the rest\n',
                "sub/a.authz": 'include "b.authz"\n  include "not-an-include.authz"\n-- include "commented.authz"\n',
                "sub/b.authz": "app role app_user\n",
            }
            for name, body in files.items():
                with open(os.path.join(d, *name.split("/")), "w", encoding="utf-8") as fh:
                    fh.write(body)
            text, got = rowstile_cli.read_policy(os.path.join(d, "main.authz"))
            self.assertEqual(text, files["main.authz"])
            self.assertEqual(got, {"sub/a.authz": files["sub/a.authz"], "sub/b.authz": files["sub/b.authz"]})

    def test_missing_includes_are_left_to_the_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "main.authz"), "w", encoding="utf-8") as fh:
                fh.write('include "nope.authz"\n')
            self.assertEqual(rowstile_cli.read_policy(os.path.join(d, "main.authz"))[1], {})

    def test_reads_nothing_outside_the_policys_folder(self) -> None:
        # the review runs on a pull request's files: an include must not read the runner's
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "p", "sub"))
            with open(os.path.join(d, "outside.authz"), "w", encoding="utf-8") as fh:
                fh.write("SECRET=1\n")
            names = [
                "../outside.authz",
                "sub/../../outside.authz",
                os.path.join(d, "outside.authz").replace(os.sep, "/"),
                "sub\\..\\..\\outside.authz",
            ]
            try:
                os.symlink(os.path.join(d, "outside.authz"), os.path.join(d, "p", "sub", "link.authz"))
                names.append("sub/link.authz")
            except OSError:
                pass  # Windows without the right to make links
            with open(os.path.join(d, "p", "main.authz"), "w", encoding="utf-8") as fh:
                fh.write("".join(f'include "{n}"\n' for n in names))
            self.assertEqual(rowstile_cli.read_policy(os.path.join(d, "p", "main.authz"))[1], {})

    def test_a_link_to_another_drive_is_outside(self) -> None:
        # on Windows, commonpath raises for paths on two drives (a link or a junction to D:): outside, not a traceback
        other_drive = mock.patch.object(
            os.path, "commonpath", side_effect=ValueError("Paths don't have the same drive")
        )
        with tempfile.TemporaryDirectory() as d:
            for name, text in (("main.authz", 'include "x.authz"\n'), ("x.authz", "")):
                with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            with other_drive:
                self.assertEqual(rowstile_cli.read_policy(os.path.join(d, "main.authz"))[1], {})
                with self.assertRaises(SystemExit):
                    rowstile_cli.Config(os.path.join(d, "rowstile.toml"), {}).inside("x.authz", "policy")

    def test_a_path_on_another_drive_is_said_as_it_is(self) -> None:
        # on Windows, relpath raises for a path on another drive than the folder it is told from: the command names
        # the path as it was given, the review reads nothing of it from git, no .gitattributes names it
        import studio

        other_drive = mock.patch.object(
            os.path, "relpath", side_effect=ValueError("path is on mount 'R:', start on mount 'C:'")
        )
        path = os.path.join(os.sep, "elsewhere", "policy.authz")
        with tempfile.TemporaryDirectory() as d, other_drive:
            self.assertIsNone(rowstile_cli.at_base("HEAD", path))
            self.assertEqual(rowstile_cli.in_repository(path), "/elsewhere/policy.authz")
            self.assertEqual(rowstile_cli.relative(path), path)
            self.assertEqual(studio.shown(path), path)
            self.assertIsNone(rowstile_cli.Config(os.path.join(d, "rowstile.toml"), {}).below(path))

    def test_prints_utf8_whatever_the_systems_encoding(self) -> None:
        # on Windows, Python writes into a pipe or a file in the system's code page: an arrow or a name in another
        # script stopped the command there (UnicodeEncodeError), and a graph written to a file was not UTF-8
        policy = (
            "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n"
            "  can view = owner or {note = '閲覧 →'}\ninvariants\n  never doc: view and not owner\n"
        )
        cli = os.path.join(ROOT, "cli", "rowstile_cli.py")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUTF8"} | {"PYTHONIOENCODING": "cp1252"}
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "policy.authz"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(policy)
            for command, shown in (("prove", "doc 1: note = '閲覧 →'"), ("graph", "doc · app.docs")):
                p = subprocess.run([sys.executable, cli, command, "policy.authz"], cwd=d, env=env, capture_output=True)
                self.assertNotIn(b"Traceback", p.stderr, command)
                self.assertIn(shown, p.stdout.decode("utf-8"), command)
            p = subprocess.run([sys.executable, cli, "check", "閲.authz"], cwd=d, env=env, capture_output=True)
            self.assertIn("閲.authz: ", p.stderr.decode("utf-8"))

    def test_a_row_that_isnt_json_is_shown_as_it_arrived(self) -> None:
        # Windows PowerShell 5 and cmd take the double quotes out of '{"column": 1}': JSON's message alone
        # ("Expecting property name enclosed in double quotes") doesn't say what happened
        import contextlib
        import io

        def refused(row: str) -> str:
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as stop:
                rowstile_cli.check_row(row)
            self.assertEqual(stop.exception.code, 2)
            return err.getvalue()

        rowstile_cli.check_row('{"project_id": 1, "author_id": 3}')
        said = refused("{project_id: 1, author_id: 3}")
        self.assertIn("--row: not JSON: {project_id: 1, author_id: 3}\n", said)
        self.assertIn("The shell took the double quotes: in Windows PowerShell write '{\\\"column\\\": 1}'", said)
        self.assertIn('in cmd "{\\"column\\": 1}"', said)
        self.assertNotIn("The shell", refused('{"project_id": }'))  # a mistake of one's own
        self.assertIn("JSON object", refused("[1]"))

    def test_only_what_is_below_is_marked_generated(self) -> None:
        # .gitattributes names files from its own folder: a migrations folder or a lock file outside it gets no line
        import migrations

        with tempfile.TemporaryDirectory() as d:
            cfg = rowstile_cli.Config(os.path.join(d, "p", "rowstile.toml"), {})
            self.assertEqual(cfg.below(os.path.join(d, "p", "db", "policy.lock")), "db/policy.lock")
            self.assertIsNone(cfg.below(os.path.join(d, "migrations")))
            self.assertIsNone(cfg.below(d))
        self.assertEqual(
            migrations.generated_patterns("prisma", "prisma/migrations", "db/policy.lock"),
            ["db/policy.lock linguist-generated=true", "prisma/migrations/*_authz_*/** linguist-generated=true"],
        )
        self.assertEqual(
            migrations.generated_patterns("sql", None, "db/policy.lock"), ["db/policy.lock linguist-generated=true"]
        )
        self.assertEqual(migrations.generated_patterns("sql", None, None), [])

    def test_review_names_files_from_this_folder_not_from_the_top_folders_path(self) -> None:
        # git names the top folder by its resolved path; through a subst drive or a junction (Windows) this
        # process reaches the same folder by another one, even on another drive, so the two are never compared
        import shutil

        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        real_git = rowstile_cli.git

        def git(*args: str) -> str | None:
            return "Z:/elsewhere\n" if args == ("rev-parse", "--show-toplevel") else real_git(*args)

        before = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "p", "tests"))
            # a name with an accent: git lists it quoted ("tests/acc\303\250s.authz") unless asked not to
            for name, text in (("a.authz", b"test one\n"), ("accès.authz", b"test two\n")):
                with open(os.path.join(d, "p", "tests", name), "wb") as fh:
                    fh.write(text)
            with open(os.path.join(d, "p", "latin1.authz"), "wb") as fh:
                fh.write("-- propriétaire\n".encode("latin-1"))
            for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
                subprocess.run(
                    ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                    cwd=d,
                    check=True,
                    capture_output=True,
                )
            os.chdir(os.path.join(d, "p"))  # the project in a folder of the repository
            try:
                cfg = rowstile_cli.Config(os.path.join(os.getcwd(), "rowstile.toml"), {"tests": ["tests/*.authz"]})
                with mock.patch.object(rowstile_cli, "git", git):
                    self.assertEqual(
                        rowstile_cli.base_tests(cfg, "HEAD"),
                        {"tests/a.authz": "test one\n", "tests/accès.authz": "test two\n"},
                    )
                    self.assertEqual(rowstile_cli.in_repository(os.path.join("tests", "a.authz")), "p/tests/a.authz")
                self.assertEqual(list(rowstile_cli.read_tests(cfg.tests())), ["tests/a.authz", "tests/accès.authz"])
                # a file at the base that isn't UTF-8 is read, the byte replaced: no traceback from the review
                self.assertEqual(rowstile_cli.at_base("HEAD", "latin1.authz"), "-- propri�taire\n")
            finally:
                os.chdir(before)

    def test_typescript_sdk_gets_only_the_names(self) -> None:
        # an app on the TypeScript SDK (a @rowstile/* dependency) gets the policy's names, registered with it
        with tempfile.TemporaryDirectory() as d:
            toml = os.path.join(d, "rowstile.toml")
            cfg = rowstile_cli.Config(toml, {"clients": {"ts": "src/authz.gen.ts", "py": "authz.py"}})
            self.assertEqual(sorted(cfg.clients), ["py", "ts"])
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as fh:
                fh.write('{"dependencies": {"next": "16", "@rowstile/prisma": "0.1.0"}}')
            self.assertEqual(sorted(cfg.clients), ["py", "ts-sdk"])
        names = Compiler(parse_policy(read(POLICIES["docs"]))).compile("x") and database.client(
            "ts-sdk", read(POLICIES["docs"])
        )
        self.assertIn('declare module "@rowstile/client"', names)
        self.assertIn("permissions: typeof permissions;", names)
        self.assertNotIn("class Refused", names)  # the SDK's own errors, or instanceof would fail

    def test_stack(self) -> None:
        import stack

        def at(files: dict[str, str]) -> str:
            d = tempfile.mkdtemp()
            for name, body in files.items():
                os.makedirs(os.path.dirname(os.path.join(d, name)) or d, exist_ok=True)
                with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                    fh.write(body)
            return d

        s = stack.detect(
            at(
                {
                    "package.json": '{"dependencies": {"drizzle-orm": "1", "pg": "8"}}',
                    "drizzle.config.ts": 'export default { out: "./db/drizzle" }',
                    "src/db.ts": "drizzle(pool)",
                }
            )
        )
        self.assertEqual(
            (s.tool, s.migrations_dir, s.clients, s.npm, s.setup_file),
            ("drizzle", "db/drizzle", {"ts": "src/authz.gen.ts"}, ["@rowstile/drizzle"], "src/db.ts"),
        )
        s = stack.detect(
            at(
                {
                    "requirements.txt": "fastapi>=0.110\nsqlmodel\n",
                    "alembic.ini": "script_location = %(here)s/alembic\n",
                    "app/main.py": "app = FastAPI()\n",
                }
            )
        )
        self.assertEqual(
            (s.found, s.tool, s.migrations_dir, s.pip, s.setup_file),
            (
                ["FastAPI", "SQLModel", "Alembic"],
                "alembic",
                "alembic/versions",
                "rowstile[fastapi,sqlalchemy]",
                "app/main.py",
            ),
        )
        self.assertFalse(s.pip_there)
        # the stack pages install FastAPI's part through rowstile's own extras: the stack is found there too, and
        # rowstile, a dependency already, isn't asked for again
        s = stack.detect(
            at(
                {
                    "pyproject.toml": '[project]\ndependencies = [\n    "rowstile[asyncpg,fastapi,sqlalchemy]>=0.1.0a4",\n]\n',
                    "alembic.ini": "script_location = migrations\n",
                }
            )
        )
        self.assertEqual((s.found, s.pip_there), (["FastAPI", "SQLAlchemy", "Alembic"], True))
        self.assertEqual(s.setup[0], "from rowstile.fastapi import Rowstile")
        # a release's name is bare; an alpha, a candidate or main's build asks for at least itself, which lets pip
        # take a pre-release (a bare name got the 0.0.0 placeholder while only an alpha was published)
        self.assertEqual(stack.pip_requirement("rowstile[fastapi]", "0.2.0"), "rowstile[fastapi]")
        self.assertEqual(stack.pip_requirement("rowstile[fastapi]", "0.1.0-alpha.1"), "rowstile[fastapi]>=0.1.0a1")
        self.assertEqual(stack.pip_requirement("rowstile", "0.2.0-rc.12"), "rowstile>=0.2.0rc12")
        self.assertEqual(stack.pip_requirement("rowstile", "0.2.0-dev"), "rowstile>=0.2.0.dev0")
        s = stack.detect(at({"migrations/0001.sql": "CREATE TABLE t ();"}))
        self.assertEqual((s.tool, s.migrations_dir, s.npm, s.pip), ("sql", "migrations", [], ""))
        d = at({"package.json": '{\n\t"dependencies": {\n\t\t"next": "16"\n\t}\n}\n'})
        self.assertEqual(stack.add_npm(d, ["@rowstile/next"], "1.2.3"), ["@rowstile/next", "rowstile"])
        with open(os.path.join(d, "package.json"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn('\t\t"@rowstile/next": "^1.2.3"', text)
        self.assertIn('"devDependencies"', text)
        self.assertEqual(stack.add_npm(d, ["@rowstile/next"], "1.2.3"), [])

    def test_no_database_named_is_said(self) -> None:
        # with no --db, no `database` in rowstile.toml and no variable, the defaults are tried (a local socket): when
        # they fail the message says nothing named a database and how to name one, not only a host nobody gave
        # (on Windows: "host=/var/run/postgresql is a Unix socket"). A database that was named fails as itself
        e = OSError("host=/var/run/postgresql is a Unix socket, which Windows doesn't have: use host=localhost")
        named = ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE")
        with mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k not in named}, clear=True):
            said = rowstile_cli.cant_connect(e, None)
            self.assertTrue(
                said.startswith("can't connect: no database was named, and the default failed (host="), said
            )
            self.assertIn("--db DSN, `database` in rowstile.toml, or DATABASE_URL", said)
            self.assertEqual(rowstile_cli.cant_connect(e, "host=db"), f"can't connect: {e}")
        with mock.patch.dict(os.environ, {"PGHOST": "db"}):
            self.assertEqual(rowstile_cli.cant_connect(e, None), f"can't connect: {e}")

    def test_env_files_are_read_for_the_database_only(self) -> None:
        # a .env file as apps write them: comments, export, quotes, ${NAME} from the environment or the lines above
        with mock.patch.dict(os.environ, {"FROM_ENV": "e"}, clear=True):  # (a PGHOST of the suite's would come first)
            self.assertEqual(
                rowstile_cli.parse_env(
                    "# the app's own\n"
                    "DATABASE_URL=postgresql://o:p@localhost:5432/dev   # the owner\n"
                    "export PGHOST = db\n"
                    'QUOTED="a \\"b\\"\\n#c"  # after\n'
                    "SINGLE='${FROM_ENV} as written' and more\n"
                    'URL="postgresql://${PGHOST}:${FROM_ENV}@${LATER}/d"\n'
                    "LATER=l\n"
                    "EMPTY=\n"
                    "not a line\n=x\n1BAD=x\nA-B=x\n"
                ),
                {
                    "DATABASE_URL": "postgresql://o:p@localhost:5432/dev",
                    "PGHOST": "db",
                    "QUOTED": 'a "b"\n#c',
                    "SINGLE": "${FROM_ENV} as written",
                    "URL": "postgresql://db:e@/d",
                    "LATER": "l",
                    "EMPTY": "",
                },
            )
        with tempfile.TemporaryDirectory() as d:

            def write(name: str, text: str) -> None:
                with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                    fh.write(text)

            write(".env", "DATABASE_URL=from-env-file\nPGHOST=h1\nOWNER=o1\nGIT_SSH_COMMAND=evil\nPATH=/evil\n")
            write(".env.local", "\ufeffPGHOST=h2\nOWNER=o2\nPGPORT=1\n")  # with a byte order mark
            # the environment first, then .env.local, then .env; and of the files' names, only those that say
            # where the database is reach the environment: a pull request's .env is read by the review in CI
            with mock.patch.dict(os.environ, {"PGPORT": "7", "PATH": "/bin"}, clear=True):
                e = rowstile_cli.EnvFiles()
                e.load(d)
                self.assertEqual(
                    dict(os.environ), {"PGPORT": "7", "PATH": "/bin", "DATABASE_URL": "from-env-file", "PGHOST": "h2"}
                )
                self.assertEqual((e.get("OWNER"), e.get("PGPORT"), e.get("NOWHERE")), ("o2", "7", None))
                self.assertEqual(e.files(["DATABASE_URL"]), ".env")
                self.assertEqual(e.files(["PGPORT"]), "")  # the environment's own
                self.assertEqual(e.files(["DATABASE_URL", "PGHOST", "OWNER"]), ".env and .env.local")
                self.assertEqual(e.skipped, [])
                # which files named the database a command uses: none for --db or a literal in rowstile.toml
                with mock.patch.object(rowstile_cli, "ENV", e):
                    config = lambda data: rowstile_cli.Config(os.path.join(d, "rowstile.toml"), data)
                    self.assertEqual(config({}).database_from(None), ".env")
                    self.assertEqual(config({}).database_from("dbname=x"), "")
                    self.assertEqual(config({"database": "env:OWNER"}).database_from(None), ".env.local")
                    self.assertEqual(config({"database": "env:OWNER"}).database, "o2")
                    self.assertEqual(config({"database": "dbname=x"}).database_from(None), "")
                    e.where = ".env"
                    said = rowstile_cli.cant_connect(OSError("refused"), "from-env-file")
                    self.assertEqual(said, "can't connect: refused\n(the database is the one .env names)")
            # a .env that is a link out of the folder isn't read (as the policy isn't), and a failure says so
            outside = os.path.join(d, "outside")
            os.mkdir(os.path.join(d, "in"))
            write("outside", "DATABASE_URL=theirs\n")
            try:
                os.symlink(outside, os.path.join(d, "in", ".env"))
            except OSError:
                return  # Windows without the right to make links
            with mock.patch.dict(os.environ, {}, clear=True):
                e = rowstile_cli.EnvFiles()
                e.load(os.path.join(d, "in"))
                self.assertNotIn("DATABASE_URL", os.environ)
                self.assertEqual(e.skipped, [".env is a link out of its folder: it isn't read"])
                with mock.patch.object(rowstile_cli, "ENV", e):
                    self.assertTrue(rowstile_cli.cant_connect(OSError("x"), None).endswith(e.skipped[0]))

    def test_without_git_and_help_after_a_command(self) -> None:
        # a machine without git: the review says so, not a traceback; `rowstile review --help` is the usage
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
                fh.write('policy = "policy.authz"\n')
            with open(os.path.join(d, "policy.authz"), "w", encoding="utf-8") as fh:
                fh.write(read(POLICIES["docs"]))
            env = dict(os.environ, PATH=d)
            run = lambda *a: subprocess.run(
                [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), *a],
                cwd=d,
                env=env,
                capture_output=True,
                text=True,
            )
            p = run("review", "--base", "main")
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertIn("git is not installed", p.stderr)
            self.assertNotIn("Traceback", p.stderr)
            # a command's own lines of the usage, where the database comes from, and nothing of the others
            p = run("review", "--help")
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(p.stdout.startswith("rowstile review  [--base REF]"), p.stdout)
            self.assertIn("\nThe database is --db DSN", p.stdout)
            self.assertIn("\nrowstile --help: every command, and rowstile.toml\n", p.stdout)
            self.assertNotIn("rowstile fmt", p.stdout)
            self.assertNotIn("policy   =", p.stdout)

    def test_every_command_has_help_of_its_own(self) -> None:
        for cmd in rowstile_cli.ARGUMENTS:
            text = rowstile_cli.command_help(cmd)
            self.assertTrue(text.startswith(f"rowstile {cmd}"), cmd)
            self.assertEqual(len(re.findall(r"^rowstile \S", text, re.M)), 2, text)  # its own, and the last line
        # init says which schema it reads when none is named: the question a first run asked of --help
        self.assertIn("those in public", rowstile_cli.command_help("init"))

    def test_array_literal(self) -> None:
        self.assertEqual(database.text_array(["1", 'a"b', "c\\d"]), '{"1","a\\"b","c\\\\d"}')


class Statements(unittest.TestCase):
    """Reading the compiled SQL back as statements, the way psql does (the migrations work on them)."""

    def test_quotes_comments_and_atomic_bodies(self) -> None:
        from authzlib.statements import split

        sql = (
            "-- a comment; not a statement\nSELECT 'a;b', E'it\\'s; fine', \"x;y\";\n"
            "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $f$ BEGIN RETURN 1; END $f$;\n"
            "CREATE FUNCTION g(p int) RETURNS int LANGUAGE sql BEGIN ATOMIC\n"
            "  SELECT CASE WHEN p > 0 THEN 1 ELSE 2 END; SELECT 3;\nEND;\n/* a; block */ DO $$ BEGIN NULL; END $$"
        )
        got = split(sql)
        self.assertEqual([c for c, _ in got], ["-- a comment; not a statement", "", "", "/* a; block */"])
        self.assertEqual(len(got), 4)
        self.assertTrue(got[2][1].endswith("SELECT 3;\nEND"))

    def test_what_each_makes(self) -> None:
        from authzlib.statements import made

        self.assertEqual(
            made(
                "CREATE FUNCTION authz.list(p_type text, p_after text DEFAULT NULL, p_limit int DEFAULT NULL) "
                "RETURNS SETOF text AS $$ $$"
            ),
            ("function", "authz.list(p_type text, p_after text, p_limit int)"),
        )
        self.assertEqual(
            made('CREATE TRIGGER "t" AFTER INSERT ON "app"."x" FOR EACH ROW EXECUTE FUNCTION f()'),
            ("trigger", '"t" ON "app"."x"'),
        )
        self.assertEqual(made("DO $mv$ BEGIN END $mv$", '-- @object view "mt"."v"'), ("view", '"mt"."v"'))
        self.assertIsNone(made("INSERT INTO authz_int.x VALUES (1)"))


def replaced(text: str, old: str, new: str) -> str:
    """text with old replaced: a test that edits a policy fails when the text it edits isn't there (rowstile fmt
    realigning a file would otherwise leave the policy as it was, and the test checking nothing)."""
    assert old in text, f"not in the policy: {old!r}"
    return text.replace(old, new)


class Migrations(unittest.TestCase):
    """What rowstile migrate writes, without a database (tests/migrate_test.py applies them)."""

    def setUp(self) -> None:
        from authzlib import migrate

        self.migrate = migrate
        self.text = read(POLICIES["docs"])

    def test_which_version_is_older(self) -> None:
        older = database.older_than
        for mine, theirs in (
            ("0.1.0-rc.1", "0.1.0-rc.2"),
            ("0.1.0-rc.2", "0.1.0"),
            ("0.9.0", "0.10.0"),
            ("0.1.0-dev+abc", "0.2.0-dev+def"),
            ("0.1.0", "1.0.0-rc.1"),
            # an alpha comes before its version's candidates, whatever their numbers
            ("0.1.0-alpha.1", "0.1.0-alpha.2"),
            ("0.1.0-alpha.9", "0.1.0-rc.1"),
            ("0.1.0-alpha.2", "0.1.0"),
            ("0.1.0", "0.2.0-alpha.1"),
            ("0.1.0-alpha.2", "0.1.0-alpha.10"),
        ):
            self.assertTrue(older(mine, theirs), (mine, theirs))
            self.assertFalse(older(theirs, mine), (theirs, mine))
        # a development build can't be placed among its own version's candidates; nothing recorded, or not a version
        for mine, theirs in (
            ("0.1.0-dev+abc", "0.1.0-rc.2"),
            ("0.1.0-rc.1", "0.1.0-dev+abc"),
            ("0.1.0-dev+a", "0.1.0-dev+b"),
            ("0.1.0-dev+abc", "0.1.0-alpha.1"),
            ("0.1.0-alpha.1", "0.1.0-dev+abc"),
            ("0.1.0-beta.1", "0.1.0"),
            ("0.1.0", "0.1.0"),
            ("0.1.0", None),
            ("0.1.0", "what"),
        ):
            self.assertFalse(older(mine, theirs), (mine, theirs))
        lock = self.migrate.lock_of(database.migratable(self.text, {})[1]).replace(
            f"# rowstile {authzlib.__version__}:", "# rowstile 99.0.0:", 1
        )
        with self.assertRaisesRegex(database.Error, r"the lock file was last written by rowstile 99\.0\.0.*\[AZ616\]"):
            database.migrations(self.text, {}, lock)
        self.assertTrue(all(m.empty for m in database.migrations(self.text, {}, lock, downgrade=True)))

    def lock(self, text: str) -> str:
        return self.migrate.lock_of(database.migratable(text, {})[1])

    def test_the_same_policy_gives_the_same_bytes(self) -> None:
        a, b = database.migration(self.text, {}, ""), database.migration(self.text, {}, "")
        self.assertEqual((a.sql, a.lock), (b.sql, b.lock))
        self.assertEqual(self.migrate.parse_lock(a.lock).text, a.lock)
        self.assertTrue(database.migration(self.text, {}, a.lock).empty)

    def test_the_first_is_the_whole_policy(self) -> None:
        m = database.migration(self.text, {}, "")
        self.assertIn(compiled("docs", transaction=False).split("\n", 1)[1], m.sql)
        self.assertNotIn("$authz_guard$", m.sql)

    def test_a_new_permission_is_a_small_migration(self) -> None:
        new = replaced(
            self.text,
            "  can share = owner or folder.share\n",
            "  can share = owner or folder.share\n  can comment = folder.view\n",
        )
        m = database.migration(new, {}, self.lock(self.text))
        self.assertIn('CREATE VIEW authz_gen."file__comment"', m.sql)
        self.assertIn("CREATE OR REPLACE FUNCTION authz.can(p_type text, p_id text, p_perm text)", m.sql)
        self.assertNotIn('CREATE TABLE authz_int."folder__parent__tree"', m.sql)
        self.assertNotIn("CREATE POLICY", m.sql)
        self.assertIn("$authz_guard$", m.sql)
        self.assertEqual(m.summary, ["+ type file: can comment = folder.view"])
        self.assertIn("> type file: can comment = folder.view", m.lock)

    def test_lines_that_only_move_need_no_migration(self) -> None:
        moved = replaced(self.text, "app role app_user\n", "app role app_user\n\n-- a note\n")
        self.assertTrue(database.migration(moved, {}, self.lock(self.text)).empty)
        sql, comp, _ = database.migratable(moved, {})
        pushed = self.migrate.migration(sql, comp, self.migrate.parse_lock(self.lock(self.text)), lines=True)
        self.assertIn("DELETE FROM authz_gen.policy_lines", pushed.sql)

    def test_a_new_version_alone_needs_no_migration(self) -> None:
        # upgrading rowstile fails no one's `migrate --check` unless the new version makes something different
        lock = self.lock(self.text)
        older = re.sub(r"^# rowstile \S+:", "# rowstile 0.0.1:", lock, count=1, flags=re.M)
        self.assertNotEqual(older, lock)
        self.assertTrue(database.migration(self.text, {}, older).empty)

    def test_a_changed_step_every_migration_runs_is_a_migration(self) -> None:
        lock = self.lock(self.text)
        self.assertRegex(lock, r"(?m)^always \| [0-9a-f]{12}$")
        m = database.migration(self.text, {}, re.sub(r"(?m)^always \| \w+$", "always | 000000000000", lock))
        self.assertIn("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;", m.sql)
        self.assertEqual(m.summary, ["the same policy; what rowstile makes of it changed"])
        self.assertIn(f"always | {self.migrate.always_hash(database.migratable(self.text, {})[1])}", m.lock)

    def test_a_lock_without_those_steps_goes_by_its_version(self) -> None:
        # a lock written before they were recorded: the version that wrote it makes the same; another may not
        lock = re.sub(r"(?m)^always \| \w+\n", "", self.lock(self.text))
        self.assertIsNone(self.migrate.parse_lock(lock).always)
        self.assertTrue(database.migration(self.text, {}, lock).empty)
        older = re.sub(r"^# rowstile \S+:", "# rowstile 0.0.1:", lock, count=1, flags=re.M)
        m = database.migration(self.text, {}, older)
        self.assertRegex(m.lock, r"(?m)^always \| [0-9a-f]{12}$")
        self.assertEqual(
            m.summary, [f"rowstile 0.0.1 -> {authzlib.__version__}: what the new version makes differently"]
        )

    def test_a_lock_rowfence_wrote_goes_by_its_version(self) -> None:
        # rowstile was called rowfence (and authzc): their lock files' headers still give the version
        lock = self.lock(self.text)
        for old in ("rowfence", "authzc"):
            renamed = re.sub(r"^# rowstile ", f"# {old} ", lock, count=1, flags=re.M)
            self.assertEqual(self.migrate.parse_lock(renamed).version, authzlib.__version__, old)
        newer = re.sub(r"^# rowstile \S+:", "# rowfence 99.0.0:", lock, count=1, flags=re.M)
        with self.assertRaises(database.Error):  # still refused when a newer one wrote it
            database.migrations(self.text, {}, newer)

    def test_a_tree_that_changes_is_built_beside_first(self) -> None:
        new = replaced(
            self.text,
            "can view  = edit or viewer or (parent.view and {inherit})",
            "can view  = edit or viewer or parent.view",
        )
        ms = database.migrations(new, {}, self.lock(self.text))
        self.assertEqual(len(ms), 2)
        self.assertIn('INSERT INTO authz_int."folder__linked_into_parent__tree__next"', ms[0].sql)
        self.assertNotIn("CREATE TRIGGER", ms[0].sql)
        self.assertIn("$authz_catch_up$", ms[1].sql)
        self.assertEqual(len(database.migrations(new, {}, self.lock(self.text), two_phase=False)), 1)

    def test_file_names(self) -> None:
        import migrations

        self.assertEqual(migrations.slug("File comment!"), "authz_file_comment")
        with tempfile.TemporaryDirectory() as d:
            self.assertRegex(migrations.sql_file_name(d, "authz_x", "20260101000000"), r"^20260101000000_authz_x\.sql$")
            open(os.path.join(d, "0004_schema.sql"), "w", encoding="utf-8").close()
            self.assertEqual(migrations.sql_file_name(d, "authz_x", "20260101000000"), "0005_authz_x.sql")

    def test_the_alembic_revision_says_asyncpg_in_a_line(self) -> None:
        # a policy's revision is one script, and asyncpg takes one statement at a time: its own error carries the
        # whole script (four thousand lines for a small policy). The revision says it first, with the way out; with a
        # sync driver it sends the script as before
        import migrations

        class Bind:
            def __init__(self, driver: str) -> None:
                self.dialect = types.SimpleNamespace(driver=driver)
                self.sent: list[str] = []

            def exec_driver_sql(self, sql: str, execution_options: dict[str, bool]) -> None:
                self.sent.append(sql)

        with tempfile.TemporaryDirectory() as d:
            py, _ = migrations.alembic(d, "authz_x", "SELECT 1;\n", 0)
            with open(py, encoding="utf-8") as fh:
                code = compile(fh.read(), py, "exec")
            for driver in ("asyncpg", "psycopg"):
                bind = Bind(driver)
                fake = types.ModuleType("alembic")
                fake.__dict__["op"] = types.SimpleNamespace(get_bind=lambda bind=bind: bind)
                scope: dict[str, object] = {"__file__": py}
                with mock.patch.dict(sys.modules, {"alembic": fake}):
                    exec(code, scope)
                    upgrade = cast(Callable[[], None], scope["upgrade"])
                    if driver == "asyncpg":
                        with self.assertRaisesRegex(RuntimeError, r"asyncpg.*one script.*postgresql\+psycopg://"):
                            upgrade()
                        self.assertEqual(bind.sent, [])
                    else:
                        upgrade()
                        self.assertEqual(bind.sent, ["SELECT 1;\n"])


class Review(unittest.TestCase):
    """rowstile review without a database; tests/review.sh runs it with git and a database."""

    def setUp(self) -> None:
        from authzlib import review

        self.review = review
        self.text = read(POLICIES["docs"])

    def run_review(
        self,
        new: str,
        tests_before: dict[str, str] | None = None,
        tests_after: dict[str, str] | None = None,
        lock: bool = True,
    ) -> Review:
        from authzlib import migrate

        base_lock = migrate.lock_of(database.migratable(self.text, {})[1]) if lock else None
        return self.review.review(
            (self.text, {}, tests_before or {}), (new, {}, tests_after or {}), base_lock, None, None, worlds=120
        )

    def test_comments_only(self) -> None:
        r = self.run_review(replaced(self.text, "app role app_user\n", "app role app_user   -- the app's role\n\n"))
        self.assertEqual(r["meaning"]["equivalent"], "text")
        self.assertEqual(r["deploy"]["migrations"], [])
        self.assertIn("**Meaning**: unchanged", self.review.markdown(r))

    def test_a_refactor_is_checked_in_small_worlds(self) -> None:
        r = self.run_review(
            replaced(
                self.text,
                "can edit  = share or editor or (parent.edit and {inherit})",
                "can edit  = editor or share or ({inherit} and parent.edit)",
            )
        )
        self.assertEqual(r["meaning"]["equivalent"], "120 small worlds")
        md = self.review.markdown(r)
        self.assertIn("unchanged: every permission and rule grants the same", md)
        self.assertNotIn("<details>", md)

    def test_what_changes_through_it(self) -> None:
        r = self.run_review(
            replaced(
                self.text,
                "can view  = edit or viewer or (parent.view and {inherit})",
                "can view  = edit or viewer or parent.view",
            )
        )
        m = r["meaning"]
        self.assertEqual([c["what"] for c in m["changed"]], ["folder.view"])
        self.assertIn({"what": "file.view", "via": ["folder.view"], "line": "line 63"}, m["through"])
        self.assertIn("a permission widened", [f["why"] for f in r["risk"]])
        self.assertEqual(len(r["deploy"]["migrations"]), 2)  # built beside, then swapped in
        self.assertTrue(r["deploy"]["migrations"][0]["builds_beside"])

    def test_a_test_file_that_doesnt_parse_is_said(self) -> None:
        # its checks are missing from the comparison, which read as "no change to what the tests claim"
        good = (
            'test "owners"\n  given ann = {INSERT INTO app.users (id) VALUES (1) RETURNING id}\n'
            "  user $ann can view folder 1\n"
        )
        after = {"tests/a.authz": good.replace("can view", "cannot view"), "tests/b.authz": 'test "broken"\n  given\n'}
        r = self.run_review(self.text, {"tests/a.authz": good}, after)
        t = r["tests"]
        # a check is on its file's line, not on a line of the policy
        self.assertEqual([(x["test"], x["line"]) for x in t["flipped"]], [("owners", "tests/a.authz line 3")])
        self.assertEqual([x["file"] for x in t["unread"]], ["tests/b.authz"])
        self.assertRegex(t["unread"][0]["error"], r"^tests/b\.authz line 2: .* \[AZ106\]$")
        self.assertIn("1 test file can't be read, so its checks aren't compared.", self.review.text(r))
        self.assertIn("  test     can't read: tests/b.authz line 2: ", self.review.text(r))
        self.assertIn("- can't read: tests/b.authz line 2: ", self.review.markdown(r))
        same = self.run_review(self.text, {"tests/a.authz": good}, {"tests/a.authz": good})
        self.assertEqual((same["tests"]["unread"], same["tests"]["flipped"], same["tests"]["count"]), ([], [], 21))

    def test_risk_flags(self) -> None:
        widened = replaced(
            self.text, "  viewer : user, team#member shared\n", "  viewer : user, team#member, anyone shared\n"
        )
        flags = {f["why"] for f in self.run_review(widened)["risk"]}
        self.assertIn("access widened", flags)
        # a relation people can newly share is flagged once, however many kinds of subjects it may be shared with
        shared = replaced(
            self.text,
            "  viewer : user, team#member shared\n",
            "  viewer : user, team#member shared\n  reader : user, team#member, org#member shared\n",
        )
        shared = replaced(shared, "  can view  = edit or viewer\n", "  can view  = edit or viewer or reader\n")
        self.assertEqual(
            [f["flag"] for f in self.run_review(shared)["risk"] if f["why"] == "a relation newly shared"],
            ["`file.reader` is newly shared (by whoever holds `share`)"],
        )
        no_deny = replaced(self.text, "           or (folder.view and not {confidential})", "           or folder.view")
        flags = {f["why"] for f in self.run_review(no_deny)["risk"]}
        self.assertIn("a deny removed", flags)
        looser = replaced(
            self.text, "  delete                            : edit", "  delete                            : view"
        )
        risk = self.run_review(looser)["risk"]
        self.assertIn("a write rule loosened", {f["why"] for f in risk})
        self.assertTrue(all(f["line"] for f in risk))
        notes = self.review.annotations(self.run_review(looser), "example/docs.authz")
        self.assertRegex(notes, r"^::warning file=example/docs.authz,line=\d+,title=rowstile review::")

    def test_a_condition_it_cannot_read_reworded(self) -> None:
        """A subquery's `id` rewritten as `this.id` (two real changes, d62fa2e and e853285) was reported as a widening
        with a made-up example: the small worlds hold such a condition as rows of their own, per text."""
        reworded = replaced(self.text, "and b.user_id = this.id)}", "and b.user_id = this.id and true)}")
        self.assertNotEqual(reworded, self.text)
        r = self.run_review(reworded)
        self.assertEqual(r["meaning"].get("unreadable"), ["user.impersonate"])
        self.assertNotIn("counterexample", r["meaning"])
        whys = [f["why"] for f in r["risk"]]
        self.assertEqual(whys, ["a condition it can't read changed"])
        self.assertIn("read both, it can't tell more from less", r["risk"][0]["flag"])
        self.assertIn("can't tell: user.impersonate", self.review.text(r))
        # a condition it reads still says what widened
        r = self.run_review(
            replaced(self.text, "can share = owner or org.admin", "can share = owner or org.admin or {true}")
        )
        self.assertIn("a permission widened", [f["why"] for f in r["risk"]])
        self.assertNotIn("unreadable", r["meaning"])

    def test_no_lock_file_is_no_migration(self) -> None:
        """A project that applies its policy keeps no lock file: Deploy said every change was the whole policy, a
        migration that locks every table and rebuilds every tree."""
        r = self.run_review(
            replaced(self.text, "app role app_user\n", "app role app_user   -- the app's role\n"), lock=False
        )
        self.assertEqual(r["deploy"]["migrations"], [])
        self.assertIn("no lock file, so no migrations: `rowstile apply`", self.review.summary(r)["Deploy"])

    def test_tests_that_flip(self) -> None:
        before = {"t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 cannot view file 12\n'}
        after = {"t.authz": 'test "carol"\n  user 3 cannot view file 11\n'}
        t = self.run_review(self.text, before, after)["tests"]
        self.assertEqual(
            [(x["before"], x["after"]) for x in t["flipped"]],
            [("user 3 can view file 11", "user 3 cannot view file 11")],
        )
        self.assertEqual([x["check"] for x in t["removed"]], ["user 3 cannot view file 12"])
        # the summary's line counts them, one or several
        both = {"t.authz": 'test "carol"\n  user 3 cannot view file 11\n  user 3 can view file 12\n'}
        one = self.review.summary(self.run_review(self.text, before, after))["Tests"]
        two = self.review.summary(self.run_review(self.text, before, both))["Tests"]
        self.assertIn("1 check changed what it expects", one)
        self.assertIn("2 checks changed what they expect", two)

    def test_a_renamed_test_is_not_its_checks_removed(self) -> None:
        # a test under a new name, with one check that changed and one more: said as a new name and the check
        # that changed. "2 checks removed" would read as tests taken out to let the change pass
        before = {"t.authz": 'test "carol, neither shares"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'}
        after = {
            "t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 can share file 11\n  user 3 can edit file 11\n'
        }
        r = self.run_review(self.text, before, after)
        t = r["tests"]
        self.assertEqual(t["renamed"], [{"before": "carol, neither shares", "after": "carol"}])
        self.assertEqual(t["removed"], [])
        self.assertEqual(
            [(x["test"], x["before"], x["after"]) for x in t["flipped"]],
            [("carol", "user 3 cannot share file 11", "user 3 can share file 11")],
        )
        self.assertEqual([x["check"] for x in t["added"]], ["user 3 can edit file 11"])
        self.assertIn("1 check changed what it expects. 1 test renamed.", self.review.summary(r)["Tests"])
        self.assertIn('- renamed: "carol, neither shares" is now "carol"', self.review.markdown(r))
        self.assertIn('  test     renamed: "carol, neither shares" is now "carol"', self.review.text(r))
        # a name alone: nothing removed, and the name is said
        same = {"t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'}
        t = self.run_review(self.text, before, same)["tests"]
        self.assertEqual(
            (t["renamed"], t["removed"], t["flipped"]),
            ([{"before": "carol, neither shares", "after": "carol"}], [], []),
        )
        # not a new name: a check of the old test is in no new one, or its checks are in two new tests
        fewer = {"t.authz": 'test "carol"\n  user 3 can view file 11\n'}
        t = self.run_review(self.text, before, fewer)["tests"]
        self.assertEqual(t["renamed"], [])
        self.assertEqual(len(t["removed"]), 2)
        twice = {
            "t.authz": 'test "a"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'
            'test "b"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'
        }
        t = self.run_review(self.text, before, twice)["tests"]
        self.assertEqual(t["renamed"], [])
        self.assertEqual(len(t["removed"]), 2)
        # two tests put into one: both names are said, nothing is removed
        two = {"t.authz": 'test "x"\n  user 3 can view file 11\ntest "y"\n  user 3 cannot share file 11\n'}
        one = {"t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 cannot share file 11\n'}
        t = self.run_review(self.text, two, one)["tests"]
        self.assertEqual([n["before"] for n in t["renamed"]], ["x", "y"])
        self.assertEqual(t["removed"], [])

    def test_a_new_permission_no_test_names(self) -> None:
        new = replaced(
            self.text,
            "  can share = owner or folder.share\n",
            "  can share = owner or folder.share\n  can comment = folder.view\n",
        )
        r = self.run_review(new)
        self.assertEqual([x["what"] for x in r["tests"]["untested"]], ["file.comment"])
        self.assertEqual(r["deploy"]["migrations"][0]["locks"], {})
        self.assertIn("No table locks", self.review.markdown(r))

    # a small policy for the changes Risk must see: each line of it is one a pull request may loosen
    SMALL = """app role app_user
type user = app.users where {active}
type org = app.orgs
  member : user = app.org_members(org_id -> user_id)
  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}
  can manage = admin
  can see = member
type folder = app.folders where {not archived}
  org    : org = org_id
  owner  : user = owner_id
  viewer : user shared by edit
  can edit = owner or org.admin
  can view = edit or viewer
  can remove = owner and {status = 'a  b'}
  can deep = owner and {c1} and {c2} and {c3} and {c4} and {c5} and {c6} and {c7} and {c8}
rules app.folders
  select : view
  update : edit
"""

    def small(self, old: str, new: str, files: dict[str, str] | None = None) -> Review:
        self.assertIn(old, self.SMALL)
        return self.review.review(
            (self.SMALL, files or {}, {}), (self.SMALL.replace(old, new), files or {}, {}), worlds=120
        )

    def test_a_widening_is_flagged_however_it_is_made(self) -> None:
        cases = {
            "a select rule loosened": ("  select : view\n", "  select : view or signed_in\n"),
            "a rule added": ("  update : edit\n", "  update : edit\n  delete : view\n"),
            "a permission widened through what it uses": (" where {role = 'admin'}", ""),  # every member an admin
            "a rule loosened through what it uses": ("owner  : user = owner_id", "owner  : user = created_by"),
            "a type's where loosened": (" where {not archived}", ""),
        }
        for why, (old, new) in cases.items():
            risk = self.small(old, new)["risk"]
            self.assertIn(why, {f["why"] for f in risk}, why)
            self.assertTrue(all(f["line"] for f in risk), why)
        self.assertIn(
            "a type's where loosened", {f["why"] for f in self.small(" where {active}", "")["risk"]}
        )  # the user type's

    def test_each_change_the_review_warns_of(self) -> None:
        def risk(base: str, head: str) -> set[str]:
            return {f["why"] for f in self.review.review((base, {}, {}), (head, {}, {}), worlds=40)["risk"]}

        mask, scope, never = (
            "  mask status : edit\n",
            "scope reading = select, view",
            "  never folder: remove and not edit",
        )
        base = self.SMALL.replace("rules app.folders\n", "rules app.folders view app.folders_seen\n") + (
            f"{mask}{scope}\ninvariants\n{never}\n"
        )
        cases = {
            "sharing needs another permission": (self.SMALL, self.SMALL.replace("shared by edit", "shared by view")),
            "a new way to reach a type": (
                self.SMALL,
                self.SMALL.replace(
                    "  owner  : user = owner_id\n", "  owner  : user = owner_id\n  parent : folder = up\n"
                ).replace("can view = edit or viewer", "can view = edit or viewer or parent.view"),
            ),
            "a new inheritance path": (
                self.SMALL,
                self.SMALL.replace("can view = edit or viewer", "can view = edit or viewer or org.see"),
            ),
            "a mask or column rule removed": (base, base.replace(mask, "")),
            "a mask changed": (base, base.replace(mask, "  mask status : view\n")),
            "a scope changed": (base, base.replace(scope, scope + ", edit")),
            "an invariant removed": (base, base.replace(f"invariants\n{never}\n", "")),
        }
        for why, (b, h) in cases.items():
            self.assertNotEqual(b, h, why)
            self.assertIn(why, risk(b, h), why)

    def test_a_tightening_is_not_flagged(self) -> None:
        for old, new in (
            ("  select : view\n", "  select : edit\n"),
            ("rules app.folders\n  select : view\n  update : edit\n", ""),  # no rules: the table stays closed
            ("  update : edit\n", "  update : edit\n  update owner_id : edit\n"),  # a column rule narrows
            ("can view = edit or viewer", "can view = viewer or edit"),
        ):
            self.assertEqual(self.small(old, new)["risk"], [], new)

    def test_text_in_quotes_is_compared_as_written(self) -> None:
        r = self.small("'a  b'", "'a b'")
        self.assertIsNone(r["meaning"]["equivalent"])
        self.assertEqual([c["what"] for c in r["meaning"]["changed"]], ["folder.remove"])
        # spaces outside quotes are still only spacing
        self.assertEqual(
            self.small("can edit = owner or org.admin", "can edit  =  owner   or org.admin")["meaning"]["equivalent"],
            "text",
        )

    def test_a_widening_behind_many_conditions(self) -> None:
        r = self.small("can deep = owner and", "can deep = (owner or viewer) and")
        self.assertIsNone(r["meaning"]["equivalent"])
        self.assertIn("a permission widened", {f["why"] for f in r["risk"]})

    def test_a_policy_with_a_mistake_is_refused_with_its_message(self) -> None:
        with self.assertRaises(PolicyError) as e:
            self.small("can view = edit or viewer", "can view = edit or viewer or nosuch.view")
        self.assertEqual(e.exception.code, "AZ203")
        with self.assertRaisesRegex(
            self.review.BaseMistake, r"the policy at the base has a mistake: line \d+: .*\[AZ\d+\]"
        ):
            self.review.review(
                (self.SMALL.replace("can see = member", "can see = nosuch"), {}, {}), (self.SMALL, {}, {})
            )

    def test_the_details_are_written_when_the_meaning_is_unchanged(self) -> None:
        before = {"t.authz": 'test "carol"\n  user 3 can view file 11\n  user 3 cannot view file 12\n'}
        after = {"t.authz": 'test "carol"\n  user 3 cannot view file 11\n'}
        r = self.run_review(self.text, before, after)
        self.assertEqual(r["meaning"]["equivalent"], "text")
        md = self.review.markdown(r)
        self.assertIn("<details><summary>Tests</summary>", md)
        self.assertIn("`user 3 can view file 11` -> `user 3 cannot view file 11`", md)
        self.assertIn("removed from carol: `user 3 cannot view file 12`", md)
        self.assertIn("removed from carol: user 3 cannot view file 12", self.review.text(r))

    # a policy as the language before this version wrote it (a pull request that upgrades rowstile rewrites it), and
    # the same policy now: `role`, `and` meeting `or`, `grant` (a role joins the permission's `or` part, under the
    # `and`), `everyone`, and a test section line that checked a user whatever its first word
    OLD = """role app_user
type user = app.users
type service = app.services principal
type org = app.orgs
  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}
  can manage_roles = admin
type folder = app.folders
  org    : org = org_id
  owner  : user = owner_id
  viewer : user shared by edit
  roles  : user grant view, edit from org
  can edit = owner or org.admin and {not locked}
  can view = (edit or viewer) and {not archived}
  can open = everyone
rules app.folders
  select : view or open
  update : edit
test
  service 1 can view folder 2
"""
    NEW = (
        OLD.replace("role app_user", "app role app_user")
        .replace("grant view, edit from org", "from org")
        .replace("owner or org.admin and {not locked}", "owner or (org.admin and {not locked}) or roles")
        .replace("(edit or viewer) and", "(edit or viewer or roles) and")
        .replace("everyone", "anyone")
        .replace("service 1 can", "user 1 can")
    )

    def test_a_base_in_the_language_before_is_read_as_it_meant(self) -> None:
        r = self.review.review((self.OLD, {}, {}), (self.NEW, {}, {}), worlds=120)
        self.assertEqual(r["meaning"]["equivalent"], "120 small worlds")
        self.assertEqual(r["risk"], [])
        self.assertEqual(
            r.get("base_previous"),
            [
                "line 1: `role app_user`, now `app role app_user`",
                "line 11: `grant view, edit`, now `roles` in view, edit",
                "line 12: `and` and `or` without parentheses, now `owner or (org.admin and {not locked})`",
                "line 14: `everyone`, now `anyone`",
                "line 19: `service 1 can view folder 2` in the test section checked user 1",
            ],
        )
        self.assertIn(
            "The policy at the base is written in the language before this version of rowstile, and was "
            "read as that version meant it: line 1: `role app_user`",
            self.review.markdown(r),
        )
        self.assertTrue(self.review.text(r).startswith("Base     The policy at the base is written in the language"))
        # the same policy in this language is read as it is, with nothing to say
        self.assertNotIn("base_previous", self.review.review((self.NEW, {}, {}), (self.NEW, {}, {}), worlds=40))

    def test_a_rewrite_that_moves_a_role_out_of_its_and_is_flagged(self) -> None:
        # `roles` outside the `and`: role holders would see archived folders, which `grant` never gave them
        head = self.NEW.replace(
            "(edit or viewer or roles) and {not archived}", "((edit or viewer) and {not archived}) or roles"
        )
        r = self.review.review((self.OLD, {}, {}), (head, {}, {}), worlds=120)
        self.assertIsNone(r["meaning"]["equivalent"])
        self.assertIn("a permission widened", {f["why"] for f in r["risk"]})

    def test_what_the_language_before_didnt_check_is_said(self) -> None:
        # no app role line (the rules applied to PUBLIC), and a permission the runtime never asked for there
        base = self.OLD.replace("role app_user\n", "").replace(
            "  can open = everyone\n", "  can open = everyone\n  can impersonate = owner\n"
        )
        r = self.review.review((base, {}, {}), (self.NEW, {}, {}), worlds=40)
        old = r.get("base_previous") or []
        self.assertIn("no app role line: the rules applied to PUBLIC", old)
        self.assertTrue(any("[AZ307] (the language before this one didn't check it)" in x for x in old), old)

    def test_a_flag_in_an_included_file_is_annotated_there(self) -> None:
        main = self.SMALL.replace(
            "type org = app.orgs\n  member : user = app.org_members(org_id -> user_id)\n"
            "  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}\n"
            "  can manage = admin\n  can see = member\n",
            'include "org.authz"\n',
        )
        org = (
            "type org = app.orgs\n  member : user = app.org_members(org_id -> user_id)\n"
            "  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}\n"
            "  can manage = admin\n  can see = member\n"
        )
        self.assertNotEqual(main, self.SMALL)
        r = self.review.review(
            (main, {"org.authz": org}, {}),
            (main, {"org.authz": org.replace("can manage = admin", "can manage = admin or member")}, {}),
            worlds=120,
        )
        notes = self.review.annotations(r, "db/policy.authz")
        self.assertRegex(notes, r"^::warning file=db/org.authz,line=4,title=rowstile review::a permission widened")


class Graph(unittest.TestCase):
    """rowstile graph: the Mermaid diagram's nodes."""

    @staticmethod
    def nodes(policy: str) -> tuple[list[str], set[str]]:
        """The ids the diagram declares (nodes and boxes), and the ids its arrows use."""
        c = Compiler(parse_policy(policy, None, files={}))
        c.compile("the policy")
        g = c.graph()
        declared = re.findall(r"^\s+([A-Za-z0-9_]+)(?:\[|\(|\(\()", g, re.M) + re.findall(
            r"^\s+subgraph ([A-Za-z0-9_]+)\[", g, re.M
        )
        used: set[str] = set()
        for a, b in re.findall(r"^\s+([A-Za-z0-9_]+) [-=.]+>(?:\|[^|]*\|)? ([A-Za-z0-9_]+)$", g, re.M):
            used |= {a, b}
        return declared, used

    def test_two_things_never_share_a_node(self) -> None:
        base = "app role app_user\ntype user = app.users\n"
        declared, used = self.nodes(
            base
            + "type team = app.teams\n  owner : user = owner_id\n  can member_view = owner\nrules app.teams\n  select : member_view\n"
            "type team_member = app.team_members\n  owner : user = owner_id\n  can view = owner\nrules app.team_members\n  select : view\n"
            "type t = app.t\n  user : user = user_id\n  can view = user\nrules app.t\n  select : view\n"
        )
        self.assertEqual(len(declared), len(set(declared)), sorted(x for x in declared if declared.count(x) > 1))
        self.assertLessEqual(used, set(declared))

    def test_every_signed_in_service_is_drawn_to_its_type(self) -> None:
        declared, used = self.nodes(
            "app role app_user\ntype user = app.users\ntype service = app.services principal\ntype doc = app.docs\n"
            "  owner : user = owner_id\n  viewer : user, service, service:*, anyone shared by view\n  can view = owner or viewer\n"
            "rules app.docs\n  select : view\n"
        )
        self.assertLessEqual(used, set(declared), sorted(used - set(declared)))
        self.assertEqual(len(declared), len(set(declared)))


class AgentsNote(unittest.TestCase):
    """rowstile init's note for the app's coding agent: written, added to a file that is there, never twice."""

    def test_written_added_and_kept(self) -> None:
        import init

        note = init.agents_note("db/policy.authz", "db/tests/*.authz", "tracker_app")
        self.assertTrue(note.startswith(init.BEGIN + "\n") and note.endswith(init.END + "\n"))
        for said in ("`db/policy.authz`", "`db/tests/*.authz`", "`rowstile.toml`", "connects as `tracker_app`"):
            self.assertIn(said, note)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "AGENTS.md")
            self.assertEqual(init.write_agents_note(note, d), "wrote")
            with open(path, encoding="utf-8", newline="") as fh:
                self.assertEqual(fh.read(), note)
            self.assertIsNone(init.write_agents_note(note, d), "run twice, it changes nothing")
            for before, after in (
                ("# My app\n\nRun the tests with make.\n", "# My app\n\nRun the tests with make.\n\n" + note),
                ("# My app", "# My app\n\n" + note),
                ("", note),
                ("# My app\r\n", "# My app\r\n\r\n" + note.replace("\n", "\r\n")),
            ):
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(before)
                self.assertEqual(init.write_agents_note(note, d), "added")
                with open(path, encoding="utf-8", newline="") as fh:
                    self.assertEqual(fh.read(), after)
                self.assertIsNone(init.write_agents_note(note, d))
            # a section someone changed is theirs: the markers are enough
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(f"# My app\n{init.BEGIN}\nours\n{init.END}\n")
            self.assertIsNone(init.write_agents_note(note, d))

    def test_it_names_commands_the_reference_has(self) -> None:
        """The commands the note names are in the reference's table, and its link is the site's llms.txt."""
        import init

        note = init.agents_note("db/policy.authz", "db/tests/*.authz", "app_user")
        with open(os.path.join(os.path.dirname(ROOT), "docs", "reference", "tools.md"), encoding="utf-8") as fh:
            tools = fh.read()
        named = set(re.findall(r"`rowstile (\w+)", note))
        self.assertEqual(named, {"check", "push", "test", "dev", "help", "migrate", "why", "mcp"})
        for command in named:
            self.assertIn(f"| `rowstile {command}", tools, f"docs/reference/tools.md has no rowstile {command}")
        self.assertIn("https://rowstile.dev/llms.txt", note)
        self.assertLessEqual(max(len(line) for line in note.split("\n")), 112)


class Draft(unittest.TestCase):
    """rowstile init: the first policy, from tables whose names are not the tidy ones (tests/devx.sh applies one)."""

    @staticmethod
    def table(
        name: str,
        columns: dict[str, str],
        pk: list[str],
        fks: tuple[tuple[list[str], str, list[str]], ...] = (),
        uniques: list[list[str]] | None = None,
    ) -> draft.Table:
        return {
            "name": name,
            "columns": list(columns.items()),
            "pk": pk,
            "fks": [{"cols": c, "ref": r, "ref_cols": rc} for c, r, rc in fks],
            "uniques": uniques or [],
        }

    def compiled(self, tables: list[draft.Table]) -> str:
        text = draft.draft(tables, schemas=("app",))
        Compiler(parse_policy(text, None, files={})).compile("the policy")  # what the guide promises: it compiles
        return text

    def test_the_first_row_of_a_tree_can_be_made(self) -> None:
        # folders inside folders: "inside one you edit" alone lets nobody make the first folder through the app, so
        # the drafted rule also lets a row with nothing above it be made, in the maker's own name. The column is
        # written as SQL reads it (a capital needs its quotes), the relation by its name
        tree = lambda parent, owner: self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.folders",
                    {"id": "bigint", parent: "bigint", owner: "bigint"},
                    ["id"],
                    (([parent], "app.folders", ["id"]), ([owner], "app.users", ["id"])),
                ),
            ]
        )
        self.assertIn(
            "  insert : owner and (parent.edit or {parent_id is null})   -- decide", tree("parent_id", "owner_id")
        )
        self.assertIn(
            '  insert : owner and (parent.edit or {"parentId" is null})   -- decide', tree("parentId", "ownerId")
        )

    def test_your_own_row_and_a_link_table_named_in_one_word(self) -> None:
        # a user's own row is drafted as the reference says to write it, a relation from the key; and a link
        # table's relation leaves the type's name out whichever way the table is spelled
        users = lambda pk: self.table("app.User", {pk: "integer"}, [pk])
        links = lambda name: self.table(
            name,
            {"teamId": "integer", "userId": "integer"},
            ["teamId", "userId"],
            ((["teamId"], "app.Team", ["id"]), (["userId"], "app.User", ["id"])),
        )
        team = self.table("app.Team", {"id": "integer"}, ["id"])
        text = self.compiled([users("id"), team, links("app.TeamMember")])
        self.assertIn("  self : user = id  -- your own row\n  can edit = self\n", text)
        self.assertNotIn("authz.uid()", text)
        self.assertIn("  member : user = app.TeamMember(teamId -> userId)\n", text)
        self.assertIn(
            "  member : user = app.team_members(teamId -> userId)\n",
            self.compiled([users("id"), team, links("app.team_members")]),
        )
        # a key under another name, and a column of the user's own that would be called self too
        boss = self.table(
            "app.User", {"userId": "integer", "selfId": "integer"}, ["userId"], ((["selfId"], "app.User", ["userId"]),)
        )
        text = self.compiled([boss])
        self.assertIn("  self2 : user = userId  -- your own row\n  self : user = selfId\n", text)
        self.assertIn("  can edit = self2 or self\n", text)

    def test_names_the_language_or_sql_reads_another_way(self) -> None:
        users = self.table("app.users", {"id": "bigint"}, ["id"])
        to_user = lambda col: ([col], "app.users", ["id"])
        text = self.compiled(
            [
                self.table("app.User", {"id": "integer"}, ["id"]),
                self.table(
                    "app.Post",
                    {"id": "integer", "authorId": "integer", "order": "integer"},
                    ["id"],
                    ((["authorId"], "app.User", ["id"]), (["order"], "app.User", ["id"])),
                ),
                self.table("app._prisma_migrations", {"id": "character varying(36)"}, ["id"]),
            ]
        )
        self.assertIn("  author : user = authorId\n", text)
        self.assertIn("  insert : author\n", text)  # the relation, not its column once more
        self.assertIn("app._prisma_migrations: the migration tool's own table", text)
        self.assertNotIn("type _prisma_migration", text)
        # a column named like a word of the language, a link table and a column named like a permission
        text = self.compiled(
            [
                users,
                self.table(
                    "app.docs",
                    {"id": "bigint", "if": "bigint", "after": "bigint", "view_id": "bigint"},
                    ["id"],
                    (to_user("if"), to_user("after"), to_user("view_id")),
                ),
                self.table(
                    "app.doc_edits",
                    {"doc_id": "bigint", "user_id": "bigint"},
                    ["doc_id", "user_id"],
                    ((["doc_id"], "app.docs", ["id"]), to_user("user_id")),
                ),
            ]
        )
        self.assertIn("  viewer : user = view_id\n", text)
        self.assertIn("  editor : user = app.doc_edits(doc_id -> user_id)\n", text)
        self.assertIn("-- left out: if (to app.users)", text)
        # names the language can't write, and a link through a unique column that isn't the key
        text = self.compiled(
            [
                users,
                self.table("app.teams", {"id": "bigint", "slug": "text"}, ["id"]),
                self.table(
                    "app.team_members",
                    {"team_slug": "text", "user_id": "bigint"},
                    ["team_slug", "user_id"],
                    ((["team_slug"], "app.teams", ["slug"]), to_user("user_id")),
                ),
                self.table("app.owner list", {"id": "bigint"}, ["id"]),
                self.table("app.docs", {"id": "bigint", "owner id": "bigint"}, ["id"], (to_user("owner id"),)),
            ]
        )
        self.assertNotIn("app.team_members(team_slug", text)
        self.assertIn("-- app.owner list: a name the policy language can't write", text)
        self.assertIn("-- left out: owner id (to app.users)", text)

    def test_the_user_table_is_users_before_accounts(self) -> None:
        """Chatwoot's accounts (its tenants) and GitLab's members (a link table) were taken over their users."""
        to_user = lambda col: ([col], "app.users", ["id"])
        text = self.compiled(
            [
                self.table("app.accounts", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.members",
                    {"id": "bigint", "user_id": "bigint", "account_id": "bigint"},
                    ["id"],
                    (to_user("user_id"), (["account_id"], "app.accounts", ["id"])),
                ),
                self.table("app.users", {"id": "bigint"}, ["id"]),
            ]
        )
        self.assertIn("type user = app.users\n", text)
        text = self.compiled(
            [self.table("app.User", {"id": "integer"}, ["id"]), self.table("app.accounts", {"id": "bigint"}, ["id"])]
        )
        self.assertIn("type user = app.User (id int)\n", text)  # Prisma's model User, before accounts

    def test_a_foreign_key_declared_twice_is_one_relation(self) -> None:
        """GitLab's project_saved_replies: the same key twice gave two relations and two `after` rules (AZ109)."""
        fk = (["project_id"], "app.projects", ["id"])
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.projects",
                    {"id": "bigint", "owner_id": "bigint"},
                    ["id"],
                    ((["owner_id"], "app.users", ["id"]),),
                ),
                self.table("app.replies", {"id": "bigint", "project_id": "bigint"}, ["id"], (fk, fk)),
            ]
        )
        self.assertEqual(text.count("update project_id after"), 1)
        self.assertNotIn("project2", text)

    def test_a_loop_of_foreign_keys_with_an_owner_compiles(self) -> None:
        """Documenso, Cal.com, Mastodon and GitLab: org -> settings -> email -> domain -> org; only orgs have owners."""
        to = lambda col, table: ([col], table, ["id"])
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.orgs",
                    {"id": "bigint", "owner_id": "bigint", "settings_id": "bigint"},
                    ["id"],
                    (to("owner_id", "app.users"), to("settings_id", "app.settings")),
                ),
                self.table(
                    "app.settings", {"id": "bigint", "email_id": "bigint"}, ["id"], (to("email_id", "app.emails"),)
                ),
                self.table(
                    "app.emails", {"id": "bigint", "domain_id": "bigint"}, ["id"], (to("domain_id", "app.domains"),)
                ),
                self.table("app.domains", {"id": "bigint", "org_id": "bigint"}, ["id"], (to("org_id", "app.orgs"),)),
            ]
        )
        self.assertIn("type domain = app.domains\n  org : org = org_id\n  can edit = org.edit", text)
        # the same loop with no owner anywhere in it (Cal.com's, Mastodon's, GitLab's): inheriting round it gives
        # nobody anything, so the draft doesn't write it, and says why
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table(
                    "app.orgs", {"id": "bigint", "settings_id": "bigint"}, ["id"], (to("settings_id", "app.settings"),)
                ),
                self.table("app.settings", {"id": "bigint", "org_id": "bigint"}, ["id"], (to("org_id", "app.orgs"),)),
            ]
        )
        self.assertIn(
            "type org = app.orgs\n  settings : setting = settings_id\n  can edit = nobody   -- decide: the loop "
            "of foreign keys it is in has no owner anywhere; who edits these?\n  can view = signed_in",
            text,
        )

    def test_a_membership_with_an_id_of_its_own_is_a_link(self) -> None:
        """Plausible's site_memberships (id, site_id, user_id, role): read as a type, so a site was everyone's."""
        to_user = lambda col: ([col], "app.users", ["id"])
        users = self.table("app.users", {"id": "bigint"}, ["id"])
        sites = self.table("app.sites", {"id": "bigint", "domain": "text"}, ["id"])
        member = lambda extra, uniques: self.table(
            "app.site_memberships",
            {"id": "bigint", "site_id": "bigint", "user_id": "bigint", **extra},
            ["id"],
            ((["site_id"], "app.sites", ["id"]), to_user("user_id")),
            uniques,
        )
        link = "  membership : user = app.site_memberships(site_id -> user_id)\n"
        for extra, uniques in (
            ({"role": "text", "inserted_at": "timestamp"}, []),  # a role and timestamps only
            ({"note": "text"}, [["site_id", "user_id"]]),
        ):  # anything, with the pair unique
            text = self.compiled([users, sites, member(extra, uniques)])
            self.assertIn(link, text)
            self.assertIn("-- decide: app.site_memberships is read as a membership", text)
            self.assertIn("  can view = edit or membership\n", text)
        # something else about a user and a site is not a membership: a note and no unique pair, or no role
        for extra in ({"note": "text"}, {}, {"inserted_at": "timestamp"}):
            self.assertNotIn(link, self.compiled([users, sites, member(extra, [])]))

    def test_view_names_each_parent_once(self) -> None:
        """`view = edit or parent.view` with `edit = ... or parent.edit` named each parent twice per level: lint's
        warning on six of nine apps' drafts."""
        to = lambda col, table: ([col], table, ["id"])
        text = self.compiled(
            [
                self.table("app.users", {"id": "bigint"}, ["id"]),
                self.table("app.sites", {"id": "bigint", "owner_id": "bigint"}, ["id"], (to("owner_id", "app.users"),)),
                self.table(
                    "app.goals",
                    {"id": "bigint", "site_id": "bigint", "creator_id": "bigint"},
                    ["id"],
                    (to("site_id", "app.sites"), to("creator_id", "app.users")),
                ),
            ]
        )
        self.assertIn("  can edit = creator or site.edit   -- decide: owners", text)
        self.assertIn("  can view = creator or site.view\n", text)

    def test_a_user_table_whose_key_it_cannot_use_is_said(self) -> None:
        with self.assertRaisesRegex(draft.DraftError, "its key is character\\(8\\).*--users"):
            draft.draft(
                [
                    self.table("app.users", {"id": "character(8)"}, ["id"]),
                    self.table("app.docs", {"id": "bigint"}, ["id"]),
                ]
            )

    def test_where_prisma_keeps_its_migrations(self) -> None:
        import stack

        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "db"))
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as fh:
                json.dump({"dependencies": {"@prisma/client": "7"}, "prisma": {"schema": "db/schema.prisma"}}, fh)
            with open(os.path.join(d, "db", "schema.prisma"), "w", encoding="utf-8") as fh:
                fh.write("datasource db {}\n")
            found = stack.detect(d)
            self.assertEqual((found.tool, found.migrations_dir), ("prisma", "db/migrations"))


class Wire(unittest.TestCase):
    """The command's own Postgres client (cli/pgwire.py): what a connection string says, and TLS, against a
    made-up server (the handshake only: no database)."""

    def setUp(self) -> None:
        import pgwire

        self.pgwire = pgwire
        self.env = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("PG")}

    def tearDown(self) -> None:
        os.environ.update(self.env)

    def test_a_url_and_its_options(self) -> None:
        parse = self.pgwire.parse_dsn
        got = parse("postgresql://ann:p%23w@db.example.com:6543/app?sslmode=require&connect_timeout=3")
        self.assertEqual(
            (got["host"], got["port"], got["user"], got["password"], got["database"], got["sslmode"], got["timeout"]),
            ("db.example.com", 6543, "ann", "p#w", "app", "require", 3.0),
        )
        got = parse("postgresql:///app?host=/tmp/sock&port=5499&user=bo")  # how a URL names a socket
        self.assertEqual((got["host"], got["port"], got["user"], got["database"]), ("/tmp/sock", 5499, "bo", "app"))
        self.assertEqual(
            parse("postgresql://h/app?schema=public&pgbouncer=true")["host"], "h"
        )  # an ORM's own: left alone
        self.assertEqual(parse("host=h sslmode=verify-full sslrootcert=ca.pem")["sslrootcert"], "ca.pem")
        self.assertEqual(parse("host=h")["sslmode"], "prefer")
        # as Neon's dashboard gives it
        got = parse("postgresql://o:p@ep.example.tech/db?sslmode=require&channel_binding=require")
        self.assertEqual((got["sslmode"], got["channel_binding"]), ("require", "require"))
        self.assertEqual(parse("host=h")["channel_binding"], "prefer")
        os.environ["PGSSLMODE"] = "require"
        self.assertEqual(parse("host=h")["sslmode"], "require")
        del os.environ["PGSSLMODE"]

    def test_what_it_cannot_honour_is_refused_not_dropped(self) -> None:
        for dsn, said in (
            ("postgresql://h/app?sslmode=maybe", "sslmode=maybe"),
            ("postgresql://h/app?sslcert=client.crt", "client certificates"),
            ("postgresql://h/app?channel_binding=maybe", "channel_binding=maybe"),
            ("host=h colour=blue", "unknown connection setting 'colour'"),
            ("postgresql://u:pa#ss@h/app", "must be written %23"),
            ('host=h password=p"w', "single quotes"),
            ("host=h port=abc", "numbers"),
        ):
            with self.assertRaisesRegex(ValueError, re.escape(said), msg=dsn):
                self.pgwire.parse_dsn(dsn)

    def server(self, tls: bool, scram: str | None = None, auth: str | None = None) -> tuple[int, dict[str, object]]:
        """A made-up server on a local port: answers the TLS request (yes with the test certificate, or no), reads
        the start-up message, says the client is signed in. seen: whether TLS was used, and the start-up parameters.
        scram: it asks for the password "secret" with SCRAM first, offering channel binding ("plus"), not offering
        it ("plain"), or holding another certificate than the one the client sees ("other": a server in the middle);
        or it answers with a nonce that isn't the client's ("badnonce"), or a proof that is wrong ("badproof").
        seen then has the mechanism the client chose and whether it bound the exchange to the certificate.
        auth: it asks for the password in clear ("cleartext") or hashed with MD5 ("md5"), and seen has what the
        client sent; or it asks in a way the client doesn't know ("gss"), offers SASL without SCRAM-SHA-256
        ("sasl-other"), or answers the TLS request as no Postgres does ("not postgres")."""
        import base64
        import hashlib
        import hmac
        import socket
        import ssl
        import struct
        import threading

        fixtures = os.path.join(ROOT, "tests", "fixtures")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        seen: dict[str, object] = {"tls": False, "asked": False}

        def exactly(conn: socket.socket, n: int) -> bytes:
            data = b""
            while len(data) < n:
                chunk = conn.recv(n - len(data))
                if not chunk:
                    raise ConnectionError("closed")
                data += chunk
            return data

        def sasl(conn: socket.socket) -> bool:
            salt, rounds = b"0123456789abcdef", 4096
            mechs = (b"" if scram == "plain" else b"SCRAM-SHA-256-PLUS\0") + b"SCRAM-SHA-256\0\0"
            conn.sendall(b"R" + struct.pack("!ii", 8 + len(mechs), 10) + mechs)
            body = exactly(conn, struct.unpack("!i", exactly(conn, 5)[1:])[0] - 4)
            mechanism, rest = body.split(b"\0", 1)
            first = rest[4:].decode()
            header, bare = first[: first.index(",,") + 2], first[first.index(",,") + 2 :]
            seen["mechanism"], seen["header"] = mechanism.decode(), header
            theirs = dict(kv.split("=", 1) for kv in bare.split(","))["r"]
            nonce = ("someone else's" if scram == "badnonce" else theirs) + "server"
            server_first = f"r={nonce},s={base64.b64encode(salt).decode()},i={rounds}"
            conn.sendall(b"R" + struct.pack("!ii", 8 + len(server_first), 11) + server_first.encode())
            final = exactly(conn, struct.unpack("!i", exactly(conn, 5)[1:])[0] - 4).decode()
            attrs = dict(kv.split("=", 1) for kv in final.split(","))
            with open(os.path.join(fixtures, "wire_test.crt"), encoding="ascii") as fh:
                certificate = ssl.PEM_cert_to_DER_cert(fh.read())
            if scram == "other":
                certificate += b"another"
            bound = hashlib.sha256(certificate).digest() if header.startswith("p=") else b""
            salted = hashlib.pbkdf2_hmac("sha256", b"secret", salt, rounds)
            stored = hashlib.sha256(hmac.new(salted, b"Client Key", hashlib.sha256).digest()).digest()
            message = f"{bare},{server_first},{final[: final.rindex(',p=')]}".encode()
            signature = hmac.new(stored, message, hashlib.sha256).digest()
            key = bytes(a ^ b for a, b in zip(base64.b64decode(attrs["p"]), signature, strict=True))
            seen["bound"] = header.startswith("p=") and attrs["c"] == base64.b64encode(header.encode() + bound).decode()
            if (
                hashlib.sha256(key).digest() != stored
                or attrs["c"] != base64.b64encode(header.encode() + bound).decode()
            ):
                refused = b"SFATAL\0C28P01\0Mpassword authentication failed\0\0"
                conn.sendall(b"E" + struct.pack("!i", 4 + len(refused)) + refused)
                return False
            proof = hmac.new(hmac.new(salted, b"Server Key", hashlib.sha256).digest(), message, hashlib.sha256).digest()
            last = b"v=" + base64.b64encode(bytes(32) if scram == "badproof" else proof)
            conn.sendall(b"R" + struct.pack("!ii", 8 + len(last), 12) + last)
            return True

        def serve() -> None:
            conn, _ = listener.accept()
            try:
                conn.settimeout(5)
                length, code = struct.unpack("!ii", exactly(conn, 8))
                if code == 80877103:
                    seen["asked"] = True
                    if auth == "not postgres":
                        conn.sendall(b"H")  # as a web server's "HTTP/1.1 400" begins
                        return
                    conn.sendall(b"S" if tls else b"N")
                    if tls:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        context.load_cert_chain(
                            os.path.join(fixtures, "wire_test.crt"), os.path.join(fixtures, "wire_test.key")
                        )
                        conn = context.wrap_socket(conn, server_side=True)
                        seen["tls"] = True
                    length, code = struct.unpack("!ii", exactly(conn, 8))
                seen["start"] = exactly(conn, length - 8).split(b"\0")
                if scram and not sasl(conn):
                    return
                if auth in ("cleartext", "md5"):
                    asked = struct.pack("!ii", 8, 3) if auth == "cleartext" else struct.pack("!ii", 12, 5) + b"salt"
                    conn.sendall(b"R" + asked)
                    seen["password"] = exactly(conn, struct.unpack("!i", exactly(conn, 5)[1:])[0] - 4)[:-1].decode()
                elif auth in ("gss", "sasl-other"):
                    mechs = b"SCRAM-SHA-1\0\0"
                    asked = (
                        struct.pack("!ii", 8, 7) if auth == "gss" else struct.pack("!ii", 8 + len(mechs), 10) + mechs
                    )
                    conn.sendall(b"R" + asked)
                    return
                conn.sendall(b"R" + struct.pack("!ii", 8, 0) + b"Z" + struct.pack("!i", 5) + b"I")
                conn.recv(16)
            except (OSError, ConnectionError):
                pass
            finally:
                conn.close()
                listener.close()

        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1], seen

    def test_tls_as_sslmode_says(self) -> None:
        connect = self.pgwire.connect
        crt = os.path.join(ROOT, "tests", "fixtures", "wire_test.crt")
        port, seen = self.server(tls=True)
        connect(host="127.0.0.1", port=port, sslmode="require", timeout=5).close()
        self.assertTrue(seen["tls"])
        start = seen["start"]
        assert isinstance(start, list)
        self.assertIn(b"rowstile", start)  # application_name
        port, seen = self.server(tls=True)
        connect(host="127.0.0.1", port=port, timeout=5).close()  # prefer: taken when the server has it
        self.assertTrue(seen["tls"])
        port, seen = self.server(tls=False)
        connect(host="127.0.0.1", port=port, timeout=5).close()  # ... and done without when it doesn't
        self.assertEqual((seen["asked"], seen["tls"]), (True, False))
        port, seen = self.server(tls=False)
        with self.assertRaisesRegex(self.pgwire.ProtocolError, "doesn't do TLS, and sslmode=require asks for it"):
            connect(host="127.0.0.1", port=port, sslmode="require", timeout=5)
        port, seen = self.server(tls=True)
        connect(host="127.0.0.1", port=port, sslmode="disable", timeout=5).close()
        self.assertFalse(seen["asked"])
        # verify-full: the certificate must be one the client trusts, for the name it connected to
        port, seen = self.server(tls=True)
        connect(host="127.0.0.1", port=port, sslmode="verify-full", sslrootcert=crt, timeout=5).close()
        self.assertTrue(seen["tls"])
        port, seen = self.server(tls=True)
        with self.assertRaisesRegex(self.pgwire.ProtocolError, "TLS with the server failed"):
            connect(
                host="127.0.0.1", port=port, sslmode="verify-full", timeout=5
            )  # not signed by anyone the system trusts

    def test_scram_is_bound_to_the_tls_channel(self) -> None:
        wrong = self.pgwire.ProtocolError

        def connect(port: int, channel_binding: str = "prefer", sslmode: str = "prefer") -> None:
            self.pgwire.connect(
                host="127.0.0.1",
                port=port,
                password="secret",
                timeout=5,
                sslmode=sslmode,
                channel_binding=channel_binding,
            ).close()

        # offered over TLS: taken, without being asked for (as libpq does)
        port, seen = self.server(tls=True, scram="plus")
        connect(port)
        self.assertEqual((seen["mechanism"], seen["bound"]), ("SCRAM-SHA-256-PLUS", True))
        port, seen = self.server(tls=True, scram="plus")
        connect(port, "require", "require")  # Neon's string
        self.assertEqual((seen["mechanism"], seen["bound"]), ("SCRAM-SHA-256-PLUS", True))
        port, seen = self.server(tls=True, scram="plus")
        connect(port, "disable")
        self.assertEqual((seen["mechanism"], seen["header"]), ("SCRAM-SHA-256", "n,,"))
        # not offered: done without, saying so (y), unless it was required
        port, seen = self.server(tls=True, scram="plain")
        connect(port)
        self.assertEqual((seen["mechanism"], seen["header"]), ("SCRAM-SHA-256", "y,,"))
        port, seen = self.server(tls=True, scram="plain")
        with self.assertRaisesRegex(wrong, "doesn't offer channel binding"):
            connect(port, "require")
        port, seen = self.server(tls=False, scram="plus")
        with self.assertRaisesRegex(wrong, "channel_binding=require needs TLS"):
            connect(port, "require")
        port, seen = self.server(tls=False, scram="plus")
        connect(port)  # no TLS: nothing to bind to
        self.assertEqual((seen["mechanism"], seen["header"]), ("SCRAM-SHA-256", "n,,"))
        port, seen = self.server(tls=True)  # signs in without asking anything
        with self.assertRaisesRegex(wrong, "without channel binding"):
            connect(port, "require")
        # a server in the middle holds another certificate than the one the client was shown: the exchange fails
        port, seen = self.server(tls=True, scram="other")
        with self.assertRaisesRegex(self.pgwire.PgError, "28P01"):
            connect(port)
        with open(os.path.join(ROOT, "tests", "fixtures", "wire_test.crt"), encoding="ascii") as fh:
            import ssl

            certificate = ssl.PEM_cert_to_DER_cert(fh.read())
        self.assertEqual(self.pgwire._signature_hash(certificate), "sha256")
        self.assertIsNone(self.pgwire._signature_hash(b"not a certificate"))

    def test_each_way_a_server_asks_for_the_password(self) -> None:
        import hashlib

        wrong = self.pgwire.ProtocolError

        def connect(port: int, password: str | None = "secret") -> None:
            self.pgwire.connect(host="127.0.0.1", port=port, user="ann", password=password, timeout=5).close()

        port, seen = self.server(tls=False, auth="cleartext")
        connect(port)
        self.assertEqual(seen["password"], "secret")
        port, seen = self.server(tls=False, auth="md5")  # md5(md5(password + user) + salt), as libpq sends it
        connect(port)
        inner = hashlib.md5(b"secretann").hexdigest()
        self.assertEqual(seen["password"], "md5" + hashlib.md5(inner.encode() + b"salt").hexdigest())
        for auth, scram, password, said in (
            ("cleartext", None, None, "the server asks for a password"),
            ("gss", None, "secret", "unsupported authentication method 7"),
            ("sasl-other", None, "secret", "unsupported SASL mechanisms"),
            (None, "badnonce", "secret", "the server's nonce does not extend ours"),
            (None, "badproof", "secret", "the server could not prove it knows the password"),
            ("not postgres", None, "secret", "the server didn't answer as Postgres does"),
        ):
            port, seen = self.server(tls=False, scram=scram, auth=auth)
            with self.assertRaisesRegex(wrong, re.escape(said), msg=auth or scram):
                connect(port, password)

    def test_what_it_refuses_to_send(self) -> None:
        port, _ = self.server(tls=False)
        conn = self.pgwire.connect(host="127.0.0.1", port=port, user="ann", timeout=5)
        try:
            with self.assertRaisesRegex(ValueError, "SQL cannot contain NUL characters"):
                conn.script("SELECT 1\0")
            with self.assertRaisesRegex(ValueError, "parameters cannot contain NUL characters"):
                conn.query("SELECT $1", ["a\0b"])
            with self.assertRaisesRegex(ValueError, "the number of %s placeholders and arguments differ"):
                conn.cursor().execute("SELECT %s, %s", (1,))
        finally:
            conn.close()

    def test_values_it_reads(self) -> None:
        convert = self.pgwire._convert
        self.assertEqual(convert(1000, b"{t,f,NULL}"), [True, False, None])  # booleans
        self.assertEqual(convert(1009, b'{"a\\"b",c}'), ['a"b', "c"])  # a quote escaped inside quotes
        self.assertEqual(convert(1007, b"{1,2,NULL}"), [1, 2, None])
        self.assertEqual(convert(1007, b"{{1,2},{3,4}}"), "{{1,2},{3,4}}")  # two dimensions: as Postgres writes it
        self.assertEqual(convert(1009, b"[0:1]={a,b}"), "[0:1]={a,b}")
        self.assertEqual(self.pgwire._saslprep("pa\u00adss\u2168"), "passIX")  # as psql prepares a password for SCRAM
        self.assertEqual(self.pgwire._saslprep("caf\u00e9"), "caf\u00e9")


class Fmt(unittest.TestCase):
    def test_every_policy_formats_the_same_twice_and_says_the_same(self) -> None:
        from authzlib.fmt import format
        from authzlib.migrate import meaning_lines

        for rel in list(POLICIES.values()) + [
            "example/docs.test.authz",
            "../docs/cookbook/sharing-and-links/policy.authz",
            "../examples/filemanager/db/policy.authz",
            "../examples/messenger/db/policy.authz",
        ]:
            text = read(rel)
            once = format(text)
            self.assertEqual(format(once), once, rel)
            self.assertEqual(meaning_lines(once, {}), meaning_lines(text, {}), rel)

    def test_the_format(self) -> None:
        from authzlib.fmt import format

        got = format(
            "app role app_user\ntype user = app.users\n\n\n\ntype doc = app.docs\n  owner : user = owner_id  -- who\n"
            "  editor:user   shared\n  can edit = owner or editor\n  can  view=   edit\n     or owner\n"
            "rules app.docs\n  select : view\n  update after : edit\n"
        )
        self.assertEqual(
            got,
            "app role app_user\n\ntype user = app.users\n\ntype doc = app.docs\n"
            "  owner  : user = owner_id  -- who\n  editor : user shared\n"
            "  can edit = owner or editor\n  can view = edit\n          or owner\n\n"
            "rules app.docs\n  select       : view\n  update after : edit\n",
        )

    BASE = (
        "app role app_user\n\ntype user = app.users\n\ntype doc = app.docs\n  owner : user = owner_id\n"
        "  can view = owner\n\nrules app.docs\n  select : view\n"
    )

    def test_tests_come_out_saying_the_same(self) -> None:
        from authzlib.fmt import format, tests_of

        for name, tests in {
            "a brace in a string": "\ntest \"one\"\n  as user 1 allowed {UPDATE app.docs SET name = '{' WHERE id = 1}\n"
            '\ntest "two"\n  user 1 can view doc 1\n',
            "names that differ by their spaces": '\ntest "a  b"\n  user 1 can view doc 1\n\ntest "a b"\n  user 1 cannot view doc 1\n',
            "a name with --": '\ntest "before -- after"  -- a comment\n  user 1 can view doc 1\n',
        }.items():
            text = self.BASE + tests
            done = format(text)
            self.assertEqual(tests_of(done, {}), tests_of(text, {}), name)
            self.assertEqual(format(done), done, name)
            Compiler(parse_policy(done, None, files={})).compile("the policy")  # it still compiles
        self.assertIn('test "a  b"', format(self.BASE + '\ntest "a  b"\n  user 1 can view doc 1\n'))
        self.assertIn(
            "{name <> '{'}", format(self.BASE.replace("can view = owner", "can view = owner and {name <> '{'}"))
        )

    def test_what_compiles_formats(self) -> None:
        from authzlib.fmt import FormatError, format

        for word in ("role", "type", "scope", "test"):  # relations may have these names
            text = self.BASE.replace("owner", word)
            self.assertEqual(format(text), text, word)
        with_include = 'include "roles.authz"\n\n' + self.BASE
        self.assertEqual(format(with_include, {"roles.authz": "-- nothing here\n"}), with_include)
        with self.assertRaisesRegex(FormatError, "AZ104"):  # a mistake: its message, not an assertion
            format(self.BASE.replace("can view = owner", "can view"))


class Confidence(unittest.TestCase):
    """rowstile prove (invariants in small worlds) and coverage (branches no test makes true)."""

    def test_prove_finds_the_smallest_counterexample(self) -> None:
        from authzlib import prove

        pol = parse_policy(read(POLICIES["docs"]), "docs.authz")
        [r] = prove.prove(pol)
        # a folder's owner may share it even if they aren't in its org: the data never has that, the policy allows it
        self.assertFalse(r["holds"])
        self.assertEqual((r["who"], r["type"]), ("1", "folder"))
        self.assertEqual(r["world"], ["user: 1", "folder: 1", "folder.owner: folder 1 -> user 1"])
        self.assertIn("no   user 1 holds it on folder 1", prove.describe([r]))

    def test_prove_says_when_none_is_found(self) -> None:
        from authzlib import evaluate, prove

        text = read(POLICIES["docs"]).replace(
            "never folder: share and not org.member", "never folder: edit and not view"
        )
        pol = parse_policy(text, "docs.authz")
        [r] = prove.prove(pol, worlds=80)
        self.assertTrue(r["holds"])
        # the 80 drawn, and each corner 3 times at each of the 4 sizes
        self.assertEqual(r["worlds"], 80 + 3 * 4 * len(evaluate.corners([pol])))

    def test_prove_finds_a_counterexample_that_needs_conditions_at_once(self) -> None:
        # a t3 holds p3 through its t1, where {b1 and b2} must hold, and the invariant asks {b1} on the t3 too: a
        # world drawn row by row has that one time in hundreds (the first found was the 191st world), a corner at
        # once (found by a soak, where 200 worlds said it holds)
        from authzlib import prove

        [r] = prove.prove(
            parse_policy(
                self.HEAD + "type t1 = app.t1\n  r1 : user = c_r1\n  parent : t1 = parent_id\n  can p2 = r1\n"
                "  can p3 = parent.p2 and {b1 and b2}\ntype t3 = app.t3\n  up : t1 = c_up\n  can p3 = up.p3\n"
                "invariants\n  never t3: p3 and {b1}\n",
                "p.authz",
            ),
            worlds=200,
        )
        self.assertFalse(r["holds"])
        self.assertLessEqual(r["worlds"], 20)
        self.assertEqual(r["world"][:3], ["user: 1", "t1: 1", "t3: 1"])

    def test_the_evaluator_reads_the_rows_of_the_data_it_is_given(self) -> None:
        # the column values it reads for a world were kept by the world's id(): once that world was gone, another
        # could be made at its address and read the first one's rows (prove counted a counterexample that wasn't).
        # Every id the same here: the rows must still be the second world's
        from unittest import mock

        from authzlib import evaluate

        pol = parse_policy(self.HEAD + "type doc = app.docs\n  can view = {published}\n", "p.authz")

        def world(published: bool) -> evaluate.Data:
            ids = {"user": ["1"], "doc": ["1"]}
            return evaluate.Data(
                ids=ids, valid=ids, columns={"user": {"1": {}}, "doc": {"1": {"published": published}}}
            )

        ref = evaluate.Reference(pol)
        with mock.patch.object(evaluate, "id", lambda _: 0, create=True):
            self.assertEqual(ref.evaluate(world(True), "1")[("doc", "view")], {"1"})
            self.assertEqual(ref.evaluate(world(False), "1")[("doc", "view")], set())

    HEAD = "app role app_user\ntype user = app.users\n"

    def proofs(self, text: str) -> list[bool]:
        from authzlib import prove

        return [r["holds"] for r in prove.prove(parse_policy(self.HEAD + text, "p.authz"))]

    def same(self, before: str, after: str) -> bool:
        from authzlib import evaluate

        return (
            evaluate.compare(parse_policy(self.HEAD + before, "a.authz"), parse_policy(self.HEAD + after, "b.authz"))
            is None
        )

    def test_anyone_nobody_and_signed_in_are_the_same_on_every_row(self) -> None:
        folder = "type folder = app.folders\n  owner : user = owner_id\n  viewer : user = viewer_id\n"
        self.assertEqual(self.proofs(folder + "  can view = anyone\ninvariants\n  never folder: not view\n"), [True])
        self.assertEqual(self.proofs(folder + "  can view = nobody\ninvariants\n  never folder: view\n"), [True])
        self.assertEqual(
            self.proofs(folder + "  can view = signed_in\ninvariants\n  never folder: owner and not view\n"), [True]
        )
        self.assertEqual(
            self.proofs(folder + "  can view = signed_in\ninvariants\n  never folder: view and not owner\n"), [False]
        )
        for word in ("anyone", "signed_in"):
            self.assertTrue(
                self.same(folder + f"  can view = viewer or {word}\n", folder + f"  can view = {word}\n"), word
            )
        self.assertTrue(self.same(folder + "  can view = viewer or nobody\n", folder + "  can view = viewer\n"))
        self.assertFalse(
            self.same(folder + "  can view = signed_in\n", folder + "  can view = anyone\n")
        )  # nobody signed in

    def test_simple_conditions_are_facts_about_the_row(self) -> None:
        folder = "type folder = app.folders\n  owner : user = owner_id\n  parent : folder = parent_id\n"
        # two spellings of one condition, and a condition that says what a relation says
        self.assertTrue(
            self.same(
                folder + "  can view = owner and {not archived}\n",
                folder + "  can view = owner and {archived = false}\n",
            )
        )
        self.assertTrue(
            self.same(
                folder + "  can view = owner and {kind in ('a', 'b')}\n",
                folder + "  can view = owner and ({kind = 'a'} or {kind = 'b'})\n",
            )
        )
        self.assertTrue(
            self.same(
                folder + "  can view = owner\nrules app.folders\n  insert : {owner_id = authz.uid()}\n",
                folder + "  can view = owner\nrules app.folders\n  insert : owner\n",
            )
        )
        self.assertTrue(
            self.same(
                folder + "  can top = owner and {parent_id is null}\n",
                folder + "  can top = owner and {this.parent_id is null}\n",
            )
        )
        # NULL: {not archived} is false where archived is NULL, not {archived} is true there
        self.assertFalse(
            self.same(
                folder + "  can view = owner and {not archived}\n", folder + "  can view = owner and not {archived}\n"
            )
        )
        self.assertFalse(
            self.same(folder + "  can view = owner and {size > 10}\n", folder + "  can view = owner and {size >= 10}\n")
        )

    def test_prove_tries_what_a_counterexample_may_need(self) -> None:
        # two rows of a type; a number either side of a bound; a text no condition names; NULL
        doc = "type doc = app.docs\n  owner : user = owner_id\n  parent : doc = parent_id\n  can edit = owner\n"
        cases = [
            "  can view = owner or parent.view\ninvariants\n  never doc: view and not owner\n",
            "  can view = {size > 8}\ninvariants\n  never doc: view and {size < 10}\n",
            "  can view = {kind <> 'a'}\ninvariants\n  never doc: view and {kind <> 'b'}\n",
            "  can view = not {archived}\ninvariants\n  never doc: view and not {archived = false}\n",
        ]
        for case in cases:
            self.assertEqual(self.proofs(doc + case), [False], case)
        # the refactor check too: two rows, and a link presented
        self.assertFalse(self.same(doc + "  can view = owner or parent.view\n", doc + "  can view = owner\n"))
        shared = (
            "type doc = app.docs\n  owner : user = owner_id\n  viewer : link shared\n  can share = owner\n"
            "  can peek = viewer\n"
        )
        self.assertFalse(self.same(shared + "  can view = owner or viewer\n", shared + "  can view = owner\n"))

    def test_a_counterexample_is_shrunk_until_nothing_more_goes(self) -> None:
        from authzlib import prove

        # p is needed while {a} holds; once a is NULL, p can go too: a second pass
        pol = parse_policy(
            self.HEAD + "type doc = app.docs\n  p : user = p_id\n  q : user = q_id\n"
            "  can view = q and (not {a} or p)\n",
            "p.authz",
        )
        ref = evaluate.Reference(pol)
        ids = {"user": ["1"], "doc": ["1"]}
        data = evaluate.Data(
            ids=ids,
            valid=ids,
            pairs={("doc", "p", 0, "user", ""): [("1", "1")], ("doc", "q", 0, "user", ""): [("1", "1")]},
            columns={"user": {"1": {}}, "doc": {"1": {"a": True}}},
        )
        small = evaluate.smallest(data, lambda d: "1" in ref.evaluate(d, "1")[("doc", "view")])
        self.assertEqual(small.pairs, {("doc", "p", 0, "user", ""): [], ("doc", "q", 0, "user", ""): [("1", "1")]})
        self.assertEqual(small.columns["doc"]["1"], {"a": None})
        # a link taken away takes its column's value with it: owner_id = authz.uid() holds only while the owner
        # link is there, so the smallest world keeps it
        [r] = prove.prove(
            parse_policy(
                self.HEAD + "type doc = app.docs\n  owner : user = owner_id\n  can see = owner\n"
                "  can edit = {owner_id = authz.uid()}\ninvariants\n  never doc: edit\n",
                "p.authz",
            )
        )
        self.assertEqual(r["world"], ["user: 1", "doc: 1", "doc.owner: doc 1 -> user 1"])

    def test_the_corners_set_a_denied_condition_false(self) -> None:
        # six conditions that must hold and two that mustn't, on one row: one row in 256 drawn row by row
        from authzlib import prove

        conds = " and ".join([*[f"{{b{i}}}" for i in range(1, 7)], "not {b7}", "not {b8}"])
        [r] = prove.prove(
            parse_policy(
                self.HEAD + f"type doc = app.docs\n  owner : user = owner_id\n  can view = owner and {conds}\n"
                "invariants\n  never doc: view\n",
                "p.authz",
            )
        )
        self.assertFalse(r["holds"])
        self.assertLessEqual(r["worlds"], 30)

    def test_a_counterexample_shows_the_columns_it_needs(self) -> None:
        from authzlib import prove

        folder = "type folder = app.folders\n  owner : user = owner_id\n  can view = owner\n"
        [r] = prove.prove(
            parse_policy(self.HEAD + folder + "invariants\n  never folder: view and {status = 'gone'}\n", "p.authz")
        )
        self.assertFalse(r["holds"])
        self.assertIn("folder 1: status = 'gone'", r["world"])
        self.assertIn("folder.owner: folder 1 -> user 1", r["world"])

    def test_a_polymorphic_row_has_one_parent(self) -> None:
        both = "  owner : user = owner_id\n  can x = owner\n  can y = not owner\n"
        text = (
            "type project = app.projects\n"
            + both
            + "type folder = app.folders\n  parent : folder, project = (parent_type, parent_id)\n"
            + both
            + "  can a = parent.x\n  can b = parent.y\ninvariants\n  never folder: a and b\n  never folder: a and not b\n"
        )
        self.assertEqual(self.proofs(text), [True, False])

    def test_a_rule_gives_no_row_the_type_leaves_out(self) -> None:
        head = "type folder = app.folders where {not archived}\n  owner : user = owner_id\n  can view = owner\nrules app.folders\n"
        self.assertTrue(
            self.same(head + "  select : {shared_flag}\n", head + "  select : {shared_flag} and {not archived}\n")
        )
        self.assertTrue(
            self.same(
                head + "  select : view or {public}\n", head + "  select : view or ({public} and {not archived})\n"
            )
        )
        self.assertFalse(self.same(head + "  select : view or {public}\n", head + "  select : view\n"))

    def test_coverage_reads_explain(self) -> None:
        from authzlib import coverage

        explain = "\n".join(
            [
                "yes  user 1 holds edit on folder 3",
                "  folder.edit = share or editor or (parent.edit and {inherit})",
                "  yes  share",
                "    folder.share = owner or org.admin or (parent.share and {inherit})",
                "    yes  owner",
                "    no   org.admin",
                "  no   editor",
                "  yes  (parent.edit and {inherit})",
            ]
        )
        self.assertEqual(
            coverage.covered([explain]),
            {
                ("folder", "edit", "share"),
                ("folder", "share", "owner"),
                ("folder", "edit", "(parent.edit and {inherit})"),
            },
        )
        c = Compiler(parse_policy(read(POLICIES["docs"])))
        c.compile("x")
        r = coverage.report(c, [explain])
        self.assertEqual(r["covered"], 3)
        self.assertIn(("line 49", "folder.edit", "editor"), r["missing"])
        self.assertIn('branches no "can" check reaches (line ', coverage.summary(r))

    def test_coverage_of_a_deny_inside_inheritance(self) -> None:
        from authzlib import coverage

        c = Compiler(
            parse_policy(
                self.HEAD + "type folder = app.folders\n  parent : folder = parent_id\n  owner : user = owner_id\n"
                "  viewer : user = viewer_id\n  can hidden = {blocked} or parent.hidden\n"
                "  can view = (owner or viewer or parent.view) and not hidden\n  can see = signed_in\n"
            )
        )
        c.compile("x")
        self.assertEqual(
            [(p, i) for _, p, i, _, _ in coverage.branches(c)],
            [
                ("hidden", "{blocked}"),
                ("hidden", "parent.hidden"),
                ("see", "signed_in"),
                ("view", "owner"),
                ("view", "viewer"),
                ("view", "parent.view (before the deny)"),
            ],
        )
        explain = "\n".join(
            [
                "yes  user 1 holds view on folder 1",
                "  folder.view = (owner or viewer or parent.view) and not hidden",
                "  yes  (view (before the deny) and not hidden)",
                "    yes  view (before the deny)",
                "      folder.view__base = (owner or viewer or parent.view) and not hidden  (its inheritance, before the deny)",
                "      yes  owner",
                "      no   viewer",
                "      no   parent.view (before the deny)",
                "    yes  not hidden",
            ]
        )
        r = coverage.report(c, [explain])
        self.assertEqual((r["covered"], r["total"]), (1, 6))
        # the branches are the ones the policy writes, in its words
        self.assertEqual(
            [(name, item) for _, name, item in r["missing"]],
            [
                ("folder.hidden", "{blocked}"),
                ("folder.hidden", "parent.hidden"),
                ("folder.see", "signed_in"),
                ("folder.view", "viewer"),
                ("folder.view", "parent.view"),
            ],
        )


class HandAnswers(unittest.TestCase):
    """The reference evaluator against answers worked out by hand from the language's reference
    (docs/reference/language.md), not by running anything. difftest holds the database to the evaluator, but both
    read the policy through one parser: a misreading there would be in both, and they would agree on it. Neither
    wrote these answers.

    A world, one fact a line:
        folder: 1, 2, 3                      the ids of a type
        folder 2 fails its where             a row the type's where leaves out
        folder 2 parent folder 1             a link: folder 2's parent is folder 1, through the relation's first
                                             source naming that subject (parent[1]: its second source)
        folder 1 viewer team#member 2        a link to a group's members; user:* *, anyone *, link tok1
        {inherit} on folder 2, 4             the rows a condition holds for (none unless said)
        doc 1: archived = false, size = 11   a row's columns: the type's simple conditions read them
        role view on folder 1 for user ann from org 1   a custom role that includes view, org 1's
    The answers: for each one asking ('' is nobody, 'service:1' a service), the ids each permission, relation or rule
    ('rule app.folders update') holds for."""

    HEAD = "app role app_user\n"

    @staticmethod
    def value(text: str) -> Scalar:
        text = text.strip()
        if text in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[text]
        if text.startswith("'"):
            return text[1:-1]
        return float(text) if "." in text else int(text)

    def world(self, pol: authzlib.parse.Policy, text: str) -> evaluate.Data:
        from authzlib.conditions import simple

        data = evaluate.Data()
        for t in pol.types.values():
            data.ids[t.name] = []
            for r in t.relations.values():
                for i, src in enumerate(r.sources):
                    for st, sr in src.subjects:
                        data.pairs[(t.name, r.name, i, st, sr or "")] = []
            if t.roles:
                for p in t.roles[1]:
                    for st, sr in t.roles[0]:
                        data.rolepairs[(t.name, p, st, sr or "")] = []
        failing: set[tuple[str, str]] = set()
        conds: dict[tuple[str, str], list[str]] = {}
        for line in [x.strip() for x in text.strip().splitlines() if x.strip()]:
            if m := re.fullmatch(r"\{(.*)\} on (\w+) (.*)", line):
                conds[(m[2], m[1])] = [x.strip() for x in m[3].split(",")]
            elif m := re.fullmatch(r"(\w+): (.*)", line):
                data.ids[m[1]] = [x.strip() for x in m[2].split(",")]
            elif m := re.fullmatch(r"(\w+) (\S+) fails its where", line):
                failing.add((m[1], m[2]))
            elif m := re.fullmatch(r"(\w+) (\S+): (.*)", line):
                data.columns.setdefault(m[1], {})[m[2]] = {
                    c.strip(): self.value(v) for c, v in (x.split("=") for x in m[3].split(","))
                }
            elif m := re.fullmatch(r"role (\w+) on (\w+) (\S+) for (\S+) (\S+)(?: from \w+ (\S+))?", line):
                st, _, sr = m[4].partition("#")
                data.rolepairs[(m[2], m[1], st, sr)].append((m[3], m[5], m[6] or ""))
            elif m := re.fullmatch(r"(\w+) (\S+) (\w+)(?:\[(\d)\])? (\S+) (\S+)", line):
                tname, oid, rname, i, subject, sid = m.groups()
                st, sr = (subject[:-2], "*") if subject.endswith(":*") else subject.partition("#")[::2]
                sources = pol.types[tname].relations[rname].sources
                n = int(i) if i else next(k for k, s in enumerate(sources) if (st, sr or None) in s.subjects)
                data.pairs[(tname, rname, n, st, sr)].append((oid, sid))
            else:
                raise ValueError(f"not a fact: {line}")
        for t in pol.types.values():
            data.valid[t.name] = [i for i in data.ids[t.name] if (t.name, i) not in failing]
            if t.name in data.columns:
                data.columns[t.name] = {i: data.columns[t.name].get(i, {}) for i in data.ids[t.name]}
        for tname, cond in evaluate.Reference(pol).conditions():
            if not (tname in data.columns and simple(cond) is not None):
                data.cond[(tname, cond)] = conds.pop((tname, cond), [])
        self.assertEqual(conds, {}, "conditions the policy doesn't have, or that its columns say")
        return data

    def check(self, policy: str, world: str, answers: dict[str, dict[str, str]], links: Sequence[str] = ()) -> None:
        # a policy the compiler takes (parsed apart: compiling splits denies, the evaluator reads them as written)
        Compiler(parse_policy(self.HEAD + policy, "hand.authz")).compile("hand.authz")
        pol = parse_policy(self.HEAD + policy, "hand.authz")
        ref = evaluate.Reference(pol)
        data = self.world(pol, world)
        rules = {f"rule {r.table} {r.command}": r for r in pol.rules}
        for who, expected in answers.items():
            state = ref.evaluate(data, who, links)
            for name, ids in expected.items():
                tname, _, perm = name.partition(".")
                got = ref.rule(state, rules[name]) if name in rules else state[(tname, perm)]
                want = {x.strip() for x in ids.split(",") if x.strip()}
                self.assertEqual(sorted(got), sorted(want), f"{name}, asked as {who or 'nobody'}")

    def test_not_takes_the_item_after_it(self) -> None:
        self.check(
            "type user = app.users\ntype doc = app.docs\n  a : user = a_id\n  b : user = b_id\n"
            "  can p = not a and b\n  can q = not (a and b)\n  can r = a or (b and not a)\n",
            "user: ann\ndoc: 1, 2, 3, 4\ndoc 1 a user ann\ndoc 1 b user ann\ndoc 2 b user ann\ndoc 3 a user ann\n",
            {
                "ann": {"doc.p": "2", "doc.q": "2, 3, 4", "doc.r": "1, 2, 3"},
                "": {"doc.p": "", "doc.q": "1, 2, 3, 4", "doc.r": ""},
            },
        )

    def test_a_condition_stops_inheritance_where_it_fails(self) -> None:
        self.check(
            "type user = app.users\ntype folder = app.folders\n  parent : folder = parent_id\n"
            "  owner : user = owner_id\n  can view = owner or (parent.view and {inherit})\n",
            "user: ann, bo\nfolder: 1, 2, 3, 4\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
            "folder 4 parent folder 3\nfolder 1 owner user ann\n{inherit} on folder 2, 4\n",
            {"ann": {"folder.view": "1, 2"}, "bo": {"folder.view": ""}, "": {"folder.view": ""}},
        )

    def test_a_row_the_where_leaves_out_holds_nothing_and_passes_nothing_on(self) -> None:
        # an archived folder and what is inside it; no rule allows anything on it either
        self.check(
            "type user = app.users\ntype folder = app.folders where {not archived}\n  parent : folder = parent_id\n"
            "  owner : user = owner_id\n  can view = owner or parent.view\n"
            "rules app.folders\n  select : view\n  update : anyone\n  delete : nobody\n",
            "user: ann, bo\nfolder: 1, 2, 3, 4\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
            "folder 4 parent folder 1\nfolder 1 owner user ann\nfolder 2 owner user bo\nfolder 2 fails its where\n",
            {
                "ann": {"folder.view": "1, 4", "rule app.folders select": "1, 4", "rule app.folders update": "1, 3, 4"},
                "bo": {"folder.view": "", "rule app.folders select": "", "rule app.folders delete": ""},
                "": {"rule app.folders update": "1, 3, 4", "rule app.folders delete": ""},
            },
        )

    def test_a_suspended_user_holds_nothing(self) -> None:
        self.check(
            "type user = app.users where {active}\ntype folder = app.folders\n  owner : user = owner_id\n"
            "  viewer : user, user:* shared\n  can share = owner\n  can view = owner or viewer\n  can open = signed_in\n",
            "user: ann, cy\nuser cy fails its where\nfolder: 1, 2, 3\nfolder 1 owner user cy\nfolder 2 viewer user:* *\n"
            "folder 3 owner user ann\n",
            {
                "ann": {"folder.view": "2, 3", "folder.share": "3", "folder.open": "1, 2, 3"},
                "cy": {"folder.view": "", "folder.share": "", "folder.open": ""},
                "": {"folder.view": "", "folder.open": ""},
            },
        )

    def test_groups_nest_loop_and_stop_at_a_group_the_where_leaves_out(self) -> None:
        self.check(
            "type user = app.users\ntype team = app.teams where {not disbanded}\n"
            "  member : user = app.team_members(team_id -> user_id)\n"
            "  member : team#member = app.teams(parent_id -> id)\n"
            "type folder = app.folders\n  owner : user = owner_id\n  viewer : user, team#member shared\n"
            "  can share = owner\n  can view = viewer\n",
            "user: ann, bo, cy\nteam: 1, 2, 3, 4, 5\nteam 3 member user ann\nteam 2 member team#member 3\n"
            "team 3 member team#member 2\nteam 1 member team#member 4\nteam 4 member user bo\nteam 4 fails its where\n"
            "team 5 member user cy\nfolder: 1, 2, 3, 4\nfolder 1 viewer team#member 2\nfolder 2 viewer team#member 1\n"
            "folder 3 viewer team#member 4\nfolder 4 viewer team#member 5\n",
            {
                "ann": {"team.member": "2, 3", "folder.view": "1"},
                "bo": {"team.member": "", "folder.view": ""},
                "cy": {"team.member": "5", "folder.view": "4"},
            },
        )

    def test_who_each_subject_is(self) -> None:
        # user:* any signed-in user, service:* any signed-in service, anyone also signed out, link who holds the
        # token; signed_in is about users; a share to service 2 is not one to user 2
        self.check(
            "type user = app.users\ntype service = app.services principal\ntype folder = app.folders\n"
            "  owner : user = owner_id\n  bot : service = bot_id\n"
            "  viewer : user, service, user:*, service:*, anyone, link shared\n"
            "  can share = owner\n  can view = owner or bot or viewer\n  can open = signed_in\n",
            "user: ann, 2\nservice: 1, 2\nfolder: 1, 2, 3, 4, 5, 6, 7\nfolder 1 viewer user:* *\n"
            "folder 2 viewer anyone *\nfolder 3 viewer link tok1\nfolder 4 viewer link tok2\n"
            "folder 5 viewer service:* *\nfolder 6 bot service 1\nfolder 7 viewer service 2\n",
            {
                "ann": {"folder.view": "1, 2, 3", "folder.open": "1, 2, 3, 4, 5, 6, 7"},
                "2": {"folder.view": "1, 2, 3", "folder.open": "1, 2, 3, 4, 5, 6, 7"},
                "service:1": {"folder.view": "2, 3, 5, 6", "folder.open": ""},
                "service:2": {"folder.view": "2, 3, 5, 7", "folder.open": ""},
                "": {"folder.view": "2, 3", "folder.open": ""},
            },
            links=["tok1"],
        )

    def test_a_deny_inside_inheritance_covers_everything_below(self) -> None:
        self.check(
            "type user = app.users\ntype folder = app.folders\n  parent : folder = parent_id\n"
            "  owner : user = owner_id\n  can hidden = {secret} or parent.hidden\n"
            "  can view = (owner or parent.view) and not hidden\n",
            "user: ann, bo, cy\nfolder: 1, 2, 3, 4, 5\nfolder 2 parent folder 1\nfolder 3 parent folder 2\n"
            "folder 4 parent folder 3\nfolder 5 parent folder 1\nfolder 1 owner user ann\nfolder 3 owner user bo\n"
            "folder 2 owner user cy\n{secret} on folder 2\n",
            {
                "ann": {"folder.view": "1, 5", "folder.hidden": "2, 3, 4"},
                "bo": {"folder.view": ""},
                "cy": {"folder.view": ""},
            },
        )

    def test_folders_and_projects_inside_each_other(self) -> None:
        self.check(
            "type user = app.users\n"
            "type project = app.projects\n  owner : user = owner_id\n  parent : folder = folder_id\n"
            "  can view = owner or parent.view\n"
            "type folder = app.folders\n  owner : user = owner_id\n  parent : folder, project = (parent_type, parent_id)\n"
            "  can view = owner or parent.view\n"
            "type file = app.files\n  folder : folder = folder_id\n  can view = folder.view\n"
            "rules app.files\n  select : view or {public}\n",
            "user: ann, bo\nproject: 1, 2\nfolder: 1, 2, 3, 4\nfile: 1, 2, 3\nproject 1 owner user ann\n"
            "folder 1 parent project 1\nfolder 2 parent folder 1\nproject 2 parent folder 2\nfolder 3 parent project 2\n"
            "folder 4 owner user bo\nfile 1 folder folder 3\nfile 2 folder folder 4\n{public} on file 3\n",
            {
                "ann": {
                    "project.view": "1, 2",
                    "folder.view": "1, 2, 3",
                    "file.view": "1",
                    "rule app.files select": "1, 3",
                },
                "bo": {"project.view": "", "folder.view": "4", "file.view": "2", "rule app.files select": "2, 3"},
                "": {"file.view": "", "rule app.files select": "3"},
            },
        )

    ROLES = (
        "type user = app.users\ntype org = app.orgs\n  admin : user = app.org_admins(org_id -> user_id)\n"
        "  can manage_roles = admin\n"
        "type folder = app.folders\n  org : org = org_id\n  owner : user = owner_id\n  roles : user{from}\n"
        "  can share = owner or org.admin\n  can view = owner or roles\n  can edit = owner or roles\n"
    )
    ROLE_WORLD = (
        "user: ann, bo\norg: 1, 2\nfolder: 1, 2, 3\nfolder 1 org org 1\nfolder 2 org org 2\n"
        "role view on folder 1 for user ann from org 1\nrole view on folder 2 for user ann from org 1\n"
        "role edit on folder 1 for user bo from org 2\nrole edit on folder 3 for user bo from org 1\n"
        "role view on folder 2 for user bo from org 2\n"
    )

    def test_roles_from_an_org_count_only_on_its_objects(self) -> None:
        self.check(
            self.ROLES.format(**{"from": " from org"}),
            self.ROLE_WORLD,
            {"ann": {"folder.view": "1", "folder.edit": ""}, "bo": {"folder.view": "2", "folder.edit": ""}},
        )

    def test_roles_without_from_count_wherever_they_are_given(self) -> None:
        self.check(
            self.ROLES.format(**{"from": ""}),
            re.sub(r" from org \d", "", self.ROLE_WORLD),
            {"ann": {"folder.view": "1, 2", "folder.edit": ""}, "bo": {"folder.view": "2", "folder.edit": "1, 3"}},
        )

    def test_simple_conditions_read_columns_as_sql_does(self) -> None:
        # NULL holds nothing: {not archived} is false where archived is NULL, not {archived} true there; NULL and
        # false is false; numbers compare as numbers; authz.uid() is a user's id, never a service's
        self.check(
            "type user = app.users\ntype service = app.services principal\ntype doc = app.docs\n"
            "  owner : user = owner_id\n  bot : service = bot_id\n  can run = bot\n"
            "  can a = owner and {not archived}\n  can b = owner and not {archived}\n"
            "  can c = {owner_id = authz.uid()}\n  can d = {size > 10 or kind in ('x', 'w')}\n"
            "  can e = {kind not in ('x', null)}\n  can f = {kind <> 'x'}\n  can g = {size > 9}\n"
            "  can h = {not (archived and kind = 'z')}\n  can i = {archived is not null}\n",
            "user: 1, 2\nservice: 1\ndoc: 1, 2, 3\ndoc 1 owner user 1\ndoc 2 owner user 1\ndoc 3 owner user 1\n"
            "doc 1: archived = false, size = 11, kind = 'z'\ndoc 2: archived = null, size = null, kind = 'x'\n"
            "doc 3: archived = true, size = 10, kind = null\n",
            {
                "1": {"doc.a": "1", "doc.b": "1, 2", "doc.c": "1, 2, 3", "doc.d": "1, 2", "doc.e": "", "doc.f": "1"},
                "2": {"doc.a": "", "doc.b": "", "doc.c": "", "doc.d": "1, 2", "doc.e": "", "doc.f": "1"},
                "service:1": {"doc.c": ""},
                "": {"doc.c": "", "doc.d": "1, 2", "doc.g": "1, 3", "doc.h": "1, 2", "doc.i": "1, 3"},
            },
        )

    def test_what_depends_on_the_column_type_is_left_to_the_database(self) -> None:
        # text in order follows the collation; text Postgres casts to the column's type; the user key's order. A
        # linked column's id compared with a number is a number (tests/conditions_test.py asks Postgres)
        from authzlib.conditions import compare, simple

        for sql in ("name < 'b'", "size = '10'", "done = 't'", "kind in ('x', 'yes')", "owner_id < authz.uid()"):
            self.assertIsNone(simple(sql), sql)
        for sql in ("name = 'b'", "size < 10", "done", "kind in ('x', 'w')", "owner_id = authz.uid()", "x = ''"):
            self.assertIsNotNone(simple(sql), sql)
        self.assertIs(compare("<", "2", 10), True)
        self.assertIs(compare("<", "2", "10"), False)

    def test_a_relation_with_two_sources(self) -> None:
        self.check(
            "type user = app.users\ntype folder = app.folders\n  viewer : user = viewer_id\n"
            "  viewer : user = app.folder_viewers(folder_id -> user_id)\n  can view = viewer\n",
            "user: ann, bo\nfolder: 1, 2, 3\nfolder 1 viewer user ann\nfolder 2 viewer[1] user ann\n"
            "folder 3 viewer[1] user bo\n",
            {"ann": {"folder.view": "1, 2"}, "bo": {"folder.view": "3"}},
        )


class Encodings(unittest.TestCase):
    """Text files are read and written as UTF-8 whatever the platform (Windows' locale is cp1252)."""

    def test_every_text_open_names_an_encoding(self) -> None:
        import ast
        import subprocess

        top = os.path.dirname(ROOT)
        try:
            listed = subprocess.run(["git", "ls-files", "*.py"], cwd=top, capture_output=True, text=True, check=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("no git here (the files are the repository's, not what builds leave)")
        missing = []
        for rel in listed.stdout.split():
            with open(os.path.join(top, rel), encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"):
                    continue
                mode = (
                    node.args[1]
                    if len(node.args) > 1
                    else next((k.value for k in node.keywords if k.arg == "mode"), None)
                )
                binary = isinstance(mode, ast.Constant) and "b" in str(mode.value)
                if not binary and not any(k.arg == "encoding" for k in node.keywords):
                    missing.append(f"{rel} line {node.lineno}")
        self.assertEqual(missing, [], 'open() without encoding="utf-8"')


class SearchPath(unittest.TestCase):
    def test_functions_that_run_conditions_resolve_names_as_the_rules_do(self) -> None:
        # a condition may name a function, operator or type without its schema ({is_open(status)}, citext's =):
        # the rules and views resolve it when applying, so every function running one resolves it on the path
        # applying vetted (SET search_path FROM CURRENT), never on pg_catalog alone, where it fails at run time
        for name, path in POLICIES.items():
            lines = [
                ln
                if re.match(r"\s*(given|as|test)\b", ln)
                else re.sub(r"\{([^{}]*)\}", lambda m: "{zz_marked((" + m.group(1) + "))}", ln)
                for ln in read(path).split("\n")
            ]
            sql = Compiler(parse_policy("\n".join(lines))).compile("x")
            running = [st for _, st in statements.split(sql) if "FUNCTION" in st[:40] and "zz_marked" in st]
            self.assertGreater(len(running), 5, name)
            for st in running:
                self.assertNotIn("search_path = pg_catalog", st.split("$f$")[0], f"{name}: {st[:120]}")


class ErrorCodes(unittest.TestCase):
    """Every mistake has a stable code and a page (authzlib/errors.py; docs/errors/ is written from it)."""

    def test_every_mistake_has_a_known_code(self) -> None:
        import ast

        from authzlib.errors import CODES

        used = set()
        for name in sorted(os.listdir(os.path.join(ROOT, "authzlib"))):
            if not name.endswith(".py") or name == "errors.py":
                continue
            src = read(f"authzlib/{name}")
            for node in ast.walk(ast.parse(src)):
                if not isinstance(node, ast.Call):
                    continue
                kind = node.func.id if isinstance(node.func, ast.Name) else None
                if kind not in ("fail", "PolicyError") or (kind == "PolicyError" and name == "parse.py"):
                    continue  # fail() itself raises the PolicyError
                code = node.args[-1] if kind == "fail" or len(node.args) == 2 else None
                value = code.value if isinstance(code, ast.Constant) else None
                self.assertTrue(
                    isinstance(value, str) and value in CODES,
                    f"authzlib/{name} line {node.lineno}: a mistake without a known code",
                )
                used.add(str(value))
            used |= {a or b for a, b in re.findall(r"\[(AZ\d{3})\]|rowstile help (AZ\d{3})", src)}
        self.assertEqual(sorted(set(CODES) - used), [], "codes nothing raises (retire them in errors.py instead)")

    # raised and caught inside rowstile, or wrapping lines that carry their own code
    UNCODED = (
        "'bad'",
        "'the policy does not match this database:%'",
        "USING ERRCODE = 'AZT00'",
        "'given ",
        "'% policy test(s) failed'",
    )

    def test_every_raise_has_a_code(self) -> None:
        """What the generated SQL raises carries a code: in its message ([AZ601], applying) or its HINT
        (rowstile help AZ701, what apps see)."""
        for name in sorted(os.listdir(os.path.join(ROOT, "authzlib"))):
            if not name.endswith(".py"):
                continue
            src = read(f"authzlib/{name}")
            for m in re.finditer(r"RAISE EXCEPTION", src):
                end = re.compile(r";(?=\n|\"|')").search(src, m.start())  # the statement's end, in SQL or a string
                stmt = src[m.start() : end.end() if end else len(src)]
                if re.search(r"\[AZ\d{3}\]|rowstile help AZ\d{3}|HINT = \{lit\(hint\)\}", stmt) or any(
                    u in stmt for u in self.UNCODED
                ):
                    continue
                self.fail(
                    f"authzlib/{name} line {src.count(chr(10), 0, m.start()) + 1}: a RAISE without a code: {stmt[:120]}"
                )

    def test_examples(self) -> None:
        """Each page's mistake gives its code; its fix compiles."""
        from authzlib import errors

        for code, c in errors.CODES.items():
            for kind, text in (("mistake", c.wrong), ("fix", c.right)):
                if not text:
                    continue
                files = dict(c.files) if kind == "fix" or code != "AZ108" else {}
                try:
                    comp = Compiler(parse_policy(errors.example(text), None, files=files))
                    comp.compile("x", transaction=False)
                    if c.when == "tests":
                        comp.compile_tests("x")
                    got = None
                except PolicyError as e:
                    got = e
                if kind == "fix" or c.when not in ("compile", "tests"):
                    self.assertIsNone(got, f"{code}'s {kind} should compile")
                else:
                    self.assertEqual(getattr(got, "code", None), code, f"{code}'s mistake gives: {got}")

    def test_pages(self) -> None:
        from authzlib import errors

        folder = os.path.join(os.path.dirname(ROOT), "docs", "errors")
        pages = {f"{code}.md": errors.page(code) for code in errors.CODES}
        pages["README.md"] = errors.index()
        if UPDATE:
            os.makedirs(folder, exist_ok=True)
            for name in os.listdir(folder):
                if name not in pages:
                    os.remove(os.path.join(folder, name))
            for name, text in pages.items():
                with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
            return
        self.assertEqual(
            sorted(os.listdir(folder)), sorted(pages), "docs/errors/ (python3 tests/unit_test.py --update)"
        )
        for name, text in pages.items():
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), text, f"docs/errors/{name} (python3 tests/unit_test.py --update)")

    def test_message_and_code(self) -> None:
        from authzlib import errors

        with self.assertRaises(PolicyError) as e:
            Compiler(
                parse_policy(
                    errors.PRELUDE + "type folder = app.folders\n  owner : person = owner_id\n  can view = owner\n"
                )
            ).compile("x")
        self.assertEqual(str(e.exception), "line 4: folder.owner: unknown type 'person' [AZ201]")
        self.assertEqual(e.exception.code, "AZ201")
        self.assertEqual(errors.split(str(e.exception)), ("line 4: folder.owner: unknown type 'person'", "AZ201"))
        self.assertEqual(errors.split("no code here"), ("no code here", None))


class StackPages(unittest.TestCase):
    """docs/stacks/: every line of code a page shows is in the tested app it comes from, so it can't drift."""

    REPO = os.path.dirname(ROOT)
    SOURCES: ClassVar[dict[str, list[str]]] = {
        "fastapi.md": ["integrations/fastapi"],
        "python.md": ["integrations/fastapi"],
        "nextjs.md": ["integrations/nextjs"],
        "node.md": ["integrations/nextjs"],
        "sql.md": ["docs/getting-started.md", "sdk/python/rowstile", "sdk/typescript"],
    }
    SKIP: ClassVar[set[str]] = {"node_modules", ".venv", ".next", ".work", "generated", "__pycache__", "dist"}
    CHECKED = ("python", "ts", "tsx", "toml", "authz", "sql")  # sh blocks are commands to type

    def lines(self, rel: str) -> set[str]:
        path = os.path.join(self.REPO, *rel.split("/"))
        files = (
            [path]
            if os.path.isfile(path)
            else [
                os.path.join(d, f)
                for d, dirs, fs in os.walk(path)
                if not dirs.__setitem__(slice(None), [x for x in dirs if x not in self.SKIP])
                for f in fs
            ]
        )
        out: set[str] = set()
        for f in files:
            if f.endswith((".py", ".ts", ".tsx", ".toml", ".authz", ".md", ".sql")):
                with open(f, encoding="utf-8") as fh:
                    out |= {" ".join(line.split()) for line in fh}
        return out

    def test_every_line_is_in_a_tested_app(self) -> None:
        folder = os.path.join(self.REPO, "docs", "stacks")
        pages = sorted(f for f in os.listdir(folder) if f.endswith(".md") and f != "README.md")
        self.assertEqual(pages, sorted(self.SOURCES), "a new page names the tested app its code comes from")
        for page in pages:
            with open(os.path.join(folder, page), encoding="utf-8") as fh:
                text = fh.read()
            have = set().union(*(self.lines(s) for s in self.SOURCES[page]))
            anywhere = "\n".join(have)
            shown = [
                (lang, " ".join(line.split()))
                for lang, block in re.findall(r"```(\w+)\n(.*?)```", text, re.S)
                if lang in self.CHECKED
                for line in block.split("\n")
                if line.strip()
            ]
            self.assertTrue(shown, page)
            missing = [
                line
                for lang, line in shown
                if line not in have and not self.caption(page, line) and not (lang == "sql" and line in anywhere)
            ]  # SQL the SDKs send, inside their strings
            self.assertEqual(
                missing, [], f"docs/stacks/{page}: lines in no tested app ({', '.join(self.SOURCES[page])})"
            )

    def caption(self, page: str, line: str) -> bool:
        """A comment naming the file a snippet is from ("// src/db.ts"), which the app has."""
        m = re.fullmatch(r"(?://|#|--) (\S+\.\w+)", line)
        return m is not None and any(
            os.path.exists(os.path.join(self.REPO, *s.split("/"), *m.group(1).split("/"))) for s in self.SOURCES[page]
        )


class Demo(unittest.TestCase):
    """demo/: the recording at the top of the README is made from the guide's own files (demo/files.py), and its
    tape still says what those files hold. The recording itself is made by hand (demo/record.sh: containers)."""

    REPO = os.path.dirname(ROOT)

    def test_the_tape_fits_the_guides_files(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("demo_files", os.path.join(self.REPO, "demo", "files.py"))
        assert spec is not None and spec.loader is not None
        files = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(files)
        with open(os.path.join(self.REPO, "demo", "demo.tape"), encoding="utf-8") as fh:
            tape = fh.read()
        with tempfile.TemporaryDirectory() as d:
            argv, sys.argv = sys.argv, ["files.py", d, os.path.join(d, "schema.sql")]
            try:
                files.main()
            finally:
                sys.argv = argv
            with open(os.path.join(d, "db", "policy.authz"), encoding="utf-8") as fh:
                policy = fh.read().split("\n")
            self.assertTrue(os.path.exists(os.path.join(d, "db", "tests", "first.authz")))
            self.assertTrue(os.path.exists(os.path.join(d, "rowstile.toml")))
            with open(os.path.join(d, "schema.sql"), encoding="utf-8") as fh:
                self.assertIn("CREATE TABLE app.notes", fh.read())
        # the lines the first scene shows: the project's relations to the note's permissions
        first, last = (int(x) for x in search(r"sed -n '(\d+),(\d+)p' db/policy.authz", tape).groups())
        self.assertEqual(policy[first - 1].split(), ["owner", ":", "user", "=", "owner_id"], "the first line shown")
        self.assertEqual(policy[last - 1].strip(), "can view = edit or project.view", "the last line shown")
        # the one word the pull request changes is there, once
        old, new = search(r"sed -i 's/([^/]+)/([^/]+)/' db/policy.authz", tape).groups()
        text = "\n".join(policy)
        self.assertEqual(text.count(old), 1, f"the tape changes {old!r}, which the guide's policy has once")
        Compiler(parse_policy(text.replace(old, new), "p.authz")).compile("p.authz")

    def test_the_readme_shows_the_recording(self) -> None:
        with open(os.path.join(self.REPO, "README.md"), encoding="utf-8") as fh:
            self.assertIn("](demo/demo.gif)", fh.read())
        size = os.path.getsize(os.path.join(self.REPO, "demo", "demo.gif"))
        self.assertLess(size, 2_000_000, "demo/demo.gif: keep it light, it loads with the README")


class ComparePages(unittest.TestCase):
    """docs/compare/: a page per alternative. What it says of rowstile is tested here (a whole policy compiles
    and is laid out as `rowstile fmt` writes it; a part of one, and the app's code, are lines of a conformance
    app); what it says of another project carries the day its docs were read, and each page says when the other
    is the better choice."""

    REPO = os.path.dirname(ROOT)
    SKIP = StackPages.SKIP
    lines = StackPages.lines
    OTHERS = ("openfga.md", "spicedb.md", "zenstack.md")  # pages that quote another project's documentation

    def test_what_the_pages_show_of_rowstile(self) -> None:
        from authzlib import fmt

        folder = os.path.join(self.REPO, "docs", "compare")
        pages = sorted(f for f in os.listdir(folder) if f.endswith(".md"))
        self.assertEqual(pages, ["app-code.md", "hand-written-rls.md", *self.OTHERS])
        have = self.lines("integrations/fastapi") | self.lines("integrations/nextjs")
        with open(os.path.join(self.REPO, "docs", "comparison.md"), encoding="utf-8") as fh:
            overview = fh.read()
        for page in pages:
            with open(os.path.join(folder, page), encoding="utf-8") as fh:
                text = fh.read()
            where = f"docs/compare/{page}"
            self.assertIn(f"](compare/{page})", overview, f"docs/comparison.md doesn't link {where}")
            self.assertIn("](../comparison.md)", text, f"{where} doesn't link the overview")
            self.assertRegex(text, r"\n## When .* the better choice\n", f"{where}: when the other is the better choice")
            if page in self.OTHERS:
                self.assertRegex(
                    text, r"read on \d{4}-\d{2}-\d{2} and linked", f"{where}: the day their docs were read"
                )
            policies = re.findall(r"```authz\n(.*?)```", text, re.S)
            self.assertTrue(policies, where)
            for policy in policies:
                if policy.startswith("app role "):
                    Compiler(parse_policy(policy, where)).compile(where)
                    self.assertEqual(fmt.format_policy(policy), policy, f"{where}: not as rowstile fmt writes it")
                else:
                    missing = [x for x in policy.split("\n") if x.strip() and " ".join(x.split()) not in have]
                    self.assertEqual(missing, [], f"{where}: policy lines in no conformance app")
            shown = [
                " ".join(line.split())
                for block in re.findall(r"```(?:python|ts|tsx)\n(.*?)```", text, re.S)
                for line in block.split("\n")
                if line.strip()
            ]
            self.assertEqual([x for x in shown if x not in have], [], f"{where}: code lines in no conformance app")

    def test_the_two_services_are_compared_with_one_policy(self) -> None:
        """The OpenFGA and the SpiceDB pages show the same model on rowstile's side: one policy, word for word."""
        shown = []
        for page in ("openfga.md", "spicedb.md"):
            with open(os.path.join(self.REPO, "docs", "compare", page), encoding="utf-8") as fh:
                shown.append(search(r"```authz\n(.*?)```", fh.read(), re.S).group(1))
        self.assertEqual(shown[0], shown[1])


class BlogPosts(unittest.TestCase):
    """docs/blog/: what a post shows can be run. Its SQL is lines of the files in the folder named like it
    (docs/blog/<slug>/, the experiment a reader can run), a policy compiles and is laid out as `rowstile fmt`
    writes it, and a plan's lines are lines of a run kept in that folder."""

    REPO = os.path.dirname(ROOT)

    def test_what_a_post_shows_is_beside_it(self) -> None:
        from authzlib import fmt

        folder = os.path.join(self.REPO, "docs", "blog")
        posts = sorted(f for f in os.listdir(folder) if re.fullmatch(r"\d{4}-\d{2}-\d{2}-[a-z0-9-]+\.md", f))
        for post in posts:
            where = f"docs/blog/{post}"
            with open(os.path.join(folder, post), encoding="utf-8") as fh:
                text = fh.read()
            beside = os.path.join(folder, post[11:-3])
            have: set[str] = set()
            runs = ""
            if os.path.isdir(beside):
                for name in sorted(os.listdir(beside)):
                    with open(os.path.join(beside, name), encoding="utf-8") as fh:
                        body = fh.read()
                    have |= {" ".join(line.split()) for line in body.split("\n")}
                    if name.endswith(".txt"):
                        runs += body
            shown = [
                " ".join(line.split())
                for block in re.findall(r"```sql\n(.*?)```", text, re.S)
                for line in block.split("\n")
                if line.strip()
            ]
            self.assertEqual([x for x in shown if x not in have], [], f"{where}: SQL in no file of its folder")
            for policy in re.findall(r"```authz\n(.*?)```", text, re.S):
                Compiler(parse_policy(policy, where)).compile(where)
                self.assertEqual(fmt.format_policy(policy), policy, f"{where}: not as rowstile fmt writes it")
            # a plan's lines are a run's own (a plan shown shortened leaves lines out, it changes none)
            plans = [
                line.strip()
                for block in re.findall(r"```\n(.*?)```", text, re.S)
                for line in block.split("\n")
                if "(actual rows=" in line or line.strip().startswith(("Filter:", "Rows Removed"))
            ]
            said = {" ".join(line.split()) for line in runs.split("\n")}
            self.assertEqual(
                [x for x in plans if " ".join(x.split()) not in said],
                [],
                f"{where}: plan lines in no run of its folder",
            )

    @staticmethod
    def shown(ms: float) -> str:
        """A timing as a post writes it: three figures from a second up, whole milliseconds from a hundred, two
        figures below."""
        if ms >= 1000:
            return f"{ms / 1000:.3g} s"
        return f"{ms:.0f} ms" if ms >= 100 else f"{ms:.2g} ms"

    def test_the_first_articles_numbers_are_its_runs(self) -> None:
        """Each cell of the article's two tables is the middle one of the three timings its run holds for that
        policy and that query, and the figures its text gives are the runs' too."""
        import statistics

        folder = os.path.join(self.REPO, "docs", "blog")
        with open(os.path.join(folder, "2026-10-07-recursive-row-level-security.md"), encoding="utf-8") as fh:
            text = fh.read()
        runs: dict[str, str] = {}
        for size, name in (("200,000 files", "run-20k-folders.txt"), ("2 million files", "run-200k-folders.txt")):
            with open(os.path.join(folder, "recursive-row-level-security", name), encoding="utf-8") as fh:
                runs[size] = fh.read()
            table = search(rf"\| {size} \|[^\n]*\n\|[-|]+\|\n((?:\|[^\n]*\n){{4}})", text).group(1)
            cells = [[c.strip() for c in row.strip("|").split("|")][1:] for row in table.strip().split("\n")]
            sections = re.split(r"\n=== ", runs[size])[1:5]
            self.assertEqual([s[:2] for s in sections], ["1.", "2.", "3.", "4."], name)
            for row, section in zip(cells, sections, strict=True):
                times = [float(x) for x in re.findall(r"Execution Time: ([\d.]+) ms", section)]
                self.assertEqual(len(times), 9, f"{name}: three queries, three times each, for {section[:40]!r}")
                medians = [statistics.median(times[i : i + 3]) for i in (0, 3, 6)]
                self.assertEqual(row, [self.shown(m) for m in medians], f"{size}: {section.splitlines()[0]}")
        small, large = runs["200,000 files"], runs["2 million files"]
        for said, run in (
            ("3,410 files in the\nsmall run, 54,610 in the large one", None),
            ("88,800 rows", small),
            ("8,728 kB", small),
            ("1,218,200", large),
            ("109 MB", large),
            ("1,365 folders", large),
            ("2,377 walks", small),
            ("5,461 folders", large),
        ):
            self.assertIn(said, text)
            if run is not None:
                number = search(r"[\d,]+", said).group(0).replace(",", "")
                self.assertRegex(run, rf"(?<!\d){number}(?!\d)", f"{said!r} is in no line of its run")
        self.assertRegex(small, r"files_user_7_sees \n-+\n\s+3410\n")
        self.assertRegex(large, r"files_user_7_sees \n-+\n\s+54610\n")
        for run in (small, large):
            # after the move, the table and a fresh build hold the same rows; and the policy on folders is refused
            self.assertRegex(
                run, r"rows_only_in_the_table \| rows_only_in_a_fresh_build \n[-+]+\n[^\n]*\|\s+0 \|\s+0\n"
            )
            self.assertIn('ERROR:  infinite recursion detected in policy for relation "folders"', run)
            self.assertIn("Parallel Index Only Scan using files_folder_id_idx on files", run.split("\n=== 4.")[1])


class SdkPackages(unittest.TestCase):
    """sdk/typescript/<package>/README.md: each package's own page on npm. It names its package, links nothing
    by a path (npm shows the file alone), and every line of code it shows is in the conformance app."""

    REPO = os.path.dirname(ROOT)
    SKIP = StackPages.SKIP
    lines = StackPages.lines

    def test_each_package_has_a_page_of_its_own(self) -> None:
        folder = os.path.join(self.REPO, "sdk", "typescript")
        packages = sorted(d for d in os.listdir(folder) if os.path.exists(os.path.join(folder, d, "package.json")))
        self.assertEqual(len(packages), 8, packages)
        have = self.lines("integrations/nextjs")
        for package in packages:
            with open(os.path.join(folder, package, "package.json"), encoding="utf-8") as fh:
                name = json.load(fh)["name"]
            path = os.path.join(folder, package, "README.md")
            self.assertTrue(os.path.exists(path), f"sdk/typescript/{package}/README.md: {name}'s page on npm")
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertTrue(text.startswith(f"# {name}\n"), f"sdk/typescript/{package}/README.md is {name}'s")
            self.assertIn(f"{name}@", text, f"sdk/typescript/{package}/README.md: the line that installs {name}")
            away = [t for t in re.findall(r"\]\(([^)]+)\)", text) if not t.startswith("https://")]
            self.assertEqual(away, [], f"sdk/typescript/{package}/README.md: links npm can't follow")
            others = set(re.findall(r"npmjs\.com/package/(@rowstile/[\w-]+)", text))
            self.assertEqual(
                others,
                {f"@rowstile/{p}" for p in packages} - {name},
                f"sdk/typescript/{package}/README.md: the other packages it lists",
            )
            shown = [
                " ".join(line.split())
                for lang, block in re.findall(r"```(\w+)\n(.*?)```", text, re.S)
                if lang in ("ts", "tsx")
                for line in block.split("\n")
                if line.strip()
            ]
            self.assertTrue(shown, package)
            missing = [
                line
                for line in shown
                if line not in have
                and not (
                    (m := re.fullmatch(r"// (\S+\.\w+)", line))
                    and os.path.exists(os.path.join(self.REPO, "integrations", "nextjs", *m.group(1).split("/")))
                )
            ]
            self.assertEqual(missing, [], f"sdk/typescript/{package}/README.md: lines not in integrations/nextjs")

    def test_the_release_ships_each_packages_own_page(self) -> None:
        with open(os.path.join(self.REPO, ".github", "workflows", "release.yml"), encoding="utf-8") as fh:
            release = fh.read()
        self.assertIn('for d in sdk/typescript/*/; do cp LICENSE "$d"; done', release)
        self.assertNotIn("cp sdk/typescript/README.md", release, "it would replace each package's own page")


def calls(text: str, opener: str) -> list[tuple[str, list[str]]]:
    """(name, arguments) for each `<opener>name(...)` in text: parentheses, brackets and quotes balanced."""
    out: list[tuple[str, list[str]]] = []
    for m in re.finditer(re.escape(opener) + r"(\w+)\(", text):
        depth, quote, args, start = 1, False, [], m.end()
        for i in range(m.end(), len(text)):
            ch = text[i]
            if ch == "'":
                quote = not quote
            elif quote:
                continue
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if not depth:
                    args.append(text[start:i])
                    out.append((m.group(1), [a.strip() for a in args if a.strip()]))
                    break
            elif ch == "," and depth == 1:
                args.append(text[start:i])
                start = i + 1
    return out


class DocPages(unittest.TestCase):
    """What the pages show that no suite runs: the language page's example compiles, the guide's files are laid
    out as `rowstile fmt` writes them, and each authz.* call a page writes is one the functions take."""

    REPO = os.path.dirname(ROOT)
    # the types the language page's example names and leaves to its include
    REST = (
        "type org = app.orgs\n  member : user = app.org_members(org_id -> user_id)\n"
        "  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}\n  can manage_roles = admin\n"
        "type project = app.projects\n  owner : user = owner_id\n  can share = owner\n  can edit = share\n"
        "  can view = edit\n"
        "type file = app.files\n  folder : folder = folder_id\n  owner : user = owner_id\n"
        "  can share = owner or folder.share\n  can edit = share or folder.edit\n  can view = edit or folder.view\n"
    )

    def page(self, *rel: str) -> str:
        with open(os.path.join(self.REPO, *rel), encoding="utf-8") as fh:
            return fh.read()

    def test_the_language_pages_example_compiles(self) -> None:
        example = search(r"```authz\n(.*?)```", self.page("docs", "reference", "language.md"), re.S).group(1)
        c = Compiler(parse_policy(example, "language.authz", files={"roles.authz": self.REST}))
        c.compile("language.authz")
        c.compile_tests("language.authz")
        # its tests name users by number (user 3, 9001): the user type's key is the default one
        self.assertEqual(c.types["user"].pktype, "bigint")

    def test_the_guides_files_are_laid_out_as_fmt_writes_them(self) -> None:
        from authzlib import fmt

        guide = self.page("docs", "getting-started.md")
        blocks = re.findall(r"```authz[ \t]+(\S+)\n(.*?)```", guide, re.S)
        self.assertEqual([name for name, _ in blocks], ["db/policy.authz", "db/tests/first.authz"])
        for name, body in blocks:
            self.assertEqual(
                fmt.format(body),
                body,
                f"docs/getting-started.md: {name} isn't as rowstile fmt writes it "
                "(the reference tells readers to run fmt --check in CI)",
            )

    def test_the_repositorys_policies_are_laid_out_as_fmt_writes_them(self) -> None:
        # what readers copy (the docs app, the cookbook, the example apps, the conformance apps): run through
        # `rowstile fmt --check` in their CI, as the reference says, they must pass. The suites' own fixtures are
        # left as they are (some are wrong on purpose)
        from authzlib import fmt

        # walked, not asked of git: CI's container doesn't own the mounted checkout, and git refuses it
        skip = {".git", "node_modules", ".venv", ".next", ".work", "dist", "tests", "editor"}
        files = []
        for top in ("core", "docs", "examples", "integrations"):
            for root, dirs, names in os.walk(os.path.join(self.REPO, top)):
                dirs[:] = [d for d in dirs if d not in skip or (d == "tests" and not root.endswith("core"))]
                files += [
                    os.path.relpath(os.path.join(root, n), self.REPO).replace(os.sep, "/")
                    for n in names
                    if n.endswith(".authz")
                ]
        self.assertGreater(len(files), 10, "the policies aren't found")
        loose = [f for f in files if fmt.format_policy(self.page(f)) != self.page(f)]
        self.assertEqual(loose, [], "not as rowstile fmt writes them: run rowstile fmt on each")

    def test_the_guides_path_is_the_commands_folder(self) -> None:
        folder = search(r'export PATH="\$PWD/([\w/]+):\$PATH"', self.page("docs", "getting-started.md")).group(1)
        self.assertTrue(
            os.path.exists(os.path.join(self.REPO, *folder.split("/"), "rowstile")),
            f"docs/getting-started.md puts {folder} on the PATH: the command isn't there",
        )

    def test_the_installing_page_holds_the_readmes_lines(self) -> None:
        import tomllib

        section = search(r"\n## Installing\n(.*?)\n## ", self.page("README.md"), re.S).group(1)
        page = self.page("docs", "installing.md")
        lines = [x for x in section.split("\n") if x.startswith("    ")]
        self.assertEqual(len(lines), 3, "README.md's Installing: npm, pip and the image")
        for line in lines:
            self.assertIn(
                line + "\n",
                page,
                "docs/installing.md (the site's page) doesn't have this line of README.md's Installing",
            )
        with open(os.path.join(self.REPO, "sdk", "python", "pyproject.toml"), "rb") as fh:
            extras = set(tomllib.load(fh)["project"]["optional-dependencies"])
        self.assertEqual(
            set(re.findall(r"`rowstile\[(\w+)\]`", page)), extras, "docs/installing.md: the Python package's extras"
        )

    def test_the_install_lines_ask_for_what_is_published(self) -> None:
        # While the version is an alpha or a candidate, a plain install gets an older release (before 0.1.0: an
        # older alpha from npm, whose `latest` doesn't move with pre-releases; pip takes the newest pre-release
        # then): each install line asks for the pre-release, and the image names its version.
        # On a final release, none still does. A build of main (-dev) is left to the release pull request.
        version = authzlib.__version__
        if version.endswith("-dev"):
            self.skipTest("main between releases: the release pull request sets the install lines")
        pre = "-" in version
        pages = [
            "README.md",
            "llms.txt",
            "sdk/python/README.md",
            "editor/README.md",
            *[
                os.path.relpath(p, self.REPO).replace(os.sep, "/")
                for p in glob.glob(os.path.join(self.REPO, "docs", "**", "*.md"), recursive=True)
            ],
            *[
                os.path.relpath(p, self.REPO).replace(os.sep, "/")
                for p in glob.glob(os.path.join(self.REPO, "sdk", "typescript", "*", "README.md"))
            ],
        ]
        wrong: list[str] = []
        for rel in pages:
            text = self.page(rel)
            if rel == "docs/installing.md":  # its section on alphas and candidates shows how to ask for one
                text = re.sub(r"\n## Alphas and release candidates\n.*?(?=\n## )", "\n", text, flags=re.S)
            fenced = False
            for line in text.split("\n"):
                if line.startswith("```"):
                    fenced = not fenced
                    continue
                if not (fenced or line.startswith(("    ", "|"))):
                    continue
                npm = re.search(r"\bnpm (?:i|install)\b.*?(?<![\w/@-])rowstile(@\w+)?(?![\w/-])", line.split("#")[0])
                pip = re.search(r"\bpip install\b.*\browstile\b", line)
                uv = re.search(r"\buv add\b.*\browstile\b", line)
                image = re.search(r"ghcr\.io/rowstile/rowstile(:[\w.-]+)?", line)
                # the SDK's packages, each with its own tag: npm's `latest` doesn't move with pre-releases, so a
                # plain `npm install @rowstile/prisma` gets the first alpha ever published
                sdk = (
                    re.findall(r"@rowstile/[\w-]+(@\w+)?", line.split("#")[0])
                    if re.search(r"\bnpm (?:i|install)\b", line)
                    else []
                )
                if pre:
                    bad = (
                        (npm and npm.group(1) != "@next")
                        or any(tag != "@next" for tag in sdk)
                        or (pip and "--pre" not in line)
                        # for uv, a requirement that names a pre-release allows rowstile's and no other
                        # package's (`--prerelease=allow` brought betas of the app's own dependencies)
                        or (uv and f">={version.split('-')[0]}a0" not in line)
                        or (image and image.group(1) != f":{version}")
                    )
                else:
                    bad = (
                        (npm and npm.group(1) == "@next")
                        or any(tag == "@next" for tag in sdk)
                        or (pip and "--pre" in line)
                        or (uv and ("--prerelease" in line or re.search(r">=[\d.]+(a|rc)\d", line)))
                        or (image and "-" in (image.group(1) or ""))
                    )
                if bad:
                    wrong.append(f"{rel}: {line.strip()}")
        self.assertEqual(
            wrong,
            [],
            f"install lines that don't get {version} ({'ask for the pre-release' if pre else 'plain installs, no pre-release'})",
        )

    def test_each_call_a_page_writes_is_one_the_functions_take(self) -> None:
        sql = Compiler(parse_policy(read("example/docs.authz"))).compile("x")
        made: dict[str, list[list[tuple[str, bool]]]] = {}  # name -> each form's (type, has a default)
        for name, params in calls(sql, "FUNCTION authz."):
            form = [(p.split()[1], "DEFAULT" in p.split()) for p in params if p.split()[0] != "OUT"]
            made.setdefault(name, []).append(form)
        pages = [
            ("README.md",),
            ("llms.txt",),
            ("core", "CONTEXT.md"),
            ("sdk", "python", "README.md"),
            ("sdk", "typescript", "README.md"),
        ]
        for folder, _, files in os.walk(os.path.join(self.REPO, "docs")):
            pages += [
                (*os.path.relpath(folder, self.REPO).split(os.sep), f) for f in sorted(files) if f.endswith(".md")
            ]
        wrong: list[str] = []
        for page in pages:
            for name, args in calls(self.page(*page), "authz."):
                if name not in made:
                    wrong.append(f"{'/'.join(page)}: authz.{name}() is not a function")
                elif (
                    args
                    and not any("..." in a for a in args)
                    and not any(
                        sum(not d for _, d in form) <= len(args) <= len(form)
                        and all(
                            form[i][0] in ("bigint", "int", "integer")
                            for i, a in enumerate(args)
                            if re.fullmatch(r"\d+", a)
                        )
                        for form in made[name]
                    )
                ):
                    wrong.append(f"{'/'.join(page)}: authz.{name}({', '.join(args)}): no form of it takes these")
        self.assertEqual(wrong, [], "calls the pages write that the functions don't take")


class Why(unittest.TestCase):
    """rowstile why: a change the database refused to try is named, not passed over (studio_test.py tries the
    ones that work, on a database)."""

    def test_a_way_that_could_not_be_tried_is_said(self) -> None:
        from authzlib import grant
        from authzlib.parse import Loc

        way = grant.Way(
            [grant.Change("link", "add user 2 to app.team_members for team 10", "INSERT ...", Loc(None, 4), 2)],
            error='null value in column "added_by" of relation "team_members" violates not-null constraint\nDETAIL: ...',
        )
        answer = grant.Answer(False, ["no   team.member"], "view = team.member  (line 7)", untried=[way])
        said = grant.describe(answer, "user:2", "doc", "1", "view").split("\n")
        self.assertEqual(
            said[-2:],
            [
                "no single change that could be tried grants it",
                "could not be tried: add user 2 to app.team_members for team 10 (null value in column "
                '"added_by" of relation "team_members" violates not-null constraint)',
            ],
        )
        nothing = grant.describe(grant.Answer(False, [], "view = owner  (line 3)"), "user:2", "doc", "1", "view")
        self.assertTrue(nothing.endswith("no single change to shares or links grants it"))

    def test_a_where_that_names_its_values(self) -> None:
        """A relation's `where` that only gives columns their values can be filled in; any other can't."""
        from authzlib import grant

        for where, held in (
            ("role = 'admin'", {"role": "admin"}),
            ("'admin' = role", {"role": "admin"}),
            ("active and not blocked and level = 2", {"active": True, "blocked": False, "level": 2}),
            ("kind in ('a', 'b') and ended is null", {"kind": "a", "ended": None}),
            ("role <> 'guest'", None),
            ("role = 'admin' or role = 'owner'", None),
            ("ended is not null", None),
            ("added_by = authz.uid()", None),
            ("expires > now()", None),
            ("role = null", None),
        ):
            with self.subTest(where=where):
                self.assertEqual(grant.settles(where), held)
        self.assertEqual(
            [grant.constant(v) for v in ("it's", 2, 1.5, True, False, None)],
            ["'it''s'", "2", "1.5", "true", "false", "NULL"],
        )

    def test_a_where_that_cannot_be_filled_in_is_named(self) -> None:
        """No candidate for it, and a note that says which relation was left out."""
        from authzlib import grant

        c = Compiler(
            parse_policy(
                errors_prelude() + "type org = app.orgs\n"
                "  admin : user = app.org_members(org_id -> user_id) where {expires > now()}\n"
                "  can manage = admin\n",
                "p.authz",
            )
        )
        g = grant.Grants(c, cast("grant.Db", None), "user", "4")
        t = c.types["org"]
        self.assertEqual(g.relation(t, "1", t.relations["admin"], 0, frozenset()), [])
        self.assertEqual(
            g.notes,
            [
                "org.admin wasn't tried: it reads app.org_members where {expires > now()}, and it isn't known "
                "which values make that true"
            ],
        )


class LlmsTxt(unittest.TestCase):
    """llms.txt links only files that exist and its policy compiles; docs/llms_full.py (run when the docs are
    published) puts the files it links, and every error page, in one."""

    REPO = os.path.dirname(ROOT)

    def test_links_and_policy(self) -> None:
        sys.path.insert(0, os.path.join(self.REPO, "docs"))
        import llms_full

        text = read("../llms.txt")
        for link in llms_full.links(text):
            self.assertTrue(os.path.exists(os.path.join(self.REPO, *link.split("/"))), f"llms.txt links {link}")
        policy = search(r"```authz\n(.*?)```", text, re.S).group(1)
        Compiler(parse_policy(policy)).compile("x")
        full = llms_full.build()
        for link in ["docs/getting-started.md", "docs/stacks/nextjs.md", "docs/errors/AZ201.md"]:
            self.assertIn(f"<!-- {link} -->", full)

    def test_the_docs_index_for_agents(self) -> None:
        # context7.json says which folders an index of docs for coding agents reads, and what an agent should
        # know first: the folders and files it names are there, and its texts fit the index's limits
        with open(os.path.join(self.REPO, "context7.json"), encoding="utf-8") as fh:
            index = json.load(fh)
        self.assertLessEqual(len(index["projectTitle"]), 100)
        self.assertLessEqual(len(index["description"]), 200)
        for folder in index["folders"]:
            self.assertTrue(os.path.isdir(os.path.join(self.REPO, folder)), f"context7.json reads {folder}/")
        for name in index["excludeFiles"]:
            self.assertTrue(os.path.isfile(os.path.join(self.REPO, name)), f"context7.json leaves out {name}")
        for folder in index["excludeFolders"]:
            self.assertTrue(
                folder.startswith("**/") or glob.glob(os.path.join(self.REPO, *folder.split("/"))),
                f"context7.json leaves out {folder}, which matches nothing",
            )
        self.assertLessEqual(len(index["rules"]), 50)
        for rule in index["rules"]:
            self.assertLessEqual(len(rule), 255, rule)


class Licence(unittest.TestCase):
    """The Python package and the Zed extension ship the licence: their copies (sdk/python/LICENSE, what the build
    takes; editor/zed/LICENSE, what Zed's registry reads) are the repository's."""

    REPO = os.path.dirname(ROOT)

    def test_the_python_package_has_the_repositorys_licence(self) -> None:
        with (
            open(os.path.join(self.REPO, "LICENSE"), encoding="utf-8") as a,
            open(os.path.join(self.REPO, "sdk", "python", "LICENSE"), encoding="utf-8") as b,
        ):
            self.assertEqual(a.read(), b.read(), "sdk/python/LICENSE: copy the repository's LICENSE")

    def test_the_zed_extension_has_the_repositorys_licence(self) -> None:
        # Zed's registry reads the licence in the extension's own folder: one at the repository's root doesn't count
        with (
            open(os.path.join(self.REPO, "LICENSE"), encoding="utf-8") as a,
            open(os.path.join(self.REPO, "editor", "zed", "LICENSE"), encoding="utf-8") as b,
        ):
            self.assertEqual(a.read(), b.read(), "editor/zed/LICENSE: copy the repository's LICENSE")


class CoverageReport(unittest.TestCase):
    """tests/coverage_report.py, which says what the suites run of authzlib and cli (ci.sh --coverage): how it reads
    runs of lines, a diff, and which steps compare the database's answers with the reference evaluator."""

    def setUp(self) -> None:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import coverage_report

        self.report = coverage_report

    def test_runs_of_lines(self) -> None:
        ranges = self.report.ranges
        # a run goes on over lines that aren't statements, and stops at one that ran
        self.assertEqual(ranges([3, 4, 6, 9, 10], [1, 3, 4, 5, 6, 8, 9, 10]), [(3, 4), (6, 6), (9, 10)])
        self.assertEqual(ranges([3, 7], [3, 7]), [(3, 7)])
        self.assertEqual(ranges([], [1, 2]), [])

    def test_the_totals(self) -> None:
        files = [
            self.report.File(name="a.py", statements=[1, 2, 3, 4], missing=[4], never={}, branches=4, branches_run=1),
            self.report.File(name="b.py", statements=[1], missing=[], never={}, branches=0, branches_run=0),
        ]
        self.assertEqual(self.report.summary(files), "run: 4 of 5 lines (80.0%), 1 of 4 branches (25.0%)")

    def test_the_lines_a_diff_changes(self) -> None:
        diff = (
            "diff --git a/core/authzlib/parse.py b/core/authzlib/parse.py\n--- a/core/authzlib/parse.py\n"
            "+++ b/core/authzlib/parse.py\n@@ -10 +12 @@ def a():\n-x\n+y\n@@ -20,2 +22,3 @@\n-a\n-b\n+c\n+d\n+e\n"
            "@@ -40,2 +44,0 @@\n-gone\n-gone\n"
            "diff --git a/core/cli/old.py b/core/cli/old.py\n--- a/core/cli/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
            "diff --git a/docs/a.md b/docs/a.md\n--- a/docs/a.md\n+++ b/docs/a.md\n@@ -1 +1 @@\n-x\n+y\n"
        )
        self.assertEqual(self.report.changed(diff), {"authzlib/parse.py": {12, 22, 23, 24}})

    def test_never_judged(self) -> None:
        judged = "random changes, compared with the reference evaluator (docs, 15 changes)"
        f = self.report.File(
            name="authzlib/compiler.py",
            statements=[1, 2, 3, 5, 6, 7],
            missing=[6, 7],
            never={},
            branches=0,
            branches_run=0,
            functions=[
                self.report.Function("Core.a", [1, 2]),
                self.report.Function("Core.b", [5, 6]),
                self.report.Function("Core.c", [7]),
            ],
            steps={1: {"unit"}, 2: {judged}, 3: {"unit", "random policies in random worlds: ..."}, 5: {"apply"}},
        )
        # Core.a's line 2 was judged; Core.b ran only where nothing compares answers; Core.c never ran
        self.assertEqual(
            self.report.never_judged(f, "a = 1\nb = 2\nc = 3\n\nd = 4\ne = 5\nf = 6\n"), ([1, 5], ["Core.b"])
        )
        # a policy's mistake is reported on lines no policy that compiles reaches: all of a fail(...) call's
        self.assertEqual(
            self.report.never_judged(
                f, 'a = 1\nb = 2\nc = 3\nif c:\n    fail(\n        "a mistake",\n        "AZ999",\n    )\n'
            ),
            ([1], ["Core.b"]),
        )
        self.assertEqual(
            self.report.mistakes("try:\n    x = 1\nexcept ValueError:\n    y = 2\nraise KeyError(\n    'k'\n)\n"),
            {3, 4, 5, 6, 7},
        )
        # a check that only reports a mistake: an if ending in one (its message made first), a loop of them
        check = "if bad:\n    msg = 'm'\n    fail(msg)\nfor x in xs:\n    if x:\n        fail('x')\n"
        self.assertEqual(self.report.mistakes(check), {1, 2, 3, 4, 5, 6})
        # but not an if with an else, nor a loop that does more than look
        does = "if bad:\n    fail('m')\nelse:\n    a = 1\nfor x in xs:\n    out.append(x)\n    assert x\n"
        self.assertEqual(self.report.mistakes(does), {2, 7})  # an assert passes: the append isn't a message
        # after a way out, what only leads on to a report makes its message
        look = "def f(n):\n    if n in names:\n        return\n    known = sorted(names)\n    fail(n, known)\n"
        self.assertEqual(self.report.mistakes(look), {4, 5})

    def test_what_nothing_runs_is_shown_with_its_text(self) -> None:
        f = self.report.File(
            name="authzlib/__init__.py",
            statements=[1, 2, 3],
            missing=[2],
            never={3: [-1, 5]},
            branches=2,
            branches_run=0,
        )
        lines = read("authzlib/__init__.py").split("\n")
        two, three = self.report.text(lines, 2), self.report.text(lines, 3)
        self.assertEqual(two, lines[1].strip())
        self.assertEqual(
            self.report.not_run(f),
            [f"{2:>11}  {two}", f"{3:>11}  never to the function's end, line 5: {three}"],
        )

    def test_what_made_a_function(self) -> None:
        kind = self.report.kind
        for (schema, name, args), want in {
            ("authz_gen", "app.files:update:refuse", "t app.files"): "authz_gen.<table>:update:refuse",
            ("authz_gen", "app.files:column_2:holds", "r app.files"): "authz_gen.<table>:column_<n>:holds",
            ("authz_int", "folder__view__why", "p_id text"): "authz_int.<type>__<name>__why",
            ("authz_int", "user__forget_id", ""): "authz_int.<type>__forget_id",
            ("authz_int", "team__update_1", ""): "authz_int.<type>__update_<n>",
            ("authz_int", "folder_project__tree2_rows_project", ""): "authz_int.<tree>_rows_<type>",
            ("authz_int", "folder_project__host_inside_parent__tree_on_links1", ""): "authz_int.<tree>_on_links<n>",
            ("authz_int", "user__manager__tree_verify", ""): "authz_int.<tree>_verify",
            ("authz_int", "rel_audit_3_ins", ""): "authz_int.rel_audit_<n>_ins",
            ("authz_gen", "folder__check_13d4d15429", ""): "authz_gen.<type>__check_<hash>",
            (
                "authz_int",
                "domain_email_org_setting__domain_email_org_settings__t_07bd0a7e",
                "",
            ): "authz_int.<tree>_<hash>",
            ("authz_int", "canon", "p_type text, p_id text"): "authz_int.canon",
            ("authz", "can", "text, text, text"): "authz.can(text, text, text)",
        }.items():
            self.assertEqual(kind(schema, name, args), want, name)
        # each function the compiler names after a policy's own words (its types, relations and permissions) has a
        # kind with none of them: a new shape of name gets a kind of its own, not one per policy
        made = r'CREATE (?:OR REPLACE )?FUNCTION (authz_gen|authz_int)\."?([^"( ]+)'
        for name, path in POLICIES.items():
            c = Compiler(parse_policy(read(path), path))
            own = {w for t in c.types.values() for w in (t.name, *t.perms, *t.relations)}
            for schema, fn in set(re.findall(made, c.compile(path))):
                if "__" in fn or ":" in fn:
                    self.assertFalse(set(re.findall(r"[a-z0-9]+", kind(schema, fn, ""))) & own, f"{name}: {fn}")

    def test_the_calls_written_beside_the_data(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "functions.tsv"), "w", encoding="utf-8") as fh:
                fh.write("step a\tauthz_x\tauthz\tcan\ttext, text, text\t3\tplpgsql definer set\n")
                fh.write("step b\tauthz_x\tauthz_gen\tapp.files:update:refuse\tt app.files\t0\tplpgsql set\n")
                fh.write("step b\tauthz_y\tauthz_gen\tapp.docs:update:refuse\tt app.docs\t2\tplpgsql set\n")
                fh.write("step b\tauthz_y\tauthz_int\tfolder__forget\t\t0\tplpgsql definer set\n")
                fh.write("step c\tauthz_y\tauthz\tverify\t\t0\tsql\n")  # inlined: never counted
                fh.write("step c\tauthz_z\tauthz\tctx\tkey text\t0\n")  # written before the language was
                fh.write("a line cut short\n")
            called = self.report.functions_measured([os.path.join(d, ".coverage")])
        self.assertEqual(len(called), 6)
        kinds = self.report.by_kind(called)
        refuse = kinds["authz_gen.<table>:update:refuse"]
        self.assertEqual((refuse.made, refuse.called, refuse.steps, refuse.counted), (2, 1, {"step b"}, True))
        self.assertFalse(kinds["authz.verify()"].counted)
        report = self.report.functions_report(called)
        # counted: can and the refusals (called), the forget and ctx (whose language was not written: counted)
        self.assertIn("2 of 4 kinds of function called", report[1])
        # never called: the one counted kind no call reached; the inlined one stands apart, not counted
        never, uncounted = (
            report.index("  authz_int.<type>__forget  (made in 1 database(s))"),
            report.index("  authz.verify()"),
        )
        self.assertLess(never, uncounted)

    def test_the_steps_that_compare_answers_are_named_so(self) -> None:
        # the report knows them by their names in run_tests.sh: a step renamed must not leave the comparison
        steps = re.split(r'\n\s*step "', read("run_tests.sh"))[1:]
        self.assertGreater(len(steps), 20)
        compares = 0
        for text in steps:
            label = text.split('"', 1)[0]
            body = re.split(r"\n\s*record ", text, maxsplit=1)[0]  # the step's own commands
            runs = re.search(r"tests/(?:difftest|genpolicy|around)\.py", body) is not None
            compares += runs
            self.assertEqual(bool(self.report.ORACLE.search(label)), runs, label)
        self.assertGreaterEqual(compares, 6)

    def test_the_settings_name_the_code(self) -> None:
        settings = read("tests/coverage.ini")
        self.assertEqual(re.findall(r"^\s+\$\{ROWSTILE_COVERAGE_CODE\}/(\S+)$", settings, re.M), ["authzlib", "cli"])
        for name in self.report.DECIDES:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, name)), name)


class Guards(unittest.TestCase):
    """Each refusal the SQL authzlib writes can raise is asked for by its own words in some suite: a check that asks
    only for an SQLSTATE can't tell which guard refused (two that answer 42501 look alike). A guard's own words are
    four in a row of the parts of its message that don't vary, which no other guard's message has, or its code
    ([AZ6xx]) when no other has that code."""

    REPO = os.path.dirname(ROOT)
    N = 4
    # guards whose every run of words another guard's message has too: words can't tell them apart, so each is
    # reached by what its check sets up. A new guard listed here wants words of its own, or a line here.
    SHARED = frozenset(
        {
            "% cannot be moved inside itself",
            "bad",
            "custom roles on % cannot grant %",
            "invalid API key",
            "no API key % of yours",
            "no caveat % in the policy",
            "no item % in review %",
            "no link % on % %",
            "no pending request %",
            "no pending request % of yours",
            "no permission %.% in the policy",
            "no role % for %",
            "no scope % in the policy",
            "no type % in the policy",
            "the policy does not allow sharing %.% with %",
            "the policy does not allow sharing %.% with a user",
            "there is no % %",
            "you cannot manage role %",
            "you cannot share % %",
            "you cannot share % % (needs %)",
            "you cannot unshare % on % %",
            "you cannot unshare % on % % (needs %)",
            "{t.name} % cannot be moved inside itself",
        }
    )
    # guards with no message of their own, in the text: a column rule's refusal, whose message is made in Python
    # (principals.sh and children.sh ask for its words), and the named tests' end, never shown (AZT00)
    NO_MESSAGE = 2

    def guards(self) -> list[tuple[str, str | None]]:
        """(file:line, the message's text as the source writes it) for each RAISE EXCEPTION in authzlib."""
        literal = re.compile(r"RAISE EXCEPTION\s+(?:USING[^;]*?MESSAGE\s*=\s*)?'((?:[^']|'')*)'")
        out = []
        for name in sorted(os.listdir(os.path.join(ROOT, "authzlib"))):
            if name.endswith(".py"):
                src = read(f"authzlib/{name}")
                for m in re.finditer(r"RAISE EXCEPTION", src):
                    lm = literal.match(src, m.start())
                    out.append((f"{name}:{src.count(chr(10), 0, m.start()) + 1}", lm.group(1) if lm else None))
        return out

    def runs(self, message: str) -> set[str]:
        """Every run of N words of the parts of the message that don't vary (% and {python} do); a part of fewer
        words, whole, if it is long enough to mean something."""
        text = message.replace("''", "'").replace("{{", "{").replace("}}", "}")
        out = set()
        for part in re.split(r"%|\{[^{}]*\}|\[AZ\d{3}\]", text):
            words = part.split()
            if len(words) >= self.N:
                out |= {" ".join(words[i : i + self.N]) for i in range(len(words) - self.N + 1)}
            elif len(" ".join(words)) >= 12:
                out.add(" ".join(words))
        return out

    def suites(self) -> str:
        """Every suite's text, white space made single and SQL's doubled quotes read back: the core's suites (but
        this file, which names the messages), the conformance apps' and the example apps' tests."""
        paths = [
            p
            for pattern in ("core/tests/*.*", "integrations/*/tests/*.*", "examples/*/backend/tests/*.*")
            for p in glob.glob(os.path.join(self.REPO, *pattern.split("/")))
            if p.endswith((".sh", ".py", ".sql", ".ts", ".tsx")) and os.path.basename(p) != "unit_test.py"
        ]
        self.assertGreater(len(paths), 40, "the suites aren't found")
        texts = []
        for p in paths:
            with open(p, encoding="utf-8", errors="replace") as fh:
                texts.append(re.sub(r"\s+", " ", fh.read()).replace("''", "'"))
        return "\n".join(texts)

    def sorted_out(self) -> tuple[list[str], set[str], int]:
        """(guards no suite asks for by their own words, the messages of those with no words of their own, how
        many have no message at all)."""
        guards = self.guards()
        seen: dict[str, int] = {}
        codes: dict[str, int] = {}
        for _, message in guards:
            for r in self.runs(message or ""):
                seen[r] = seen.get(r, 0) + 1
            for c in set(re.findall(r"\[(AZ\d{3})\]", message or "")):
                codes[c] = codes.get(c, 0) + 1
        text = self.suites()
        unasked, shared, no_message = [], set(), 0
        for where, message in guards:
            if message is None:
                no_message += 1
                continue
            own = {r for r in self.runs(message) if seen[r] == 1}
            own_codes = {c for c in re.findall(r"\[(AZ\d{3})\]", message) if codes[c] == 1}
            if not own and not own_codes:
                # its words are another's too: some check still asks for them, all of them, in order
                shared.add(message)
                parts = [p.strip() for p in re.split(r"%|\{[^{}]*\}", message.replace("''", "'")) if p.strip()]
                if not re.search(r"[^\n]{0,80}?".join(re.escape(p) for p in parts), text):
                    unasked.append(f"{where}: {message[:100]} (words another guard has too)")
            elif not any(r in text for r in own) and not any(re.search(c + r"\b", text) for c in own_codes):
                unasked.append(f"{where}: {message[:100]}")
        return unasked, shared, no_message

    def test_each_guard_is_asked_for_by_its_words(self) -> None:
        unasked, shared, no_message = self.sorted_out()
        self.assertEqual(unasked, [], "a guard no suite asks for by its own words: write a check that does")
        self.assertEqual(sorted(shared), sorted(self.SHARED), "guards whose words another has (Guards.SHARED)")
        self.assertEqual(no_message, self.NO_MESSAGE, "guards with no message of their own (Guards.NO_MESSAGE)")

    def test_the_rule(self) -> None:
        self.assertEqual(
            self.runs("you cannot give role % on % %: you do not hold %"),
            {"you cannot give role", ": you do not", "you do not hold"},
        )
        self.assertEqual(self.runs("no type % in the policy"), {"in the policy"})
        self.assertEqual(self.runs("bad"), set())
        self.assertIn("doesn't own", " ".join(self.runs("role % belongs to % %, which doesn''t own % %")))


class ParseAgreement(unittest.TestCase):
    """tests/parse_agreement.py, which compares the editors' grammar's reading of each policy with parse.py's (the
    editor job runs it on Tree-sitter's XML): it finds them alike when they are, and says where they differ."""

    POLICY = "app role app_user\ntype user = app.users\ntype doc = app.docs\n  owner : user = owner_id\n  can view = owner or {public}\n"
    # what `tree-sitter parse --xml` writes for it, cut to what the comparison reads ({public} is row 4, columns 22-30)
    XML = (
        '<sources><source name="{path}"><source_file>'
        '<app_role>app role<identifier field="name">app_user</identifier></app_role>'
        '<type>type<identifier field="name">user</identifier>=<table_name field="table">'
        '<identifier field="schema">app</identifier>.<identifier field="name">users</identifier></table_name></type>'
        '<type>type<identifier field="name">doc</identifier>=<table_name field="table">'
        '<identifier field="schema">app</identifier>.<identifier field="name">docs</identifier></table_name>'
        '<relation><identifier field="name">owner</identifier>:<subject><identifier field="type">user</identifier>'
        "</subject>=<column><identifier>owner_id</identifier></column></relation>"
        '<permission>can<identifier field="name">view</identifier>=<{op} field="expression"><ref><identifier>owner'
        '</identifier></ref>or<sql srow="4" scol="22" erow="4" ecol="30">{{<sql_text>public</sql_text>}}</sql></{op}>'
        "</permission></type></source_file></source></sources>"
    )

    def compare(self, op: str) -> tuple[int, int, list[str]]:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import parse_agreement

        with tempfile.TemporaryDirectory() as d:
            policy, xml = os.path.join(d, "p.authz"), os.path.join(d, "all.xml")
            with open(policy, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(self.POLICY)
            with open(xml, "w", encoding="utf-8") as fh:
                fh.write(self.XML.format(path=policy, op=op))
            return parse_agreement.compare(xml)

    def test_alike(self) -> None:
        self.assertEqual(self.compare("or"), (1, 0, []))

    def test_a_difference_is_found_and_placed(self) -> None:
        compared, _, problems = self.compare("and")
        self.assertEqual(compared, 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("/types/doc/perms/view[0]: the parser reads 'or', the grammar 'and'", problems[0])


class Respelling(unittest.TestCase):
    """genpolicy names a third of its policies' tables and columns as an app's own may be (capitals, words SQL
    reserves, 63 bytes): the same policies, the names alone changed, written bare in the policy and quoted in SQL."""

    def setUp(self) -> None:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import genpolicy

        self.g = genpolicy

    def test_the_same_policy_renamed(self) -> None:
        for seed in range(1, 30):
            plain, awkward = self.g.make(seed, respell=False), self.g.make(seed, respell=True)
            self.assertEqual((plain.objs, plain.invariants), (awkward.objs, awkward.invariants), seed)
            self.assertNotEqual(self.g.policy_text(plain), self.g.policy_text(awkward))
            parse_policy(self.g.policy_text(awkward), "gen.authz")  # the parser takes it
        drawn = [self.g.make(seed).spelling.awkward for seed in range(1, 301)]
        self.assertTrue(60 < sum(drawn) < 140, sum(drawn))  # about a third, drawn apart from the policy

    def test_the_names(self) -> None:
        self.assertEqual(len(self.g.AWKWARD["t3"].encode()), 63)  # as long as Postgres allows
        s = self.g.Spelling(awkward=True)
        self.assertEqual(s.policy_table("t1"), "Gp.select")
        self.assertEqual(s.table("t1"), '"Gp"."select"')
        self.assertEqual(s.table("t1_r1"), '"Gp"."Link_t1_r1"')
        self.assertEqual(
            s.cond("{exists (select 1 from gp.t1 x where x.id = this.id + 1 and x.b2)}"),
            '{exists (select 1 from "Gp"."select" x where x."Id" = this."Id" + 1 and x."order")}',
        )
        self.assertEqual(self.g.Spelling().cond("{not b3}"), "{not b3}")  # plain: as before

    def test_sql_quotes_every_awkward_name(self) -> None:
        spec = next(s for s in map(self.g.make, range(1, 50)) if s.spelling.awkward)
        sql = self.g.schema_text(spec)
        for name in ("Gp", "user", "select", "Id", "order", "parentId"):
            self.assertIn(f'"{name}"', sql)
        self.assertNotRegex(sql, r"(?<![\"\w])(Gp|parentId|Archived)(?![\"\w])", "a name unquoted")


class CheckCounts(unittest.TestCase):
    """tests/check_counts.py, which ci.sh runs on run_tests.sh's log: each suite passes as many checks as
    tests/check_counts.txt says, no fewer and no more; the random ones aren't counted."""

    LOG = (
        "=== the share API\nok    one\nok    two\n--- passed: multi scenario (1s)\n"
        "=== the scenario\n93 checks passed\n--- passed: scenario (1s)\n"
        "Ran 216 tests in 69.120s\n\nOK\n--- passed: unit (69s)\n"
        "policy errors: 132 of 133 cases\n--- FAILED: policy errors (2s)\n"
        "ok    drawn at random\n--- passed: difftest docs (14s)\n"
        "--- passed: re-apply (0s)\n"
    )

    def setUp(self) -> None:
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import check_counts

        self.c = check_counts

    def test_what_a_log_counts(self) -> None:
        self.assertEqual(
            self.c.counted(self.LOG),
            {"multi scenario": 2, "scenario": 93, "unit": 216, "policy errors": 132, "re-apply": 0},
        )

    def test_fewer_or_more_is_said(self) -> None:
        want = {"multi scenario": 3, "scenario": 93, "unit": 215, "cli": 80}  # cli: not in this log, not asked
        self.assertEqual(
            self.c.differences(self.c.counted(self.LOG), want),
            [
                "multi scenario passed 2 checks, check_counts.txt says 3",
                "policy errors passed 132 checks, check_counts.txt doesn't name it",
                "unit passed 216 checks, check_counts.txt says 215",
            ],
        )

    def test_a_count_that_isnt_fixed(self) -> None:
        got, unfixed = self.c.together([{"a": 1}, {"a": 1, "b": 2}, {"a": 3}])
        self.assertEqual(got, {"a": 1, "b": 2})
        self.assertEqual(unfixed, ["a passed 1 checks in one log and 3 in another: its count isn't fixed"])

    def test_writing_keeps_the_comments(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "counts.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# what this is\nunit 1\n")
            self.c.write(path, {"unit": 216, "scenario": 93, "re-apply": 0})
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "# what this is\nscenario 93\nunit 216\n")
            self.assertEqual(self.c.expected(path), {"scenario": 93, "unit": 216})

    def test_each_suite_written_is_one_run_tests_records(self) -> None:
        with open(os.path.join(ROOT, "run_tests.sh"), encoding="utf-8") as fh:
            recorded = set(re.findall(r'^\s*record \S+ "([^"$]+)"$', fh.read(), re.M))
        written = self.c.expected()
        self.assertEqual(sorted(set(written) - recorded), [])
        self.assertEqual(sorted(k for k in written if not self.c.FIXED.match(k)), [])  # random ones aren't counted
        self.assertNotIn(0, written.values())


class Delivery(unittest.TestCase):
    """What the workflows run, what the packages are built from, and what this folder's README says is tested."""

    REPO = os.path.dirname(ROOT)

    def workflows(self) -> dict[str, list[str]]:
        paths = sorted(glob.glob(os.path.join(self.REPO, ".github", "workflows", "*.yml")))
        # the checks below loop over these: if they weren't found, the loops would check nothing and pass
        found = {os.path.basename(p) for p in paths}
        self.assertLessEqual({"ci.yml", "nightly.yml", "pr.yml", "release.yml"}, found, "the workflows aren't found")
        paths.append(os.path.join(self.REPO, "review-ci", "github", "action.yml"))
        out: dict[str, list[str]] = {}
        for path in paths:
            with open(path, encoding="utf-8") as fh:
                out[os.path.relpath(path, self.REPO).replace(os.sep, "/")] = fh.read().split("\n")
        return out

    def test_the_workflow_checks_need_their_files(self) -> None:
        # a loop over files that aren't there checks nothing, and passes: workflows() refuses to be empty
        with mock.patch.object(glob, "glob", return_value=[]), self.assertRaises(AssertionError):
            self.workflows()

    def test_actions_are_pinned_by_commit(self) -> None:
        # a tag can be moved to another commit, which then runs with the job's rights (release.yml's publish)
        loose = []
        for path, lines in self.workflows().items():
            for n, line in enumerate(lines, 1):
                m = re.match(r"\s*(?:- )?uses: (\S+)", line)
                if m and not m.group(1).startswith("./") and not re.search(r"@[0-9a-f]{40}$", m.group(1)):
                    loose.append(f"{path}:{n}: {m.group(1)}")
        self.assertEqual(loose, [], "an action by tag or branch: name its commit, the tag in a comment")

    def test_uv_and_vsce_have_a_version(self) -> None:
        # setup-uv without one asks GitHub for uv's latest release on each run; npx takes the newest in a range
        for path, lines in self.workflows().items():
            for n, line in enumerate(lines):
                if re.match(r"\s*(?:- )?uses: astral-sh/setup-uv@", line):
                    self.assertRegex(lines[n + 1], r'^\s+with: \{version: "\d+\.\d+\.\d+"\}$', f"{path}:{n + 1}")
                for tool in re.findall(r"npx --yes (\S+)", line):
                    self.assertRegex(tool, r"@\d+\.\d+\.\d+$", f"{path}:{n + 1}")

    def test_workflows_read_only_unless_a_job_says(self) -> None:
        for path, lines in self.workflows().items():
            if path.startswith(".github/"):
                self.assertIn("permissions: {contents: read}", lines, path)

    def test_a_site_tag_publishes_pages_and_no_package(self) -> None:
        # site-v3 deploys the site with the blog and the comparison pages (site.yml); only a release's tag
        # reaches the registries, so no pattern release.yml runs on may match a site tag
        on_tags: dict[str, list[str]] = {}
        for path, lines in self.workflows().items():
            for line in lines:
                m = re.fullmatch(r"    tags: \[(.*)\]", line)
                if m:
                    on_tags[path] = re.findall(r'"([^"]+)"', m.group(1))
        self.assertEqual(
            on_tags,
            {".github/workflows/release.yml": ["v*"], ".github/workflows/site.yml": ["v*", "site-v*"]},
        )
        for pattern in on_tags[".github/workflows/release.yml"]:
            self.assertFalse(fnmatch.fnmatchcase("site-v3", pattern), pattern)
        # the folders a site tag publishes are the ones the release steps name
        folders = re.findall(
            r'"([^"]+)"', search(r"export const FOLDERS = \[(.*?)\];", read("../site/source.mjs")).group(1)
        )
        self.assertEqual(folders, ["docs/blog", "docs/compare"])
        releasing = read("../RELEASING.md")
        for folder in folders:
            self.assertIn(f"`{folder}/`", releasing)

    def test_the_launcher_knows_the_platforms_built(self) -> None:
        build = read("../packaging/npm/build.mjs")
        targets = dict(re.findall(r'^  "([a-z0-9-]+)": \{ triple: [^\n]*\n\s+sha256: "([0-9a-f]*)" \}', build, re.M))
        launcher = search(
            r"const PLATFORMS = \[(.*?)\];", read("../packaging/npm/rowstile/bin/rowstile.js"), re.S
        ).group(1)
        self.assertEqual(sorted(targets), sorted(re.findall(r'"([a-z0-9-]+)"', launcher)))
        # each Python is the bytes its release published
        self.assertEqual([k for k, sha in targets.items() if not re.fullmatch(r"[0-9a-f]{64}", sha)], [])
        self.assertGreaterEqual(len(targets), 7)

    def test_the_readme_lists_every_suite(self) -> None:
        def suites(text: str) -> set[str]:
            return set(re.findall(r"tests/[a-z_0-9]+\.(?:sh|py|sql)", text))

        missing = suites(read("run_tests.sh")) - {"tests/make_owner.sh"} - suites(read("README.md"))
        self.assertEqual(sorted(missing), [], "core/README.md's table: a suite run_tests.sh runs isn't in it")

    def job(self, workflow: str, name: str) -> str:
        """A job's text in a workflow."""
        text = "\n".join(self.workflows()[f".github/workflows/{workflow}"])
        return search(rf"^  {name}:\n(.*?)(?=^  [a-z-]+:\n|\Z)", text, re.S | re.M).group(1)

    def test_the_workflows_run_every_part_of_a_run(self) -> None:
        # run_tests.sh's parts run side by side, a job each: a part no job names would run nowhere
        runner = read("run_tests.sh")
        parts = {k: search(rf'^PARTS_{k}="([^"]+)"', runner, re.M).group(1).split() for k in ("SUITES", "SOAK")}
        # ... and the script's steps are in those parts, by those names
        self.assertEqual(set(re.findall(r"\bpart ([a-z0-9-]+);", runner)), {*parts["SUITES"], *parts["SOAK"]})
        for workflow, name, kind in (
            ("ci.yml", "suites", "SUITES"),
            ("nightly.yml", "suites", "SUITES"),
            ("nightly.yml", "soak", "SOAK"),
        ):
            with self.subTest(workflow=workflow, job=name):
                body = self.job(workflow, name)
                self.assertEqual(search(r"^        part: \[([^\]]+)\]$", body, re.M).group(1).split(", "), parts[kind])
                self.assertIn('ROWSTILE_PART: "${{ matrix.part }}"', body)
        # ci.sh hands the part to the run in the container
        self.assertIn('-e ROWSTILE_PART="${ROWSTILE_PART:-}"', read("ci.sh"))

    def test_a_command_on_one_line_is_one_yaml_value(self) -> None:
        # `run: echo "a: b"` is not a string to YAML but a mapping inside one, and the whole workflow is refused
        # when it is pushed (no job runs): a command with ": " or " #" in it goes in a block (`run: |`)
        for path, lines in self.workflows().items():
            for n, line in enumerate(lines, 1):
                m = re.match(r"\s*(?:- )?run: (?![|>])(.*)$", line)
                if m:
                    self.assertNotRegex(m.group(1), r": | #", f"{path}:{n}")

    def test_the_required_checks_fail_unless_every_part_passed(self) -> None:
        # `main` requires a check per version ("postgres (16)"): a job that waits for the version's parts. A job
        # that is skipped counts as passed, so it runs whatever became of them, and fails unless they passed
        body = self.job("ci.yml", "postgres")
        self.assertIn("    needs: suites\n", body)
        self.assertIn("    if: always()\n", body)
        self.assertIn('test "$SUITES" = success', body)
        self.assertIn('SUITES: "${{ needs.suites.result }}"', body)
        self.assertEqual(
            re.findall(r'\{pg: "(\d+)", mode: "([^"]*)"\}', body), [("16", ""), ("17", "--short"), ("18", "--short")]
        )
        self.assertEqual(
            re.findall(r'\{pg: "(\d+)", mode: "([^"]*)"\}', self.job("ci.yml", "suites")),
            [("16", ""), ("17", "--short"), ("18", "--short")],
        )

    def test_a_releases_tag(self) -> None:
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import version
        finally:
            sys.path.pop(0)
        tags = ["v0.1.0-rc.1", "v0.1.0", "v0.2.0-rc.1", "v0.2.0", "v0.10.0-rc.1"]
        self.assertEqual(version.dist_tag("0.2.0", tags), "latest")
        self.assertEqual(version.dist_tag("0.2.1", tags), "latest")
        self.assertEqual(version.dist_tag("0.10.0-rc.1", tags), "next")
        # an alpha is published like a candidate: never what `npm i rowstile` installs, also when it is the first
        self.assertEqual(version.dist_tag("0.1.0-alpha.1", []), "next")
        self.assertEqual(version.dist_tag("0.11.0-alpha.2", tags), "next")
        for good in ("0.1.0", "0.1.0-alpha.1", "0.1.0-alpha.12", "0.1.0-rc.2", "0.2.0-dev"):
            self.assertTrue(version.VERSION.match(good), good)
        for bad in ("0.1.0-alpha", "0.1.0-alpha1", "0.1.0a1", "0.1.0-beta.1", "0.1.0-alpha.1-dev", "v0.1.0-alpha.1"):
            self.assertFalse(version.VERSION.match(bad), bad)
        # a patch to an older line doesn't become what `npm i rowstile` installs
        self.assertEqual(version.dist_tag("0.1.1", [*tags, "v0.1.1"]), "release-0.1")
        self.assertEqual(version.dist_tag("0.9.3", [*tags, "v0.10.0"]), "release-0.9")
        self.assertEqual(version.dist_tag("0.1.0", []), "latest")

    def test_a_tag_leaves_nothing_unreleased(self) -> None:
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import changelog
        finally:
            sys.path.pop(0)
        text = "# Changelog\n\n## Unreleased\n\n### Fixed\n- one\n- two\n\n## 0.2.0 (release candidate)\n- older\n"
        self.assertEqual(changelog.unreleased(text), ["- one", "- two"])
        self.assertEqual(changelog.unreleased(text.replace("- one\n- two\n", "")), [])
        # an alpha's notes are its version's section, as a candidate's are
        alpha = text.replace("(release candidate)", "(alpha)")
        self.assertEqual(changelog.heading("0.2.0-alpha.1", alpha), "## 0.2.0 (alpha)")
        self.assertEqual(changelog.section("0.2.0-alpha.1", alpha), "- older\n")
        self.assertEqual(changelog.section("0.3.0-alpha.1", alpha), "")


class Editors(unittest.TestCase):
    """Zed reads its queries from the extension's folder: they are the grammar's (editor/tree-sitter-authz),
    copied. The grammar itself is tested by editor/test.sh (it needs the Tree-sitter CLI)."""

    REPO = os.path.dirname(ROOT)

    def test_zed_has_the_grammars_queries(self) -> None:
        grammar = os.path.join(self.REPO, "editor", "tree-sitter-authz", "queries")
        zed = os.path.join(self.REPO, "editor", "zed", "languages", "authz")
        names = sorted(f for f in os.listdir(grammar) if f.endswith(".scm"))
        self.assertEqual(names, sorted(f for f in os.listdir(zed) if f.endswith(".scm")))
        for name in names:
            with (
                open(os.path.join(grammar, name), encoding="utf-8") as a,
                open(os.path.join(zed, name), encoding="utf-8") as b,
            ):
                self.assertEqual(
                    a.read(), b.read(), f"editor/zed/languages/authz/{name}: copy it from the grammar's queries"
                )

    def test_zed_builds_this_grammar(self) -> None:
        # extension.toml names the commit Zed fetches the grammar from: its grammar must be this one
        with open(os.path.join(self.REPO, "editor", "zed", "extension.toml"), encoding="utf-8") as fh:
            rev = search(r'^rev = "([0-9a-f]{40})"', fh.read(), re.M).group(1)
        try:
            known = (
                subprocess.run(
                    ["git", "cat-file", "-e", f"{rev}^{{commit}}"], cwd=self.REPO, capture_output=True
                ).returncode
                == 0
            )
        except OSError:
            known = False
        if not known:
            shallow = subprocess.run(
                ["git", "rev-parse", "--is-shallow-repository"], cwd=self.REPO, capture_output=True, text=True
            ).stdout.strip()
            if shallow != "false":
                self.skipTest(f"commit {rev[:7]} isn't in this shallow checkout")
        # an ancestor: a rebase or squash merge would leave it out of main, and Zed couldn't fetch it
        self.assertEqual(
            subprocess.run(["git", "merge-base", "--is-ancestor", rev, "HEAD"], cwd=self.REPO).returncode,
            0,
            f"commit {rev[:7]} (editor/zed/extension.toml) isn't in this branch's history: merge the "
            "grammar's commit with a merge commit, or set rev to a commit that is",
        )
        # Zed builds the parser from src/ (editor/test.sh checks src/ is what grammar.js generates): a change to
        # grammar.js that generates the same src/, a comment, needs no new rev
        diff = subprocess.run(
            ["git", "diff", "--stat", rev, "--", "editor/tree-sitter-authz/src"],
            cwd=self.REPO,
            capture_output=True,
            text=True,
        ).stdout
        self.assertEqual(
            diff,
            "",
            "the grammar changed since the commit editor/zed/extension.toml names: "
            "commit it, then set rev to that commit",
        )


class Layout(unittest.TestCase):
    """One Ruff lays the Python out: the version CI checks with is the one the pre-commit hook runs and the one
    the rules for contributors name, so a commit the hook lets through passes CI's layout check. And the commits
    that only laid code out, which `git blame` skips, are commits of this history."""

    REPO = os.path.dirname(ROOT)
    NAMED_IN = (".github/workflows/ci.yml", ".githooks/pre-commit", "CONTRIBUTING.md", "CLAUDE.md", "ruff.toml")

    def test_one_ruff_everywhere(self) -> None:
        versions: dict[str, set[str]] = {}
        for path in self.NAMED_IN:
            with open(os.path.join(self.REPO, path), encoding="utf-8") as fh:
                versions[path] = set(re.findall(r"ruff@(\d+(?:\.\d+)+)", fh.read()))
        ci = versions[".github/workflows/ci.yml"]
        self.assertEqual(len(ci), 1, "CI runs one version of Ruff")
        self.assertEqual({path: found for path, found in versions.items() if found != ci}, {})

    def test_blame_skips_commits_of_main(self) -> None:
        # .git-blame-ignore-revs: git stops at a line that isn't a full hash, and skips one it doesn't know in silence
        with open(os.path.join(self.REPO, ".git-blame-ignore-revs"), encoding="utf-8") as fh:
            revs = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        self.assertTrue(revs)
        self.assertEqual([rev for rev in revs if not re.fullmatch(r"[0-9a-f]{40}", rev)], [], "full hashes only")
        try:
            shallow = subprocess.run(
                ["git", "rev-parse", "--is-shallow-repository"], cwd=self.REPO, capture_output=True, text=True
            ).stdout.strip()
        except OSError:
            shallow = ""
        if shallow != "false":
            self.skipTest("the history isn't all here")
        # an ancestor: a rebase or squash merge gives the commit another hash, and blame would skip nothing
        lost = [
            rev
            for rev in revs
            if subprocess.run(
                ["git", "merge-base", "--is-ancestor", rev, "HEAD"], cwd=self.REPO, capture_output=True
            ).returncode
        ]
        self.assertEqual(lost, [], "not in this branch's history: name commits that are on main already")


class Executable(unittest.TestCase):
    """A script that starts with #! is executable in git: on Windows (core.fileMode off) nothing shows it
    isn't, and on Linux the suite that runs it directly fails (`git update-index --chmod=+x`)."""

    REPO = os.path.dirname(ROOT)

    def test_scripts_are_executable(self) -> None:
        try:
            out = subprocess.run(
                ["git", "ls-files", "-s"], cwd=self.REPO, capture_output=True, text=True, check=True
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        missing = []
        for line in out.splitlines():
            meta, path = line.split("\t", 1)
            if meta.startswith("100644") and os.path.isfile(os.path.join(self.REPO, path)):
                with open(os.path.join(self.REPO, path), "rb") as fh:
                    if fh.read(2) == b"#!":
                        missing.append(path)
        self.assertEqual(missing, [])


class Private(unittest.TestCase):
    """Decisions and plans are kept out of this repository: no file points at them, so no reader meets a link
    they can't follow. (The patterns are split so this file doesn't match itself.)"""

    REPO = os.path.dirname(ROOT)
    SKIP: ClassVar[set[str]] = {"node_modules", "generated", "__pycache__", "dist", "out", "grammars"}
    # folders whose name starts with a dot are a tool's own (git's, an editor's, a cache), but for these two
    DOTTED: ClassVar[set[str]] = {".github", ".vitepress"}
    # (two names that stay out of the repository too, in a file or a pull request; the conventions file keeps its own)
    WORDS = re.compile(
        r"\bADRs?" + r" ?\d{4}|docs/" + r"adr\b|\b(roadmap|v1-design|developer-experience|"
        r"language-review)" + r"\.md\b|rowstile-" + r"internal|(?i:cl" + r"aude(?!\.md\b)|anth" + r"ropic)"
    )

    def test_nothing_points_at_them(self) -> None:
        self.assertFalse(
            os.path.isdir(os.path.join(self.REPO, "docs", "adr")), "decisions are kept outside this repository"
        )
        found = []
        for d, dirs, files in os.walk(self.REPO):
            dirs[:] = [x for x in dirs if x not in self.SKIP and (not x.startswith(".") or x in self.DOTTED)]
            for f in files:
                path = os.path.join(d, f)
                if os.path.getsize(path) > 4_000_000:
                    continue
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    for n, line in enumerate(fh, 1):
                        if self.WORDS.search(line):
                            found.append(f"{os.path.relpath(path, self.REPO)}:{n}: {line.strip()[:100]}")
        self.assertEqual(found, [])


class Version(unittest.TestCase):
    REPO = os.path.dirname(ROOT)

    def test_semver(self) -> None:
        self.assertRegex(authzlib.__version__, r"^\d+\.\d+\.\d+(-(alpha|rc)\.\d+|-dev)?$")

    def test_changelog_has_the_version(self) -> None:
        # a release's notes are its changelog section (packaging/changelog.py); main, at X.Y.Z-dev, needs none yet
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import changelog
        finally:
            sys.path.pop(0)
        text = changelog.read()
        self.assertTrue(text.startswith("# Changelog\n"), "CHANGELOG.md starts with its title")
        self.assertIn("\n## Unreleased\n", text)
        if not authzlib.__version__.endswith("-dev"):
            self.assertTrue(changelog.section(authzlib.__version__, text).strip(), authzlib.__version__)

    def test_a_dev_build_names_its_sources(self) -> None:
        # apply trusts "same version, same policy": two builds of main must not look the same
        if authzlib.__version__.endswith("-dev"):
            self.assertRegex(authzlib.BUILD, r"^\d+\.\d+\.\d+-dev\+[0-9a-f]{12}$")
        else:
            self.assertEqual(authzlib.BUILD, authzlib.__version__)

    def test_one_version(self) -> None:
        # the packages and the review for CI carry the compiler's version (packaging/version.py sets them all)
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import version
        finally:
            sys.path.pop(0)
        self.assertEqual(list(version.found()), [authzlib.__version__])

    def test_npms_latest_follows_next_until_a_release(self) -> None:
        # while only alphas and candidates are published, a plain `npm i rowstile` gets the newest: each release
        # moves `latest` to where `next` is (packaging/npm_latest.py); a final release ends that
        sys.path.insert(0, os.path.join(self.REPO, "packaging"))
        try:
            import npm_latest
        finally:
            sys.path.pop(0)
        target = npm_latest.target
        alphas = ["0.1.0-alpha.5", "0.1.0-alpha.6"]
        self.assertEqual(target({"next": "0.1.0-alpha.6", "latest": "0.1.0-alpha.5"}, alphas)[0], "0.1.0-alpha.6")
        self.assertEqual(target({"next": "0.1.0-alpha.6"}, alphas)[0], "0.1.0-alpha.6")
        self.assertEqual(
            target({"next": "0.1.0-rc.1", "latest": "0.1.0-alpha.6"}, [*alphas, "0.1.0-rc.1"])[0], "0.1.0-rc.1"
        )
        for tags, versions, why in (
            ({"next": "0.1.0-alpha.6", "latest": "0.1.0-alpha.6"}, alphas, "latest is 0.1.0-alpha.6 already"),
            ({"latest": "0.1.0-alpha.5"}, alphas, "nothing is published under next"),
            # once released, `latest` is a release's: an alpha of the next version stays under `next`
            ({"next": "0.2.0-alpha.1", "latest": "0.1.0"}, [*alphas, "0.1.0", "0.2.0-alpha.1"], "0.1.0 is released"),
            ({"next": "0.1.0-rc.1", "latest": "0.1.0-alpha.6"}, [*alphas, "0.1.0-rc.1", "0.1.0"], "0.1.0 is released"),
        ):
            version, said = target(tags, versions)
            self.assertIsNone(version, said)
            self.assertIn(why, said)
        # every package the release publishes: the launcher, one per platform it knows, the SDK's
        names = npm_latest.names()
        launcher = search(
            r"const PLATFORMS = \[(.*?)\];", read("../packaging/npm/rowstile/bin/rowstile.js"), re.S
        ).group(1)
        platforms = [f"@rowstile/cli-{p}" for p in re.findall(r'"([a-z0-9-]+)"', launcher)]
        sdk = glob.glob(os.path.join(self.REPO, "sdk", "typescript", "*", "package.json"))
        self.assertEqual(names[0], "rowstile")
        self.assertEqual(sorted(names[1 : 1 + len(platforms)]), sorted(platforms))
        self.assertEqual(len(names), 1 + len(platforms) + len(sdk))
        self.assertEqual(len(set(names)), len(names))
        self.assertIn("@rowstile/prisma", names)
        # moving a tag by trusted publishing takes a newer npm than Node brings: both jobs install one, by version
        for npm, enough in (("11.19.0", False), ("11.21.0", True), ("11.30.1", True), ("12.0.0", False)):
            self.assertEqual(npm_latest.new_enough(npm), enough, npm)
        self.assertTrue(npm_latest.new_enough("12.2.0") and npm_latest.new_enough("13.0.0"))
        release = read("../.github/workflows/release.yml")
        installed = re.findall(r"^      - run: npm install --global npm@(\S+)$", release, re.M)
        self.assertEqual(len(installed), 2, "the npm job and the latest job")
        for npm in installed:
            self.assertRegex(npm, r"^\d+\.\d+\.\d+$")
            self.assertTrue(npm_latest.new_enough(npm), npm)
        self.assertEqual(release.count("        run: python3 packaging/npm_latest.py --move\n"), 2)
        # by hand with latest=true nothing else runs: every other job needs `check`, which is skipped
        self.assertIn("  check:\n    if: ${{ !inputs.latest }}\n", release)
        self.assertIn("  latest:\n    if: ${{ github.event_name == 'workflow_dispatch' && inputs.latest }}\n", release)
        jobs = re.findall(r"^  ([a-z-]+):\n((?:    .*\n|\n)*)", release.split("\njobs:\n", 1)[1], re.M)
        for job, body in jobs:
            if job not in ("check", "latest"):
                self.assertRegex(body, r"    needs: (check|\[check, )", job)

    def test_the_mcp_registrys_entry_names_the_npm_package(self) -> None:
        # the registry takes server.json only if the npm package it names says the same name back (`mcpName`), and
        # refuses a description over 100 characters; `rowstile mcp` is how the package starts the server
        with open(os.path.join(self.REPO, "server.json"), encoding="utf-8") as fh:
            entry = json.load(fh)
        with open(os.path.join(self.REPO, "packaging", "npm", "rowstile", "package.json"), encoding="utf-8") as fh:
            package = json.load(fh)
        self.assertEqual(entry["name"], package["mcpName"])
        self.assertLessEqual(len(entry["description"]), 100)
        (npm,) = entry["packages"]
        self.assertEqual((npm["registryType"], npm["identifier"]), ("npm", package["name"]))
        self.assertEqual(npm["packageArguments"], [{"type": "positional", "value": "mcp"}])
        self.assertEqual(npm["version"], entry["version"])

    def test_npm_packages_name_the_repository(self) -> None:
        # npm refuses a package published with provenance unless repository.url is the repository it came from;
        # the extension's is its Marketplace page's link
        url = "git+https://github.com/rowstile/rowstile.git"
        sdks = sorted(glob.glob(os.path.join(self.REPO, "sdk", "typescript", "*", "")))
        self.assertLessEqual(
            {"client", "pg", "postgres", "prisma", "drizzle", "next", "react", "vitest"},
            {os.path.basename(os.path.dirname(d)) for d in sdks},
            "the SDK's packages aren't found",
        )
        for d in sdks + [os.path.join(self.REPO, "packaging", "npm", "rowstile"), os.path.join(self.REPO, "editor")]:
            with open(os.path.join(d, "package.json"), encoding="utf-8") as fh:
                repo = json.load(fh).get("repository", {})
            self.assertEqual(
                (repo.get("url"), repo.get("directory")), (url, os.path.relpath(d, self.REPO).replace(os.sep, "/")), d
            )
        with open(os.path.join(self.REPO, "packaging", "npm", "build.mjs"), encoding="utf-8") as fh:
            self.assertIn(f'url: "{url}"', fh.read())

    def test_applying_records_it(self) -> None:
        self.assertIn("version text NOT NULL", compiled("docs"))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if a != "--update"], verbosity=1)
