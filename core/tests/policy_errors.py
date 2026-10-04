#!/usr/bin/env python3
"""policy_errors: mistakes in a policy are reported clearly, with a line number.

    python3 tests/policy_errors.py [--db authz_errors]

Compile-time cases need nothing else. Apply-time cases (the database is the only
one who knows) run against tests/alt_schema.sql in a scratch database.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import re  # noqa: E402

from authzlib import Compiler, PolicyError, parse_policy  # noqa: E402
from authzlib.errors import CODES, split  # noqa: E402


def coded(message: str) -> bool:
    """The message ends with a known code (authzlib/errors.py)."""
    return split(message.strip())[1] in CODES

BASE = """app role app_user
type user = alt.users
type grp = alt.groups (gid)
  member : user = alt.group_members(group_id -> user_id)
type doc = alt.docs (doc_no)
  owner  : user = owner_id
  parent : doc  = up
  reader : user, grp#member  shared
  can share = owner or parent.owner
"""

# (what, policy text appended to BASE, expected piece of the message, expected line or None)
COMPILE = [
    ("a dollar-quote tag in a condition", "  can see = owner and {up <> 0 or '$f$' = ''}\n",
     "contains $f$, which ends the generated function it goes in", 10),
    ("a character that doesn't print, shown escaped", "  can see = owner \x01\n", "unexpected '\\x01' in expression", 10),
    ("a typo in a relation's only use: the typo is named, not the relation as unused",
     "  editor : user = owner_id\n  can edit = editr\n", "doc has no relation or permission 'editr'", 11),
    ("custom roles from a shared relation", "  roles : user from reader\n  can view = owner or roles\n",
     "custom roles on doc come from 'reader', which must be a relation of doc kept in a column or a table", 10),
    ("custom roles from a relation that isn't there", "  roles : user from org\n  can view = owner or roles\n",
     "custom roles on doc come from 'org'", 10),
    ("custom roles written the old way", "  roles : user, grp#member grant view, share from parent\n",
     "custom roles are written where they give a permission now: `roles : user, grp#member from parent`, and "
     "`roles` in each of view, share", 10),
    ("roles under a not", "  roles : user\n  can view = owner and not roles\n",
     "doc.view: `not roles` would take a permission away", 11),
    ("a roles line no permission uses", "  roles : user\n", "no permission writes `roles`", 10),
    ("roles in a type without a roles line", "  can view = owner or roles\n",
     "doc.view writes `roles`, but doc has no `roles : ...` line", 10),
    ("roles in a rule", "  roles : user\n  can view = owner or roles\nrules alt.docs\n  select : view or roles\n",
     "`roles` goes in a permission, which says what a custom role gives", 13),
    ("roles in an invariant", "  roles : user\n  can view = owner or roles\ninvariants\n  never doc: roles\n",
     "`roles` goes in a permission", 13),
    ("roles followed by a dot", "  roles : user\n  can view = owner or roles.view\n",
     "doc.view: `roles` gives the permission it is written in; it isn't a relation to follow", 11),
    ("a relation named roles", "  roles : user = owner_id\n",
     "`roles : ...` says who may hold custom roles; name the relation something else", 10),
    ("a permission named roles", "  can roles = owner\n", "'roles' is where custom roles give a permission", 10),
    ("a relation named like a word that continues a line", "  where : user = owner_id\n", "'where' is a word of the language", 10),
    ("a relation named and", "  and : user = owner_id\n", "'and' is a word of the language", 10),
    ("a permission named or", "  can or = owner\n", "'or' is a word of the language", 10),
    ("a plain update rule written with before", "rules alt.docs\n  update before : share\n",
     "a plain update rule is checked on the row before and after", 11),
    ("anyone or link with a relation",
     "type thing = alt.docs (doc_no)" + chr(10) + "  viewer : user, link#member  shared" + chr(10), "link stands alone", 11),
    ("a type named like a special subject",
     "type anyone = alt.docs (doc_no)" + chr(10), "subject of its own", 10),
    ("unknown subject type",
     "  editor : robot = owner_id\n", "unknown type 'robot'", 10),
    ("unknown group relation",
     "  editor : grp#admin shared\n", "grp has no relation or permission 'admin'", 10),
    ("unknown name in a permission",
     "  can view = owner or viewer\n", "doc has no relation or permission 'viewer'", 10),
    ("following a permission with a dot",
     "  can view = owner\n  can edit = view.x\n", "'view' is a permission; only relations can be followed", 11),
    ("following a relation to users, to something they don't have",
     "  can view = owner.view\n", "user has no relation or permission 'view'", 10),
    ("following a relation to groups",
     "  can view = reader.member\n", "doc.reader links to groups, anyone or links, so there is nothing to follow", 10),
    ("using a link as if it held users",
     "  can view = parent\n", "doc.parent links to doc objects, not users; follow it with a dot", 10),
    ("permissions that depend on each other",
     "  can a = owner or b\n  can b = a\n", "depends on itself", None),
    ("inheritance with no starting point",
     "  can view = parent.view\n", "doc.view needs a starting point besides inheritance", 10),
    ("inheritance narrowed by something other than a condition",
     "  can view = owner or (parent.view and reader)\n",
     "inheritance through parent can only be narrowed with {conditions}", 10),
    ("inheritance that depends on the time",
     "  can view = owner or (parent.view and {created_at > now() - interval '1 day'})\n",
     "can't limit inheritance: it depends on now", 10),
    ("inheritance that depends on the user",
     "  can view = owner or (parent.view and {owner_id <> authz.uid()})\n",
     "can't limit inheritance: it depends on authz.uid", 10),
    ("a group made only of itself",
     "type team = alt.groups (gid)\n  member : team#member shared by x\n  can x = member\n",
     "team.member only contains itself; add a source of users", 11),
    ("a relation defined as a permission too",
     "  can view = owner\n  view : user = owner_id\n", "doc.view is already a permission", 11),
    ("two kinds of subject on a column",
     "  editor : user, grp#member = owner_id\n", "a column or table source links to exactly one kind of subject", 10),
    ("a rule for a table with no type",
     "rules alt.nothing\n  select : view\n", "rules for alt.nothing, but no type maps to that table", 11),
    ("update after without update",
     "  can view = owner\nrules alt.docs\n  select : view\n  update after : view\n",
     "'update after' refines updates, so alt.docs needs an 'update' rule too", 13),
    ("a relation named like a word the language had",
     "  everyone : user = owner_id\n  can view = everyone\n", "'everyone' is a word of the language", 10),
    ("a relation named like a word of the language",
     "  nobody : user = owner_id\n  can view = nobody\n", "'nobody' is a word of the language", 10),
    ("a permission named anyone", "  can anyone = owner\n", "'anyone' is a word of the language", 10),
    ("everyone in an expression", "  can view = owner or everyone\n",
     "write `anyone` instead of `everyone` (signed in or not", 10),
    ("and next to or", "  can view = owner or parent.owner and {not locked}\n",
     "`and` and `or` meet without parentheses, which reads two ways: write owner or (parent.owner and {not locked})", 10),
    ("and next to or, the other way", "  can view = not {locked} and owner or anyone\n",
     "write (not {locked} and owner) or anyone", 10),
    ("and next to or across a continuation line", "  can view = owner\n           or parent.owner and {not locked}\n",
     "write owner or (parent.owner and {not locked})", 10),
    ("the old 'check' keyword",
     "  can view = owner\nrules alt.docs\n  select : view\n  update : view\n  update up check : view\n",
     "write 'after' instead of 'check' (checked on the row after the change): update up after : ...", 14),
    ("before or after on a command other than update",
     "  can view = owner\nrules alt.docs\n  select after : view\n",
     "only update rules can name columns, 'before' or 'after'", 12),
    ("a relation nothing uses (a typo for a second source)",
     "  reader : grp#member = alt.doc_groups(doc_no -> gid)\n  raeder : user = alt.doc_readers(doc_no -> user_id)\n"
     "  can view = owner or reader\n",
     "doc.raeder is declared but nothing uses it", 11),
    ("shared without a share permission to share it",
     "type memo = alt.docs (doc_no)\n  owner : user = owner_id\n  reader : user  shared\n  can view = owner or reader\n",
     "memo.reader is shared, which needs a share permission on memo", 12),
    ("a column rule on select",
     "  can view = owner\nrules alt.docs\n  select owner_id : view\n",
     "only update rules can name columns", 12),
    ("the same rule twice",
     "  can view = owner\nrules alt.docs\n  select : view\n  select : owner\n",
     "alt.docs has two 'select' rules", 13),
    ("an expression that doesn't parse",
     "  can view = owner or (parent.view and {x}\n", "missing )", 10),
    ("an unclosed condition",
     "  can view = owner or {x = 1\n", "a { condition is missing its closing }", 10),
    ("a badly written relation",
     "  editor user = owner_id\n", "write relations as", 10),
    ("a name with the separator generated names use",
     "type my__doc = alt.docs (doc_no)\n", "names can't contain '__'", 10),
    ("brackets for a key of one column",
     "  dp : grp = [owner_id, up]\n", "the subject is a grp, whose key is one column, but this source gives 2 columns", 10),
    ("one column for a composite key",
     "type pair = alt.doc_links (child, parent)\ntype thing = alt.docs (doc_no)\n  p : pair = up\n  can view = p.x\n",
     "the subject is a pair, whose key is [child, parent], but this source gives 1 column: write them in square brackets", 12),
    ("a composite key with a timestamp",
     "type ev = alt.docs (doc_no, created timestamptz)\n", "created is timestamptz: a composite key's columns must be", 10),
    ("a badly written key",
     "type ev = alt.docs (doc_no bigint uuid)\n", "write the key as (column [type])", 10),
    ("type:* of a type that doesn't sign in",
     "  sh : user, grp:*  shared\n  can view = owner or sh\n", "grp:* means any signed-in grp, but grp doesn't sign in", 10),
    ("a principal type with a composite key",
     "type svc = alt.doc_links (child, parent) principal\n", "the svc type signs in, so it needs a key of one column", 10),
    ("referring to a generated name",
     "  can view = owner or parent.view__base\n", "names with '__' are generated ones", 10),
    ("a deny that doesn't cover what is below",
     "  can denied = owner\n  can view = (reader or parent.view) and not denied\n",
     "`not denied` must cover everything below, so denied must inherit through parent", 11),
    ("a deny by a relation",
     "  blocked : user = owner_id\n  can view = (reader or parent.view) and not blocked\n",
     "blocked is a relation: make a permission that inherits", 11),
    ("a deny that has a deny of its own",
     "  can gone = owner or parent.gone\n  can denied = (reader or parent.denied) and not gone\n"
     "  can view = (owner or parent.view) and not denied\n",
     "denied has a deny of its own, which can cut it below a denied object", 12),
    ("rules for a table two types map to",
     "type doc2 = alt.docs (doc_no)\n  owner : user = owner_id\n  can see = owner\nrules alt.docs\n  select : see\n",
     "rules for alt.docs, which types doc and doc2 both map to", 14),
    ("a scope naming a generated permission",
     "  can view = (owner or parent.view) and not share\nscope s = doc.view__base\n",
     "names with '__' are generated ones", 11),
    ("a deny through a link, not a permission",
     "  can denied = owner or parent.denied\n  can view = (reader or parent.view) and not parent.denied\n",
     "a deny on it is `not <permission of doc>`", 11),
    ("inheritance joined with another permission",
     "  can view = (reader or parent.view) and owner\n",
     "can only join its inheritance with {conditions} and `not <permission>`", 10),
    ("inheritance limited by the literal 'now'",
     "  can view = owner or (parent.view and {'now'::timestamptz > created})\n",
     "'now' means the current time", 10),
    ("an inheritance link table filtered by time",
     "  linked : doc = alt.doc_links(child -> parent) where {now() > '2000-01-01'}\n  can view = owner or linked.view\n",
     "can't limit inheritance: it depends on now", 10),
    ("following a relation to two types when one lacks the permission",
     "  holder : doc, grp = (holder_type, holder_id)\n  can view = owner or holder.view\n",
     "grp has no relation or permission 'view'", 11),
    ("user:* on a column",
     "  editor : user:* = owner_id\n", "user:* (or another type:*), anyone and link can only be used with 'shared'", 10),
    ("inheritance through a relation shared with anyone",
     "  shortcut : doc, anyone shared\n  can view = owner or shortcut.view\n",
     "doc.shortcut links to groups, anyone or links, so there is nothing to follow", 11),
    ("a type whose where depends on the time, with inheritance",
     "  can view = owner or parent.view\ntype doc2 = alt.docs (doc_no) where {created > now()}\n"
     "  up : doc2 = up\n  owner : user = owner_id\n  can see = owner or up.see\n",
     "can't decide who inherits (the type's where): it depends on now", 11),
    ("sharing by a permission that does not exist",
     "  writer : user shared by edit\n", "doc.writer is shared by 'edit', but doc has no such permission", 10),
    ("two permissions of one type inheriting through each other",
     "  can a = owner or parent.b\n  can b = parent.a\n", "inherit through each other", None),
    ("an inheritance link table filtered by another table",
     "  linked : doc = alt.doc_links(child -> parent) where {exists (select 1 from alt.holds)}\n"
     "  can view = owner or linked.view\n",
     "doc.linked is used for inheritance, so its where {...} can only use the columns of alt.doc_links", 10),
    ("a mask without a view",
     "  can view = owner\nrules alt.docs\n  select : view\n  mask title : owner\n",
     "masks are applied by a view: write 'rules alt.docs view <schema.view_name>'", 13),
    ("a masked view without a select rule",
     "  can view = owner\nrules alt.docs view alt.docs_v\n  update : view\n",
     "the view alt.docs_v shows the rows 'select' allows, so alt.docs needs a select rule", 11),
    ("a column masked twice",
     "  can view = owner\nrules alt.docs view alt.docs_v\n  select : view\n  mask title : owner\n  mask title : view\n",
     "alt.docs.title is masked twice", 14),
    ("an invariant on an unknown type",
     "  can view = owner\ninvariants\n  never robot: view\n", "unknown type 'robot'", 12),
    ("the app role named twice", "app role other_app\n", "the app role is named twice (app_user and other_app)", 10),
    ("impersonate on a type other than user", "  can impersonate = owner\n",
     "doc.impersonate: authz.view_as asks for `impersonate` on the user type", 10),
    ("manage_keys on a type that doesn't sign in", "  can manage_keys = owner\n",
     "doc.manage_keys: API keys are made for types that sign in, and doc doesn't", 10),
    ("break_glass with nothing to give", "type grp2 = alt.groups (gid)\n  boss : user = owner_id\n  can break_glass = boss\n",
     "grp2.break_glass: authz.break_glass gives its holder a relation of grp2 shared with a user", 12),
    ("manage_roles with no roles to make", "  can manage_roles = owner\n",
     "doc.manage_roles lets people create custom roles owned by a doc, but no roles line counts them", 10),
    ("roles from an owner nobody may make roles for", "  roles : user from parent\n  can view = owner or roles\n",
     "custom roles on doc are the roles of its parent, which people with manage_roles on a doc create, and doc has "
     "no `can manage_roles`", 10),
    ("this in a caveat", "caveat near = {this.up = 1}\n", "caveat near: a caveat is checked with each request", 10),
    ("this as a table's name in a condition",
     "  can view = owner or {exists (select 1 from alt.holds this where this.target = doc_no)}\n",
     "`this` is the row the condition is about (this.column); call the table something else", 10),
    ("roles nobody may make", "  roles : user\n  can view = owner or roles\n",
     "custom roles on doc are made by people with manage_roles on their owner, and no type has `can manage_roles`", 10),
]

# whole policies, without BASE: (what, policy, expected piece of the message, expected line)
WHOLE = [
    ("no app role", "type user = alt.users\n", "name the app role, the Postgres role your app connects as", 1),
    ("the app role written the old way", "role app_user\ntype user = alt.users\n", "write `app role app_user`", 1),
    ("PUBLIC as the app role", "app role public\ntype user = alt.users\n", "not PUBLIC", 1),
]

APPLY = [
    ("a table that doesn't exist",
     "type thing = alt.things\n  owner : user = owner_id\n  can view = owner\n",
     "line 10: table alt.things not found"),
    ("a column that doesn't exist",
     "  editor : user = editor_id\n  can view = editor\n", "line 10: column editor_id not found in alt.docs"),
    ("inheritance reading a view",
     "  can view = owner or (parent.view and {not exists (select 1 from alt.held h where h.target = doc_no)})\n",
     "reads alt.held, which is not a table"),
    ("inheritance calling a function that isn't IMMUTABLE",
     "  can view = owner or (parent.view and {alt.is_open(doc_no)})\n",
     "line 10: a condition used for inheritance calls alt.is_open(bigint), which is not IMMUTABLE"),
    ("a key declared with the wrong type",
     "type doc3 = alt.docs (doc_no uuid)\n  owner : user = owner_id\n  can see = owner\n",
     "line 10: alt.docs.doc_no is not uuid; write its type after the key"),
    ("inheritance limited by a time-zone dependent expression",
     "  can view = owner or (parent.view and {created + interval '1 day' > '2020-01-01'})\n",
     "line 10: a condition that limits inheritance must give the same answer for every user at any time"),
]

# policies that must apply cleanly although their names are awkward
APPLY_OK = [
    ("names longer than Postgres allows (63 bytes) are shortened consistently",
     "type a_type_with_a_really_quite_extraordinarily_long_name_for_testing = alt.docs (doc_no)\n"
     "  an_equally_long_relation_name_that_goes_on_and_on_and_on : a_type_with_a_really_quite_extraordinarily_long_name_for_testing = up\n"
     "  owner : user = owner_id\n"
     "  can a_permission_whose_name_is_also_far_too_long_to_fit = owner\n"
     "     or an_equally_long_relation_name_that_goes_on_and_on_and_on.a_permission_whose_name_is_also_far_too_long_to_fit\n", {}),
    ("an empty search_path while applying",
     "  can view = owner\n", {"PGOPTIONS": "-c search_path="}),
    ("a table named with a reserved word",
     "type grp2 = alt.group (gid)\n  owner : user = owner_id\n  can see = owner\nrules alt.group\n  select : see\n", {}),
    ("memberships read from a view (not audited, but usable)",
     "type grp4 = alt.groups (gid)\n  member : user = alt.member_view(group_id -> user_id)\n  can see = member\n", {},
     "INSERT INTO alt.users VALUES (1); INSERT INTO alt.groups VALUES (1, 1); INSERT INTO alt.group_members VALUES (1, 1);"
     "SET authz.user_id = 1; DO $$ BEGIN IF NOT authz.can('grp4', '1', 'see') THEN RAISE EXCEPTION 'no'; END IF; END $$;"),
    ("a link table's where calling a function found on the search_path; writes to the table still work",
     "type grp3 = alt.groups (gid)\n  member : user = alt.group_members(group_id -> user_id) where {is_active(active)}\n"
     "  can see = member\n", {"PGOPTIONS": "-c search_path=alt,public"},
     "INSERT INTO alt.users VALUES (1); INSERT INTO alt.groups VALUES (1, 1); INSERT INTO alt.group_members VALUES (1, 1);"
     "UPDATE alt.group_members SET active = false; DELETE FROM alt.group_members; TRUNCATE alt.group_members;"),
]

APPLY_SETUP = """
CREATE VIEW alt.held AS SELECT target FROM alt.holds;
CREATE FUNCTION alt.is_open(bigint) RETURNS boolean LANGUAGE sql STABLE AS 'SELECT true';
CREATE TABLE alt."group" (gid bigint PRIMARY KEY, owner_id bigint);
GRANT SELECT ON alt."group" TO app_user;
CREATE VIEW alt.member_view AS SELECT group_id, user_id FROM alt.group_members;
CREATE FUNCTION alt.is_active(boolean) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT $1';
"""


# Included files passed as a map, the way the rowfence command passes them: never read from disk.
# (what, main policy, files, expected start of the message)
INCLUDES = [
    ("an include missing from the files", 'include "roles.authz"\n', {}, "line 1: can't find roles.authz"),
    ("a server file", 'include "/etc/passwd"\n', {"/etc/passwd": BASE},
     "line 1: /etc/passwd: an included file is in the policy's folder"),
    ("a file above the policy's folder", 'include "sub/../../x.authz"\n', {"../x.authz": BASE},
     "line 1: sub/../../x.authz: an included file is in the policy's folder"),
    ("a file above, from an included file", 'include "sub/a.authz"\n',
     {"sub/a.authz": 'include "../../x.authz"\n', "../x.authz": BASE},
     "sub/a.authz line 1: ../../x.authz: an included file is in the policy's folder"),
    ("a backslash", 'include "sub\\x.authz"\n', {"sub\\x.authz": BASE},
     "line 1: sub\\x.authz: an included file is in the policy's folder"),
    ("a drive", 'include "C:x.authz"\n', {"C:x.authz": BASE}, "line 1: C:x.authz: an included file is in the policy's folder"),
    ("a mistake in an included file names that file",
     'include "sub/x.authz"\n', {"sub/x.authz": BASE + "  can view = no_such_name\n"}, "sub/x.authz line 10:"),
    ("an include resolved from the including file's folder",
     'include "sub/a.authz"\n', {"sub/a.authz": 'include "b.authz"\n', "b.authz": BASE}, "sub/a.authz line 1: can't find b.authz"),
    ("the same file twice", 'include "a.authz"\ninclude "a.authz"\n', {"a.authz": BASE}, "line 2: a.authz is included twice"),
]


# named tests (compiled with their SQL): (what, text appended to BASE, expected piece of the message, expected line)
TESTS = [
    ("a $name used before a given names it", 'test "t"\n  user $ann can share doc 1\n', "$ann is not named yet", 11),
    ("... also inside a statement", 'test "t"\n  as user 1 refused {INSERT INTO alt.docs VALUES ($doc)}\n',
     "$doc is not named yet", 11),
    ("acting as a type that doesn't sign in", 'test "t"\n  given g = {SELECT 1}\n  grp $g can share doc 1\n',
     "'grp' doesn't sign in", 12),
    ("a line that is none of a test's", 'test "t"\n  user 1 maybe share doc 1\n', "a test's lines are", 11),
    ("a test with no lines", 'test "t"\n', "test 't' has no lines", 10),
    ("two tests with one name", 'test "a"\n  user 1 can share doc 1\ntest "a"\n  user 1 can share doc 1\n',
     "already a test named 'a'", 12),
    ("a permission that doesn't exist, in a named test", 'test "t"\n  user 1 can edit doc 1\n',
     "doc has no permission 'edit'", 11),
    ("the test section acting as a type that doesn't sign in", "test\n  grp 1 can share doc 1\n",
     "'grp' doesn't sign in", 11),
    ("the test section acting as a type that isn't there", "test\n  bot 1 can share doc 1\n",
     "'bot' doesn't sign in", 11),
    ("a statement in the test section", "test\n  as user 1 allowed {SELECT 1}\n",
     "the test section checks the data already there", 11),
    ("a $name in the test section", "test\n  user $ann can share doc 1\n", "$ann is not named yet", 11),
]


def compile_policy(text: str, tests: bool = False, files: dict[str, str] | None = None) -> str:
    c = Compiler(parse_policy(text, files=files))
    return c.compile_tests("t") if tests else c.compile("t")


def main() -> None:
    db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_errors"
    os.chdir(os.path.dirname(HERE))
    fails = 0
    for what, extra, want, line in COMPILE:
        try:
            compile_policy(BASE + extra)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = want in got and (line is None or got.startswith(f"line {line}:")) and coded(got)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what}: {got}")
    for what, text, want, line in WHOLE:
        try:
            compile_policy(text)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = want in got and got.startswith(f"line {line}:") and coded(got)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what}: {got}")

    try:
        compile_policy(BASE + "  can view = owner\ntest\n  user 1 can edit doc 1\n", tests=True)
        got = "(compiled without error)"
    except PolicyError as e:
        got = str(e)
    ok = "doc has no permission 'edit'" in got and coded(got)
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  a test of a permission that doesn't exist: {got}")

    for what, extra, want, line in TESTS:
        try:
            compile_policy(BASE + extra, tests=True)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = want in got and got.startswith(f"line {line}:") and coded(got)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  named tests: {what}: {got}")
    try:
        c = Compiler(parse_policy(BASE))
        c.add_test_files({"more.authz": "type x = alt.x\n"})
        got = "(compiled without error)"
    except PolicyError as e:
        got = str(e)
    ok = got.startswith("more.authz: a test file holds only named tests") and coded(got)
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  named tests: a test file with a type in it: {got}")
    try:
        c = Compiler(parse_policy(BASE))
        c.add_test_files({"more.authz": 'test "t"\n  user 1 can view doc 1\n'})
        c.tests_function_sql()
        got = "(compiled without error)"
    except PolicyError as e:
        got = str(e)
    ok = got.startswith("more.authz line 2: doc has no permission 'view'") and coded(got)
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'}  named tests: a mistake in a test file names the file: {got}")

    for what, main_text, files, want in INCLUDES:
        try:
            compile_policy(main_text, files=files)
            got = "(compiled without error)"
        except PolicyError as e:
            got = str(e)
        ok = got.startswith(want) and coded(got)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  included files: {what}: {got}")
    try:
        compile_policy('include "sub/a.authz"\n', files={"sub/a.authz": 'include "b.authz"\n', "sub/b.authz": BASE})
        got = ""
    except PolicyError as e:
        got = str(e)
    fails += bool(got)
    print(f"{'ok  ' if not got else 'FAIL'}  included files: nested includes compile{': ' + got if got else ''}")

    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True, capture_output=True)
    for what, extra, want in APPLY:
        subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", "tests/alt_schema.sql"],
                       check=True, capture_output=True)
        subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", APPLY_SETUP],
                       check=True, capture_output=True)
        sql = compile_policy(BASE + extra)
        p = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db],
                           input=sql, capture_output=True, text=True)
        err = next((ln for ln in p.stderr.splitlines() if "ERROR" in ln), "(applied without error)")
        ok = p.returncode != 0 and want in p.stderr and re.search(r"\[AZ6\d\d\]", p.stderr) is not None
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  applying {what}: {err.split('ERROR:', 1)[-1].strip()}")
    for what, extra, env, *after in APPLY_OK:
        subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", "tests/alt_schema.sql"],
                       check=True, capture_output=True)
        subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", APPLY_SETUP],
                       check=True, capture_output=True)
        try:
            sql = compile_policy(BASE + extra)
            p = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db],
                               input=sql + "\nSELECT authz.verify();\n" + "".join(after), capture_output=True, text=True,
                               env={**os.environ, **env})
            err = next((ln for ln in p.stderr.splitlines() if "ERROR" in ln), "")
            ok = p.returncode == 0
        except PolicyError as e:
            ok, err = False, str(e)
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'}  {what}{': ' + err if err else ''}")
    # a shared relation with expiring shares can't later become a link for inheritance
    reset = lambda: [subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", "tests/alt_schema.sql"],
                                    check=True, capture_output=True)]
    reset()
    v1 = compile_policy(BASE + "  shortcut : doc shared\n  can view = owner or shortcut.owner\n")
    v2 = compile_policy(BASE + "  shortcut : doc shared\n  can view = owner or shortcut.view\n")
    setup = ("INSERT INTO alt.users VALUES (1); INSERT INTO alt.docs (doc_no, owner_id) VALUES (1, 1), (2, 1);"
             "INSERT INTO authz.shares VALUES ('doc', 1, 'shortcut', 'doc', 2, '', now() + interval '1 day');")
    subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db], input=v1 + setup,
                   check=True, capture_output=True, text=True)
    p = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db], input=v2, capture_output=True, text=True)
    want = "1 existing shares of doc.shortcut have an expiry, a start time or a caveat, but links used for inheritance cannot"
    ok = p.returncode != 0 and want in p.stderr and "[AZ605]" in p.stderr
    fails += not ok
    err = next((ln for ln in p.stderr.splitlines() if "ERROR" in ln), "(applied without error)")
    print(f"{'ok  ' if ok else 'FAIL'}  turning expiring shares into inheritance links: {err.split('ERROR:', 1)[-1].strip()}")

    subprocess.run(["dropdb", db], capture_output=True)
    total = len(COMPILE) + 1 + len(TESTS) + 2 + len(INCLUDES) + 1 + len(APPLY) + len(APPLY_OK) + 1
    print(f"policy errors: {total - fails} of {total} cases behave as expected")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
