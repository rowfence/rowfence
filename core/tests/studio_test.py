#!/usr/bin/env python3
"""studio_test: rowstile why (the smallest changes that would grant a permission) and Studio's API, on the
docs example: read-only by default (nothing it does stays, and it refuses to change shares), able to write
with --write (shares and decisions made as the person it views as, so the database decides), and only for the
page that has the token, on localhost. And rowstile studio, the command: what it prints, and what stops it.

    PGHOST=... PGUSER=... python3 tests/studio_test.py [--db authz_studio]
"""

import http.client
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any, NamedTuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLI = os.path.join(ROOT, "cli", "rowstile_cli.py")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import rowstile_cli  # noqa: E402
import studio  # noqa: E402

fails = 0
# an answer from Studio's API: its shape is what the checks check
Answer = Any


def check(label: str, ok: object, detail: object = "") -> None:
    global fails
    if ok:
        print(f"ok    {label}")
    else:
        fails += 1
        print(f"FAIL  {label}{': ' + str(detail)[:600] if detail else ''}")


def psql(db: str, sql: str) -> str:
    r = subprocess.run(
        ["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql],
        capture_output=True,
        text=True,
        env=dict(os.environ, PGOPTIONS="-c client_min_messages=error"),
    )
    if r.returncode:
        raise SystemExit(f"psql failed: {r.stderr}")
    return r.stdout.strip()


def cli(db: str, *args: str) -> tuple[int, str]:
    return command(f"dbname={db}", *args)


def command(dsn: str, *args: str) -> tuple[int, str]:
    """The command run with --db DSN: its exit code, and what it printed."""
    r = subprocess.run([sys.executable, CLI, "--db", dsn, *args], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout + r.stderr


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Served(NamedTuple):
    """A Studio the command started: where it listens, and the token it printed."""

    port: int
    token: str


def serving(db: str, *flags: str) -> tuple[subprocess.Popen[str], str, Served]:
    """rowstile studio, started as in a terminal: the process, the line it printed first (its error, if it
    didn't start), and where it is."""
    port = free_port()
    p = subprocess.Popen(
        [sys.executable, CLI, "--db", f"dbname={db}", "studio", "--port", str(port), *flags],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert p.stdout is not None
    ready, _, _ = select.select([p.stdout], [], [], 60)
    line = p.stdout.readline() if ready else ""
    return p, line, Served(port, line.split("token=", 1)[1].split()[0] if "token=" in line else "")


def stopped(p: subprocess.Popen[str]) -> int | None:
    """Ctrl-C, as in a terminal: the exit code (None: still running after 20 seconds, so killed)."""
    p.send_signal(signal.SIGINT)
    try:
        p.communicate(timeout=20)
        return p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        return None


def made_and_copied(db: str, named: str, var: str, table: str, where: str) -> tuple[str, str]:
    """The row a named test's `given <var>` makes (in a transaction rolled back), and the row it copies, each
    as JSON without its key: the same when the copy is faithful. Or what the database said of the given."""
    given = named.split(f"given {var} = {{", 1)[-1].split("}\n", 1)[0].replace(' RETURNING "id"', " RETURNING *")
    r = subprocess.run(
        [
            "psql",
            "-X",
            "-q",
            "-At",
            "-d",
            db,
            "-c",
            f"BEGIN; WITH n AS ({given}) SELECT to_jsonb(n) - 'id' FROM n; ROLLBACK",
        ],
        capture_output=True,
        text=True,
    )
    return (r.stdout + r.stderr).strip(), psql(db, f"SELECT to_jsonb(r) - 'id' FROM {table} r WHERE {where}")


class Client:
    def __init__(self, s: studio.Studio | Served, token: str | None = None) -> None:
        self.base, self.token = f"http://127.0.0.1:{s.port}", s.token if token is None else token

    def call(self, path: str, body: object = None, host: str | None = None) -> tuple[int, Answer]:
        headers: dict[str, str] = {"X-Studio-Token": self.token}
        if host:
            headers["Host"] = host
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method="POST" if body is not None else "GET"
        )
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return r.status, json.loads(raw) if path.startswith("/api/") else raw.decode()
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode()


def main() -> None:
    db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_studio"
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", os.path.join(ROOT, "example", "app_schema.sql")],
        check=True,
        capture_output=True,
    )
    policy = os.path.join(ROOT, "example", "docs.authz")
    rc, out = cli(db, "apply", policy)
    if rc:
        raise SystemExit(out)
    # carol and the others are members of Acme (org 1): erin shares Company with them
    psql(db, "SELECT authz.act_as('user', '5'); SELECT authz.share('folder', '1', 'viewer', 'org', '1', 'member')")
    shares = lambda: psql(db, "SELECT count(*) FROM authz.shares")

    print("-- rowstile why")
    rc, out = cli(db, "why", "--as", "user:3", "folder", "3", "edit")
    lines = out.splitlines()
    ways = (
        [x.strip() for x in lines[lines.index("would be granted by:") + 1 :]] if "would be granted by:" in lines else []
    )
    check("no, and why not", rc == 0 and lines[0] == "no: user:3 does not hold edit on folder 3", out)
    check(
        "the smallest change first: a share on the folder itself",
        ways and ways[0].startswith("share editor on folder 3 with user 3"),
        out,
    )
    check(
        "... with what else it grants, and the policy line it adds to",
        ways and "(also gives edit on" in ways[0] and "[line " in ways[0],
        out,
    )
    check(
        "a group the object is linked to: join it",
        any(w.startswith("add user 3 to app.team_members for team") for w in ways),
        out,
    )

    def granted_by(*question: str) -> tuple[list[str], str]:
        _, said = cli(db, "why", *question)
        after = said.splitlines()
        return (
            [x.strip() for x in after[after.index("would be granted by:") + 1 :]]
            if "would be granted by:" in after
            else []
        ), said

    asked, out = granted_by("--as", "user:6", "folder", "2", "view")
    check(
        "the way that gives the least comes first: a viewer, before an editor",
        asked
        and asked[0].startswith("share viewer on folder 2 with user 6")
        and "also gives" not in asked[0]
        and any(w.startswith("share editor on folder 2 with user 6 (also gives edit on it") for w in asked),
        out,
    )
    asked, out = granted_by("--as", "user:3", "folder", "3", "share")
    ways_of_share, said_of_share = asked, out
    owner = next((w for w in asked if w.startswith("set owner_id of folder 3 to 3")), "")
    check(
        "a column: the folder's owner, with the other permissions it gives and whom it takes it from",
        "(also gives edit" in owner and "(takes share on it from 1 person)" in owner,
        out,
    )
    asked, out = granted_by("--as", "user:6", "folder", "2", "share")
    check(
        "a relation with a where: the row, with the column the condition asks",
        any(w.startswith("add user 6 to app.org_members for org 1, with role = 'admin'") for w in asked),
        out,
    )
    check(
        "... and when the row is there, left out by the condition, its column changes",
        any(w.startswith("set role = 'admin' on user 3's row of app.org_members for org 1") for w in ways_of_share),
        said_of_share,
    )
    asked, out = granted_by("--as", "user:2", "folder", "5", "edit")
    check(
        "... for a group's link too",
        any(w.startswith("set access = 'edit' on team 11's row of app.folder_team_access for folder 5") for w in asked),
        out,
    )
    check(
        "... and nothing of it stays",
        psql(db, "SELECT role FROM app.org_members WHERE org_id = 1 AND user_id = 3") == "member"
        and psql(db, "SELECT count(*) FROM app.org_members WHERE user_id = 6 AND org_id = 1") == "0"
        and psql(db, "SELECT access FROM app.folder_team_access WHERE folder_id = 5") == "view",
    )
    rc, out = cli(db, "why", "--as", "user:1", "folder", "3", "edit")
    check("yes, and why", rc == 0 and out.startswith("yes: user:1 holds edit on folder 3") and "owner" in out, out)
    rc, out = cli(db, "why", "--as", "user:2", "folder", "3", "fly")
    check("a permission the type doesn't have is named", rc != 0 and "folder has no permission fly" in out, out)
    before = shares()
    rc, out = cli(db, "why", "--as", "user:7", "file", "10", "view")
    check("nothing it tried stays", shares() == before and "share viewer on file 10 with user 7" in out, out)

    print("-- Studio, read-only")
    dsn = f"dbname={db}"
    ro = studio.Studio(dsn, None, policy, writable=False, port=0, read_policy=rowstile_cli.read_policy)
    ro.start(background=True)
    c = Client(ro)
    try:
        status, page = c.call("/")
        check("the page, without the token (it carries no data)", status == 200 and "rowstile Studio" in page, status)
        check("the API needs the token", Client(ro, token="wrong").call("/api/overview")[0] == 401)
        check(
            "... and a request for localhost (not a DNS name pointed here)",
            c.call("/api/overview", host="evil.example:4983")[0] == 403,
        )
        check(
            "... a page opened at localhost by hand is answered too",
            c.call("/api/overview", host=f"localhost:{ro.port}")[0] == 200,
        )
        check("no file outside the page's folder", c.call("/..%2fstudio.py")[0] == 404 and c.call("/.hidden")[0] == 404)
        # a path as no browser sends it: backslashes, a drive letter (on Windows these named any file on the disk)
        for raw in ("/x\\..\\..\\studio.py", "/C:\\Windows\\win.ini", "/\\Windows\\win.ini", "/studio.py"):
            conn = http.client.HTTPConnection("127.0.0.1", ro.port, timeout=10)
            conn.putrequest("GET", raw, skip_host=True)
            conn.putheader("Host", f"localhost:{ro.port}")
            conn.endheaders()
            got = conn.getresponse()
            got.read()
            check(f"... nor {raw}", got.status == 404, got.status)
            conn.close()
        check(
            "a token that isn't ASCII is a wrong token",
            Client(ro, token="caf\u00e9".encode().decode("latin-1")).call("/api/overview")[0] == 401,
        )
        status, o = c.call("/api/overview")
        check(
            "the overview: the database, the types, the tables",
            status == 200
            and not o["writable"]
            and "app.folders" in o["tables"]
            and any(t["name"] == "folder" and any(p["name"] == "edit" for p in t["perms"]) for t in o["types"]),
            o,
        )
        status, r = c.call("/api/rows?table=app.folders&as=user:2")
        hidden = [x for x in r["rows"] if not x["visible"]]
        check(
            "the rows as bob: some hidden, each with his permissions",
            status == 200
            and 0 < r["visible_total"] < r["total"]
            and hidden
            and all(x["perms"] == [] for x in hidden)
            and any("view" in x["perms"] for x in r["rows"] if x["visible"]),
            r,
        )
        status, r2 = c.call("/api/rows?table=app.folders&as=anyone")
        check("... and as nobody", status == 200 and r2["visible_total"] < r["visible_total"], r2)
        status, same = c.call("/api/rows?table=app.folders&as=2")
        check("someone written without a type is a user: as=2 sees what user:2 sees", status == 200 and same == r, same)
        check("only tables the policy governs", c.call("/api/rows?table=pg_catalog.pg_authid&as=user:2")[0] == 404)
        before = shares()
        status, w = c.call("/api/why?as=user:3&type=folder&id=3&perm=edit")
        check(
            "why not, and the changes that might grant it, none tried (read-only)",
            status == 200
            and w["holds"] is False
            and w["tried"] is False
            and w["ways"]
            and w["ways"][0]["text"] == "share editor on folder 3 with user 3"
            and shares() == before,
            w,
        )
        status, e = c.call(
            "/api/share",
            {
                "as": "user:1",
                "type": "folder",
                "id": "3",
                "relation": "editor",
                "subject_type": "user",
                "subject_id": "2",
            },
        )
        check("read-only: no shares made", status == 403 and "read-only" in e["detail"] and shares() == before, e)
        status, t = c.call("/api/test?as=user:3&type=folder&id=3&perm=edit&expect=cannot")
        check(
            "a test from what should hold: the check on the data there now",
            status == 200 and t["check"] == "user 3 cannot edit folder 3",
            t,
        )
        check(
            "... and a named test with its own rows (the key left to the table)",
            'given it = {INSERT INTO "app"."folders" (' in t["named"]
            and "user $who cannot edit folder $it" in t["named"]
            and '("id",' not in t["named"].split('"app"."folders"', 1)[1].split(")")[0],
            t["named"],
        )
        check(
            "... the person's row copied with a key of its own (the table doesn't fill it)",
            'given who = {INSERT INTO "app"."users" ("id", "name") VALUES ((SELECT coalesce(max("id"), 0) + 1 FROM "app"."users"), '
            in t["named"],
            t["named"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
                fh.write(t["named"])
            rc, out = cli(db, "test", os.path.join(tmp, "made.authz"))
        made = out.split("user 3 cannot edit folder 3", 1)[-1].split("invariants", 1)[0]
        check(
            "... and the test runs as it is: its rows are made, its check passes",
            "user 3 cannot edit folder 3" in out
            and "ok    " in made
            and "FAIL" not in made
            and "duplicate key" not in out,
            out[-800:],
        )
        status, t = c.call("/api/test?as=user:3&type=folder&id=1&perm=view&expect=cannot")
        made, row = made_and_copied(db, t.get("named", ""), "it", "app.folders", "id = 1")
        check(
            "a copy of a row with a NULL (folder 1 has no parent): every column the same, the key aside",
            status == 200 and made == row and '"parent_id": null' in row,
            (made, row),
        )
        # a test names what isn't there as it is, and brings no copy of it
        for label, path, givens, last in (
            (
                "an object that isn't there",
                "as=user:3&type=folder&id=999&perm=view",
                ["who"],
                "user $who can view folder 999",
            ),
            (
                "someone who isn't there",
                "as=user:999&type=folder&id=1&perm=view",
                ["it"],
                "user 999 can view folder $it",
            ),
            (
                "nobody signed in",
                "as=anyone&type=folder&id=1&perm=view&expect=cannot",
                ["it"],
                "anyone cannot view folder $it",
            ),
        ):
            status, t = c.call(f"/api/test?{path}")
            lines = [x.strip() for x in t.get("named", "").splitlines()]
            check(
                f"a test for {label}: named as it is, with no copy of it",
                status == 200
                and [x.split(" = {", 1)[0].removeprefix("given ") for x in lines if x.startswith("given ")] == givens
                and lines[-1] == last,
                (status, t),
            )
        status, g = c.call("/api/graph")
        check("the graph", status == 200 and g["mermaid"].startswith("%%") and "flowchart" in g["mermaid"], g)
        status, d = c.call("/api/diff")
        check(
            "the access diff: the file is the policy in force",
            status == 200 and d["same_text"] and d["summary"] == [],
            d,
        )
        status, sh = c.call("/api/shares?type=folder&id=1")
        check(
            "the shares on an object, as an administrator",
            status == 200 and any(x["subject_type"] == "org" for x in sh["shares"]),
            sh,
        )
        owner = psql(db, "SELECT owner_id FROM app.folders WHERE id = 1")
        status, w = c.call(f"/api/why?as=user:{owner}&type=folder&id=1&perm=edit")
        check(
            "why for someone who holds it: yes, and nothing to grant", status == 200 and w["holds"] and not w["ways"], w
        )
        # what a page asks wrongly is answered with a problem: its status, and words that say what to change
        for label, path, want, words in (
            ("someone to view as, written wrongly", "/api/rows?table=app.folders&as=user:", 400, "as whom? 'user:'"),
            ("why for nobody", "/api/why?as=anyone&type=folder&id=3&perm=edit", 400, "why for nobody"),
            ("why on a type the policy doesn't have", "/api/why?as=user:3&type=nothing&id=3&perm=edit", 404, "no type"),
            ("why on a permission the type doesn't have", "/api/why?as=user:3&type=folder&id=3&perm=nope", 404, "nope"),
            ("a test expecting neither", "/api/test?as=user:3&type=folder&id=3&perm=edit&expect=maybe", 400, "expect:"),
            (
                "a test on a type the policy doesn't have",
                "/api/test?as=user:3&type=nothing&id=3&perm=edit",
                404,
                "no type",
            ),
            ("an address it doesn't answer", "/api/nothing", 404, "nothing"),
        ):
            status, p = c.call(path)
            check(f"{label}: {want}, and says so", status == want and words in str(p.get("detail", "")), (status, p))
    finally:
        ro.stop()

    with tempfile.TemporaryDirectory() as tmp:
        changed = os.path.join(tmp, "docs.authz")
        with open(policy, encoding="utf-8") as fh:
            text = fh.read()
        with open(changed, "w", encoding="utf-8") as fh:
            fh.write(
                text.replace(
                    "  can edit  = share or editor or (parent.edit and {inherit})",
                    "  can edit  = share or editor or viewer or (parent.edit and {inherit})",
                )
            )
        s = studio.Studio(dsn, None, changed, writable=False, port=0, read_policy=rowstile_cli.read_policy)
        s.start(background=True)
        try:
            status, d = Client(s).call("/api/diff")
            check(
                "read-only: no access diff of a changed file (it would lock the app's tables), and why",
                status == 409 and "locks the app's tables" in d["detail"],
                d,
            )
        finally:
            s.stop()
        s = studio.Studio(dsn, None, changed, writable=True, port=0, read_policy=rowstile_cli.read_policy)
        s.start(background=True)
        try:
            before = psql(db, "SELECT count(*) FROM authz.policy_versions")
            status, d = Client(s).call("/api/diff")
            check(
                "the access diff of a changed file: who gains what, on this data, and nothing applied",
                status == 200
                and not d["same_text"]
                and any(
                    x["change"] == "gains" and x["what"] == "permission edit" and x["type"] == "folder"
                    for x in d["summary"]
                )
                and psql(db, "SELECT count(*) FROM authz.policy_versions") == before,
                d,
            )
        finally:
            s.stop()
        # what the access diff can't compare with: said on the page's tab
        broken = os.path.join(tmp, "broken.authz")
        edit = "  can edit  = share or editor or (parent.edit and {inherit})"
        with open(broken, "w", encoding="utf-8") as fh:
            fh.write(text.replace(edit, edit.replace("editor", "editr")))
        line = text.splitlines().index(edit) + 1
        for label, path, writable, want, starts, ends in (
            ("no policy file", None, False, 404, "no policy file to compare with (rowstile.toml's policy)", ""),
            (
                "a policy file that isn't there",
                "/nowhere/p.authz",
                False,
                404,
                "/nowhere/p.authz: No such file or directory",
                "",
            ),
            # on a Studio that may build it: the file's mistake, with its line
            (
                "a policy file with a mistake",
                broken,
                True,
                400,
                f"policy line {line}: folder has no relation or permission 'editr' (it has: ",
                ") [AZ203]",
            ),
        ):
            s = studio.Studio(dsn, None, path, writable=writable, port=0, read_policy=rowstile_cli.read_policy)
            s.start(background=True)
            try:
                status, d = Client(s).call("/api/diff")
                said = str(d.get("detail", ""))
                check(
                    f"the access diff with {label}: {want}, and says so",
                    status == want
                    and (said == starts if not ends else said.startswith(starts) and said.endswith(ends)),
                    (status, d),
                )
            finally:
                s.stop()

    print("-- Studio, able to write (rowstile dev, or --write)")
    rw = studio.Studio(dsn, None, policy, writable=True, port=0, read_policy=rowstile_cli.read_policy)
    rw.start(background=True)
    c = Client(rw)
    try:
        before = shares()
        status, w = c.call("/api/why?as=user:3&type=folder&id=3&perm=edit")
        check(
            "why not: each change tried and undone",
            status == 200
            and w["tried"]
            and all(x["grants"] for x in w["ways"])
            and w["ways"][0]["more_objects"] > 0
            and shares() == before,
            w,
        )
        body = {"type": "folder", "id": "3", "relation": "editor", "subject_type": "user", "subject_id": "3"}
        status, e = c.call("/api/share", {**body, "as": "user:3"})
        check(
            "a share as someone who may not: refused, with the database's reason",
            status == 403 and "cannot share" in e["detail"],
            e,
        )
        # the folder's owner may share it: what stops these is Studio
        status, e = c.call("/api/share", {**body, "as": "user:1"}, host="evil.example:4983")
        check(
            "a share asked for another host (a DNS name pointed here): refused, and nothing changes",
            status == 403 and e["detail"] == "Studio answers on localhost only" and shares() == before,
            e,
        )
        status, e = c.call("/api/share", body)
        check(
            "a share with nobody to make it: refused, and says to pick someone",
            status == 400
            and e["detail"] == "as whom? pick someone to view as: they make the change"
            and shares() == before,
            e,
        )
        for label, path, sent, words in (
            ("a share that names no type", "/api/share", {"as": "user:1", "id": "3"}, "'type'"),
            (
                "a body that isn't JSON",
                "/api/share",
                b"as=user:1&type=folder",
                "Expecting value: line 1 column 1 (char 0)",
            ),
            (
                "an offset that isn't a number",
                "/api/rows?table=app.folders&as=user:1&offset=two",
                None,
                "invalid literal for int() with base 10: 'two'",
            ),
        ):
            status, e = c.call(path, sent)
            check(f"{label}: 400, missing or wrong", status == 400 and e["detail"] == f"missing or wrong: {words}", e)
        status, e = c.call("/api/why?as=user:3&type=folder&id=3&perm=fly")
        check(
            "why, trying changes, on a permission the type doesn't have: says so",
            status == 400 and e["detail"] == "folder has no permission fly",
            (status, e),
        )
        status, _ = c.call("/api/share", {**body, "as": "user:1"})
        _, r = c.call("/api/rows?table=app.folders&as=user:3")
        check(
            "a share as the folder's owner, and carol can edit it",
            status == 200 and any(x["id"] == "3" and "edit" in x["perms"] for x in r["rows"]),
            (status, r),
        )
        status, _ = c.call("/api/unshare", {**body, "as": "user:1"})
        check("... and unsharing it", status == 200 and shares() == before)
        psql(
            db,
            "SELECT authz.act_as('user', '2'); SELECT authz.request_access('folder', '5', 'viewer', 'for the audit')",
        )
        status, sh = c.call("/api/shares")
        req = [x for x in sh["requests"] if x["object_id"] == "5"]
        check("a pending access request", status == 200 and req and req[0]["requester"] == "2", sh)
        status, e = c.call("/api/decide", {"as": "user:2", "request": req[0]["id"], "approve": True})
        check("deciding your own request is refused", status == 403, e)
        status, _ = c.call("/api/decide", {"as": "user:5", "request": req[0]["id"], "approve": True})
        check(
            "... the owner approves it, and it is a share",
            status == 200
            and psql(db, "SELECT count(*) FROM authz.shares WHERE object_id = '5' AND subject_id = '2'") == "1",
        )
    finally:
        rw.stop()

    print("-- a test's copy of a row: each value as the column holds it")
    psql(
        db,
        "ALTER TABLE app.folders ADD COLUMN tags text[], ADD COLUMN meta jsonb, ADD COLUMN size numeric, "
        "ADD COLUMN label text GENERATED ALWAYS AS (upper(name)) STORED; "
        'UPDATE app.folders SET tags = \'{plans,"q3 review"}\', meta = \'{"color": "red"}\', '
        "size = 12345678901234567.89 WHERE id = 5",
    )
    s = studio.Studio(dsn, None, policy, writable=False, port=0, read_policy=rowstile_cli.read_policy)
    s.start(background=True)
    try:
        # Secrets doesn't inherit, where the column's default does: the policy reads the row's value
        status, t = Client(s).call("/api/test?as=user:3&type=folder&id=5&perm=edit&expect=cannot")
        made, row = made_and_copied(db, t.get("named", ""), "it", "app.folders", "id = 5")
        check(
            "a column with a default, an array, json, a number with a fraction, a column the table makes: the copy "
            "is the row",
            status == 200 and made == row and '"inherit": false' in row and '"tags": ["plans", "q3 review"]' in row,
            (made, row),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
                fh.write(t.get("named", ""))
            _, out = cli(db, "test", os.path.join(tmp, "made.authz"))
        ran = out.split("user 3 cannot edit folder 5", 1)[-1].split("invariants", 1)[0]
        check(
            "... and the test runs as it is",
            "user 3 cannot edit folder 5" in out and "ok    " in ran and "FAIL" not in ran,
            out[-800:],
        )
    finally:
        s.stop()

    print("-- rowstile studio, the command")
    p, line, at = serving(db)
    check(
        "it says where it is (the address it listens on), with a token, and that it is read-only",
        line == f"rowstile studio: http://127.0.0.1:{at.port}/?token={at.token}  (read-only; Ctrl-C stops it)\n"
        and len(at.token) >= 20,
        line,
    )
    status, o = Client(at).call("/api/overview")
    check("... answers the page that has the token", status == 200 and o["writable"] is False, (status, o))
    check("... and Ctrl-C stops it", stopped(p) == 0)
    p, line, at = serving(db, "--write")
    status, o = Client(at).call("/api/overview")
    stopped(p)
    check(
        "with --write it says it can write, and does",
        line.endswith(f"/?token={at.token}  (can write: shares and requests; Ctrl-C stops it)\n")
        and status == 200
        and o["writable"] is True,
        (line, status, o),
    )
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        held.listen()
        rc, out = cli(db, "studio", "--port", str(held.getsockname()[1]))
    check(
        "a port another program listens on: it didn't start, and how to pick another, exit 2",
        rc == 2
        and out.startswith("Studio didn't start (")
        and out.endswith("): rowstile studio --port N for another port\n"),
        (rc, out),
    )
    rc, out = cli(db, "studio", "--port", "99999")
    check(
        "... a port there can't be",
        (rc, out)
        == (2, "Studio didn't start (bind(): port must be 0-65535.): rowstile studio --port N for another port\n"),
        (rc, out),
    )
    for label, target, said in (
        ("a database that isn't there", f"dbname={db}_nowhere", f'3D000: database "{db}_nowhere" does not exist'),
        ("a server that isn't there", "host=/nowhere dbname=x", "[Errno 2] No such file or directory"),
        (
            "an address it can't read",
            "postgres://a@localhost:port/x",
            "the URL's port isn't a number: a #, ? or / in the password must be written %23, %3F, %2F",
        ),
        (
            "a setting it doesn't know",
            "colour=blue",
            "unknown connection setting 'colour' (use host, port, user, password, dbname, sslmode)",
        ),
    ):
        rc, out = command(target, "studio", "--port", str(free_port()))
        check(
            f"{label}: can't connect, as the other commands say it, exit 2",
            (rc, out) == (2, f"can't connect: {said}\n"),
            (rc, out),
        )
    # a role that may log in and read nothing of rowstile's (an app's own DATABASE_URL, say)
    psql(db, "DROP ROLE IF EXISTS authz_studio_login; CREATE ROLE authz_studio_login LOGIN")
    rc, out = command(f"dbname={db} user=authz_studio_login", "studio", "--port", str(free_port()))
    psql(db, "DROP ROLE authz_studio_login")
    check(
        "connected as a role that can't read rowstile's tables: the database's words, exit 1",
        (rc, out) == (1, "rowstile studio: permission denied for schema authz\n"),
        (rc, out),
    )

    print("-- Studio when the database can't be reached")
    gone = studio.Studio(
        "host=/nowhere dbname=x", None, None, writable=False, port=0, read_policy=rowstile_cli.read_policy
    )
    gone.start(background=True)
    try:
        status, e = Client(gone).call("/api/overview")
        check(
            "the page is told it can't connect, as the command says it (503)",
            status == 503 and e["detail"] == "can't connect: [Errno 2] No such file or directory",
            (status, e),
        )
    finally:
        gone.stop()

    print("-- the policy taken out while Studio runs (rowstile remove)")
    rc, out = cli(db, "remove", "--yes")
    if rc:
        raise SystemExit(out)
    ro = studio.Studio(dsn, None, policy, writable=False, port=0, read_policy=rowstile_cli.read_policy)
    rw = studio.Studio(dsn, None, policy, writable=True, port=0, read_policy=rowstile_cli.read_policy)
    ro.start(background=True)
    rw.start(background=True)
    try:
        for label, s, path in (
            ("the overview", ro, "/api/overview"),
            ("the graph", ro, "/api/graph"),
            ("the rows", ro, "/api/rows?table=app.folders&as=user:2"),
            ("the shares and requests", ro, "/api/shares"),
            ("why", ro, "/api/why?as=user:3&type=folder&id=3&perm=edit"),
            ("why, trying changes", rw, "/api/why?as=user:3&type=folder&id=3&perm=edit"),
            ("the access diff", rw, "/api/diff"),
            ("a test", ro, "/api/test?as=user:3&type=folder&id=3&perm=edit"),
        ):
            status, e = Client(s).call(path)
            check(
                f"{label}: no policy is applied, and how to apply one",
                status == 400 and e.get("detail") == "no policy is applied [AZ609] (rowstile apply db/policy.authz)",
                (status, e),
            )
    finally:
        ro.stop()
        rw.stop()
    rc, out = cli(db, "studio", "--port", str(free_port()))
    check(
        "rowstile studio on a database with no policy in force: says so, and how to apply one, exit 1",
        (rc, out) == (1, "rowstile studio: no policy is applied [AZ609]\nHINT: rowstile apply db/policy.authz\n"),
        (rc, out),
    )

    print("-- Studio on a table with a masked column (tests/multi.authz: mask body : edit)")
    masks = f"{db}_masks"
    subprocess.run(["dropdb", "--if-exists", masks], capture_output=True)
    subprocess.run(["createdb", masks], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", masks, "-f", os.path.join(HERE, "multi_schema.sql")],
        check=True,
        capture_output=True,
    )
    lead, bob, carol = (f"00000000-0000-4000-8000-00000000000{n}" for n in (1, 2, 3))
    plain, bobs = "10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002"
    psql(
        masks,
        f"INSERT INTO mt.users VALUES ('{lead}'), ('{bob}'), ('{carol}'); INSERT INTO mt.orgs VALUES (1); "
        f"INSERT INTO mt.projects (id, org_id, lead_id) VALUES (1, 1, '{lead}'); "
        f"INSERT INTO mt.docs VALUES ('{plain}', 'project', 1, NULL, 'secret text'), ('{bobs}', 'project', 1, '{bob}', 'bob wrote this')",
    )
    rc, out = cli(masks, "apply", os.path.join(HERE, "multi.authz"))
    if rc:
        raise SystemExit(out)
    psql(masks, f"SELECT authz.act_as('user', '{lead}'); SELECT authz.share('project', '1', 'viewer', 'user', '{bob}')")
    ms = studio.Studio(
        f"dbname={masks}",
        None,
        os.path.join(HERE, "multi.authz"),
        writable=False,
        port=0,
        read_policy=rowstile_cli.read_policy,
    )
    ms.start(background=True)
    c = Client(ms)
    try:

        def docs(who: str) -> tuple[int, Answer, dict[str, Answer]]:
            status, r = c.call(f"/api/rows?table=mt.docs&as={who}")
            return status, r, {x["id"]: x for x in r["rows"]} if status == 200 else {}

        status, r, by = docs(f"user:{lead}")
        check(
            "the project's lead may edit: both rows, the masked column in full",
            status == 200
            and r["visible_total"] == 2
            and by[plain]["values"]["body"] == "secret text"
            and by[plain]["masked"] == []
            and by[bobs]["masked"] == [],
            r,
        )
        status, r, by = docs(f"user:{bob}")
        check(
            "a viewer sees the rows, and the masked column as they get it: empty, and named",
            status == 200
            and r["visible_total"] == 2
            and by[plain]["visible"]
            and by[plain]["values"]["body"] is None
            and by[plain]["masked"] == ["body"],
            r,
        )
        check(
            "... but in full on the document they wrote (the mask's rule holds there)",
            status == 200 and by[bobs]["values"]["body"] == "bob wrote this" and by[bobs]["masked"] == [],
            r,
        )
        status, r, by = docs(f"user:{carol}")
        check(
            "someone with no access: every row hidden",
            status == 200
            and r["visible_total"] == 0
            and r["total"] == 2
            and not any(x["visible"] for x in r["rows"])
            and all(x["masked"] == [] for x in r["rows"]),
            r,
        )
        # why on a policy with a container of two types and custom roles: the ways through the project the doc
        # sits in, and its own author; a custom role is no way rowstile why offers (roles are made at run time)
        _, said = cli(masks, "why", "--as", f"user:{carol}", "doc", plain, "edit")
        lines = said.splitlines()
        ways = (
            [x.strip() for x in lines[lines.index("would be granted by:") + 1 :]]
            if "would be granted by:" in lines
            else []
        )
        check(
            "why through a container of two types: the project's lead, or the doc's author",
            any(w.startswith(f"set lead_id of project 1 to {carol}") for w in ways)
            and any(w.startswith(f"set author_id of doc {plain} to {carol}") for w in ways)
            and not any("role:" in w or "custom role" in w for w in ways),
            said,
        )
        # rows keyed by uuid: the copies a test brings get keys of their own, and the rest as the rows hold it
        status, t = c.call(f"/api/test?as=user:{bob}&type=doc&id={plain}&perm=edit&expect=cannot")
        named = t.get("named", "") if status == 200 else ""
        made, row = made_and_copied(masks, named, "it", "mt.docs", f"id = '{plain}'")
        check(
            "a test on rows keyed by uuid: new keys for the copies, and the copy is the row",
            status == 200
            and 'given who = {INSERT INTO "mt"."users" ("id", "active") VALUES (gen_random_uuid(), true) RETURNING "id"}'
            in named
            and made == row
            and '"body": "secret text"' in row,
            (status, t, made, row),
        )
    finally:
        ms.stop()
    subprocess.run(["dropdb", "--if-exists", masks], capture_output=True)

    print("-- a test on a key of several columns, and on text in a key (tests/composite.authz)")
    keys = f"{db}_keys"
    subprocess.run(["dropdb", "--if-exists", keys], capture_output=True)
    subprocess.run(["createdb", keys], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", keys, "-f", os.path.join(HERE, "composite_schema.sql")],
        check=True,
        capture_output=True,
    )
    psql(
        keys,
        "INSERT INTO cx.users VALUES (1, NULL), (2, 1); INSERT INTO cx.orgs VALUES (1); "
        "INSERT INTO cx.teams (org_id, slug, lead_id) VALUES (1, 'a b', 1), (1, 'it''s', 1); "
        "INSERT INTO cx.projects VALUES (1, 5, 1, NULL)",
    )
    rc, out = cli(keys, "apply", os.path.join(HERE, "composite.authz"))
    if rc:
        raise SystemExit(out)
    ks = studio.Studio(
        f"dbname={keys}", None, os.path.join(HERE, "composite.authz"), port=0, read_policy=rowstile_cli.read_policy
    )
    ks.start(background=True)
    try:
        for label, ask, written in (
            ("a key of several columns", "type=project&id=(1,5)&perm=edit", "edit project (1,5)"),
            (
                "a key with a space in its text: quoted",
                "type=team&id=(1,%22a%20b%22)&perm=share",
                "share team '(1,\"a b\")'",
            ),
            (
                "... and an apostrophe: quoted, and doubled",
                "type=team&id=(1,it%27s)&perm=share",
                "share team '(1,it''s)'",
            ),
        ):
            status, t = Client(ks).call(f"/api/test?as=user:2&{ask}&expect=cannot")
            rc, out = -1, ""
            if status == 200:
                with tempfile.TemporaryDirectory() as tmp:
                    with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
                        fh.write(f'test "on the data there"\n  {t["check"]}\n\n{t["named"]}')
                    rc, out = cli(keys, "test", os.path.join(tmp, "made.authz"))
            check(
                f"a test on {label}: no copy of the row, and the check and the test run as written",
                status == 200
                and t["check"] == f"user 2 cannot {written}"
                and "given it" not in t["named"]
                and rc == 0
                and out.count("ok    ") == 2,
                (status, t, out[-600:]),
            )
    finally:
        ks.stop()
    subprocess.run(["dropdb", "--if-exists", keys], capture_output=True)

    print("-- a test on tables named with capitals, as Prisma names them (tests/prisma.authz)")
    caps = f"{db}_caps"
    subprocess.run(["dropdb", "--if-exists", caps], capture_output=True)
    subprocess.run(["createdb", caps], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", caps, "-f", os.path.join(HERE, "prisma_schema.sql")],
        check=True,
        capture_output=True,
    )
    psql(caps, 'UPDATE "Note" SET locked = true WHERE id = 2')  # its managers' only: the policy reads it
    rc, out = cli(caps, "apply", os.path.join(HERE, "prisma.authz"))
    if rc:
        raise SystemExit(out)
    s = studio.Studio(
        f"dbname={caps}", None, os.path.join(HERE, "prisma.authz"), port=0, read_policy=rowstile_cli.read_policy
    )
    s.start(background=True)
    try:
        status, t = Client(s).call("/api/test?as=user:2&type=note&id=2&perm=edit&expect=cannot")
    finally:
        s.stop()
    named = t.get("named", "") if status == 200 else ""
    made, row = made_and_copied(caps, named, "it", 'public."Note"', "id = 2")
    check(
        "a test on tables named with capitals: the person's key left to its sequence, the locked note's copy is the row",
        status == 200
        and 'given who = {INSERT INTO "public"."User" ("name") VALUES (\'bo\') RETURNING "id"}' in named
        and made == row
        and '"locked": true' in row,
        (status, t, made, row),
    )
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
            fh.write(named)
        _, out = cli(caps, "test", os.path.join(tmp, "made.authz"))
    ran = out.split("user 2 cannot edit note 2", 1)[-1].split("invariants", 1)[0]
    check(
        "... and the test runs as it is",
        "user 2 cannot edit note 2" in out and "ok    " in ran and "FAIL" not in ran,
        out[-800:],
    )
    subprocess.run(["dropdb", "--if-exists", caps], capture_output=True)

    print("-- Studio through an app role the owner may not take, with no rules, and users keyed by text")
    # since PostgreSQL 16 a role that makes another gets ADMIN on it, not SET (the suites' owner has
    # createrole_self_grant, which would hide it): as on managed Postgres until the owner grants itself the role
    plain, app = f"{db}_plain", "authz_studio_plain_app"
    subprocess.run(["dropdb", "--if-exists", plain], capture_output=True)
    psql("postgres", f"DROP ROLE IF EXISTS {app}")
    subprocess.run(["createdb", plain], check=True)
    subprocess.run(
        [
            "psql",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            plain,
            "-c",
            f"CREATE ROLE {app}",
            "-c",
            "CREATE SCHEMA app; CREATE TABLE app.users (id text PRIMARY KEY); "
            "CREATE TABLE app.notes (id bigint PRIMARY KEY, owner_id text NOT NULL REFERENCES app.users, body text); "
            f"GRANT USAGE ON SCHEMA app TO {app}; GRANT SELECT ON app.users TO {app}; "
            f"GRANT SELECT, UPDATE ON app.notes TO {app}; "
            "INSERT INTO app.users VALUES ('1'), ('o''brien'); INSERT INTO app.notes VALUES (1, '1', 'mine')",
        ],
        env=dict(os.environ, PGOPTIONS="-c createrole_self_grant= -c client_min_messages=error"),
        check=True,
        capture_output=True,
    )
    me = psql(plain, "SELECT current_user")
    types = f"app role {app}\ntype user = app.users (id text)\ntype note = app.notes\n  owner : user = owner_id\n  can edit = owner\n"
    with tempfile.TemporaryDirectory() as tmp:
        for label, text, want, said in (
            (
                "the rows, through an app role the owner may not take: what to grant, as the other commands say it",
                types + "rules app.notes\n  select : edit\n  update : edit\n",
                400,
                f"{me} may not switch to the app role {app} (SET ROLE), and this looks at the data as the app does "
                f'[AZ618] (once, as {me} if it made {app}, else as the role that did or a superuser: GRANT "{app}" TO "{me}")',
            ),
            (
                "a policy with no rules: no app role to look through, and says so",
                types,
                409,
                "no policy with rules is applied, so there is no app role to look through",
            ),
        ):
            path = os.path.join(tmp, "plain.authz")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            rc, out = cli(plain, "apply", path)
            if rc:
                raise SystemExit(out)
            s = studio.Studio(f"dbname={plain}", None, path, port=0, read_policy=rowstile_cli.read_policy)
            s.start(background=True)
            try:
                status, e = Client(s).call("/api/rows?table=app.notes&as=user:1")
                check(f"{label} ({want})", status == want and e.get("detail") == said, (status, e))
            finally:
                s.stop()
        # its users are keyed by text: a test as someone whose id isn't one word
        s = studio.Studio(f"dbname={plain}", None, path, port=0, read_policy=rowstile_cli.read_policy)
        s.start(background=True)
        try:
            status, t = Client(s).call("/api/test?as=user:o%27brien&type=note&id=1&perm=edit&expect=cannot")
        finally:
            s.stop()
        rc, out = -1, ""
        if status == 200:
            with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
                fh.write(f'test "on the data there"\n  {t["check"]}\n\n{t["named"]}')
            rc, out = cli(plain, "test", os.path.join(tmp, "made.authz"))
        check(
            "a test as someone whose id isn't one word: quoted, and the check and the test run as written",
            status == 200
            and t["check"] == "user 'o''brien' cannot edit note 1"
            and rc == 0
            and out.count("ok    ") == 2,
            (status, t, out[-600:]),
        )
    subprocess.run(["dropdb", "--if-exists", plain], capture_output=True)
    psql("postgres", f"DROP ROLE IF EXISTS {app}")

    print("-- rowstile why through a table that names its rows' type (tests/cross.authz: a project's backers)")
    cross = db + "_cross"
    subprocess.run(["dropdb", "--if-exists", cross], capture_output=True)
    subprocess.run(["createdb", cross], check=True)
    subprocess.run(
        [
            "psql",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            cross,
            "-f",
            os.path.join(ROOT, "tests", "cross_schema.sql"),
        ],
        check=True,
        capture_output=True,
    )
    rc, out = cli(cross, "apply", os.path.join(ROOT, "tests", "cross.authz"))
    if rc:
        raise SystemExit(out)
    # bo leads project 1, which region 2 backs; folder 2, which has the same id, doesn't back it. Ann funds the
    # project through its backer: the region's chief, not the folder's owner (a row's type, read as it is written)
    psql(
        cross,
        "INSERT INTO cx.users VALUES (1, 'ann'), (2, 'bo'); INSERT INTO cx.folders (id, owner_id) VALUES (2, 2); "
        "INSERT INTO cx.regions (id, chief_id) VALUES (2, 2); INSERT INTO cx.projects (id, lead_id) VALUES (1, 2); "
        "INSERT INTO cx.backings VALUES (1, 'region', 2)",
    )
    rc, said = cli(cross, "why", "--as", "user:1", "project", "1", "fund")
    after = said.splitlines()
    ways = (
        [x.strip() for x in after[after.index("would be granted by:") + 1 :]] if "would be granted by:" in after else []
    )
    check(
        "the backer of the type its row names: the region's chief, and nothing of the folder of the same id",
        rc == 0
        and any(w.startswith(("set chief_id of region 2 to 1", "share chief on region 2 with user 1")) for w in ways)
        and not any("folder 2" in w for w in ways),
        said,
    )
    check("... and nothing of it stays", psql(cross, "SELECT chief_id FROM cx.regions WHERE id = 2") == "2")
    subprocess.run(["dropdb", "--if-exists", cross], capture_output=True)

    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    print("studio: all passed" if not fails else f"studio: {fails} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
