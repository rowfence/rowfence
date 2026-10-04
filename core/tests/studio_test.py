#!/usr/bin/env python3
"""studio_test: rowfence why (the smallest changes that would grant a permission) and Studio's API, on the
docs example: read-only by default (nothing it does stays, and it refuses to change shares), able to write
with --write (shares and decisions made as the person it views as, so the database decides), and only for the
page that has the token, on localhost.

    PGHOST=... PGUSER=... python3 tests/studio_test.py [--db authz_studio]
"""
import http.client
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import rowfence_cli  # noqa: E402
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
    r = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql], capture_output=True, text=True,
                       env=dict(os.environ, PGOPTIONS="-c client_min_messages=error"))
    if r.returncode:
        raise SystemExit(f"psql failed: {r.stderr}")
    return r.stdout.strip()


def cli(db: str, *args: str) -> tuple[int, str]:
    r = subprocess.run([sys.executable, os.path.join(ROOT, "cli", "rowfence_cli.py"), "--db", f"dbname={db}", *args],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


class Client:
    def __init__(self, s: studio.Studio, token: str | None = None) -> None:
        self.base, self.token = f"http://127.0.0.1:{s.port}", s.token if token is None else token

    def call(self, path: str, body: object = None, host: str | None = None) -> tuple[int, Answer]:
        headers: dict[str, str] = {"X-Studio-Token": self.token}
        if host:
            headers["Host"] = host
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method="POST" if body is not None else "GET")
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
    subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", os.path.join(ROOT, "example", "app_schema.sql")],
                   check=True, capture_output=True)
    policy = os.path.join(ROOT, "example", "docs.authz")
    rc, out = cli(db, "apply", policy)
    if rc:
        raise SystemExit(out)
    # carol and the others are members of Acme (org 1): erin shares Company with them
    psql(db, "SELECT authz.act_as('user', '5'); SELECT authz.share('folder', '1', 'viewer', 'org', '1', 'member')")
    shares = lambda: psql(db, "SELECT count(*) FROM authz.shares")

    print("-- rowfence why")
    rc, out = cli(db, "why", "--as", "user:3", "folder", "3", "edit")
    lines = out.splitlines()
    ways = [x.strip() for x in lines[lines.index("would be granted by:") + 1:]] if "would be granted by:" in lines else []
    check("no, and why not", rc == 0 and lines[0] == "no: user:3 does not hold edit on folder 3", out)
    check("the smallest change first: a share on the folder itself", ways and ways[0].startswith("share editor on folder 3 with user 3"), out)
    check("... with what else it grants, and the policy line it adds to",
          ways and "(also gives edit on" in ways[0] and "[line " in ways[0], out)
    check("a group the object is linked to: join it", any(w.startswith("add user 3 to app.team_members for team") for w in ways), out)

    def granted_by(*question: str) -> tuple[list[str], str]:
        _, said = cli(db, "why", *question)
        after = said.splitlines()
        return ([x.strip() for x in after[after.index("would be granted by:") + 1:]] if "would be granted by:" in after else []), said
    asked, out = granted_by("--as", "user:6", "folder", "2", "view")
    check("the way that gives the least comes first: a viewer, before an editor",
          asked and asked[0].startswith("share viewer on folder 2 with user 6") and "also gives" not in asked[0]
          and any(w.startswith("share editor on folder 2 with user 6 (also gives edit on it") for w in asked), out)
    asked, out = granted_by("--as", "user:3", "folder", "3", "share")
    owner = next((w for w in asked if w.startswith("set owner_id of folder 3 to 3")), "")
    check("a column: the folder's owner, with the other permissions it gives and whom it takes it from",
          "(also gives edit" in owner and "(takes share on it from 1 person)" in owner, out)
    rc, out = cli(db, "why", "--as", "user:1", "folder", "3", "edit")
    check("yes, and why", rc == 0 and out.startswith("yes: user:1 holds edit on folder 3") and "owner" in out, out)
    rc, out = cli(db, "why", "--as", "user:2", "folder", "3", "fly")
    check("a permission the type doesn't have is named", rc != 0 and "folder has no permission fly" in out, out)
    before = shares()
    rc, out = cli(db, "why", "--as", "user:7", "file", "10", "view")
    check("nothing it tried stays", shares() == before and "share viewer on file 10 with user 7" in out, out)

    print("-- Studio, read-only")
    dsn = f"dbname={db}"
    ro = studio.Studio(dsn, None, policy, writable=False, port=0, read_policy=rowfence_cli.read_policy)
    ro.start(background=True)
    c = Client(ro)
    try:
        status, page = c.call("/")
        check("the page, without the token (it carries no data)", status == 200 and "rowfence Studio" in page, status)
        check("the API needs the token", Client(ro, token="wrong").call("/api/overview")[0] == 401)
        check("... and a request for localhost (not a DNS name pointed here)", c.call("/api/overview", host="evil.example:4983")[0] == 403)
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
        check("a token that isn't ASCII is a wrong token", Client(ro, token="caf\u00e9".encode().decode("latin-1")).call("/api/overview")[0] == 401)
        status, o = c.call("/api/overview")
        check("the overview: the database, the types, the tables", status == 200 and not o["writable"] and "app.folders" in o["tables"]
              and any(t["name"] == "folder" and any(p["name"] == "edit" for p in t["perms"]) for t in o["types"]), o)
        status, r = c.call("/api/rows?table=app.folders&as=user:2")
        hidden = [x for x in r["rows"] if not x["visible"]]
        check("the rows as bob: some hidden, each with his permissions",
              status == 200 and 0 < r["visible_total"] < r["total"] and hidden and all(x["perms"] == [] for x in hidden)
              and any("view" in x["perms"] for x in r["rows"] if x["visible"]), r)
        status, r2 = c.call("/api/rows?table=app.folders&as=anyone")
        check("... and as nobody", status == 200 and r2["visible_total"] < r["visible_total"], r2)
        check("only tables the policy governs", c.call("/api/rows?table=pg_catalog.pg_authid&as=user:2")[0] == 404)
        before = shares()
        status, w = c.call("/api/why?as=user:3&type=folder&id=3&perm=edit")
        check("why not, and the changes that might grant it, none tried (read-only)",
              status == 200 and w["holds"] is False and w["tried"] is False and w["ways"]
              and w["ways"][0]["text"] == "share editor on folder 3 with user 3" and shares() == before, w)
        status, e = c.call("/api/share", {"as": "user:1", "type": "folder", "id": "3", "relation": "editor", "subject_type": "user", "subject_id": "2"})
        check("read-only: no shares made", status == 403 and "read-only" in e["detail"] and shares() == before, e)
        status, t = c.call("/api/test?as=user:3&type=folder&id=3&perm=edit&expect=cannot")
        check("a test from what should hold: the check on the data there now",
              status == 200 and t["check"] == "user 3 cannot edit folder 3", t)
        check("... and a named test with its own rows (the key left to the table)",
              'given it = {INSERT INTO "app"."folders" (' in t["named"] and "user $who cannot edit folder $it" in t["named"]
              and '("id",' not in t["named"].split('"app"."folders"', 1)[1].split(")")[0], t["named"])
        check("... the person's row copied with a key of its own (the table doesn't fill it)",
              'given who = {INSERT INTO "app"."users" ("id", "name") VALUES ((SELECT coalesce(max("id"), 0) + 1 FROM "app"."users"), '
              in t["named"], t["named"])
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "made.authz"), "w", encoding="utf-8") as fh:
                fh.write(t["named"])
            rc, out = cli(db, "test", os.path.join(tmp, "made.authz"))
        made = out.split("user 3 cannot edit folder 3", 1)[-1].split("invariants", 1)[0]
        check("... and the test runs as it is: its rows are made, its check passes",
              "user 3 cannot edit folder 3" in out and "ok    " in made and "FAIL" not in made and "duplicate key" not in out, out[-800:])
        status, g = c.call("/api/graph")
        check("the graph", status == 200 and g["mermaid"].startswith("%%") and "flowchart" in g["mermaid"], g)
        status, d = c.call("/api/diff")
        check("the access diff: the file is the policy in force", status == 200 and d["same_text"] and d["summary"] == [], d)
        status, sh = c.call("/api/shares?type=folder&id=1")
        check("the shares on an object, as an administrator", status == 200 and any(x["subject_type"] == "org" for x in sh["shares"]), sh)
    finally:
        ro.stop()

    with tempfile.TemporaryDirectory() as tmp:
        changed = os.path.join(tmp, "docs.authz")
        with open(policy, encoding="utf-8") as fh:
            text = fh.read()
        with open(changed, "w", encoding="utf-8") as fh:
            fh.write(text.replace("  can edit  = share or editor or (parent.edit and {inherit})",
                                  "  can edit  = share or editor or viewer or (parent.edit and {inherit})"))
        s = studio.Studio(dsn, None, changed, writable=False, port=0, read_policy=rowfence_cli.read_policy)
        s.start(background=True)
        try:
            status, d = Client(s).call("/api/diff")
            check("read-only: no access diff of a changed file (it would lock the app's tables), and why",
                  status == 409 and "locks the app's tables" in d["detail"], d)
        finally:
            s.stop()
        s = studio.Studio(dsn, None, changed, writable=True, port=0, read_policy=rowfence_cli.read_policy)
        s.start(background=True)
        try:
            before = psql(db, "SELECT count(*) FROM authz.policy_versions")
            status, d = Client(s).call("/api/diff")
            check("the access diff of a changed file: who gains what, on this data, and nothing applied",
                  status == 200 and not d["same_text"] and any(x["change"] == "gains" and x["what"] == "permission edit" and x["type"] == "folder" for x in d["summary"])
                  and psql(db, "SELECT count(*) FROM authz.policy_versions") == before, d)
        finally:
            s.stop()

    print("-- Studio, able to write (rowfence dev, or --write)")
    rw = studio.Studio(dsn, None, policy, writable=True, port=0, read_policy=rowfence_cli.read_policy)
    rw.start(background=True)
    c = Client(rw)
    try:
        before = shares()
        status, w = c.call("/api/why?as=user:3&type=folder&id=3&perm=edit")
        check("why not: each change tried and undone", status == 200 and w["tried"] and all(x["grants"] for x in w["ways"])
              and w["ways"][0]["more_objects"] > 0 and shares() == before, w)
        body = {"type": "folder", "id": "3", "relation": "editor", "subject_type": "user", "subject_id": "3"}
        status, e = c.call("/api/share", {**body, "as": "user:3"})
        check("a share as someone who may not: refused, with the database's reason", status == 403 and "cannot share" in e["detail"], e)
        status, _ = c.call("/api/share", {**body, "as": "user:1"})
        _, r = c.call("/api/rows?table=app.folders&as=user:3")
        check("a share as the folder's owner, and carol can edit it", status == 200 and
              any(x["id"] == "3" and "edit" in x["perms"] for x in r["rows"]), (status, r))
        status, _ = c.call("/api/unshare", {**body, "as": "user:1"})
        check("... and unsharing it", status == 200 and shares() == before)
        psql(db, "SELECT authz.act_as('user', '2'); SELECT authz.request_access('folder', '5', 'viewer', 'for the audit')")
        status, sh = c.call("/api/shares")
        req = [x for x in sh["requests"] if x["object_id"] == "5"]
        check("a pending access request", status == 200 and req and req[0]["requester"] == "2", sh)
        status, e = c.call("/api/decide", {"as": "user:2", "request": req[0]["id"], "approve": True})
        check("deciding your own request is refused", status == 403, e)
        status, _ = c.call("/api/decide", {"as": "user:5", "request": req[0]["id"], "approve": True})
        check("... the owner approves it, and it is a share", status == 200 and
              psql(db, "SELECT count(*) FROM authz.shares WHERE object_id = '5' AND subject_id = '2'") == "1")
    finally:
        rw.stop()

    print("-- Studio on a table with a masked column (tests/multi.authz: mask body : edit)")
    masks = f"{db}_masks"
    subprocess.run(["dropdb", "--if-exists", masks], capture_output=True)
    subprocess.run(["createdb", masks], check=True)
    subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", masks, "-f", os.path.join(HERE, "multi_schema.sql")],
                   check=True, capture_output=True)
    lead, bob, carol = (f"00000000-0000-4000-8000-00000000000{n}" for n in (1, 2, 3))
    plain, bobs = "10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002"
    psql(masks, f"INSERT INTO mt.users VALUES ('{lead}'), ('{bob}'), ('{carol}'); INSERT INTO mt.orgs VALUES (1); "
                f"INSERT INTO mt.projects (id, org_id, lead_id) VALUES (1, 1, '{lead}'); "
                f"INSERT INTO mt.docs VALUES ('{plain}', 'project', 1, NULL, 'secret text'), ('{bobs}', 'project', 1, '{bob}', 'bob wrote this')")
    rc, out = cli(masks, "apply", os.path.join(HERE, "multi.authz"))
    if rc:
        raise SystemExit(out)
    psql(masks, f"SELECT authz.act_as('user', '{lead}'); SELECT authz.share('project', '1', 'viewer', 'user', '{bob}')")
    ms = studio.Studio(f"dbname={masks}", None, os.path.join(HERE, "multi.authz"), writable=False, port=0,
                       read_policy=rowfence_cli.read_policy)
    ms.start(background=True)
    c = Client(ms)
    try:
        def docs(who: str) -> tuple[int, Answer, dict[str, Answer]]:
            status, r = c.call(f"/api/rows?table=mt.docs&as={who}")
            return status, r, {x["id"]: x for x in r["rows"]} if status == 200 else {}
        status, r, by = docs(f"user:{lead}")
        check("the project's lead may edit: both rows, the masked column in full",
              status == 200 and r["visible_total"] == 2 and by[plain]["values"]["body"] == "secret text"
              and by[plain]["masked"] == [] and by[bobs]["masked"] == [], r)
        status, r, by = docs(f"user:{bob}")
        check("a viewer sees the rows, and the masked column as they get it: empty, and named",
              status == 200 and r["visible_total"] == 2 and by[plain]["visible"] and by[plain]["values"]["body"] is None
              and by[plain]["masked"] == ["body"], r)
        check("... but in full on the document they wrote (the mask's rule holds there)",
              status == 200 and by[bobs]["values"]["body"] == "bob wrote this" and by[bobs]["masked"] == [], r)
        status, r, by = docs(f"user:{carol}")
        check("someone with no access: every row hidden",
              status == 200 and r["visible_total"] == 0 and r["total"] == 2 and not any(x["visible"] for x in r["rows"])
              and all(x["masked"] == [] for x in r["rows"]), r)
    finally:
        ms.stop()
    subprocess.run(["dropdb", "--if-exists", masks], capture_output=True)

    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    print("studio: all passed" if not fails else f"studio: {fails} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
