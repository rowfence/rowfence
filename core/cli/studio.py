"""rowfence Studio: a local web page over a database with a policy in force.

    rowfence studio [--port 4983] [--write]     (rowfence dev starts it too, able to write: a development database)

Browse the app's tables as anyone (rows they can't see greyed, masked columns as they get them), see why they hold a permission or not and the
smallest change that would grant it (authz grant.py, each change tried and undone), the policy as a graph,
what the policy file on disk would change on this data (the access diff), the shares on an object and the
pending access requests, and turn "Ann should see this row" into a test.

Read-only by default: every request runs in a READ ONLY transaction that is rolled back, so it can point at
staging or production; how-to-grant then lists the changes without trying them. With --write (and in dev),
sharing, unsharing and deciding requests act as the person you view as, so the database decides whether they
may. It listens on 127.0.0.1 only, and every API call needs the token in the URL it prints (a page on another
site can't read it, and a DNS name pointing here is refused).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
import threading
import traceback
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, TypeVar
from urllib.parse import parse_qs, urlparse

import pgwire
from authzlib import Compiler, database, grant
from authzlib.connection import Value as Json
from authzlib.parse import Ref, Type
from authzlib.sqlutil import lit, qt
from authzlib.sqlutil import q as quoted

if TYPE_CHECKING:
    from rowfence_cli import Config, Db

T = TypeVar("T")
Message = dict[str, Json]
Query = dict[str, str]          # the request's query parameters
Who = tuple[str | None, str | None]  # (principal type, id); (None, None): nobody
PolicyReader = Callable[[str], tuple[str, dict[str, str]]]

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "studio")
ROWS = 50
# the page's files, and nothing else: a request never names a path on the disk
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}


class Problem(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def principal(who: str | None) -> Who:
    """'user:42' -> ('user', '42'); 'anyone' or '' -> (None, None): nobody."""
    who = (who or "").strip()
    if who in ("", "anyone", "nobody"):
        return None, None
    kind, sep, ident = who.partition(":")
    if not sep:
        kind, ident = "user", who
    if not ident or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", kind):
        raise Problem(f"as whom? {who!r}: write user:42, bot:7 or anyone")
    return kind, ident


class Studio:
    def __init__(self, dsn: str | None, cfg: Config | None = None, policy_path: str | None = None, writable: bool = False,
                 port: int = 4983, token: str | None = None, read_policy: PolicyReader | None = None) -> None:
        self.dsn, self.cfg, self.policy_path, self.writable = dsn, cfg, policy_path, writable
        self.port, self.token = port, token or secrets.token_urlsafe(18)
        self.read_policy = read_policy        # path -> (text, files): the command's reader (includes from disk)
        # the policy in force, compiled once: (its text and files, the compiler)
        self._compiled: tuple[tuple[str, str], Compiler] | None = None
        self.lock = threading.Lock()
        self.server: ThreadingHTTPServer | None = None

    # --- the database ----------------------------------------------------------------------------------
    def connect(self) -> pgwire.Connection:
        return pgwire.connect(**pgwire.parse_dsn(self.dsn))

    def work(self, fn: Callable[[Db], T], write: bool = False) -> T:
        """fn(db) in one transaction: READ ONLY and rolled back, unless this is a write Studio may make."""
        from rowfence_cli import Db
        conn = self.connect()
        try:
            conn.execute("BEGIN" if (self.writable and write) else "BEGIN READ ONLY")
            try:
                out = fn(Db(conn))
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT" if (self.writable and write) else "ROLLBACK")
            return out
        finally:
            conn.close()

    def compiler(self, db: Db) -> Compiler:
        policy, files = database.applied(db)
        key = (policy, json.dumps(files, sort_keys=True))
        with self.lock:
            if self._compiled is None or self._compiled[0] != key:
                self._compiled = (key, database.policy_compiler(policy, files))
            return self._compiled[1]

    @staticmethod
    def act_as(db: Db, who: Who) -> None:
        kind, ident = who
        db.rows("SELECT authz.act_as($1, $2)", [kind, ident])

    @staticmethod
    def app_role(db: Db) -> str:
        rows = db.rows("SELECT DISTINCT r.rolname AS r FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_description d "
                       "ON d.objoid = p.oid AND d.classoid = 'pg_catalog.pg_policy'::regclass AND d.description = 'rowfence' "
                       "CROSS JOIN unnest(p.polroles) ro JOIN pg_catalog.pg_roles r ON r.oid = ro")
        if not rows:
            raise Problem("no policy with rules is applied, so there is no app role to look through", 409)
        return str(rows[0]["r"])

    # --- what the page asks ----------------------------------------------------------------------------
    def overview(self, q: Query) -> Message:
        def run(db: Db) -> Message:
            c = self.compiler(db)
            name = db.rows("SELECT current_database() AS d, current_user AS u")[0]
            types: list[Json] = []
            for t in c.types.values():
                perms: list[Json] = [{"name": n, "src": p.src, "line": str(p.loc)} for n, p in t.perms.items() if not p.hidden]
                rels: list[Json] = [{"name": n, "line": str(r.loc), "subjects": ["#".join(x for x in s if x) for s in r.subjects()],
                         "shared": any(src.kind == "shared" for src in r.sources)} for n, r in t.relations.items()
                        if not r.synthetic]
                types.append({"name": t.name, "table": t.table, "principal": t.principal, "perms": perms, "relations": rels,
                              "line": str(t.loc)})
            tables = sorted({r.table for r in c.pol.rules} | {t.table for t in c.types.values()})
            principals: list[Json] = [t.name for t in c.types.values() if t.principal]
            return {"database": name["d"], "as": name["u"], "writable": self.writable, "types": types, "tables": list[Json](tables),
                    "principals": principals,
                    "policy_file": os.path.relpath(self.policy_path) if self.policy_path else None}
        return self.work(run)

    def rows(self, q: Query) -> Message:
        table = q.get("table", "")
        who = principal(q.get("as"))
        offset = max(0, int(q.get("offset", "0") or 0))

        def run(db: Db) -> Message:
            c = self.compiler(db)
            known = {r.table for r in c.pol.rules} | {t.table for t in c.types.values()}
            if table not in known:
                raise Problem(f"{table!r} is not a table the policy governs", 404)
            t = next((t for t in c.types.values() if t.table == table), None)
            view = c.pol.views.get(table)
            masked = sorted({col for r in c.pol.rules if r.table == table and r.command == "mask" for col in r.columns})
            key = f"({c.key(t, 'r')})::text" if t else "NULL::text"
            order = key if t else "r.ctid"
            data = db.rows(f"SELECT r.ctid::text AS authz_ctid, {key} AS authz_id, to_jsonb(r) AS authz_row "
                           f"FROM {qt(table)} r ORDER BY {order} LIMIT {ROWS + 1} OFFSET {offset}")
            more, data = len(data) > ROWS, data[:ROWS]
            total = db.rows(f"SELECT count(*) AS n FROM {qt(table)}")[0]["n"]
            # as the app role, signed in as them: which of these rows they see
            role = self.app_role(db)
            self.act_as(db, who)
            try:
                with database.savepoint(db, "authz_studio_role"):
                    db.rows(f'SET LOCAL ROLE "{role}"')
            except db.errors:
                raise Problem(f"Studio looks at the rows through the app role, {role}, and this connection can't take it: "
                              f"GRANT {role} TO the role Studio connects as (the tables' owner)", 409) from None
            ids = [str(r["authz_id"]) for r in data]
            theirs: dict[str, Message] = {}
            if view and t:
                # a table read through its masked view (the app role can't read the table's masked columns, nor
                # its ctid): the rows they see, with each masked column as they get it
                seen = set[Json]()
                theirs = {str(r["id"]): as_object(r["authz_row"]) for r in db.rows(
                    f"SELECT {key} AS id, to_jsonb(r) AS authz_row FROM {qt(view)} r WHERE {key} = ANY ($1::text[])",
                    [database.text_array(ids)])}
                seen_total = db.rows(f"SELECT count(*) AS n FROM {qt(view)}")[0]["n"]
            else:
                ctids = [str(r["authz_ctid"]) for r in data]
                seen = {r["c"] for r in db.rows(f"SELECT r.ctid::text AS c FROM {qt(table)} r WHERE r.ctid = ANY ($1::tid[])",
                                                      [database.text_array(ctids)])}
                seen_total = db.rows(f"SELECT count(*) AS n FROM {qt(table)}")[0]["n"]
            db.rows("RESET ROLE")
            perms: dict[str, Json] = {}
            if t:
                perms = {str(r["id"]): r["perms"] or [] for r in db.rows("SELECT id, perms FROM authz.perms_of($1, $2::text[])",
                                                                          [t.name, database.text_array(ids)])}
            values = [as_object(r["authz_row"]) for r in data]
            columns: list[Json] = list(values[0]) if values else []
            out: list[Json] = []
            for r, row in zip(data, values, strict=True):
                # a row they see shows what they get: a masked column they may not read is empty, and named. A
                # row hidden from them stays as the owner reads it, greyed
                mine = theirs.get(str(r["authz_id"]))
                hidden_cols: list[Json] = [col for col in masked if mine is not None and mine.get(col) is None
                                           and row.get(col) is not None]
                out.append({"id": r["authz_id"], "visible": r["authz_ctid"] in seen or mine is not None,
                            "values": row if mine is None else mine, "masked": hidden_cols,
                            "perms": perms.get(str(r["authz_id"]), [])})
            return {"table": table, "type": t.name if t else None, "columns": columns, "rows": out, "offset": offset,
                    "more": more, "total": total, "visible_total": seen_total}
        return self.work(run)

    def why(self, q: Query) -> Message:
        kind, ident = principal(q.get("as"))
        if kind is None or ident is None:
            raise Problem("why for nobody: pick someone to view as (user:42)")

        def run(db: Db) -> Message:
            c = self.compiler(db)
            if self.writable:
                answer = database.why(db, kind, ident, q.get("type", ""), q.get("id", ""), q.get("perm", ""), compiler=c)
                tried = True
            else:
                answer, tried = untried(c, db, (kind, ident), q), False
            return {"holds": answer.holds, "explain": list[Json](answer.explain), "needs": answer.needs, "tried": tried,
                    "notes": list[Json](answer.notes),
                    "ways": [{"text": w.text, "grants": w.grants, "more_objects": w.more_objects, "more_people": w.more_people,
                              "also": list[Json](w.also), "fewer_people": w.fewer_people,
                              "lines": list[Json](sorted({str(ch.loc) for ch in w.changes})), "kinds": list[Json]([ch.kind for ch in w.changes])}
                             for w in answer.ways]}
        try:
            return self.work(run, write=True)          # each change is undone in its savepoint either way
        except database.Error as e:
            raise Problem(str(e)) from e

    def graph(self, q: Query) -> Message:
        return self.work(lambda db: {"mermaid": database.graph(*database.applied(db))})

    def diff(self, q: Query) -> Message:
        if not self.policy_path or not self.read_policy:
            raise Problem("no policy file to compare with (rowfence.toml's policy)", 404)
        try:
            text, files = self.read_policy(self.policy_path)
        except OSError as e:
            raise Problem(f"{self.policy_path}: {e.strerror}", 404) from None

        def run(db: Db) -> Message:
            in_force, in_force_files = database.applied(db)
            if in_force == text and in_force_files == files:
                return {"same_text": True, "summary": [], "rows": [], "truncated": False}
            if not self.writable:
                # it builds the file's policy in a transaction it undoes, which locks the app's tables
                raise Problem("the access diff builds the policy file's policy in a transaction it undoes, which locks the "
                              "app's tables: only on a development database (rowfence dev, or studio --write); for staging, "
                              "rowfence review --db on a copy", 409)
            rows = database.diff(db, text, files)
            users: dict[tuple[str, str, str], set[str]] = {}
            ids: dict[tuple[str, str, str], set[str]] = {}
            for r in rows:
                k = (r["change"], r["type"], r["what"])
                users.setdefault(k, set()).add(r["user_id"] or "anyone")
                ids.setdefault(k, set()).add(r["id"])
            summary: list[Json] = [{"change": c, "type": t, "what": w, "users": len(users[(c, t, w)]), "objects": len(ids[(c, t, w)])}
                                   for c, t, w in users]
            shown: list[Json] = [dict(r) for r in rows[:500]]
            return {"same_text": in_force == text, "summary": summary, "rows": shown, "truncated": len(rows) > 500}
        try:
            return self.work(run, write=True)          # the diff undoes itself (a savepoint)
        except database.Error as e:
            raise Problem(str(e)) from e

    def shares(self, q: Query) -> Message:
        def run(db: Db) -> Message:
            db.rows("SELECT authz.act_as(NULL, NULL)")
            shares: list[Json] = []
            if q.get("type") and q.get("id"):
                shares = [*db.rows("SELECT * FROM authz.list_shares($1, $2)", [q["type"], q["id"]])]
            requests: list[Json] = [*db.rows("SELECT id, object_type, object_id, relation, requester, reason, duration::text AS duration, "
                                              "created_at FROM authz.requests WHERE status = 'pending' ORDER BY id LIMIT 200")]
            return {"shares": shares, "requests": requests}
        return self.work(run)

    def change(self, what: str, body: Message) -> Message:
        """A share, unshare or decision, made as the person Studio views as (only with --write)."""
        if not self.writable:
            raise Problem("Studio is read-only here: start it with --write (or use rowfence dev) to change shares", 403)
        who = principal(str(body.get("as") or ""))
        if who[0] is None:
            raise Problem("as whom? pick someone to view as: they make the change")

        def run(db: Db) -> Message:
            self.act_as(db, who)
            if what == "share":
                db.rows("SELECT 1 AS ok FROM authz.share($1, $2, $3, $4, $5, $6)",
                        [body["type"], str(body["id"]), body["relation"], body["subject_type"], str(body["subject_id"]),
                         body.get("subject_relation") or ""])
            elif what == "unshare":
                db.rows("SELECT 1 AS ok FROM authz.unshare($1, $2, $3, $4, $5, $6)",
                        [body["type"], str(body["id"]), body["relation"], body["subject_type"], str(body["subject_id"]),
                         body.get("subject_relation") or ""])
            elif what == "decide":
                db.rows("SELECT 1 AS ok FROM authz.decide_request($1::bigint, $2, $3)",
                        [str(body["request"]), bool(body["approve"]), body.get("note")])
            return {"ok": True}
        return self.work(run, write=True)

    def test(self, q: Query) -> Message:
        """A test that says what should hold: a check on the data there now (the policy's test section), and a
        named test that brings the object's own row (its links to others are for you to add)."""
        who = principal(q.get("as"))
        type_name, oid, perm = q.get("type", ""), q.get("id", ""), q.get("perm", "")
        expect = q.get("expect", "can")
        if expect not in ("can", "cannot"):
            raise Problem("expect: can or cannot")
        subject = "anyone" if who[0] is None else f"{who[0]} {who[1]}" if who[0] != "user" else f"user {who[1]}"

        def run(db: Db) -> Message:
            c = self.compiler(db)
            if type_name not in c.types:
                raise Problem(f"no type {type_name} in the policy", 404)
            t = c.types[type_name]
            check = f"{subject} {expect} {perm} {type_name} {oid}"

            def value(v: Json) -> str:
                if v is None:
                    return "NULL"
                if isinstance(v, bool):
                    return "true" if v else "false"
                if isinstance(v, (int, float)):
                    return str(v)
                return lit(json.dumps(v) if isinstance(v, (dict, list)) else str(v))

            def insert(tt: Type, ident: str | None, var: str) -> str | None:
                """A given that makes a copy of the row, as a new row: None when it isn't there, or its key has
                several columns (the test then names the row that is there)."""
                if tt.pk is None or tt.composite:
                    return None
                row = db.rows(f"SELECT to_jsonb(r) AS j FROM {qt(tt.table)} r WHERE {c.key_is(tt, 'r', lit(ident))}")
                if not row:
                    return None
                j = as_object(row[0]["j"])
                # the columns the table fills itself (a serial key) are left to it; a key it doesn't fill gets a
                # new value, or the copy would collide with the row it was copied from
                own = {r["a"] for r in db.rows("SELECT attname AS a FROM pg_catalog.pg_attribute WHERE attrelid = $1::regclass "
                                               "AND attnum > 0 AND (atthasdef OR attidentity <> '')", [tt.table])}
                j = {k: v for k, v in j.items() if k not in own}
                vals = {k: value(v) for k, v in j.items()}
                if tt.pk in vals:
                    kind = tt.key[0][1]
                    vals[tt.pk] = ("gen_random_uuid()" if kind == "uuid" else lit(f"{j[tt.pk]} (a copy)") if kind in ("text", "varchar")
                                   else f"(SELECT coalesce(max({quoted(tt.pk)}), 0) + 1 FROM {qt(tt.table)})")
                cols = ", ".join(quoted(k) for k in vals)
                return (f"  given {var} = {{INSERT INTO {qt(tt.table)} ({cols}) VALUES ({', '.join(vals.values())}) "
                        f"RETURNING {quoted(tt.pk)}}}")
            lines = [f'test "{check}"']
            someone = "anyone" if who[0] is None else f"{who[0]} {who[1]}"
            if who[0] is not None and who[0] in c.types:
                g = insert(c.types[who[0]], who[1], "who")
                if g:
                    lines.append(g)
                    someone = f"{who[0]} $who"
            g = insert(t, oid, "it")
            if g:
                lines.append(g)
            lines.append("  -- add the rows that link them (the relations the explanation names), and change what must be unique")
            lines.append(f"  {someone} {expect} {perm} {type_name} {'$it' if g else oid}")
            return {"check": check, "named": "\n".join(lines) + "\n"}
        return self.work(run)

    # --- serving -----------------------------------------------------------------------------------------
    def url(self) -> str:
        return f"http://localhost:{self.port}/?token={self.token}"

    def start(self, background: bool = True) -> str:
        studio = self
        gets: dict[str, Callable[[Query], Message]] = {
            "overview": studio.overview, "rows": studio.rows, "why": studio.why, "graph": studio.graph,
            "diff": studio.diff, "shares": studio.shares, "test": studio.test}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                pass

            def send(self, status: int, body: bytes | Json, ctype: str = "application/json") -> None:
                data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(data)

            def allowed(self) -> bool:
                host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
                if host not in ("localhost", "127.0.0.1", "::1"):
                    self.send(403, {"title": "Forbidden", "status": 403, "detail": "Studio answers on localhost only"})
                    return False
                return True

            def api(self, method: str) -> None:
                parsed = urlparse(self.path)
                # as bytes: a header may hold anything, and compare_digest takes text only if it is ASCII
                if not secrets.compare_digest(self.headers.get("X-Studio-Token", "").encode("latin-1", "replace"),
                                              studio.token.encode()):
                    return self.send(401, {"title": "Unauthorized", "status": 401, "detail": "the token from the URL rowfence printed"})
                q = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
                name = parsed.path[len("/api/"):]
                try:
                    if method == "GET" and name in gets:
                        return self.send(200, gets[name](q))
                    if method == "POST" and name in ("share", "unshare", "decide"):
                        length = int(self.headers.get("Content-Length") or 0)
                        return self.send(200, studio.change(name, as_object(json.loads(self.rfile.read(length) or b"{}"))))
                    return self.send(404, {"title": "Not Found", "status": 404, "detail": name})
                except Problem as e:
                    return self.send(e.status, {"title": "Problem", "status": e.status, "detail": str(e)})
                except database.Error as e:
                    return self.send(400, {"title": "Problem", "status": 400, "detail": str(e) + (f" ({e.hint})" if e.hint else "")})
                except pgwire.PgError as e:
                    status = 403 if e.fields.get("C") == "42501" else 400
                    return self.send(status, {"title": "Database", "status": status, "detail": e.message,
                                              "why": (e.fields.get("D") or "").split("\n") if e.fields.get("D") else []})
                except (KeyError, ValueError) as e:
                    return self.send(400, {"title": "Problem", "status": 400, "detail": f"missing or wrong: {e}"})
                except Exception as e:        # the page shows it; the server goes on
                    traceback.print_exc()
                    return self.send(500, {"title": "Error", "status": 500, "detail": str(e)})

            def do_GET(self) -> None:
                if not self.allowed():
                    return
                path = urlparse(self.path).path
                if path.startswith("/api/"):
                    return self.api("GET")
                if path not in STATIC:
                    return self.send(404, b"not found", "text/plain")
                name, ctype = STATIC[path]
                with open(os.path.join(PAGE, name), "rb") as fh:
                    self.send(200, fh.read(), ctype)

            def do_POST(self) -> None:
                if self.allowed():
                    self.api("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.port = self.server.server_address[1]
        if background:
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
        else:
            self.server.serve_forever()
        return self.url()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()


def as_object(value: Json) -> Message:
    """A JSON object from the database: jsonb comes as a dict, json as its text."""
    got = json.loads(value) if isinstance(value, str) else value
    return got if isinstance(got, dict) else {}


def untried(c: Compiler, db: Db, who: tuple[str, str], q: Query) -> grant.Answer:
    """how_to_grant on a read-only Studio: the answer and the candidate changes, none tried."""
    g = grant.Grants(c, db, who[0], who[1])
    type_name, oid, perm = q.get("type", ""), q.get("id", ""), q.get("perm", "")
    if type_name not in c.types:
        raise Problem(f"no type {type_name} in the policy", 404)
    t = c.types[type_name]
    if perm not in t.perms and perm not in t.relations:
        raise Problem(f"{type_name} has no permission {perm}", 404)
    g.sign_in(False)
    explain = [str(x["l"]) for x in db.rows("SELECT l FROM authz.explain($1, $2, $3, $4) l", [type_name, oid, perm, who[1]])] \
        if who[0] == "user" else []
    g.sign_in()
    holds = db.rows("SELECT authz.can($1, $2, $3) AS ok", [type_name, oid, perm])[0]["ok"] is True
    p = t.perms.get(perm)
    answer = grant.Answer(holds, explain, f"{perm} = {p.src}  ({p.loc})" if p else f"{perm}: a relation")
    if not holds:
        seen: set[tuple[str, ...]] = set()
        for changes in g.ways(t, oid, Ref("ref", perm), 0, frozenset()):
            key = tuple(ch.sql for ch in changes)
            if key not in seen:
                seen.add(key)
                answer.ways.append(grant.Way(changes))
        answer.ways.sort(key=lambda w: (len(w.changes), sum(ch.cost for ch in w.changes)))
        answer.ways = answer.ways[:grant.SHOWN]
        answer.notes = list(dict.fromkeys(g.notes))
    return answer


def serve(dsn: str | None, cfg: Config, policy_path: str | None, writable: bool, port: int, read_policy: PolicyReader) -> None:
    studio = Studio(dsn, cfg, policy_path, writable, port, read_policy=read_policy)
    try:
        studio.work(lambda db: database.applied(db))
    except database.Error as e:
        print(f"rowfence studio: {e}" + (f"\nHINT: {e.hint}" if e.hint else ""), file=sys.stderr)
        sys.exit(1)
    url = studio.start(background=True)
    print(f"rowfence studio: {url}  ({'can write: shares and requests' if writable else 'read-only'}; Ctrl-C stops it)",
          flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        studio.stop()
