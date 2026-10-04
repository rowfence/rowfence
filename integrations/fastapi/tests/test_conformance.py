"""The conformance suite (integrations/README.md): the same checks for every stack. This is FastAPI,
SQLAlchemy async on asyncpg, Alembic. test.sh does check 11 (a fresh database: migrate, the policy's tests,
then Alembic's own diff shows no change) before these run."""
import asyncio
import os
import shutil
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import asyncpg
import httpx
import psycopg
import pytest
import rowfence
from app.main import digest, make_app
from fastapi import FastAPI
from rowfence import ConnectionProblem, Refused
from rowfence.testing import AssertNotFound, AssertRefused, AsUser

from .conftest import OWNER, libpq

pytestmark = pytest.mark.anyio
APP = os.environ.get("ROWFENCE_APP_URL", "")
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED: dict[str | None, list[int]] = {"1": [1, 3, 4], "2": [2, 3], "3": [1, 3, 4], None: [3]}
PROJECTS: dict[str | None, list[int]] = {"1": [1, 3], "2": [2, 3], None: [3]}      # the projects each may see


def client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://conformance")


def as_(user: str | None) -> dict[str, str]:
    return {"x-user": user} if user else {}


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    a = make_app(APP, check_connection=False)
    yield a
    await a.state.engine.dispose()


# 1, 2: a list shows only the user's rows; signed out on purpose, only what anyone may see
async def test_1_2_lists_show_what_each_may_see(app: FastAPI) -> None:
    async with client(app) as c:
        for user, notes in EXPECTED.items():
            assert (await c.get("/notes", headers=as_(user))).json() == notes, user
        assert (await c.get("/projects", headers=as_(None))).json() == [3]


# 3: not signed in at all: the strict sign-in error, naming act_as
async def test_3_not_signed_in_is_an_error_that_says_how() -> None:
    conn = await asyncpg.connect(libpq(APP))
    try:
        async with conn.transaction():
            with pytest.raises(asyncpg.PostgresError) as e:
                await conn.fetchval("SELECT count(*) FROM app.notes")
        hint = str(getattr(e.value, "hint", "") or "")            # asyncpg sets its fields at run time
        assert rowfence.sqlstate(e.value) == "28000" and "act_as" in hint, (rowfence.sqlstate(e.value), hint)
        assert rowfence.error_code(e.value) == "AZ701", hint                # rowfence help AZ701
    finally:
        await conn.close()


# 4: one pooled connection, Ann then Bob: Bob never sees Ann's rows
async def test_4_a_pooled_connection_carries_no_one_over() -> None:
    a = make_app(APP, check_connection=False, pool_size=1)
    async with client(a) as c:
        assert (await c.get("/notes", headers=as_("1"))).json() == EXPECTED["1"]
        assert (await c.get("/notes", headers=as_("2"))).json() == EXPECTED["2"]
        assert (await c.get("/notes")).json() == EXPECTED[None]
    await a.state.engine.dispose()


# 5: concurrent requests never mix users
async def test_5_concurrent_requests_never_mix_users(app: FastAPI) -> None:
    users = ["1", "2", "3", None] * 10
    async with client(app) as c:
        got = await asyncio.gather(*[c.get("/notes", headers=as_(u)) for u in users])
    assert [r.json() for r in got] == [EXPECTED[u] for u in users]


# 6: a refused insert: 403, with the problem body naming the rule
async def test_6_a_refused_insert_says_which_rule(app: FastAPI) -> None:
    async with client(app) as c:
        r = await c.post("/notes", json={"project_id": 3, "body": "hi"}, headers=as_("2"))
    assert r.status_code == 403, r.text
    body = r.json()
    assert r.headers["content-type"] == "application/problem+json"
    assert body["table"] == "app.notes" and body["command"] == "insert", body
    assert body["code"] == "AZ709", body                                # rowfence help AZ709
    assert "user 2 may not insert this row into app.notes" in body["detail"]
    assert any("project.edit" in line for line in body["why"]), body["why"]


# 7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason
async def test_7_hidden_is_404_and_not_allowed_is_403(app: FastAPI) -> None:
    async with client(app) as c:
        hidden = await c.patch("/notes/1", json={"body": "x"}, headers=as_("2"))
        refused = await c.patch("/notes/1", json={"body": "x"}, headers=as_("3"))
        mine = await c.patch("/notes/4", json={"body": "better idea"}, headers=as_("3"))
        gone = await c.delete("/notes/2", headers=as_("1"))
        no = await c.delete("/notes/1", headers=as_("3"))
    assert hidden.status_code == 404, hidden.text
    assert refused.status_code == 403 and refused.json()["command"] == "update", refused.text
    assert any("edit" in line for line in refused.json()["why"]), refused.json()
    assert mine.status_code == 200, mine.text
    assert gone.status_code == 404, gone.text
    assert no.status_code == 403 and no.json()["command"] == "delete" and no.json()["why"], no.text


# 8: an insert read back works when the select rule allows it, and is explained when not
async def test_8_insert_then_read_back(app: FastAPI) -> None:
    async with client(app) as c:
        ok = await c.post("/notes", json={"project_id": 1, "body": "new"}, headers=as_("1"))
        unreadable = await c.post("/inbox", json={"recipient_id": 2, "body": "hi bo"}, headers=as_("1"))
        quiet = await c.post("/inbox/quietly", json={"recipient_id": 2, "body": "hi bo"}, headers=as_("1"))
    assert ok.status_code == 201 and ok.json()["id"] > 100, ok.text
    assert unreadable.status_code == 403, unreadable.text
    assert unreadable.json()["command"] == "select" and "read the row back" in unreadable.json()["detail"]
    assert quiet.status_code == 202, quiet.text


# 9: the generated names type-check, and a wrong permission name doesn't
def test_9_generated_names_type_check(tmp_path: Path) -> None:
    subprocess.run([sys.executable, "-m", "rowfence", "client"],
                   cwd=HERE, check=True, capture_output=True)
    good = tmp_path / "good.py"
    bad = tmp_path / "bad.py"
    use = "from app.authz_client import Authz\n\ndef f(a: Authz) -> bool:\n    return a.can('note', 1, {!r})\n"
    good.write_text(use.format("edit"))
    bad.write_text(use.format("edt"))
    env = {**os.environ, "MYPYPATH": HERE}
    ok = subprocess.run([sys.executable, "-m", "mypy", "--no-error-summary", str(good)], env=env, capture_output=True, text=True)
    wrong = subprocess.run([sys.executable, "-m", "mypy", "--no-error-summary", str(bad)], env=env, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout
    assert wrong.returncode != 0 and "edt" in wrong.stdout, wrong.stdout


# 10: a background job signs in as a service principal
async def test_10_a_job_acts_as_its_service(app: FastAPI) -> None:
    with rowfence.acting_as(3):                    # whatever started it
        count, who = await digest(app.state.Session)
    assert who == rowfence.Principal("service", "1")
    assert count == 2                              # project 1 (it is added to) and the public one


# ... and only when the code names it: an id is a user's, whatever it holds (ids come from outside)
def test_10_an_id_with_a_colon_is_a_users_not_a_service() -> None:
    assert rowfence.Principal.of("service:1") == rowfence.Principal("user", "service:1")
    assert rowfence.Principal.of(("service", 1)) == rowfence.Principal("service", "1")
    with rowfence.acting_as("service:1"):
        assert rowfence.current() == rowfence.Principal("user", "service:1")
    # what str() wrote, read back, for text the app wrote itself
    assert rowfence.Principal.parse(str(rowfence.Principal("service", "1"))) == rowfence.Principal("service", "1")
    assert rowfence.Principal.parse("42") == rowfence.Principal("user", "42")
    assert rowfence.Principal.parse("nobody") == rowfence.NOBODY


# 13: the app refuses to start on a connection that skips row-level security
async def test_13_refuses_a_connection_that_skips_rls() -> None:
    owner_app = make_app(OWNER.replace("+psycopg", "+asyncpg"), check_connection=False)
    with pytest.raises(ConnectionProblem) as e:
        await owner_app.state.authz.check()
    assert "owners skip row-level security" in str(e.value) or "superuser" in str(e.value)
    await owner_app.state.engine.dispose()
    fine = make_app(APP, check_connection=False)
    await fine.state.authz.check()
    await fine.state.engine.dispose()


# queries by permission: set checks, and one call for a list's buttons
async def test_queries_by_permission(app: FastAPI) -> None:
    async with client(app) as c:
        assert (await c.get("/projects/editable", headers=as_("3"))).json() == [1]
        assert (await c.get("/projects/buttons", headers=as_("3"))).json() == {"1": ["edit", "view"], "3": ["view"]}


# SQLAlchemy's sync engine and ORM (and so SQLModel, which is built on them)
def test_sqlalchemy_sync_engine() -> None:
    from app.models import Note
    from rowfence import sqlalchemy as authz_sa
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session
    from sqlalchemy.orm.exc import StaleDataError
    engine = authz_sa.install(create_engine(APP.replace("+asyncpg", "+psycopg")))
    try:
        with rowfence.acting_as(2), Session(engine) as s:
            assert sorted(s.scalars(select(Note.id)).all()) == [2, 3]
            assert authz_sa.can_sync(s, "note", 2, "edit") and not authz_sa.can_sync(s, "note", 3, "edit")
        with rowfence.acting_as(3):
            with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
                note = s.get(Note, 1)
                assert note is not None
                note.body = "x"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused) and verdict.why, verdict
    finally:
        engine.dispose()


# the drivers without SQLAlchemy
def test_psycopg_transactions() -> None:
    import rowfence.psycopg as pgp
    with psycopg.connect(libpq(APP)) as conn:
        with pgp.transaction(conn, 2):
            assert [r[0] for r in conn.execute("SELECT id FROM app.notes ORDER BY id")] == [2, 3]
        with pytest.raises(Refused), pgp.transaction(conn, 3):
            cur = conn.execute("UPDATE app.notes SET body = 'x' WHERE id = 1")
            pgp.expect(conn, cur.rowcount, "app.notes", "update", 1)


async def test_asyncpg_transactions() -> None:
    import rowfence.asyncpg as pga
    conn = await asyncpg.connect(libpq(APP))
    try:
        with rowfence.acting_as(("service", "1")):
            async with pga.transaction(conn):
                assert [r["id"] for r in await conn.fetch("SELECT id FROM app.projects ORDER BY id")] == [1, 3]
        async with pga.transaction(conn, 2):
            with pytest.raises(rowfence.NotFound):
                await pga.expect(conn, await conn.execute("DELETE FROM app.notes WHERE id = 1"), "app.notes", "delete", 1)
    finally:
        await conn.close()


# 13, as it happens: the app refuses to start, whether or not it has a lifespan of its own
async def test_13_the_app_does_not_start_on_a_connection_that_skips_rls() -> None:
    import contextlib

    from rowfence.fastapi import Rowfence
    from sqlalchemy.ext.asyncio import create_async_engine
    started: list[str] = []

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        started.append("the app's own lifespan")
        yield

    for own in (None, lifespan):
        engine = create_async_engine(OWNER.replace("+psycopg", "+asyncpg"))
        a = FastAPI(lifespan=own)
        Rowfence(a, engine, user=lambda request: request.headers.get("x-user"))
        with pytest.raises(ConnectionProblem):
            async with a.router.lifespan_context(a):
                pass
        await engine.dispose()
    assert started == []
    # and on the app role's connection it starts, with its own lifespan run
    engine = create_async_engine(APP)
    a = FastAPI(lifespan=lifespan)
    Rowfence(a, engine, user=lambda request: request.headers.get("x-user"))
    async with a.router.lifespan_context(a):
        assert started == ["the app's own lifespan"]
    await engine.dispose()


# who the request is may be refused by the app (a bad token): its answer, not a 500
async def test_user_may_raise() -> None:
    from fastapi import HTTPException
    from rowfence.fastapi import Rowfence
    from starlette.requests import Request

    def who(request: Request) -> str | None:
        if request.headers.get("authorization") == "Bearer bad":
            raise HTTPException(401, "bad token")
        return request.headers.get("x-user")

    a = FastAPI()
    Rowfence(a, None, user=who)

    @a.get("/me")
    async def me() -> str:
        return str(rowfence.current())

    async with client(a) as c:
        bad = await c.get("/me", headers={"authorization": "Bearer bad"})
        assert bad.status_code == 401 and bad.json() == {"detail": "bad token"}, bad.text
        assert (await c.get("/me", headers=as_("2"))).json() == "2"


# None is nobody, also inside acting_as; only a left-out argument means whoever the code acts for
async def test_none_is_nobody_inside_acting_as() -> None:
    import rowfence.asyncpg as pga
    import rowfence.psycopg as pgp
    with rowfence.acting_as(1):
        assert rowfence.act_as_args(None) == (None, None) and rowfence.act_as_args() == ("user", "1")
        assert rowfence.act_as_sql(None) == "SELECT authz.act_as(NULL, NULL)"
        with psycopg.connect(libpq(APP)) as conn:
            with pgp.transaction(conn, None):
                assert [r[0] for r in conn.execute("SELECT id FROM app.projects ORDER BY id")] == PROJECTS[None]
            with pgp.transaction(conn):
                assert [r[0] for r in conn.execute("SELECT id FROM app.projects ORDER BY id")] == PROJECTS["1"]
        aconn = await asyncpg.connect(libpq(APP))
        try:
            async with pga.transaction(aconn, None):
                assert [r["id"] for r in await aconn.fetch("SELECT id FROM app.projects ORDER BY id")] == PROJECTS[None]
        finally:
            await aconn.close()


# a block inside a transaction already open is a savepoint: the sign-in ends with the block all the same
async def test_a_block_inside_an_open_transaction_signs_out_again() -> None:
    import rowfence.asyncpg as pga
    import rowfence.psycopg as pgp
    projects = "SELECT id FROM app.projects ORDER BY id"      # (the projects: no test adds one)
    with psycopg.connect(libpq(APP)) as conn:
        conn.execute("SELECT 1")                               # psycopg begins a transaction here
        with pgp.transaction(conn, 2):
            assert [r[0] for r in conn.execute(projects)] == PROJECTS["2"]
        assert [r[0] for r in conn.execute(projects)] == PROJECTS[None]      # nobody, not bo
        conn.rollback()
        with pgp.transaction(conn, 1):
            with pgp.transaction(conn, 2):
                assert [r[0] for r in conn.execute(projects)] == PROJECTS["2"]
            assert [r[0] for r in conn.execute(projects)] == PROJECTS["1"]   # back to the block around it
    if sys.platform != "win32":                                # psycopg's async connections need a selector loop
        async with await psycopg.AsyncConnection.connect(libpq(APP)) as aconn:
            await aconn.execute("SELECT 1")
            async with pgp.atransaction(aconn, 2):
                pass
            assert [r[0] for r in await (await aconn.execute(projects)).fetchall()] == PROJECTS[None]
    pconn = await asyncpg.connect(libpq(APP))
    try:
        async with pconn.transaction():
            async with pga.transaction(pconn, 2):
                assert [r["id"] for r in await pconn.fetch(projects)] == PROJECTS["2"]
            assert [r["id"] for r in await pconn.fetch(projects)] == PROJECTS[None]
    finally:
        await pconn.close()


# a flush of several rows: the verdict is about the row that was refused, not the last one written;
# an id with a % reaches the database as it is; a model that names no schema is found on the search_path
def test_sqlalchemy_which_row_and_which_table() -> None:
    from app.models import Note
    from rowfence import sqlalchemy as authz_sa
    from sqlalchemy import BigInteger, Text, create_engine, text
    from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
    from sqlalchemy.orm.exc import StaleDataError
    engine = authz_sa.install(create_engine(APP.replace("+asyncpg", "+psycopg")))
    try:
        with rowfence.acting_as(3):                            # cy may edit note 4, not note 1
            with pytest.raises(StaleDataError) as e, Session(engine) as s, s.begin():
                first, last = s.get(Note, 1), s.get(Note, 4)
                assert first is not None and last is not None
                first.body, last.body = "x", "y"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused) and "app.notes 1" in verdict.message, verdict
            assert verdict.why[0].startswith("no"), verdict.why
        for who in ("50%", "a%sb", "%(x)s"):                   # not a user of this app: nobody, and no error
            with rowfence.acting_as(who), Session(engine) as s:
                assert s.scalars(text("SELECT id FROM app.notes ORDER BY id")).all() == EXPECTED[None]
    finally:
        engine.dispose()

    class Base(DeclarativeBase):
        pass

    class BareNote(Base):
        __tablename__ = "notes"
        id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
        body: Mapped[str] = mapped_column(Text)

    bare = authz_sa.install(create_engine(APP.replace("+asyncpg", "+psycopg"), connect_args={"options": "-c search_path=app"}))
    try:
        with rowfence.acting_as(3):
            with pytest.raises(StaleDataError) as e, Session(bare) as s, s.begin():
                note = s.get(BareNote, 1)
                assert note is not None
                note.body = "x"
            verdict = authz_sa.why_stale_sync(e.value)
            assert isinstance(verdict, Refused) and verdict.why[0].startswith("no"), verdict
    finally:
        bare.dispose()


# an UPDATE that matched nothing for another reason than access isn't a refusal; expect takes the cursor too;
# a 42501 that isn't a policy's (a table the app role was never granted) isn't one either
def test_refused_means_the_database_said_no() -> None:
    import rowfence.psycopg as pgp
    with psycopg.connect(libpq(APP)) as conn:
        with pytest.raises(rowfence.NotFound), pgp.transaction(conn, 3):          # cy may edit note 4
            cur = conn.execute("UPDATE app.notes SET body = 'x' WHERE id = 4 AND body = 'something else'")
            pgp.expect(conn, cur.rowcount, "app.notes", "update", 4)
        with pytest.raises(Refused), pgp.transaction(conn, 3):
            pgp.expect(conn, conn.execute("UPDATE app.notes SET body = 'x' WHERE id = 1"), "app.notes", "update", 1)
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as e, pgp.transaction(conn, 1):
            conn.execute("SELECT * FROM public.alembic_version")
        assert rowfence.refusal(e.value) is None
    assert rowfence.key_text(("a,b", 1)) == '("a,b","1")' and rowfence.key_text((7,)) == "7"


# the pytest helpers (rowfence.testing), with sync and async functions
async def test_the_pytest_helpers(as_user: AsUser, assert_refused: AssertRefused, assert_not_found: AssertNotFound) -> None:
    import rowfence.psycopg as pgp

    def update(note: int) -> None:
        with psycopg.connect(libpq(APP)) as conn, pgp.transaction(conn):
            pgp.expect(conn, conn.execute("UPDATE app.notes SET body = 'x' WHERE id = %s", (note,)), "app.notes", "update", note)

    async def insert_later() -> None:
        with psycopg.connect(libpq(APP)) as conn, pgp.transaction(conn):
            conn.execute("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")

    with as_user(3):
        assert assert_refused(lambda: update(1), command="update", table="app.notes").why
        with pytest.raises(AssertionError, match="expected the delete rule"):
            assert_refused(lambda: update(1), command="delete")
        with pytest.raises(AssertionError, match="expected a refusal"):
            assert_refused(lambda: update(4))
    with as_user(2):
        assert_not_found(lambda: update(1))
        assert (await assert_refused(insert_later, command="insert")).table == "app.notes"


# 14: after a policy change and a new migration, the app works with the new generated names
def test_14_a_policy_change_ships_as_the_next_migration(tmp_path: Path) -> None:
    work = tmp_path / "app"
    shutil.copytree(HERE, work, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", ".mypy_cache"))
    policy = work / "db" / "policy.authz"
    policy.write_text(policy.read_text().replace("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n"))
    cli = "-m", "rowfence"                          # the command, as the rowfence package installs it
    subprocess.run([sys.executable, *cli, "migrate"], cwd=work, check=True, capture_output=True)
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=work, check=True, capture_output=True)
    subprocess.run([sys.executable, *cli, "client"], cwd=work, check=True, capture_output=True)
    assert '"reply"' in (work / "app" / "authz_client.py").read_text()
    with psycopg.connect(libpq(APP)) as conn, conn.transaction():
        conn.execute("SELECT authz.act_as(%s, %s)", rowfence.act_as_args(2))
        got = conn.execute("SELECT authz.perms('message', id::text) FROM app.inbox WHERE recipient_id = 2").fetchall()
    assert got and all("reply" in r[0] for r in got), got
