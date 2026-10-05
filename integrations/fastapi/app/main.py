"""The conformance app: no permission checks anywhere. rowstile signs each request's transactions in, the
database filters reads and refuses writes, and the SDK turns refusals into 403 and hidden rows into 404."""

import os

import rowstile
from fastapi import FastAPI, Request
from pydantic import BaseModel
from rowstile import NotFound, Principal
from rowstile import sqlalchemy as authz_sa
from rowstile.fastapi import Rowstile
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .authz_client import ObjectType, Permission
from .models import Message, Note, Project

# the queries by permission, taking only the policy's names: a misspelled one doesn't type-check
queries = authz_sa.Queries[ObjectType, Permission]()


def user_of(request: Request) -> str | None:
    """Who the request is: a real app would read its session or token; here a header (none: nobody)."""
    return request.headers.get("x-user")


def signed_in() -> int:
    """The user the request acts for (Rowstile set it from user_of), as the tables' key."""
    who = rowstile.current()
    return int(who.id) if who is not None and who.id is not None else 0


def make_app(url: str | None = None, check_connection: bool = True, pool_size: int = 5) -> FastAPI:
    engine = create_async_engine(url or os.environ["ROWSTILE_APP_URL"], pool_size=pool_size, max_overflow=0)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    app = FastAPI()
    app.state.engine, app.state.Session = engine, Session
    authz = Rowstile(app, engine, user=user_of, check_connection=check_connection)
    app.state.authz = authz

    @app.get("/projects")
    async def projects() -> list[int]:
        async with Session() as s:
            return sorted((await s.scalars(select(Project.id))).all())

    @app.get("/projects/editable")
    async def editable() -> list[int]:
        async with Session() as s:
            return sorted(
                (await s.scalars(select(Project.id).where(Project.id.in_(queries.ids("project", "edit"))))).all()
            )

    @app.get("/projects/buttons")
    async def buttons() -> dict[str, list[Permission]]:
        async with Session() as s:
            ids = (await s.scalars(select(Project.id))).all()
            return await queries.perms_of(s, "project", ids)

    @app.get("/notes")
    async def notes() -> list[int]:
        async with Session() as s:
            return sorted((await s.scalars(select(Note.id))).all())

    class NewNote(BaseModel):
        project_id: int
        body: str

    @app.post("/notes", status_code=201)
    async def add_note(n: NewNote) -> dict[str, int]:
        async with Session.begin() as s:
            note = Note(project_id=n.project_id, author_id=signed_in(), body=n.body)
            s.add(note)
            await s.flush()
            return {"id": note.id}

    class Body(BaseModel):
        body: str

    @app.patch("/notes/{note_id}")
    async def edit_note(note_id: int, b: Body) -> dict[str, int]:
        async with Session.begin() as s:
            note = await s.get(Note, note_id)
            if note is None:
                raise NotFound("app.notes", note_id)
            note.body = b.body  # an update the rules may refuse: StaleDataError -> 403 with the reason
        return {"id": note_id}

    @app.delete("/notes/{note_id}", status_code=204)
    async def remove_note(note_id: int) -> None:
        async with Session.begin() as s:
            result = await s.execute(delete(Note).where(Note.id == note_id))
            await authz_sa.expect(s, result, "app.notes", "delete", note_id)

    class NewMessage(BaseModel):
        recipient_id: int
        body: str

    @app.post("/inbox", status_code=201)
    async def send(m: NewMessage) -> dict[str, int]:
        async with Session.begin() as s:
            msg = Message(sender_id=signed_in(), recipient_id=m.recipient_id, body=m.body)
            s.add(msg)
            await s.flush()  # reads the id back (RETURNING): only the recipient may read it
            return {"id": msg.id}

    @app.post("/inbox/quietly", status_code=202)
    async def send_quietly(m: NewMessage) -> dict[str, int]:
        # without reading the row back (SQLAlchemy's insert() would, with RETURNING, to learn the new id)
        async with Session.begin() as s:
            await s.execute(
                text("INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (:s, :r, :b)"),
                {"s": signed_in(), "r": m.recipient_id, "b": m.body},
            )
        return {}

    return app


@rowstile.job(("service", 1))
async def digest(Session: async_sessionmaker[AsyncSession]) -> tuple[int, Principal | None]:
    """A background job: it signs in as service 1, whatever request started it."""
    async with Session() as s:
        return (await s.scalar(select(func.count()).select_from(Project))) or 0, rowstile.current()
