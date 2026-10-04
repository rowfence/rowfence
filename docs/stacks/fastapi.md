# FastAPI, SQLAlchemy and Alembic

<!-- tested: every line of code below is in integrations/fastapi (tests/unit_test.py checks it) -->

A FastAPI app on SQLAlchemy (async, asyncpg) whose migrations are Alembic's. The routes check nothing: each
request's transactions sign in as its user, the database filters what they read and refuses what they may
not write, and the SDK answers a refusal with 403 and a hidden row with 404.

Everything here comes from `integrations/fastapi`, the conformance suite: a small app and the checks every
supported stack passes (`integrations/fastapi/test.sh`).

## Install

```sh
uv add "rowfence[fastapi,sqlalchemy,asyncpg]"
uv run rowfence init        # a first policy from your tables, a test file, rowfence.toml
```

`init` finds FastAPI and Alembic, and writes `rowfence.toml` for them. The conformance app's, with its own
name for the variable that holds the owner's connection and for the client:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWFENCE_OWNER_DSN"
[clients]
py = "app/authz_client.py"
[migrations]
tool = "alembic"
dir  = "migrations/versions"
```

Two roles connect. The owner of the tables runs the migrations (`ROWFENCE_OWNER_DSN` for the command, and
the same as an SQLAlchemy URL, `ROWFENCE_OWNER_URL`, for Alembic), and the app connects
as the role the policy names (`app role conf_app`), which row-level security applies to (`ROWFENCE_APP_URL`).

## The policy

```authz
app role conf_app

type user = app.users

type service = app.services principal

type project = app.projects
  owner   : user    = owner_id
  member  : user    = app.members(project_id -> user_id)
  service : service = app.project_services(project_id -> service_id)

  can edit = owner or member
  can view = edit or service or {public}

type note = app.notes
  project : project = project_id
  author  : user    = author_id

  can edit = author or project.owner
  can view = project.view

rules app.notes
  select : view
  insert : project.edit and author
  update : edit
  delete : edit
```

## The app

`Rowfence` signs in every transaction the engine begins, as whoever `user` returns for the request (`None`:
nobody, who sees only what `anyone` may). It also refuses to start on a connection that skips row-level
security, whether or not the app has a `lifespan` of its own.

`user(request)` runs in a middleware that `Rowfence(...)` adds: read the session or the token from the request
itself. What a middleware of yours puts on `request.state` is there only if that middleware was added after
`Rowfence(...)` (Starlette runs the one added last first). It may raise an `HTTPException` (a 401 for a bad
token). WebSockets are not signed in: use `rowfence.acting_as()` in the endpoint.

```python
from rowfence.fastapi import Rowfence

def user_of(request: Request) -> str | None:
    """Who the request is: a real app would read its session or token; here a header (none: nobody)."""
    return request.headers.get("x-user")


def make_app(url: str | None = None, check_connection: bool = True, pool_size: int = 5) -> FastAPI:
    engine = create_async_engine(url or os.environ["ROWFENCE_APP_URL"], pool_size=pool_size, max_overflow=0)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    app = FastAPI()
    authz = Rowfence(app, engine, user=user_of, check_connection=check_connection)
```

Then routes are plain SQLAlchemy. A list shows only the user's rows:

```python
    @app.get("/notes")
    async def notes() -> list[int]:
        async with Session() as s:
            return sorted((await s.scalars(select(Note.id))).all())
```

An update the rules refuse makes SQLAlchemy raise `StaleDataError` (0 rows changed). The SDK asks the
database why and answers 403 with the rule and the reason, or 404 when the user can't see the row:

```python
    @app.patch("/notes/{note_id}")
    async def edit_note(note_id: int, b: Body) -> dict[str, int]:
        async with Session.begin() as s:
            note = await s.get(Note, note_id)
            if note is None:
                raise NotFound("app.notes", note_id)
            note.body = b.body          # an update the rules may refuse: StaleDataError -> 403 with the reason
        return {"id": note_id}
```

A flush of several rows is asked about row by row: the answer is about the first one the database says no
for. A Core `delete()` or `update()` reports 0 rows without an error; `expect` turns that into the same
answers (404 too when the user may change the row and the statement matched nothing for another reason, such
as a `where` with more than the key):

```python
            result = await s.execute(delete(Note).where(Note.id == note_id))
            await authz_sa.expect(s, result, "app.notes", "delete", note_id)
```

An insert that reads the new row back (`flush()` uses `RETURNING`) also needs the select rule: if the user may
insert but not read the row, the 403 names the select rule.

## Lists by permission

`ids(type, perm)` filters a query to the objects the user holds a permission on; `perms_of` answers a list's
buttons in one call:

```python
from rowfence import sqlalchemy as authz_sa

    @app.get("/projects/editable")
    async def editable() -> list[int]:
        async with Session() as s:
            return sorted((await s.scalars(select(Project.id).where(Project.id.in_(authz_sa.ids("project", "edit"))))).all())

    @app.get("/projects/buttons")
    async def buttons() -> dict[str, list[str]]:
        async with Session() as s:
            ids = (await s.scalars(select(Project.id))).all()
            return await authz_sa.perms_of(s, "project", ids)
```

## Background jobs

A job acts for a principal of its own, whatever request started it (`type service = app.services principal`
in the policy):

```python
@rowfence.job(("service", 1))
async def digest(Session: async_sessionmaker[AsyncSession]) -> tuple[int, Principal | None]:
    """A background job: it signs in as service 1, whatever request started it."""
```

Anywhere else, `with rowfence.acting_as(2):` signs in the transactions inside it.

## Migrations

The policy ships as Alembic revisions. `rowfence migrate` writes the next one (only what changed since
`db/policy.lock`); `alembic upgrade head` applies it with the others. Tell autogenerate to leave rowfence's
objects alone, so `alembic check` shows no change:

```python
from rowfence.alembic import include_name, include_object

    context.configure(connection=connection, target_metadata=Base.metadata, include_schemas=True,
                      include_name=include_name, include_object=include_object)
```

```sh
uv run rowfence migrate            # after changing the policy
uv run alembic upgrade head
uv run rowfence migrate --check    # in CI: exit 1 if a policy change has no migration
```

While you edit, `rowfence dev` checks, pushes to the development database, runs the tests and rewrites
`app/authz_client.py` on every save (and writes the migration once you stop editing).

## Tests

The policy's own tests run with `rowfence test`. In pytest, sign in the way the app does:

```python
        with rowfence.acting_as(2), Session(engine) as s:
            assert sorted(s.scalars(select(Note.id)).all()) == [2, 3]
```

## Other drivers

The sync engine (and SQLModel, built on it) takes `install(engine)`. psycopg and asyncpg without SQLAlchemy:
[Python apps](python.md).
