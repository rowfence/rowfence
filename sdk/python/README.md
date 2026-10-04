# rowfence for Python

`pip install --pre rowfence` (`--pre` while only an alpha is published) installs the `rowfence` command (`rowfence init`, `dev`, `migrate`, `review`; also
`python -m rowfence`) and the SDK for Python apps. Extras bring the integrations' dependencies:
`rowfence[fastapi]`, `[sqlalchemy]`, `[psycopg]`, `[asyncpg]`. Python 3.11 or newer.

The SDK for Python apps on a rowfence policy: every transaction signs in as whoever the request or
the job acts for, refused writes become a 403 with the database's reason, rows the user can't see a 404,
and the app refuses to start on a connection that skips row-level security. It holds no rowfence logic: it
calls the `authz.*` functions the policy made, and translates their answers.

```python
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine
from rowfence.fastapi import Rowfence

engine = create_async_engine("postgresql+asyncpg://app@db/app")
app = FastAPI()
Rowfence(app, engine, user=current_user)     # current_user(request): its user's id, or None; before adding routes
```

| module | what |
|---|---|
| `rowfence` | `acting_as(who)`, `@job(who)`, `Principal`, `Refused`, `NotFound`, `refusal(exc)`, `error_code(exc)` (rowfence's code for any database error: `AZ709`), `act_as_sql()` |
| `rowfence.fastapi` | `Rowfence(app, engine, user=...)`: the request's principal, 403/404 problem bodies, the start-up check |
| `rowfence.sqlalchemy` | `install(engine)` (sync or async; SQLModel too), `ids(type, perm)` for `where`, `perms_of()` for a list's buttons, `can()`, `expect()` for Core updates and deletes, `why_stale()` for the ORM's StaleDataError |
| `rowfence.psycopg` | `transaction(conn, who)`, `atransaction(aconn, who)`, `expect()`, `aexpect()` |
| `rowfence.asyncpg` | `transaction(conn, who)`, `expect()` |
| `rowfence.alembic` | `include_name`, `include_object`: autogenerate leaves rowfence's objects alone |
| `rowfence.testing` | pytest fixtures: `as_user`, `assert_refused`, `assert_not_found` (awaited, with an async function), `authz_owner_url`, `authz_app_url` |

Who a transaction acts for: `42` or `"42"` (a user), `("service", 3)` (another principal type of the policy),
or `None` (nobody: only what `anyone` may see; `None` given to a call is nobody too, whoever the code around
it acts for). A plain id is always a user's, whatever it holds: `"service:3"` is the user with that id, so an
id from outside (a username, an identity provider's subject) can't name a service. `Principal.parse("service:3")`
reads back what `str()` wrote, for text your own code wrote. Every transaction signs in, even when nobody is signed in, and nothing
uses a session-level `SET`, so pools and poolers in transaction mode are safe; behind one that keeps no prepared
statements, turn the driver's off ([Behind a pooler](../../docs/operations.md#behind-a-pooler)).

With FastAPI: `user(request)` runs in a middleware that `Rowfence(...)` adds, so give it the session or the
token to read from the request itself. What a middleware of yours puts on `request.state` is there only if
that middleware was added after `Rowfence(...)` (Starlette runs the one added last first); added before, it
hasn't run yet. `user` may raise an `HTTPException`. The start-up check runs whether or not the app has a `lifespan`. WebSockets
are not signed in: use `rowfence.acting_as()` in the endpoint. An engine in `AUTOCOMMIT` can't be signed in
(the sign-in lasts a transaction): its queries fail with `NotSignedIn`.

Policy changes ship as migrations for your tool (`rowfence migrate`, with `tool = "alembic"` in
`rowfence.toml`). The types and permissions of your policy are generated names (`rowfence client py`), so a
misspelled permission doesn't type-check.

`integrations/fastapi/` is the conformance suite: a small FastAPI app on SQLAlchemy (async, asyncpg) and
Alembic, and the checks every supported stack passes (`integrations/fastapi/test.sh`).
