"""rowstile with SQLAlchemy 2 (sync and async engines, the ORM, SQLModel).

    engine = create_async_engine(url)
    rowstile.sqlalchemy.install(engine)           # every transaction signs in as rowstile.current()

Queries by permission use set checks, never a function call per row:

    select(Folder).where(Folder.id.in_(ids("folder", "edit")))
    await perms_of(session, "folder", [f.id for f in folders])      # {id: ["view", "edit"]}: a list's buttons

Queries[ObjectType, Permission]() has the same queries taking only the policy's names (the generated client's),
so a misspelled one doesn't type-check.

An ORM update of a row the user may not change matches no row, and SQLAlchemy raises StaleDataError;
why_stale() asks the database which it was, for each row of the flush that failed: NotFound (the row is
hidden) or Refused (and why) for the first one the database says no for. The rows are remembered per request
or acting_as block; outside one, per thread (or task), for the transaction it began last. An ORM delete that
matches no row is only a warning in SQLAlchemy (an error with a version column alone): delete with Core's
delete() and expect().
"""

from __future__ import annotations

import contextvars
import typing
from collections.abc import Callable, Iterable, Sequence
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from sqlalchemy import (
    BigInteger,
    Connection,
    Engine,
    Select,
    Table,
    TextClause,
    cast,
    event,
    func,
    select,
    text,
)
from sqlalchemy.orm import Mapper, Session
from sqlalchemy.types import TypeEngine

from . import (
    NOBODY,
    Id,
    NotFound,
    Principal,
    Refused,
    Who,
    _Write,
    _writes,
    act_as_args,
    act_as_sql,
    answer,
    current,
    explain_rule_args,
    explain_rule_sql,
    verdict,
)

try:
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession
except ImportError:
    # SQLAlchemy's asyncio needs greenlet, which SQLAlchemy 2.1 installs only when asked (sqlalchemy[asyncio]):
    # an app on the sync engine has neither, and needs neither
    if not TYPE_CHECKING:

        class AsyncEngine:
            """Stands in where SQLAlchemy's asyncio can't be loaded: no engine is one."""

        AsyncConnection = AsyncSession = AsyncEngine

AnyEngine = TypeVar("AnyEngine", bound="Engine | AsyncEngine")
Result = TypeVar("Result")
# the policy's names, as the generated client writes them (ObjectType, Permission): Queries
TypeName = TypeVar("TypeName", bound=str)
PermissionName = TypeVar("PermissionName", bound=str)

_engines: dict[Engine, Engine | AsyncEngine] = {}  # sync engine -> the engine install() was given (async or not)
_mapper_events = False
# the writes remembered outside a request or acting_as block: each thread's or task's own (never one list for the
# process: another thread's writes are another person's), those of the transaction it began last
_outside: contextvars.ContextVar[list[_Write] | None] = contextvars.ContextVar("rowstile_writes_outside", default=None)


def _outside_writes(begin: bool = False) -> list[_Write]:
    """Where the writes made outside a block go: this thread's or task's list; a new one when a transaction
    begins (begin), so that why_stale doesn't answer about an earlier transaction's rows."""
    writes = None if begin else _outside.get()
    if writes is None:
        writes = []
        _outside.set(writes)
    return writes


def install(engine: AnyEngine, user: Callable[[], Who] | None = None) -> AnyEngine:
    """Signs every transaction on `engine` in as whoever the code acts for (rowstile.acting_as, or the web
    integration), else as user() if given, else as nobody. Also remembers the rows each ORM flush updates
    or deletes, for why_stale()."""
    global _mapper_events
    sync = engine.sync_engine if isinstance(engine, AsyncEngine) else engine
    if sync in _engines:
        return engine
    _engines[sync] = engine

    @event.listens_for(sync, "begin")
    def _sign_in(conn: Connection) -> None:
        _outside_writes(begin=True)
        who = current()
        if who is None and user is not None:
            who = Principal.of(user())
        who = who or NOBODY
        # the id as a parameter where the driver takes them this way: psycopg reads % in a statement, so an id
        # written into it would be changed ('%s') or refused ('50%')
        style = conn.dialect.paramstyle
        if style in ("pyformat", "format"):
            conn.exec_driver_sql("SELECT authz.act_as(%s, %s)", act_as_args(who))
        elif style == "numeric_dollar":
            conn.exec_driver_sql("SELECT authz.act_as($1, $2)", act_as_args(who))
        else:
            conn.exec_driver_sql(act_as_sql(who))

    if not _mapper_events:
        _mapper_events = True
        event.listen(Mapper, "before_update", _remember("update"))
        event.listen(Mapper, "before_delete", _remember("delete"))
    return engine


def _remember(command: str) -> Callable[[Mapper[Any], Connection, object], None]:
    def remember(mapper: Mapper[Any], connection: Connection, target: object) -> None:
        table = mapper.local_table
        if not isinstance(table, Table):
            return  # mapped to a join or a query: no one table to ask about
        name = f"{table.schema}.{table.name}" if table.schema else table.name
        key = mapper.primary_key_from_instance(target)
        writes = _writes.get()
        if writes is None:
            writes = _outside_writes()
        writes.append((connection.engine, name, command, key))
        del writes[:-20]

    return remember


_EXPLAIN = explain_rule_sql("CAST(:t AS text)", ":c", ":k")


def _explain_sql(table: str, command: str, key: object) -> TextClause:
    t, c, k = explain_rule_args(table, command, key)
    return text(_EXPLAIN).bindparams(t=t, c=c, k=k)


def _flush(exc: BaseException | None) -> list[_Write]:
    """The writes the failed flush was about, the latest first: SQLAlchemy tells every row of a flush before it
    sends the statements, so the row that was refused is one of the last run of writes to the same table. In a
    block, its own writes only, even when it made none."""
    recent = _writes.get()
    if recent is None:
        recent = _outside.get() or []
    out: list[_Write] = []
    for write in reversed(recent):
        if out and write[:3] != out[0][:3]:
            break
        out.append(write)
    return out


def why_stale_sync(exc: BaseException | None = None) -> NotFound | Refused | None:
    """For a StaleDataError: NotFound or Refused for the row it was about (sync engines). Returns the error
    to raise (or None when it can't tell)."""
    for engine, table, command, key in _flush(exc):
        original = _engines.get(engine, engine)
        if isinstance(original, AsyncEngine):
            raise TypeError("an async engine's write: await rowstile.sqlalchemy.why_stale()")
        with original.connect() as conn:
            lines, who, named = answer(conn.execute(_explain_sql(table, command, key)).first())
            conn.rollback()
        if not _allowed(lines):
            return verdict(table, command, key, lines, who, named)
    return None


async def why_stale(exc: BaseException | None = None) -> NotFound | Refused | None:
    """For a StaleDataError: NotFound (the user can't see the row) or Refused (they may not, and why), asked
    in a new transaction as the same user. Returns the error to raise, or None when it can't tell."""
    for engine, table, command, key in _flush(exc):
        original = _engines.get(engine, engine)
        if isinstance(original, AsyncEngine):
            async with original.connect() as aconn:
                lines, who, named = answer((await aconn.execute(_explain_sql(table, command, key))).first())
                await aconn.rollback()
        else:
            with original.connect() as conn:
                lines, who, named = answer(conn.execute(_explain_sql(table, command, key)).first())
                conn.rollback()
        if not _allowed(lines):
            return verdict(table, command, key, lines, who, named)
    return None


def _allowed(lines: Sequence[str] | None) -> bool:
    """Whether authz.explain_rule's answer says the user may: this row of the flush isn't the one refused."""
    return bool(lines) and lines is not None and lines[0].lstrip().startswith("yes")


async def expect(
    session: AsyncSession | AsyncConnection, result: Result, table: str, command: str, key: object
) -> Result:
    """A Core UPDATE or DELETE's result: returned if it changed a row (rowcount), else NotFound or Refused,
    asked in the same transaction: delete(Note).where(Note.id == 7) that matched nothing, and why."""
    if getattr(result, "rowcount", 1):
        return result
    raise verdict(table, command, key, *answer((await session.execute(_explain_sql(table, command, key))).first()))


def expect_sync(session: Session | Connection, result: Result, table: str, command: str, key: object) -> Result:
    if getattr(result, "rowcount", 1):
        return result
    raise verdict(table, command, key, *answer(session.execute(_explain_sql(table, command, key)).first()))


# --- queries by permission ------------------------------------------------------------------------------
def ids(type_: str, perm: str, key_type: type[TypeEngine[Any]] | TypeEngine[Any] | None = BigInteger) -> Select[Any]:
    """The ids the signed-in user holds `perm` on, as a subquery: Folder.id.in_(ids("folder", "edit")).
    key_type: the key's SQL type (BigInteger by default; String for text and uuid keys: pass None)."""
    listed = func.authz.list(type_, perm).table_valued("id").render_derived(name="authz_ids")
    col = listed.c.id if key_type is None else cast(listed.c.id, key_type)
    return select(col)


async def can(session: AsyncSession | AsyncConnection, type_: str, id_: Id, perm: str) -> bool:
    return bool(await session.scalar(select(func.authz.can(type_, str(id_), perm))))


def can_sync(session: Session | Connection, type_: str, id_: Id, perm: str) -> bool:
    return bool(session.scalar(select(func.authz.can(type_, str(id_), perm))))


_PERMS_OF = text("SELECT id, perms FROM authz.perms_of(:t, CAST(:ids AS text[]))")


async def perms_of(session: AsyncSession | AsyncConnection, type_: str, ids_: Iterable[Id]) -> dict[str, list[str]]:
    """{id: [permissions]} for many objects in one call (a list's buttons)."""
    rows = (await session.execute(_PERMS_OF.bindparams(t=type_, ids=[str(i) for i in ids_]))).all()
    return {r[0]: list(r[1] or []) for r in rows}


def perms_of_sync(session: Session | Connection, type_: str, ids_: Iterable[Id]) -> dict[str, list[str]]:
    rows = session.execute(_PERMS_OF.bindparams(t=type_, ids=[str(i) for i in ids_])).all()
    return {r[0]: list(r[1] or []) for r in rows}


class Queries(Generic[TypeName, PermissionName]):
    """The queries by permission, taking only the policy's names, so a misspelled type or permission doesn't
    type-check. The names are the generated client's (rowstile client py):

        from app.authz_client import ObjectType, Permission
        queries = Queries[ObjectType, Permission]()
        select(Folder).where(Folder.id.in_(queries.ids("folder", "edit")))

    Each method is the function of the same name."""

    def ids(
        self,
        type_: TypeName,
        perm: PermissionName,
        key_type: type[TypeEngine[Any]] | TypeEngine[Any] | None = BigInteger,
    ) -> Select[Any]:
        return ids(type_, perm, key_type)

    async def can(
        self, session: AsyncSession | AsyncConnection, type_: TypeName, id_: Id, perm: PermissionName
    ) -> bool:
        return await can(session, type_, id_, perm)

    def can_sync(self, session: Session | Connection, type_: TypeName, id_: Id, perm: PermissionName) -> bool:
        return can_sync(session, type_, id_, perm)

    async def perms_of(
        self, session: AsyncSession | AsyncConnection, type_: TypeName, ids_: Iterable[Id]
    ) -> dict[str, list[PermissionName]]:
        return typing.cast("dict[str, list[PermissionName]]", await perms_of(session, type_, ids_))

    def perms_of_sync(
        self, session: Session | Connection, type_: TypeName, ids_: Iterable[Id]
    ) -> dict[str, list[PermissionName]]:
        return typing.cast("dict[str, list[PermissionName]]", perms_of_sync(session, type_, ids_))


async def connection_check(engine: Engine | AsyncEngine) -> list[tuple[str, str]]:
    """authz.connection_check()'s rows (severity, problem) for this engine's connections."""
    query = text("SELECT severity, problem FROM authz.connection_check()")
    if isinstance(engine, AsyncEngine):
        async with engine.connect() as aconn:
            rows = (await aconn.execute(query)).all()
            await aconn.rollback()
    else:
        with engine.connect() as conn:
            rows = conn.execute(query).all()
            conn.rollback()
    return [(r[0], r[1]) for r in rows]
