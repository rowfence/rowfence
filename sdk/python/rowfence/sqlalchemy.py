"""rowfence with SQLAlchemy 2 (sync and async engines, the ORM, SQLModel).

    engine = create_async_engine(url)
    rowfence.sqlalchemy.install(engine)           # every transaction signs in as rowfence.current()

Queries by permission use set checks, never a function call per row:

    select(Folder).where(Folder.id.in_(ids("folder", "edit")))
    await perms_of(session, "folder", [f.id for f in folders])      # {id: ["view", "edit"]}: a list's buttons

An ORM update or delete of a row the user may not change matches no row, and SQLAlchemy raises StaleDataError;
why_stale() asks the database which it was, for each row of the flush that failed: NotFound (the row is
hidden) or Refused (and why) for the first one the database says no for.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import TYPE_CHECKING, Any, TypeVar

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

_engines: dict[Engine, Engine | AsyncEngine] = {}   # sync engine -> the engine install() was given (async or not)
_mapper_events = False
_recent: list[_Write] = []                          # when no request or acting_as block made a list


def install(engine: AnyEngine, user: Callable[[], Who] | None = None) -> AnyEngine:
    """Signs every transaction on `engine` in as whoever the code acts for (rowfence.acting_as, or the web
    integration), else as user() if given, else as nobody. Also remembers the rows each ORM flush updates
    or deletes, for why_stale()."""
    global _mapper_events
    sync = engine.sync_engine if isinstance(engine, AsyncEngine) else engine
    if sync in _engines:
        return engine
    _engines[sync] = engine

    @event.listens_for(sync, "begin")
    def _sign_in(conn: Connection) -> None:
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
            return                      # mapped to a join or a query: no one table to ask about
        name = f"{table.schema}.{table.name}" if table.schema else table.name
        key = mapper.primary_key_from_instance(target)
        writes = _writes.get()
        if writes is None:
            writes = _recent
        writes.append((connection.engine, name, command, key))
        del writes[:-20]
    return remember


_EXPLAIN = explain_rule_sql("CAST(:t AS text)", ":c", ":k")


def _explain_sql(table: str, command: str, key: object) -> TextClause:
    t, c, k = explain_rule_args(table, command, key)
    return text(_EXPLAIN).bindparams(t=t, c=c, k=k)


def _flush(exc: BaseException | None) -> list[_Write]:
    """The writes the failed flush was about, the latest first: SQLAlchemy tells every row of a flush before it
    sends the statements, so the row that was refused is one of the last run of writes to the same table."""
    recent = _writes.get() or _recent
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
            raise TypeError("an async engine's write: await rowfence.sqlalchemy.why_stale()")
        with original.connect() as conn:
            lines = conn.execute(_explain_sql(table, command, key)).scalar()
            conn.rollback()
        if not _allowed(lines):
            return verdict(table, command, key, lines)
    return None


async def why_stale(exc: BaseException | None = None) -> NotFound | Refused | None:
    """For a StaleDataError: NotFound (the user can't see the row) or Refused (they may not, and why), asked
    in a new transaction as the same user. Returns the error to raise, or None when it can't tell."""
    for engine, table, command, key in _flush(exc):
        original = _engines.get(engine, engine)
        if isinstance(original, AsyncEngine):
            async with original.connect() as aconn:
                lines = (await aconn.execute(_explain_sql(table, command, key))).scalar()
                await aconn.rollback()
        else:
            with original.connect() as conn:
                lines = conn.execute(_explain_sql(table, command, key)).scalar()
                conn.rollback()
        if not _allowed(lines):
            return verdict(table, command, key, lines)
    return None


def _allowed(lines: Sequence[str] | None) -> bool:
    """Whether authz.explain_rule's answer says the user may: this row of the flush isn't the one refused."""
    return bool(lines) and lines is not None and lines[0].lstrip().startswith("yes")


async def expect(session: AsyncSession | AsyncConnection, result: Result, table: str, command: str,
                 key: object) -> Result:
    """A Core UPDATE or DELETE's result: returned if it changed a row (rowcount), else NotFound or Refused,
    asked in the same transaction: delete(Note).where(Note.id == 7) that matched nothing, and why."""
    if getattr(result, "rowcount", 1):
        return result
    lines = (await session.execute(_explain_sql(table, command, key))).scalar()
    raise verdict(table, command, key, lines)


def expect_sync(session: Session | Connection, result: Result, table: str, command: str, key: object) -> Result:
    if getattr(result, "rowcount", 1):
        return result
    raise verdict(table, command, key, session.execute(_explain_sql(table, command, key)).scalar())


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
