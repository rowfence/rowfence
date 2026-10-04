"""Database access. Every request runs in a transaction signed in as the person (or the bot) asking,
so row-level security decides what it sees and changes. There are no permission checks in Python."""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import LiteralString

from psycopg import Connection
from psycopg.abc import Params
from psycopg.rows import DictRow, TupleRow, dict_row
from psycopg_pool import ConnectionPool

from .authz_client import Authz, Id

_pool: ConnectionPool | None = None


def open_pool(url: str) -> None:
    global _pool
    _pool = ConnectionPool(url, min_size=1, max_size=10, open=True)


def close_pool() -> None:
    if _pool is not None:
        _pool.close()


def pool() -> ConnectionPool:
    if _pool is None:
        raise RuntimeError("the database pool isn't open (the app's lifespan opens it)")
    return _pool


@contextmanager
def as_user(user_id: Id | None, links: Iterable[str] = ()) -> Iterator[Tx]:
    """A transaction in which the database sees `user_id` (None: nobody signed in), holding the invite
    links whose tokens are in `links`."""
    with pool().connection() as conn, conn.transaction():
        az = Authz(conn)
        az.sign_in(user_id)
        if links:
            az.use_links(list(links))
        yield Tx(conn, az)


@contextmanager
def as_bot(api_key: str) -> Iterator[Tx]:
    """A transaction signed in as the bot whose API key this is (authz.login_key: the database checks the
    key; the backend never learns which bot it is unless it asks)."""
    with pool().connection() as conn, conn.transaction():
        az = Authz(conn)
        az.login_key(api_key)
        yield Tx(conn, az)


class Tx:
    def __init__(self, conn: Connection[TupleRow], az: Authz) -> None:
        self.conn, self.authz = conn, az

    def rows(self, sql: LiteralString, args: Params = ()) -> list[DictRow]:
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, args)
            return cur.fetchall()

    def row(self, sql: LiteralString, args: Params = ()) -> DictRow | None:
        rows = self.rows(sql, args)
        return rows[0] if rows else None

    def one(self, sql: LiteralString, args: Params = ()) -> DictRow:
        """The row a statement always returns (INSERT ... RETURNING, a function's result)."""
        row = self.row(sql, args)
        if row is None:
            raise RuntimeError("the statement returned no row")
        return row

    def run(self, sql: LiteralString, args: Params = ()) -> int:
        with self.conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.rowcount
