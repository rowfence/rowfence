"""Database access. Every request that touches files or folders runs in a transaction signed in as the
user (authz.user_id, through the generated client), so row-level security decides what it sees."""

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
    """A transaction in which the database sees `user_id` (None: nobody signed in), holding the share
    links whose tokens are in `links`."""
    with pool().connection() as conn, conn.transaction():
        az = Authz(conn)
        az.sign_in(user_id)
        if links:
            az.use_links(list(links))
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
