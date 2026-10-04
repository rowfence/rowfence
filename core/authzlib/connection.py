"""The database connection authzlib works with, and the values its rows hold.

The command gives authzlib.database a Db over its own connection (cli/pgwire.py): rows come back as dicts
of text, integers, booleans, arrays of those, and JSON. The accessors below read one value as the type the
query gives it, and fail loudly if it isn't: the types come from the SQL, which no checker sees.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, TypeAlias

# what a column holds, as pgwire decodes it: NULL, a boolean, an integer, text, an array, or JSON
Value: TypeAlias = "None | bool | int | float | str | list[Value] | dict[str, Value]"
Row: TypeAlias = "dict[str, Value]"


class Db(Protocol):
    """A connection, inside the caller's transaction."""

    @property
    def errors(self) -> type[Exception]:
        """What its statements raise (pgwire.PgError: with .message, .code, .hint)."""
        ...

    def rows(self, sql: str, args: Sequence[Value] = ()) -> list[Row]:
        """The rows of one statement ($1, $2, ... are args)."""
        ...

    def script(self, sql: str) -> None:
        """Many statements, no arguments."""
        ...

    def warn(self, message: str, detail: str | None = None, hint: str | None = None) -> None:
        """A warning for whoever runs the command, as if the database had raised it."""
        ...


def _wrong(row: Row, key: str, what: str) -> TypeError:
    return TypeError(f"{key} is {row.get(key)!r}, not {what}")


def text(row: Row, key: str) -> str:
    v = row[key]
    if isinstance(v, str):
        return v
    raise _wrong(row, key, "text")


def text_or_none(row: Row, key: str) -> str | None:
    v = row[key]
    if v is None or isinstance(v, str):
        return v
    raise _wrong(row, key, "text or NULL")


def number(row: Row, key: str) -> int:
    v = row[key]
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    raise _wrong(row, key, "an integer")


def number_or_none(row: Row, key: str) -> int | None:
    v = row[key]
    if v is None or (isinstance(v, int) and not isinstance(v, bool)):
        return v
    raise _wrong(row, key, "an integer or NULL")


def flag(row: Row, key: str) -> bool:
    v = row[key]
    if isinstance(v, bool):
        return v
    raise _wrong(row, key, "a boolean")


def texts(row: Row, key: str) -> list[str]:
    """A text[] (NULL: none); NULL items are left out."""
    v = row[key]
    if v is None:
        return []
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    raise _wrong(row, key, "a text array")
