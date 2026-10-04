"""pytest fixtures for apps that use rowstile (loaded by the pytest11 entry point, or with
`pytest_plugins = ["rowstile.testing"]`).

    def test_bob_cannot_rename(client, as_user, assert_refused):
        with as_user(2):
            assert_refused(lambda: rename(note_id, "x"), command="update")

Environment: ROWSTILE_OWNER_URL (the tables' owner: migrations, test data) and ROWSTILE_APP_URL (the app's
role: what the app sees), both SQLAlchemy or libpq URLs, give the authz_owner_url and authz_app_url fixtures.
The fixtures' types, for annotating a test's arguments: AsUser, AssertRefused, AssertNotFound.

With an async function, await the helper in an async test: `await assert_refused(lambda: rename(note_id, "x"))`.
"""
from __future__ import annotations

import inspect
import os
from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager
from typing import Protocol, TypeVar, cast, overload

import pytest

from . import NotFound, Principal, Refused, Who, acting_as, refusal

AsUser = Callable[[Who], AbstractContextManager["Principal | None"]]


Raised = TypeVar("Raised", Refused, NotFound)


class AssertRefused(Protocol):
    @overload
    def __call__(self, fn: Callable[[], Awaitable[object]], command: str | None = None,
                 table: str | None = None) -> Awaitable[Refused]: ...

    @overload
    def __call__(self, fn: Callable[[], object], command: str | None = None, table: str | None = None) -> Refused: ...


class AssertNotFound(Protocol):
    @overload
    def __call__(self, fn: Callable[[], Awaitable[object]]) -> Awaitable[NotFound]: ...

    @overload
    def __call__(self, fn: Callable[[], object]) -> NotFound: ...


@pytest.fixture
def as_user() -> AsUser:
    """as_user(42), as_user(("service", 3)), as_user(None): everything in the block acts for them."""
    return acting_as


def _raised(e: Exception, expected: type[Raised]) -> Raised:
    """e as the error expected, or e raised again: a driver's refusal counts as Refused."""
    if isinstance(e, expected):
        return e
    r = refusal(e)
    if r is not None and isinstance(r, expected):
        return r
    raise e


def _checked(fn: Callable[[], object], expected: type[Raised], what: str,
             check: Callable[[Raised], None]) -> Raised | Awaitable[Raised]:
    """fn() must raise `expected`: the error, checked; for an async function, an awaitable of it."""
    try:
        out = fn()
    except Exception as e:
        err = _raised(e, expected)
        check(err)
        return err
    if not inspect.isawaitable(out):
        raise AssertionError(f"expected {what}, got {out!r}")
    pending = out

    async def later() -> Raised:
        try:
            got = await pending
        except Exception as e:
            err = _raised(e, expected)
            check(err)
            return err
        raise AssertionError(f"expected {what}, got {got!r}")
    return later()


@pytest.fixture
def assert_refused() -> AssertRefused:
    """assert_refused(fn, command=None, table=None): fn() must be refused by the policy; returns the Refused."""
    def check(fn: Callable[[], object], command: str | None = None,
              table: str | None = None) -> Refused | Awaitable[Refused]:
        def the_rule(err: Refused) -> None:
            if command:
                named = err.command is not None and err.command.startswith(command)
                assert named, f"expected the {command} rule to refuse it, but: {err.command}: {err.message}"
            if table:
                assert err.table == table, err.table
        return _checked(fn, Refused, "a refusal", the_rule)
    return cast("AssertRefused", check)


@pytest.fixture
def assert_not_found() -> AssertNotFound:
    def check(fn: Callable[[], object]) -> NotFound | Awaitable[NotFound]:
        return _checked(fn, NotFound, "NotFound", lambda err: None)
    return cast("AssertNotFound", check)


@pytest.fixture
def authz_owner_url() -> str:
    url = os.environ.get("ROWSTILE_OWNER_URL")
    if not url:
        pytest.skip("ROWSTILE_OWNER_URL is not set")
    return url


@pytest.fixture
def authz_app_url() -> str:
    url = os.environ.get("ROWSTILE_APP_URL")
    if not url:
        pytest.skip("ROWSTILE_APP_URL is not set")
    return url
