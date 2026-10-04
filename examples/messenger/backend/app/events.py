"""Live updates. The database announces "chat N changed" (ms.announce, on NOTIFY ms_events); for each
connected person the backend asks the database whether they may read chat N, as them, and only then
passes the chat's number on. The browser fetches what changed through the API, which row-level
security filters like any other read. So a WebSocket never carries a message, and can't leak one.
"""
import asyncio
import json
import logging
import threading

import psycopg
from fastapi import WebSocket

from . import db

log = logging.getLogger("messenger.events")


class Hub:
    def __init__(self) -> None:
        # socket -> the person connected on it, and the event loop the socket lives on
        self.sockets: dict[WebSocket, tuple[str, asyncio.AbstractEventLoop]] = {}

    def add(self, ws: WebSocket, user_id: str) -> None:
        self.sockets[ws] = (user_id, asyncio.get_running_loop())

    def remove(self, ws: WebSocket) -> None:
        self.sockets.pop(ws, None)

    async def announce(self, payload: str) -> None:
        chat_id, _, about = payload.partition(":")    # "N", or "N:user" for a membership change
        people = {user_id for user_id, _ in self.sockets.values()}
        readers = await asyncio.to_thread(self.who_may_read, int(chat_id), people)
        text = json.dumps({"chat": int(chat_id)})
        for ws, (user_id, loop) in list(self.sockets.items()):
            # someone whose own membership changed hears of it, even if they may no longer read the chat
            if user_id in readers or user_id == about:
                try:
                    await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(ws.send_text(text), loop))
                except Exception:      # a socket that closed meanwhile
                    self.remove(ws)

    @staticmethod
    def who_may_read(chat_id: int, people: set[str]) -> set[str]:
        """One question to the database for everyone connected (authz.who_among)."""
        with db.as_user(None) as tx:
            return set(tx.authz.who_among("chat", chat_id, "read", sorted(people)))


hub = Hub()


def listen(database_url: str, loop: asyncio.AbstractEventLoop, stop: threading.Event) -> None:
    """LISTEN ms_events until stop is set (a thread: psycopg's async mode needs a selector event loop,
    which Windows doesn't use by default); each notice is handed to the hub on the app's loop."""
    while not stop.is_set():
        try:
            with psycopg.connect(database_url, autocommit=True) as conn:
                conn.execute("LISTEN ms_events")
                while not stop.is_set():
                    for note in conn.notifies(timeout=1):
                        asyncio.run_coroutine_threadsafe(hub.announce(note.payload), loop)
        except Exception as e:                        # the database restarted, say
            log.warning("event listener: %s; reconnecting", e)
            stop.wait(2)
