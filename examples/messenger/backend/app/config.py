"""Settings, from the environment."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str          # as ms_app: row-level security applies
    session_days: int
    cookie_secure: bool
    invite_days: int           # how long an invite link works


def load() -> Settings:
    env = os.environ.get
    return Settings(
        database_url=env("MS_DATABASE_URL", "postgresql://ms_app:ms_app@localhost:25433/messenger"),
        session_days=int(env("MS_SESSION_DAYS", "30")),
        cookie_secure=env("MS_COOKIE_SECURE", "false") == "true",
        invite_days=int(env("MS_INVITE_DAYS", "7")),
    )
