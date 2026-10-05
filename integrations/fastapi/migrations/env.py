"""Alembic, as the tables' owner (ROWSTILE_OWNER_URL). rowstile's migrations are revisions like the others;
autogenerate leaves what rowstile made alone (rowstile.alembic)."""

import os

from alembic import context
from app.models import Base
from rowstile.alembic import include_name, include_object
from sqlalchemy import create_engine

engine = create_engine(os.environ["ROWSTILE_OWNER_URL"])
with engine.connect() as connection:
    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        include_schemas=True,
        include_name=include_name,
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()
    connection.commit()
