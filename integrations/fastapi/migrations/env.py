"""Alembic, as the tables' owner (ROWFENCE_OWNER_URL). rowfence's migrations are revisions like the others;
autogenerate leaves what rowfence made alone (rowfence.alembic)."""
import os

from alembic import context
from app.models import Base
from rowfence.alembic import include_name, include_object
from sqlalchemy import create_engine

engine = create_engine(os.environ["ROWFENCE_OWNER_URL"])
with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata, include_schemas=True,
                      include_name=include_name, include_object=include_object)
    with context.begin_transaction():
        context.run_migrations()
    connection.commit()
