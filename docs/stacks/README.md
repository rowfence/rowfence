# rowfence in your stack

The policy and the database work the same everywhere. What changes from one stack to another is how the app
signs in each transaction, reads a refusal, and ships the policy with its migrations.

| stack | page | SDK |
|---|---|---|
| FastAPI, SQLAlchemy (async), Alembic | [fastapi.md](fastapi.md) | `pip install --pre rowfence` |
| Next.js, Prisma, React | [nextjs.md](nextjs.md) | `@rowfence/prisma`, `/next`, `/react` |
| Node: pg, postgres.js, Drizzle (Express, Hono, workers) | [node.md](node.md) | `@rowfence/pg`, `/postgres`, `/drizzle` |
| Python: SQLAlchemy (sync), SQLModel, psycopg, asyncpg | [python.md](python.md) | `pip install --pre rowfence` |
| Anything else (Go, Ruby, Java, Rust, ...) | [sql.md](sql.md) | none: a few SQL statements |

Every line of code these pages show is in a tested app (`integrations/fastapi`, `integrations/nextjs`, the
conformance suites) or in `docs/getting-started.md`, which runs as written; `core/tests/unit_test.py`
checks it, so the pages can't drift from what works.

Start with [getting started](../getting-started.md) for the policy itself.
