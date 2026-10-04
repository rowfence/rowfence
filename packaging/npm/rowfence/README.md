# rowfence

Access rules for Postgres: a policy language that the `rowfence` command compiles into row-level security, and
ships as migrations for your app's tool (Prisma, Drizzle Kit, Alembic, SQL files).

    npx rowfence init        # a first policy from your tables, rowfence.toml, the SDK for your stack
    npx rowfence dev         # on each save: check, apply to the development database, test, write the types

The command runs on the Python that comes with it (the package for your platform, `@rowfence/cli-<platform>`):
a TypeScript app needs no Python. For app code, the SDK: `@rowfence/prisma`, `/next`, `/react`, `/drizzle`,
`/pg`, `/postgres`, `/vitest`.
