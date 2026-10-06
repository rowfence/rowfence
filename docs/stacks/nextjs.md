# Next.js and Prisma

<!-- tested: every line of code below is in integrations/nextjs (tests/unit_test.py checks it) -->

A Next.js app (App Router) on Prisma 7, whose migrations are Prisma Migrate's. Route handlers, server actions and
pages check nothing: each transaction signs in as the request's user, the database filters what it reads and
refuses what it may not write, and the SDK answers a refusal with 403 and a hidden row with 404. Signed-in
reads never land in a cache another user could be served from.

Everything here comes from `integrations/nextjs`, the conformance suite: a small app and the checks every
supported stack passes (`integrations/nextjs/test.sh`, against the production build). Drizzle, pg and
postgres.js: [Node apps](node.md).

## Install

```sh
# @next on each while only an alpha is published: a plain install gets an older one
npm install @rowstile/client@next @rowstile/prisma@next @rowstile/next@next @rowstile/react@next
npm install --save-dev rowstile@next @rowstile/vitest@next
npx rowstile init        # a first policy from your tables, a test file, rowstile.toml
```

The `rowstile` package is the command, with its own Python: nothing else to install. `init` finds Next.js and
Prisma, and writes `rowstile.toml` for them. The conformance app's, with its own name for the variable that
holds the owner's connection:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_DSN"
[clients]
ts = "src/authz.gen.ts"
[migrations]
tool = "prisma"
dir  = "prisma/migrations"
```

Two roles connect. The owner of the tables runs the migrations (`ROWSTILE_OWNER_DSN`), and the app connects
as the role the policy names, which row-level security applies to (`ROWSTILE_APP_URL`).

## The database client

`signedIn` wraps Prisma's driver adapter: every transaction Prisma begins signs in as whoever `user` returns
for the request (`null`: nobody, who sees only what `anyone` may). `authz()` turns Prisma's "record not found"
into 404 or 403 with the reason, and adds `db.$authz`. Use the client `$extends(authz())` returns, and only
that one: the client it was made from is refused whenever it is used, inside your own Prisma extensions too
(add them to the client `authz()` returns: they are placed before it, and each hook runs once for a call).
Importing `@rowstile/next` keeps signed-in reads out of Next.js's caches, and `authz.gen.ts` (written by
`rowstile client`) gives the SDK the policy's names, so a misspelled permission doesn't type-check.

```ts
import { PrismaPg } from "@prisma/adapter-pg";
import { headers } from "next/headers";
import pg from "pg";
import { authz, signedIn } from "@rowstile/prisma";
import "@rowstile/next";                              // signed-in reads never land in a cache
import { PrismaClient } from "./generated/prisma/client.ts";
import "./authz.gen.ts";                              // the policy's names, for the SDK's types

/** Who the request is. A real app reads its session (auth()); the conformance app, a header. */
export async function requestUser(): Promise<string | null> {
  return (await headers()).get("x-user");
}

const url = process.env.ROWSTILE_APP_URL;
export const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const db = new PrismaClient({ adapter: signedIn(new PrismaPg(pool), { user: requestUser }) }).$extends(authz());
```

At start-up, the server stops if its connection skips row-level security (a superuser, BYPASSRLS, the tables'
owner), where the database would filter nothing:

```ts
// instrumentation.ts
import { checkAtStart } from "@rowstile/next";

export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") await checkAtStart((await import("./src/db.ts")).db.$authz);
}
```

## Pages, route handlers and server actions

A page reads as the request's user:

```tsx
export default async function Notes() {
  const notes = await db.note.findMany({ select: { id: true, body: true }, orderBy: { id: "asc" } });
```

`route()` answers a refusal with a problem body: 404 for a row the user can't see, 403 with the rule and the
reason for one they may not change.

```ts
import { route } from "@rowstile/next";
import { db } from "@/db";

type Params = { params: Promise<{ id: string }> };

// an update the rules may refuse: a hidden note is 404, one the user may not edit 403 with the reason
export const PATCH = route(async (req: Request, { params }: Params) => {
  const id = Number((await params).id);
  const { body } = (await req.json()) as { body: string };
  await db.note.update({ where: { id }, data: { body } });
  return Response.json({ id });
});
```

Next.js hides a server action's thrown error from the browser, so `action()` returns the problem instead,
`{ ok: false, problem }`:

```ts
"use server";
import { action } from "@rowstile/next";

export const renameNote = action(async (id: number, body: string) => {
  await db.note.update({ where: { id }, data: { body } });
  return id;
});
```

Prisma's `create` reads the new row back, so an insert also needs the select rule; if the user may insert but
not read the row, the 403 names the select rule.

Two Prisma habits are handled: each `findUnique` runs in a transaction of its own (Prisma answers the calls of
one tick together, from the first caller's context), and array transactions, `$transaction([...])`, are
refused for the same reason. Use `$transaction(async (tx) => ...)`. Those transactions wait for a connection
as long as Prisma's `transactionOptions` say, 2 seconds by default: with the database far away and many
`findUnique` calls at once, give the client a longer `maxWait` (or a bigger pool), or they fail with
"Unable to start a transaction in the given time".

## Buttons, sharing and live updates (React)

`authzRoutes()` is what the React kit calls: permissions for a list, shares, access requests, and live updates
from the change feed.

```ts
// app/api/authz/[...authz]/route.ts
import { authzRoutes } from "@rowstile/next";
import { db, feed } from "@/db";

export const { GET, POST } = authzRoutes({ calls: db.$authz, changes: feed });
```

```ts
import { changes } from "@rowstile/pg";

// live updates for @rowstile/react: one connection that LISTENs, beside the pool, straight to Postgres
// (through a pooler in transaction mode LISTEN hears nothing: ROWSTILE_FEED_URL is the direct URL then)
export const feed = changes(new pg.Pool({ connectionString: process.env.ROWSTILE_FEED_URL ?? url, max: 1 }));
```

`usePerms` answers a list's buttons in one call, and `<Can>` shows what the user may do:

```tsx
function Buttons() {
  const perms = usePerms("project", [1, 2, 3]);
  if (perms.loading) return <p>loading</p>;
  return <ul>{[1, 2, 3].map((id) => <li key={id}>{id}:{perms(id).perms.join(",")}{perms(id).can("edit") && " [rename]"}</li>)}</ul>;
}
      <Can type="project" id={1} perm="edit" fallback={<span>no edit on 1</span>}><span>edit on 1</span></Can>
```

`useShares` and a headless `<ShareDialog>` share and unshare as the database allows; `useAccessRequest` asks
for access. They stay current over server-sent events.

## Background jobs

A job acts for a principal of its own (`type service = app.services principal` in the policy), whatever
started it: `after()`, a queue worker, a cron route.

```ts
import { current, job } from "@rowstile/client";

export const digest = job(["service", 1], async () => ({ count: await db.project.count(), who: current() }));
```

Anywhere else, `actingAs("3", () => ...)` signs in what runs inside it.

## Migrations

The policy ships as Prisma migrations. `rowstile migrate` writes the next one (only what changed since
`db/policy.lock`), and Prisma applies it with the others; Prisma's own diff then shows no change.

```sh
npx rowstile migrate               # after changing the policy
npx prisma migrate deploy
npx rowstile migrate --check       # in CI: exit 1 if a policy change has no migration
```

While you edit, `npx rowstile dev` checks, pushes to the development database, runs the tests and rewrites
`src/authz.gen.ts` on every save (and writes the migration once you stop editing).

## Tests

The policy's own tests run with `rowstile test`. In Vitest, the matchers read the refusal:

```ts
import { expect } from "vitest";
import { matchers } from "@rowstile/vitest";

expect.extend(matchers);
```

```ts
  await expect(actingAs("3", () => db.$transaction((tx) => tx.note.update({ where: { id: 1 }, data: { body: "x" } }))))
    .rejects.toBeRefused("update", "note.edit");
  await expect(actingAs("2", () => db.note.delete({ where: { id: 1 } }))).rejects.toBeNotFound();
```

`databasePerWorker(ownerUrl)` copies the migrated test database once for each Vitest worker, so tests that
write don't meet each other. The copy needs nobody connected to the original; where the service keeps one
(Neon does, for minutes after a connection), it says so and what to use instead ([Managed
Postgres](../managed-postgres.md)).
