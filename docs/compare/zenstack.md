# rowstile and ZenStack

Both keep the facts in the app's own tables and write the rules in one place, beside the model. They differ
in who enforces. ZenStack's engine adds the rules to the queries it writes, in the application. rowstile
compiles them into row-level security, and Postgres applies them to every query, whoever wrote it.

What this page says of ZenStack is from its own documentation, read on 2026-10-07 and linked. If a line is
wrong or out of date, an issue is welcome. The short version for every alternative is on
[rowstile and the alternatives](../comparison.md).

## The same rules in both

Posts that their author manages and that signed-in people read once published. This is the example of
ZenStack's page on [writing policies](https://zenstack.dev/docs/orm/access-control/write-policies):

```
model Post {
    id        Int     @id @default(autoincrement())
    title     String
    published Boolean @default(false)
    author    User    @relation(fields: [authorId], references: [id])
    authorId  Int
    @@deny('all', auth() == null)
    @@allow('read', published)
    @@allow('all', auth().id == authorId)
}
```

In rowstile's language, over the table that model makes:

```authz
app role app_user

type user = app.users

type post = app.posts
  author : user = author_id

  can manage = author
  can view   = manage or (signed_in and {published})

rules app.posts
  select           : view
  insert           : author
  update           : manage
  update author_id : nobody
  delete           : manage
```

ZenStack's rules live in the model, with its fields. rowstile's live in a file of their own and name the
table and the column each relation is read from. One line has no twin above, `update author_id : nobody`:
the author's column is what gives `manage`, so the policy says nobody changes it (`authz.lint()` warns
when such a column is left open).

## Who enforces

ZenStack: "When querying data, the engine converts the policies into SQL filters and injects them into the
generated queries" ([access control](https://zenstack.dev/docs/orm/access-control)). The rules hold for what
goes through its client. Its docs say what doesn't: "Raw SQL queries executed via `$executeRaw()` and
`$queryRaw()` are not subject to access control enforcement", and the same for raw queries in its query
builder ([querying](https://zenstack.dev/docs/orm/access-control/query)).

rowstile's rules are in the database. They hold for the ORM's queries, for raw SQL, for a second service on
the same database, for a report or a job, for a console opened as the app's role. What they need in return
is Postgres, and a transaction that says who is signed in.

## A write that is refused

ZenStack answers a write to a row the rules don't allow with "an `ORMError` with `reason` set to
`NOT_FOUND`".

rowstile tells the two cases apart. A row the user can't see is not found. One they see and may not change is
refused, and the error says which rule and which part of it was missing:

```
ERROR:  permission denied: user 3 may not insert this row into app.posts
DETAIL:  no   insert : author  (line 13)
  no   author
```

## What each is built for

ZenStack calls its approach "database-type agnostic", needing no migration for a rule, and it gives an app
its models, its API and its rules from one schema, in TypeScript.

rowstile is built for what gets hard in SQL: access that passes down a tree to any depth and is kept in a
table so reads stay fast, groups inside groups, shares that start and end, share links, a review of each
change that says who gains or loses access, and the same rules for a Python backend and a TypeScript one.
A rule change is a migration.

## When ZenStack is the better choice

- **The app is TypeScript only**, and everything reaches the database through one client.
- **You want the models, the API and the rules from one schema.**
- **The database isn't Postgres**, or may change.
- **The rules are per model and flat**: an owner, a published flag, a role. rowstile's compiler earns its
  place when access is shared, inherited or grouped.

## Try it

[Rows only their owner can see and change](../cookbook/owner-only.md) and
[rules that depend on the row](../cookbook/conditions-on-the-row.md) are this page's rules as tested recipes,
each with a link that opens it in the playground.
