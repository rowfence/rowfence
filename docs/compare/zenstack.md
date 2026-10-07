# rowstile and ZenStack

Both keep the facts in the app's own tables and write the rules in one place, apart from the handlers. They
differ in who enforces. ZenStack's engine adds the rules to the queries it writes, in the application.
rowstile compiles them into row-level security, and Postgres applies them to every query, whoever wrote it.

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

    // no anonymous access
    @@deny('all', auth() == null)

    // published posts are readable by anyone
    @@allow('read', published)

    // author has full access
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
goes through its client, the ORM's calls and its query builder's alike. Its docs say what they don't hold
for: "Raw SQL queries executed via `$executeRaw()` and `$queryRaw()` are not subject to access control
enforcement", nor are raw queries written with the query builder's `sql` tag
([querying](https://zenstack.dev/docs/orm/access-control/query)).

rowstile's rules are in the database. They hold for the ORM's queries, for raw SQL, for a second service on
the same database, for a report or a job, for a console opened as the app's role. What they need in return
is Postgres, and a transaction that says who is signed in.

## A write that is refused

In ZenStack an update or a delete of one row the rules don't allow throws "an `ORMError` with `reason` set
to `NOT_FOUND`", and the page says why: "the rationale is rows that don't satisfy the policies 'don't
exist'". That holds whether the user may read the row or not.

rowstile tells the two cases apart. A row the user can't see is not found. One they see and may not change is
refused, with the rule and the part of it that was missing. For user 3, who reads a published post of
someone else and tries to change it, `authz.explain_rule` answers what the SDKs put in their 403:

```
no   update : manage  (line 14)
  no   manage
    no   user 3 does not hold manage on post 2
      post.manage = author
      no   author
```

For a draft of someone else, which user 3 can't read, it answers nothing, and the SDKs answer 404.

## Rules that follow relations

Neither stops at a row's own columns. A ZenStack rule reaches through the model's relations: to-one
relations with dots ("you can chain as deeply as you need"), to-many ones with a predicate over the related
rows, and `check()` hands the decision to a related model's own rules ("`check()` currently only supports
to-one relations"), all on the page on
[writing policies](https://zenstack.dev/docs/orm/access-control/write-policies).

A rowstile permission follows a relation to another type's permission (`project.edit`), a group to its
members (`team#member`, teams inside teams), and a tree to any depth (`or parent.view`), which it keeps in
a table so that reads stay fast.

## What each is built for

ZenStack calls itself "the data layer for modern TypeScript applications": a schema language for "data,
relations, access control, and more, in one place", an ORM, and a service that "provides a full-fledged data
API without the need to code it up" ([its docs](https://zenstack.dev/docs)). Of its access control it says that
"as the enforcement happens on the application side, it's database-type agnostic, doesn't involve database
schema migrations".

rowstile does one thing, access rules, in the database: for a Python backend and a TypeScript one alike,
with shares that people hand each other, that start and end, and share links, and with a review of each
change that says who gains or loses access. It needs Postgres, and a rule change is a migration.

## When ZenStack is the better choice

- **The app is TypeScript only**, and everything reaches the database through ZenStack's client.
- **You want the models, the API and the rules from one schema.**
- **The database isn't Postgres**, or may change.
- **You don't want a rule change to be a migration.**

## Try it

Two tested recipes hold this page's two kinds of rule, each with a link that opens it in the playground:
[rows only their owner can see and change](../cookbook/owner-only.md) and
[rules that depend on the row](../cookbook/conditions-on-the-row.md).
