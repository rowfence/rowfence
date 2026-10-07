# rowstile and row-level security by hand

What rowstile writes is row-level security. The enforcement is the same either way: Postgres applies the
policies to every query. The question is who writes the SQL, and how far you can go before writing it by hand
gets hard. This page shows where that point is, with statements you can run.

The short version for every alternative is on [rowstile and the alternatives](../comparison.md).

## A flat rule is easy by hand

"A folder is seen by its owner":

```sql
ALTER TABLE app.folders ENABLE ROW LEVEL SECURITY;
CREATE POLICY folders_owner ON app.folders FOR SELECT TO app_user
  USING (owner_id = current_setting('app.user_id')::bigint);
```

As a policy file:

```authz
app role app_user

type user = app.users

type folder = app.folders
  owner : user = owner_id

  can view = owner

rules app.folders
  select : view
```

For rules like this one, and for `tenant_id = ...` on every table, the SQL is short and you don't need a
compiler.

## A tree is where it gets hard

"The owner of a folder also sees what is inside it." The natural policy walks up the tree:

```sql
CREATE POLICY folders_tree ON app.folders FOR SELECT TO app_user USING (
  EXISTS (
    WITH RECURSIVE up AS (
      SELECT f.id, f.parent_id, f.owner_id FROM app.folders f WHERE f.id = folders.id
      UNION ALL
      SELECT p.id, p.parent_id, p.owner_id FROM app.folders p JOIN up ON p.id = up.parent_id
    )
    SELECT 1 FROM up WHERE up.owner_id = current_setting('app.user_id')::bigint));
```

Postgres refuses the first query through it:

```
ERROR:  infinite recursion detected in policy for relation "folders"
```

A policy on a table can't read that table through the policy again. The way out is a `SECURITY DEFINER`
function: it runs as its owner, the tables' owner, whom the policy doesn't apply to, so it reads past it.
Its `search_path` is pinned, and the policy calls it for each row:

```sql
CREATE FUNCTION app.owns_above(p_id bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  WITH RECURSIVE up AS (
    SELECT f.id, f.parent_id, f.owner_id FROM app.folders f WHERE f.id = p_id
    UNION ALL
    SELECT p.id, p.parent_id, p.owner_id FROM app.folders p JOIN up ON p.id = up.parent_id
  )
  SELECT EXISTS (SELECT 1 FROM up WHERE up.owner_id = current_setting('app.user_id')::bigint) $$;
CREATE POLICY folders_tree ON app.folders FOR SELECT TO app_user USING (app.owns_above(id));
```

That works, and it walks the tree once for every row a query reads. A list of a thousand folders is a
thousand walks. The usual next step is a table of every folder's ancestors, kept by triggers, with the
locking that a move of a folder needs so that two moves at once can't make a loop.

In a policy file it is one more relation, and `or parent.view`:

```authz
app role app_user

type user = app.users

type folder = app.folders
  owner  : user   = owner_id
  parent : folder = parent_id

  can view = owner or parent.view

rules app.folders
  select : view
```

From it rowstile writes the ancestors' table (`authz_int.folder__parent__tree` here), the triggers on
`app.folders` that keep it, and their lock. The policy it writes for `SELECT` looks each row up in the set
of folders the user may see, which Postgres can compute once for a query, where the function above ran for
each row. [How it works](../reference/guarantees.md) shows what is generated;
[Speed and limits](../reference/limits.md) has the numbers.

## What else gets hard by hand

- **Who is asking.** `current_setting('app.user_id')` believes whoever set it. Any SQL that runs as the app's
  role can set it to someone else, and behind a pooler a setting made with `SET` can outlive its request.
  rowstile signs each sign-in: the settings are believed only with a signature the app's role can't make
  ([Identity](../reference/identity.md)).
- **A write that says why.** By hand, a refused insert says
  `new row violates row-level security policy for table "folders"`, and an update of a row the policy
  hides changes no row and says nothing. rowstile's refused insert names the rule and the part of it that
  was missing, and for an update or a delete that changed nothing, `authz.explain_rule` says the same
  (the SDKs ask it, and answer 403 or 404).
- **Groups inside groups, shares that end, share links.** Each is a table, a few functions and a policy
  that must not leak. In a policy file each is a line or two.
- **Tests.** A policy is tested by signing in as someone and reading. rowstile's tests sit beside the policy
  (`user 2 cannot view folder 7`), run on every save, and `rowstile prove` checks an invariant in many small
  worlds.
- **What a change does.** Editing a `USING` clause changes who sees what, and nothing says for whom.
  `rowstile review` says on the pull request who gains and who loses access.
- **The details that leak.** A table without `FORCE ROW LEVEL SECURITY` read by its owner, a role with
  `BYPASSRLS`, a view that runs with its owner's rights, a permissive policy somebody added later.
  `authz.lint()` reports each.

## What stays the same

It is still row-level security, so what holds for it holds here: the app connects as a role that policies
apply to, never as the tables' owner; a planner that can't push a condition through a policy makes a slow
query; and `EXPLAIN` is still the way to see what happened. rowstile doesn't hide the SQL: `rowstile migrate`
writes it into a migration you can read.

## A note for Supabase

Supabase's Data API reaches the database as its own roles (`anon`, `authenticated`), and policies written by
hand for those roles are how a browser reads tables there. rowstile's policies are for one role, the app's
own, used by a backend that connects to Postgres: [Managed Postgres](../managed-postgres.md) says what works.

## When by hand is the better choice

- **A handful of flat rules that will not change**: a tenant column, an owner column.
- **A browser reads the tables through Supabase's Data API.**
- **You may not add a tool to the build.** What rowstile leaves in the database is plain SQL and keeps working
  without the command, but changing the policy needs it.

## Try it

[Folders that inherit](../cookbook/folders-that-inherit.md) is the tree above as a tested recipe, with a link
that opens it in the playground.
