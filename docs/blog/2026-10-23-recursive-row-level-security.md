# Why a recursive row-level security policy is slow, and what fixes it

*Salaheddine El Hssani, 2026-10-23*

A Postgres row-level security policy that walks up a tree of folders does the walk for every row a query
reads: counting two million files takes fourteen seconds. With the tree kept in a table, the same count takes
40 to 150 milliseconds. This post takes the rule everyone expects of folders inside folders, "whoever may see
a folder may see what is in it", writes it four ways, shows the plan of each, and says what the fast one costs
on writes.

## The setup

Two tables: `folders (id, parent_id, owner_id, name)` and `files (id, folder_id, name)`. A hundred workspaces
at the top, each with its own owner, and under each a tree four folders wide. Ten files in every folder. The
rule: you see a file if you own its folder, or any folder above it.

Everything below comes from one script,
[experiment.sql](recursive-row-level-security/experiment.sql), run twice on PostgreSQL 16 in a container on a
laptop, with default settings and JIT off: once with 20,000 folders and 200,000 files (the tree is five deep),
once with 200,000 folders and two million files (seven deep). The full output of both runs is beside it
([small](recursive-row-level-security/run-20k-folders.txt),
[large](recursive-row-level-security/run-200k-folders.txt)). Your numbers will differ; the ratios should not.

Three queries are timed as user 7, who owns one workspace and so sees what is under it (3,410 files in the
small run, 54,610 in the large one):

- **the count**: `SELECT count(*) FROM demo.files`, which reads every row;
- **the first page**: `SELECT id, name FROM demo.files ORDER BY name LIMIT 50`, which follows an index and
  stops at fifty;
- **one file**: `SELECT id, name FROM demo.files WHERE id = 61`.

Each number is the middle one of three runs.

| 2 million files | the count | the first page | one file |
|---|---|---|---|
| 1. a recursive query in the policy | 13.8 s | 16 ms | 0.04 ms |
| 2. the walk in a function | 21.8 s | 21 ms | 0.27 ms |
| 3. a table of ancestors, `EXISTS` | 152 ms | 1.6 ms | 0.02 ms |
| 4. a table of ancestors, `IN` | 38 ms | 1.8 ms | 0.69 ms |

| 200,000 files | the count | the first page | one file |
|---|---|---|---|
| 1. a recursive query in the policy | 836 ms | 12 ms | 0.03 ms |
| 2. the walk in a function | 1.58 s | 21 ms | 0.22 ms |
| 3. a table of ancestors, `EXISTS` | 12 ms | 0.7 ms | 0.02 ms |
| 4. a table of ancestors, `IN` | 6.6 ms | 0.7 ms | 0.07 ms |

## 1. The natural policy

```sql
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  EXISTS (
    WITH RECURSIVE up AS (
      SELECT f.id, f.parent_id, f.owner_id FROM demo.folders f WHERE f.id = files.folder_id
      UNION ALL
      SELECT p.id, p.parent_id, p.owner_id FROM demo.folders p JOIN up ON p.id = up.parent_id
    )
    SELECT 1 FROM up WHERE up.owner_id = current_setting('demo.user_id')::bigint));
```

It is correct, and for one file it is as fast as anything: a handful of index lookups. The trouble is in the
count's plan (the small run, shortened):

```
 Aggregate (actual rows=1 loops=1)
   ->  Seq Scan on files (actual rows=3410 loops=1)
         Filter: (SubPlan 2)
         Rows Removed by Filter: 196590
         SubPlan 2
           ->  CTE Scan on up up_1 (actual rows=0 loops=200000)
                 CTE up
                   ->  Recursive Union (actual rows=4 loops=200000)
                         ->  Index Scan using folders_pkey on folders f (actual rows=1 loops=200000)
                         ->  Nested Loop (actual rows=1 loops=884590)
                               ->  Index Scan using folders_pkey on folders p (actual rows=1 loops=884590)
```

`loops=200000`: the walk runs once for each file, because it starts from that file's folder. Nothing in it
can be computed once and reused. Two hundred thousand files cost 1.1 million index lookups, and ten times the
files in a tree two levels deeper cost sixteen times the time.

The first page looks fine, and it is a trap. The index hands files over in name order, and the policy is
asked about each until fifty pass. User 7 sees about one file in sixty, so 2,377 walks gave 50 rows. A user
who sees one file in ten thousand waits for half a million walks to fill the same page.

One more thing happens if the folders themselves get this policy. A policy on `folders` that reads `folders`
is refused when the first query runs: `infinite recursion detected in policy for relation "folders"`.

## 2. The walk in a function

The way out of that error is the usual advice: put the walk in a `SECURITY DEFINER` function, which reads the
table past its policy, and call it from the policy.

```sql
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (demo.owns_above(folder_id));
```

The plan gets shorter and tells you less:

```
 Aggregate (actual rows=1 loops=1)
   ->  Seq Scan on files (actual rows=3410 loops=1)
         Filter: demo.owns_above(folder_id)
         Rows Removed by Filter: 196590
```

It is the same walk for each row, plus the cost of calling a function each time, and the planner can no
longer see inside. In both runs it is the slowest of the four, one and a half to two times the first. A
function fixes the error. It doesn't fix the cost.

## 3. A table of ancestors

The walk is slow because it is done at read time, for each row. So do it at write time, once: keep a table
with a row for every folder and each folder above it, itself included.

```sql
CREATE TABLE demo.folder_tree (
  descendant bigint NOT NULL REFERENCES demo.folders ON DELETE CASCADE,
  ancestor   bigint NOT NULL REFERENCES demo.folders ON DELETE CASCADE,
  PRIMARY KEY (descendant, ancestor)
);
CREATE INDEX ON demo.folder_tree (ancestor);
```

This is a closure table. It holds 88,800 rows for the 20,000 folders (8.7 MB) and 1.2 million for the 200,000
(109 MB): a folder's depth in rows, for each folder. The policy becomes a lookup:

```sql
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  EXISTS (SELECT 1 FROM demo.folder_tree t JOIN demo.folders a ON a.id = t.ancestor
          WHERE t.descendant = files.folder_id AND a.owner_id = current_setting('demo.user_id')::bigint));
```

And the count's plan changes shape (shortened again):

```
 Aggregate (actual rows=1 loops=1)
   ->  Seq Scan on files (actual rows=3410 loops=1)
         Filter: (hashed SubPlan 2)
         Rows Removed by Filter: 196590
         SubPlan 2
           ->  Nested Loop (actual rows=341 loops=1)
                 ->  Bitmap Heap Scan on folders a (actual rows=1 loops=1)
                 ->  Index Scan using folder_tree_ancestor_idx on folder_tree t (actual rows=341 loops=1)
```

`hashed SubPlan`, `loops=1`. Postgres turned the question around. It no longer asks, for each file, "is
there an owner above this folder?". It asks once, "which folders are under something user 7 owns?" (341 of
them, two index scans), keeps the answer in a hash table, and each file is then one probe. That is the whole
difference between 836 milliseconds and 12.

For the single file it does not build the set. It starts from the file's folder and looks up, two index
lookups. Postgres plans an `EXISTS` both ways and picks one by its estimate of how many rows it will check.

## 4. Saying the set outright

```sql
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  folder_id IN (SELECT t.descendant FROM demo.folder_tree t JOIN demo.folders a ON a.id = t.ancestor
                WHERE a.owner_id = current_setting('demo.user_id')::bigint));
```

`IN` over a subquery that doesn't mention the row leaves no choice: it is always the set. Here the count
got a parallel index-only scan with it and is the fastest of the four. The single file is where it loses: it
builds all 5,461 folders of the large run to answer for one row, 0.69 ms against 0.02. For user 7 that is
nothing. For an administrator who sees a million folders it is a million rows fetched to open one file.

So the two questions want opposite plans. A list wants the set, computed once. A single row, and every write
that checks one row, wants to start from the row and look up. `EXISTS` lets the planner choose and its
choice rests on an estimate; if you know which question a policy answers, you can write the form it needs.

## What the table costs

It has to be kept. A new folder adds one row for each folder above it. A folder that moves takes everything
under it along: the rows tying those folders to what was above the old place go, and rows for what is above
the new place come. The script does it by hand in the large run, for a folder that is 1,365 folders with all
under it: 0.3 ms for the update, 1.4 ms to delete 1,365 rows, 10.8 ms to insert 1,365, and the table equals
a fresh build afterwards.

Done properly that is triggers on `folders`, and the timings are the easy part. The hard part is two moves at
once. Each reads the tree before the other commits, and together they can put a folder inside itself or leave
rows for a place nothing is in any more. So moves take a lock, and a table that is written with triggers off
(a restore, a bulk load) has to be checked and rebuilt.

## At twenty million files

The same idea at a larger size, from [rowstile's benchmark](../../core/bench/README.md): 20 million files and
a million folders in a tree twenty levels deep, with 40,000 users, on the same laptop with 8 GB of shared
buffers. Reads through the rules have a 95th percentile of 4.3 to 4.6 ms while 20 tree writes a second
arrive beside them, tree writes 28 to 38 ms, and the folder with the most below it (54,000 folders) moves in
2 to 3.7 seconds. [Speed and limits](../reference/limits.md) has the conditions and what doesn't scale.

That is where this post comes from. [rowstile](../../site/index.md) is a small language for access rules that
compiles to row-level security, and the rule of this post is one line of it:

```authz
app role app_user

type user = app.users

type folder = app.folders
  owner  : user   = owner_id
  parent : folder = parent_id

  can view = owner or parent.view

type file = app.files
  folder : folder = folder_id

  can view = folder.view

rules app.files
  select : view
```

From `or parent.view` it writes the table of ancestors, the triggers that keep it and their lock, a policy in
the set form for reads and a check from the row for writes. [Folders that inherit](../cookbook/folders-that-inherit.md)
is that policy with its tests, and opens in the playground. If you would rather write the SQL yourself,
[experiment.sql](recursive-row-level-security/experiment.sql) is a place to start.
