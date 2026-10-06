# How it works

## What it compiles to

- Each relation and permission becomes a view of the ids the current user holds it
  on. The app role reads only these (`authz_gen`), never raw shares or internals.
- Inheritance becomes a closure table per set of links, kept current by triggers on
  the object table, every link table, the shares table, and any table an inheritance
  condition reads. It is backfilled when applying; `authz.verify()` compares it with
  a rebuild. Moving a folder, or linking it, shifts the stored rows of everything below
  it to its new ancestors instead of recomputing them (unless a link loops back into
  the moved part).
- Rules become RLS policies on the row itself, so `INSERT ... RETURNING` works. Rules
  on changed columns become `BEFORE UPDATE` triggers. Each check lists its cheapest
  items first (columns, then small per-user sets, then inherited permissions), and an
  inherited permission is first checked against what the object's own columns give
  (owner, org admin): one index lookup, where users who reach a lot stop.
- Writes and `authz.can` check one object by walking its ancestors; reads and lists
  test each row and let Postgres hash the user's sets once for many rows.
- Relations read your tables live: when someone leaves a team, the next query knows.

## What it guarantees

- **Shares die with their row.** Deleting a row, changing its id or truncating its
  table removes the shares on it and to it. `authz.share` locks the object and the
  subject, so a concurrent delete can't slip in between.
- **Inheritance can't go stale.** Writes to closure tables take a lock row per type;
  in REPEATABLE READ or SERIALIZABLE a writer with an old snapshot gets a
  serialization error to retry instead of storing stale ancestors. What they can't follow is a write made
  with the triggers off (`session_replication_role = replica`, `ALTER TABLE ... DISABLE TRIGGER`, a bulk
  load or a restore that turns them off): `authz.verify()` then says false, and `rowstile reapply --force`
  computes the tables again.
- **No loops through columns**, even across several rows or two concurrent
  transactions. Loops through link tables are allowed and harmless.
- **Stored decisions don't depend on time or user.** Conditions that limit
  inheritance are rejected if they use the clock, the user or settings (checked in the
  text, then by Postgres when applying). Links made by sharing can't expire.
- **You can't share more than you hold**, or share what the policy doesn't declare as
  shared, or decide your own access request.
- **Mistakes are reported with line numbers**, at compile time or when applying.
- **Re-applying replaces the old version**, keeps shares, removes access for roles the
  policy no longer names, and warns about cascading foreign keys and tables that lost
  their rules. Inheritance tables whose definition didn't change are kept, not rebuilt:
  a new permission or rule applies in about 0.1 s with 50k folders.

## Security

The app role is not trusted: it may do what the rules allow and nothing else. Policy authors,
the database owner and the backend that says who is signed in are trusted. What that protects,
the attacks tried and the known limits (side channels such as `EXPLAIN ANALYZE` row counts, for
code that can run arbitrary SQL as the app role) are in [the threat model](../threat-model.md).
[How rowstile is checked](../how-it-is-checked.md) says which tests hold it to that.

**rowstile has not been audited by anyone outside the project.** It has had self-review and the
[tests](../../core/README.md#tested), including an adversarial suite and a parser fuzzer.
