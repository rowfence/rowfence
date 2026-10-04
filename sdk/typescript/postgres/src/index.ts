/**
 * rowstile with postgres.js.
 *
 *     const db = authz(postgres(url), { user: async () => (await auth())?.user.id });
 *     const notes = await db.begin((sql) => sql`SELECT * FROM app.notes`);
 *
 * Every transaction signs in with authz.act_as() as whoever the code acts for (actingAs, a job), else user(),
 * else nobody. A refused write throws Refused (with the rule and why), strict sign-in's error NotSignedIn.
 * With PgBouncer in transaction mode, create the client with { prepare: false }, as postgres.js says.
 */
import type { Sql, TransactionSql } from "postgres";
import { actAs, calls, signingIn, translate, type Queryable, type UserResolver, type Who } from "@rowstile/client";

export interface Options {
  /** Who the request is, when nothing set it with actingAs. */
  user?: UserResolver;
}

/** A postgres.js transaction as the runtime's functions take it. */
export function queryable(sql: Sql | TransactionSql): Queryable {
  return {
    query: async (text, values = []) => {
      const rows = await sql.unsafe(text, values as any[]);
      return { rows: [...rows], rowCount: rows.count };
    },
  };
}

export function authz(sql: Sql, options: Options = {}) {
  const begin = async <R>(fn: (tx: TransactionSql) => Promise<R>, who?: Who): Promise<R> => {
    const p = await signingIn(options.user, who);
    try {
      return (await sql.begin(async (tx) => {
        const a = actAs(p);
        await tx.unsafe(a.text, a.values);
        return fn(tx);
      })) as R;
    } catch (e) {
      throw translate(e) ?? e;
    }
  };
  const each: Queryable = { query: (text, values) => begin((tx) => queryable(tx).query(text, values)) };
  return {
    sql,
    /** Runs fn in a transaction signed in as whoever the code acts for (or `who`, if given). */
    begin,
    /** The runtime's functions (can, permsOf, list, share, ...), each in its own signed-in transaction; inside
     *  a transaction, use calls(queryable(tx)). */
    ...calls(each),
  };
}

export { calls };
