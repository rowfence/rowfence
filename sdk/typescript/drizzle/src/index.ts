/**
 * rowfence with Drizzle ORM (node-postgres or postgres.js underneath).
 *
 *     const authz = withAuthz(drizzle(pool), { user: async () => (await auth())?.user.id });
 *     const mine = await authz.transaction((tx) =>
 *       tx.select().from(notes).where(inIds(notes.projectId, "project", "edit")));
 *
 * Every transaction signs in with authz.act_as() as whoever the code acts for (actingAs, a job), else user(),
 * else nobody. Queries by permission are set checks (a subquery on authz.list), never a function call per row.
 * A refused write throws Refused (with the rule and why), strict sign-in's error NotSignedIn; an UPDATE or
 * DELETE that changed nothing: expect(tx, result, ...) says NotFound or Refused.
 */
import { sql, type SQL, type Column } from "drizzle-orm";
import {
  actAs, calls, signingIn, translate,
  type Id, type ObjectType, type Permission, type Queryable, type UserResolver, type Who,
} from "@rowfence/client";

export interface Options {
  /** Who the request is, when nothing set it with actingAs. */
  user?: UserResolver;
}

/** What Drizzle's databases and transactions have in common here. */
interface Executes {
  execute(query: SQL): Promise<unknown>;
}
interface Transacts<Tx> {
  transaction<R>(fn: (tx: Tx) => Promise<R>, config?: unknown): Promise<R>;
}

const rowsOf = (r: unknown): any[] => (Array.isArray(r) ? [...r] : ((r as { rows?: any[] })?.rows ?? []));

/** SQL with $1, $2 placeholders as a Drizzle query. */
function statement(text: string, values: unknown[] = []): SQL {
  const parts = text.split(/\$(\d+)/);
  // sql.param: one parameter each, an array too (Drizzle writes a bare array out as a list of parameters)
  const chunks: SQL[] = parts.map((p, i) => (i % 2 ? sql`${sql.param(values[Number(p) - 1])}` : sql.raw(p)));
  return sql.join(chunks, sql.raw(""));
}

/** A Drizzle transaction as the runtime's functions take it. */
export function queryable(tx: Executes): Queryable {
  return {
    query: async (text, values) => {
      const r = await tx.execute(statement(text, values));
      const rows = rowsOf(r);
      const o = r as { rowCount?: number | null; count?: number };
      return { rows, rowCount: o.rowCount ?? o.count ?? rows.length };
    },
  };
}

export function withAuthz<Tx extends Executes>(db: Transacts<Tx>, options: Options = {}) {
  const transaction = async <R>(fn: (tx: Tx) => Promise<R>, who?: Who): Promise<R> => {
    const p = await signingIn(options.user, who);
    try {
      return await db.transaction(async (tx) => {
        const a = actAs(p);
        await tx.execute(statement(a.text, a.values));
        return fn(tx);
      });
    } catch (e) {
      throw translate(e) ?? e;
    }
  };
  const each: Queryable = { query: (text, values) => transaction((tx) => queryable(tx).query(text, values)) };
  return {
    /** Runs fn in a transaction signed in as whoever the code acts for (or `who`, if given). */
    transaction,
    /** The runtime's functions (can, permsOf, list, share, ...), each in its own signed-in transaction; inside
     *  a transaction, use calls(queryable(tx)). */
    ...calls(each),
  };
}

/** The ids the signed-in user holds perm on, as a subquery of the key's type (bigint by default). */
export function ids<T extends ObjectType>(type: T, perm: Permission<T>, keyType = "bigint"): SQL {
  // a type's name, with its length or precision if it has one: varchar(30), numeric(10, 0)
  if (!/^[a-z_][a-z0-9_ ]*(\(\s*\d+\s*(,\s*\d+\s*)?\))?(\[\])?$/i.test(keyType)) throw new Error(`not a type name: ${keyType}`);
  return sql`(SELECT authz_ids.x::${sql.raw(keyType)} FROM authz.list(${type}, ${perm}) AS authz_ids(x))`;
}

/** column IN (the ids the user holds perm on): where(inIds(folders.id, "folder", "edit")). */
export function inIds<T extends ObjectType>(column: Column, type: T, perm: Permission<T>): SQL {
  const serial: Record<string, string> = { serial: "integer", bigserial: "bigint", smallserial: "smallint" };
  const t = column.getSQLType();
  return sql`${column} IN ${ids(type, perm, serial[t] ?? t)}`;
}

/** An UPDATE or DELETE's result (rows from .returning(), or the driver's result): returned if it changed a row,
 *  otherwise NotFound (the user can't see it) or Refused (they may not, and why), asked in the same transaction. */
export async function expect<R>(tx: Executes, result: R, table: string, command: "update" | "delete", id: Id, row?: object): Promise<R> {
  return calls(queryable(tx)).expect(result, table, command, id, row);
}

export { calls };
