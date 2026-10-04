/**
 * rowfence with Prisma (7 and later: driver adapters).
 *
 *     const adapter = signedIn(new PrismaPg({ connectionString }), { user: async () => (await auth())?.user.id });
 *     export const db = new PrismaClient({ adapter }).$extends(authz());
 *
 * `signedIn` wraps the driver adapter, so every transaction Prisma begins (interactive, a nested write) signs
 * in with authz.act_as() as whoever the code acts for (actingAs, a job), else user(), else nobody; a query
 * outside a transaction runs in one of its own. `authz()` turns the answers into errors: an update or delete
 * of a row the user can't see is NotFound (Prisma's P2025), of one they may not change Refused with the
 * reason, a refused create Refused naming the rule; and adds db.$authz (can, ids, permsOf, ...). It refuses
 * array transactions, $transaction([...]): Prisma starts them from another caller's context.
 *
 * Use the client `$extends(authz())` returns, and only that one: the client it was made from is refused
 * whenever it is used (Prisma answers the findUnique calls of one tick with one query, signed in as whoever
 * called first).
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { Prisma } from "@prisma/client/extension";
import {
  actAs, calls, idText, signingIn, translate, verdict,
  type AuthzCalls, type Id, type ObjectType, type Permission, type Queryable, type UserResolver,
} from "@rowfence/client";

export interface Options {
  /** Who the request is, when nothing set it with actingAs. */
  user?: UserResolver;
}

// The driver adapter interfaces (@prisma/driver-adapter-utils), as much of them as this uses.
interface SqlQuery { sql: string; args: unknown[]; argTypes: unknown[] }
interface Queries {
  queryRaw(q: SqlQuery): Promise<unknown>;
  executeRaw(q: SqlQuery): Promise<number>;
}
interface Transaction extends Queries {
  readonly options?: { usePhantomQuery?: boolean };
  commit(): Promise<void>;
  rollback(): Promise<void>;
}
interface Adapter extends Queries {
  startTransaction(isolationLevel?: string): Promise<Transaction>;
  [other: string]: unknown;
}
interface AdapterFactory {
  connect(): Promise<Adapter>;
  [other: string]: unknown;
}

const ARG_TEXT = { scalarType: "string", dbType: undefined, arity: "scalar" };

// Unless the adapter says otherwise (usePhantomQuery), Prisma sends COMMIT and ROLLBACK itself, and the
// adapter's commit() and rollback() only give the connection back: so these send them too
async function end(tx: Transaction, how: "COMMIT" | "ROLLBACK"): Promise<void> {
  try {
    if (!tx.options?.usePhantomQuery) await tx.executeRaw({ sql: how, args: [], argTypes: [] });
  } finally {
    await (how === "COMMIT" ? tx.commit() : tx.rollback());
  }
}

// Set while a call comes through a client extended with authz(): the adapter refuses any other call (signedIn).
// One store for the process, even if a bundler loads this module more than once.
const KEY = Symbol.for("rowfence.prisma.extended");
const through: AsyncLocalStorage<true> = ((globalThis as Record<symbol, unknown>)[KEY] as AsyncLocalStorage<true> | undefined) ??
  ((globalThis as Record<symbol, unknown>)[KEY] = new AsyncLocalStorage<true>()) as AsyncLocalStorage<true>;
// (awaited inside: Prisma's promises only start when they are awaited)
const extended = <R>(fn: () => PromiseLike<R>): Promise<R> => through.run(true, async () => await fn());
function mustBeExtended(): void {
  if (through.getStore()) return;
  // without authz(), Prisma may answer two users' findUnique calls with one query, signed in as one of them,
  // and starts an array transaction from whichever caller came first
  throw new Error("@rowfence/prisma: this client isn't extended with authz(). Use the client $extends returns, and " +
    "only that one: export const db = new PrismaClient({ adapter }).$extends(authz())");
}

/** A driver adapter whose every transaction signs in (authz.act_as), and whose queries outside a transaction
 *  each run in a signed-in transaction of their own. */
export function signedIn<F extends object>(factory: F, options: Options = {}): F {
  const inner = factory as unknown as AdapterFactory;
  // who, before the transaction begins: at build time Next.js stops a render there (a signed-in page is dynamic)
  const who = async () => actAs(await signingIn(options.user));
  const signIn = async (tx: Transaction, a: { text: string; values: (string | null)[] }) => {
    await tx.executeRaw({ sql: a.text, args: a.values, argTypes: a.values.map(() => ARG_TEXT) });
  };
  const wrap = (adapter: Adapter): Adapter => {
    const alone = async <R>(run: (tx: Transaction) => Promise<R>): Promise<R> => {
      mustBeExtended();
      const a = await who();
      const tx = await adapter.startTransaction();
      let out: R;
      try {
        await signIn(tx, a);
        out = await run(tx);
      } catch (e) {
        await end(tx, "ROLLBACK").catch(() => undefined);
        throw e;
      }
      await end(tx, "COMMIT");
      return out;
    };
    return new Proxy(adapter, {
      get(target, prop, receiver) {
        if (prop === "queryRaw") return (q: SqlQuery) => alone((tx) => tx.queryRaw(q));
        if (prop === "executeRaw") return (q: SqlQuery) => alone((tx) => tx.executeRaw(q));
        if (prop === "startTransaction") {
          return async (isolationLevel?: string) => {
            mustBeExtended();
            const a = await who();
            const tx = await target.startTransaction(isolationLevel);
            try {
              await signIn(tx, a);
            } catch (e) {
              await end(tx, "ROLLBACK").catch(() => undefined);
              throw e;
            }
            return tx;
          };
        }
        const v = Reflect.get(target, prop, receiver);
        return typeof v === "function" ? v.bind(target) : v;
      },
    });
  };
  return new Proxy(inner, {
    get(target, prop, receiver) {
      if (prop === "connect") return async () => wrap(await target.connect());
      const v = Reflect.get(target, prop, receiver);
      return typeof v === "function" ? v.bind(target) : v;
    },
  }) as unknown as F;
}

interface ModelInfo { dbName?: string | null; schema?: string | null }
interface RawClient {
  $queryRawUnsafe(query: string, ...values: unknown[]): Promise<any[]>;
  $transaction<R>(fn: (tx: unknown) => Promise<R>): Promise<R>;
  _runtimeDataModel?: { models: Record<string, ModelInfo> };
}

/** The runtime's functions on a Prisma client, and db.$authz's type. */
export type PrismaAuthz = ReturnType<typeof calls> & {
  /** The ids the signed-in user holds perm on (Prisma has no subqueries): where: { id: { in: await
   *  db.$authz.ids("folder", "edit", Number) } }. For a long list, prefer a view or a raw query. */
  ids<T extends ObjectType, K = string>(type: T, perm: Permission<T>, as?: (id: string) => K): Promise<K[]>;
};

export interface ExtensionOptions {
  /** A model's key fields, in the policy's key order, where it isn't `id` or the where's one unique field. */
  keys?: Record<string, string[]>;
}

/** The client extension: refusals and hidden rows as errors, and db.$authz. */
export function authz(options: ExtensionOptions = {}) {
  return Prisma.defineExtension((client) => {
    const raw = client as unknown as RawClient;
    const models = raw._runtimeDataModel?.models ?? {};
    const schemaOf = (table: string) => {
      for (const m of Object.values(models)) if (m.dbName === table && m.schema) return m.schema;
      return undefined;
    };
    const tableOf = (model: string) => {
      const m = models[model];
      const name = m?.dbName ?? model;
      return m?.schema ? `${m.schema}.${name}` : name;
    };
    // the row's key (the policy's key for the table) from the where of an update or delete: the fields
    // options.keys names for the model, else id, else its one unique field or compound key
    const keyOf = (model: string, where: Record<string, unknown> | undefined): Id | undefined => {
      if (!where) return undefined;
      const named = options.keys?.[model];
      if (named) {
        const vals = named.map((k) => where[k]);
        if (vals.every(isScalar)) return (vals.length === 1 ? vals[0] : vals) as Id;
        for (const v of Object.values(where)) {
          const o = v as Record<string, unknown> | null;
          if (o && typeof o === "object" && named.every((k) => isScalar(o[k]))) return named.map((k) => o[k]) as Id;
        }
        return undefined;
      }
      if (isScalar(where.id)) return where.id as Id;
      const entries = Object.entries(where);
      if (entries.length !== 1) return undefined;
      const [, v] = entries[0];
      if (isScalar(v)) return v as Id;
      if (v && typeof v === "object" && Object.values(v).every(isScalar)) return Object.values(v) as Id;
      return undefined;
    };
    const q: Queryable = {
      query: async (text, values = []) => ({ rows: await extended(() => raw.$queryRawUnsafe(text, ...values)) }),
    };
    const c = calls(q);
    const $authz: PrismaAuthz = {
      ...c,
      ids: async (type, perm, as) => {
        const out = await c.list(type, perm);
        return (as ? out.map(as) : out) as any[];
      },
    };
    const hooks = client.$extends({
      name: "rowfence",
      query: {
        async $allOperations({ model, operation, args, query, ...rest }) {
          const internal = (rest as { __internalParams?: { transaction?: { kind?: string } } }).__internalParams;
          if (internal?.transaction?.kind === "batch") {
            // Prisma starts an array's transaction later, from whichever request came first in that tick: it
            // might sign in as someone else
            throw new Error("@rowfence/prisma: $transaction([...]) can't be signed in as the right user; use " +
              "$transaction(async (tx) => { ... }) instead");
          }
          try {
            if (!internal?.transaction && model && (operation === "findUnique" || operation === "findUniqueOrThrow")) {
              // Prisma answers the findUnique calls of one tick together, from the first caller's context: run each
              // in an interactive transaction of its own, which begins (and signs in) in this caller's context
              const delegate = model.charAt(0).toLowerCase() + model.slice(1);
              return await extended(() => raw.$transaction(async (tx) =>
                (tx as unknown as Record<string, Record<string, (a: unknown) => Promise<unknown>>>)[delegate][operation](args)));
            }
            return await extended(() => query(args));
          } catch (e) {
            if (model && isP2025(e) && (operation === "update" || operation === "delete")) {
              const table = tableOf(model);
              const key = keyOf(model, (args as { where?: Record<string, unknown> }).where);
              if (key !== undefined) {
                const why = await c.explainRule(table, operation, key).catch(() => undefined);
                if (why !== undefined) {
                  const v = verdict(table, operation, key, why);
                  (v as { cause?: unknown }).cause = e;
                  throw v;
                }
              }
            }
            throw translate(e, schemaOf) ?? e;
          }
        },
      },
      client: { $authz },
    });
    // a second layer, so that $parent has the hooks above: transactions begin through this client too. It
    // changes nothing in $transaction's type.
    // The transaction begins inside the mark, but the app's callback runs outside it: the callback is the app's
    // code, and a client not extended with authz() is refused there as anywhere (its findUnique calls would be
    // answered together). Queries through tx go through the transaction, which needs no mark. What the callback
    // returns is awaited outside the mark too: a Prisma query it returns unawaited starts only then.
    const transactions = {
      $transaction(this: unknown, ...args: unknown[]) {
        const parent = (Prisma.getExtensionContext(this) as unknown as { $parent: { $transaction(...a: unknown[]): Promise<unknown> } }).$parent;
        const [fn, ...rest] = args;
        const app = typeof fn === "function"
          ? (tx: unknown) => through.exit(async () => await (fn as (tx: unknown) => unknown)(tx)) : fn;
        return extended(() => parent.$transaction(app, ...rest));
      },
    };
    return hooks.$extends({ name: "rowfence-transactions", client: transactions as {} });
  });
}

function isScalar(v: unknown): boolean {
  return typeof v === "string" || typeof v === "number" || typeof v === "bigint";
}

function isP2025(e: unknown): boolean {
  return Boolean(e && typeof e === "object" && (e as { code?: unknown }).code === "P2025");
}

export { idText, type AuthzCalls };
