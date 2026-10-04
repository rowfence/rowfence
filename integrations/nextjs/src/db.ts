// The app's database: Prisma, signed in as the request's user on every transaction (@rowfence/prisma).
import { PrismaPg } from "@prisma/adapter-pg";
import { headers } from "next/headers";
import pg from "pg";
import { authz, signedIn } from "@rowfence/prisma";
import { changes } from "@rowfence/pg";
import "@rowfence/next";                              // signed-in reads never land in a cache
import { PrismaClient } from "./generated/prisma/client.ts";
import "./authz.gen.ts";                              // the policy's names, for the SDK's types

/** Who the request is. A real app reads its session (auth()); the conformance app, a header. */
export async function requestUser(): Promise<string | null> {
  return (await headers()).get("x-user");
}

const url = process.env.ROWFENCE_APP_URL;
export const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const db = new PrismaClient({ adapter: signedIn(new PrismaPg(pool), { user: requestUser }) }).$extends(authz());

// live updates for @rowfence/react: one connection that LISTENs, beside the pool, straight to Postgres
// (through a pooler in transaction mode LISTEN hears nothing: ROWFENCE_FEED_URL is the direct URL then)
export const feed = changes(new pg.Pool({ connectionString: process.env.ROWFENCE_FEED_URL ?? url, max: 1 }));
