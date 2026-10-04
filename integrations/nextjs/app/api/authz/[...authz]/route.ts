// What @rowstile/react calls: permissions for a list, shares, access requests, live updates
import { authzRoutes } from "@rowstile/next";
import { db, feed } from "@/db";

export const { GET, POST } = authzRoutes({ calls: db.$authz, changes: feed });
