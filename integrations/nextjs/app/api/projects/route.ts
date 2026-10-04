import { route } from "@rowstile/next";
import { db } from "@/db";

export const GET = route(async () =>
  Response.json((await db.project.findMany({ select: { id: true }, orderBy: { id: "asc" } })).map((p) => p.id)));
