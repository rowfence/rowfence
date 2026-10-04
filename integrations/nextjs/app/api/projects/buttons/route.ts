// A list's buttons: every project's permissions in one call
import { route } from "@rowfence/next";
import { db } from "@/db";

export const GET = route(async () => {
  const projects = await db.project.findMany({ select: { id: true }, orderBy: { id: "asc" } });
  return Response.json(await db.$authz.permsOf("project", projects.map((p) => p.id)));
});
