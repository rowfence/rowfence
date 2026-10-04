// A query by permission: the projects the user may edit (a set check, not a check per row)
import { route } from "@rowstile/next";
import { db } from "@/db";

export const GET = route(async () => {
  const ids = await db.$authz.ids("project", "edit", Number);
  const projects = await db.project.findMany({ where: { id: { in: ids } }, select: { id: true }, orderBy: { id: "asc" } });
  return Response.json(projects.map((p) => p.id));
});
