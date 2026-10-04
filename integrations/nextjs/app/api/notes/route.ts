import { route } from "@rowfence/next";
import { db, requestUser } from "@/db";

export const GET = route(async () =>
  Response.json((await db.note.findMany({ select: { id: true }, orderBy: { id: "asc" } })).map((n) => n.id)));

// a create the insert rule may refuse: 403 with the rule and why
export const POST = route(async (req: Request) => {
  const { project_id, body } = (await req.json()) as { project_id: number; body: string };
  const note = await db.note.create({ data: { project_id, body, author_id: Number(await requestUser() ?? 0) } });
  return Response.json({ id: note.id }, { status: 201 });
});
