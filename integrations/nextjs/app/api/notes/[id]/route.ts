import { route } from "@rowfence/next";
import { db } from "@/db";

type Params = { params: Promise<{ id: string }> };

// an update the rules may refuse: a hidden note is 404, one the user may not edit 403 with the reason
export const PATCH = route(async (req: Request, { params }: Params) => {
  const id = Number((await params).id);
  const { body } = (await req.json()) as { body: string };
  await db.note.update({ where: { id }, data: { body } });
  return Response.json({ id });
});

export const DELETE = route(async (_req: Request, { params }: Params) => {
  await db.note.delete({ where: { id: Number((await params).id) } });
  return new Response(null, { status: 204 });
});
