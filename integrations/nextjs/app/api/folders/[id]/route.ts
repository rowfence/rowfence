import { route } from "@rowstile/next";
import { db } from "@/db";

type Params = { params: Promise<{ id: string }> };

// a folder moved into another: inside one of its own subfolders is 409, in the database's words
export const PATCH = route(async (req: Request, { params }: Params) => {
  const id = Number((await params).id);
  const { parent_id } = (await req.json()) as { parent_id: number | null };
  await db.folder.update({ where: { id }, data: { parent_id } });
  return Response.json({ id });
});
