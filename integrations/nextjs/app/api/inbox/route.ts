import { route } from "@rowfence/next";
import { db, requestUser } from "@/db";

// Prisma's create reads the new row back (RETURNING): only its recipient may, so the sender gets a 403 that
// names the select rule
export const POST = route(async (req: Request) => {
  const { recipient_id, body } = (await req.json()) as { recipient_id: number; body: string };
  const msg = await db.message.create({ data: { recipient_id, body, sender_id: Number(await requestUser() ?? 0) } });
  return Response.json({ id: msg.id }, { status: 201 });
});
