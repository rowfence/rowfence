import { route } from "@rowfence/next";
import { db, requestUser } from "@/db";

// the same insert without reading the row back
export const POST = route(async (req: Request) => {
  const { recipient_id, body } = (await req.json()) as { recipient_id: number; body: string };
  const sender = Number(await requestUser() ?? 0);
  await db.$executeRaw`INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (${sender}, ${recipient_id}, ${body})`;
  return Response.json({}, { status: 202 });
});
