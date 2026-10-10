import { route } from "@rowstile/next";
import { db } from "@/db";

type Params = { params: Promise<{ id: string }> };

// read and write back in one interactive transaction: why a write was refused is asked inside it, so it needs no
// second connection (test.sh starts a server with a pool of one)
export const POST = route(async (req: Request, { params }: Params) => {
  const id = Number((await params).id);
  const { text } = (await req.json()) as { text: string };
  await db.$transaction(async (tx) => {
    const note = await tx.note.findUniqueOrThrow({ where: { id } });
    await tx.note.update({ where: { id }, data: { body: note.body + text } });
  });
  return Response.json({ id });
});
