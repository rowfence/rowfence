// Sharing from the app's own code: the database decides who may (the relation's "shared by"), and a refusal is 403
import { route } from "@rowstile/next";
import { db } from "@/db";

type Params = { params: Promise<{ id: string }> };

export const POST = route(async (req: Request, { params }: Params) => {
  const { user } = (await req.json()) as { user: number };
  await db.$authz.share("project", Number((await params).id), "viewer", "user", user);
  return new Response(null, { status: 204 });
});
