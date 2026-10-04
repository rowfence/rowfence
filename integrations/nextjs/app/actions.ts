"use server";
// A server action: a refusal comes back as { ok: false, problem } (Next.js hides a thrown error's message)
import { action } from "@rowfence/next";
import { db } from "@/db";

export const renameNote = action(async (id: number, body: string) => {
  await db.note.update({ where: { id }, data: { body } });
  return id;
});
