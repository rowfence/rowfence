// A signed-in page: the notes the request's user may see. No checks here: the database filters the rows.
import { db } from "@/db";

export default async function Notes() {
  const notes = await db.note.findMany({ select: { id: true, body: true }, orderBy: { id: "asc" } });
  return (
    <ul id="notes">
      {notes.map((n) => <li key={n.id} data-note={n.id}>{n.body}</li>)}
    </ul>
  );
}
