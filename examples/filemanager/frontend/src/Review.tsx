import { useEffect, useState } from "react";
import { api, ReviewItem } from "./api";
import { go } from "./route";

/** An access review: each share kept or revoked; closing it removes what was revoked. */
export function Review({ id }: { id: number }) {
  const [items, setItems] = useState<ReviewItem[] | null>(null);
  const [revokeUndecided, setRevokeUndecided] = useState(false);
  const [error, setError] = useState("");
  const load = () => api.review(id).then(setItems, (e) => setError(e.message));
  useEffect(() => { load(); }, [id]);
  const run = async (fn: () => Promise<unknown>) => {
    setError("");
    try { await fn(); await load(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  if (items === null) return <p className="hint">{error || "Loading..."}</p>;
  return (
    <section className="narrow">
      <h2>Access review #{id}</h2>
      <p className="hint">Keep or revoke each share. Closing the review removes the revoked ones.</p>
      <table className="list"><tbody>
        {items.length === 0 && <tr><td className="hint">Nothing was shared.</td></tr>}
        {items.map((i) => (
          <tr key={i.item}>
            <td>{i.subject_type === "group" ? "👥 " : ""}{i.subject_name ?? i.subject_id}</td>
            <td>{i.relation === "editor" ? "can edit" : "can view"}</td>
            <td className="actions">
              <button className={i.keep === true ? "on" : "link"} onClick={() => run(() => api.reviewDecide(id, i.item, true))}>Keep</button>
              <button className={i.keep === false ? "on danger" : "link"} onClick={() => run(() => api.reviewDecide(id, i.item, false))}>
                Revoke</button>
            </td>
          </tr>))}
      </tbody></table>
      <label className="check">
        <input type="checkbox" checked={revokeUndecided} onChange={(e) => setRevokeUndecided(e.target.checked)} />
        Also revoke the ones not decided</label>
      <div className="buttons">
        <button onClick={() => run(async () => {
          const r = await api.closeReview(id, revokeUndecided);
          alert(`Review closed: ${r.revoked} revoked.`);
          go("/");
        })}>Close the review</button>
      </div>
      {error && <p className="error">{error}</p>}
    </section>
  );
}
