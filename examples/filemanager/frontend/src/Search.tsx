import { useEffect, useState } from "react";
import { api, FileRow, Folder, size } from "./api";

/** Folders and files whose name contains the words, among those the user can see. */
export function Search({ q }: { q: string }) {
  const [result, setResult] = useState<{ folders: Folder[]; files: FileRow[] } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    setResult(null); setError("");
    api.search(q).then(setResult, (e) => setError(e.message));
  }, [q]);
  const download = async (id: number) => {
    try { window.location.href = (await api.downloadUrl(id)).url; } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  return (
    <section>
      <h2>Search: {q}</h2>
      {error && <p className="error">{error}</p>}
      {result === null ? !error && <p className="hint">Searching...</p> :
        result.folders.length + result.files.length === 0 ? <p className="empty">Nothing found.</p> :
        <table className="list"><tbody>
          {result.folders.map((f) => <tr key={`d${f.id}`}><td className="name"><a href={`#/folder/${f.id}`}>📁 {f.name}</a></td><td /></tr>)}
          {result.files.map((f) => (
            <tr key={`f${f.id}`}>
              <td className="name"><button className="link" onClick={() => download(f.id)}>📄 {f.name}</button>{" "}
                <a className="hint" href={`#/folder/${f.folder_id}`}>open its folder</a></td>
              <td className="size">{size(f.size)}</td>
            </tr>))}
        </tbody></table>}
    </section>
  );
}
