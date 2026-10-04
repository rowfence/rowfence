import { useEffect, useState } from "react";
import { api, FileRow, FolderPage, size } from "./api";

/** A folder or file opened with a share link: read-only, no sign-in needed. */
export function LinkView({ kind, id, token, at }: { kind: "folder" | "file"; id: number; token: string; at: number | null }) {
  const [folder, setFolder] = useState<Omit<FolderPage, "perms"> | null>(null);
  const [file, setFile] = useState<FileRow | null>(null);
  const [error, setError] = useState("");
  const base = `#/link/${kind}/${id}/${token}`;
  useEffect(() => {
    setError("");
    if (kind === "file") api.publicFile(id, token).then(setFile, () => setError("This link doesn't work (anymore)."));
    else api.publicFolder(at ?? id, token).then(setFolder, () => setError("This link doesn't work (anymore)."));
  }, [kind, id, token, at]);
  const download = async (fileId: number) => {
    try { window.location.href = (await api.publicDownload(fileId, token)).url; }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  // the way from the shared folder down to where we are (the link reaches no higher)
  const path = folder ? folder.path.slice(folder.path.findIndex((p) => p.id === id)) : [];
  return (
    <div className="app">
      <header><span className="brand">Files</span><nav /><a href="#/">Sign in</a></header>
      <main>
        {error && <p className="error">{error}</p>}
        {file && <section className="narrow">
          <h2>📄 {file.name}</h2>
          <p className="hint">{size(file.size)}, shared with a link</p>
          <button onClick={() => download(file.id)}>Download</button>
        </section>}
        {folder && <section>
          <div className="crumbs">{path.map((p, i) => <span key={p.id}>{i > 0 && " / "}
            <a href={p.id === id ? base : `${base}/${p.id}`}>{p.name}</a></span>)}</div>
          <p className="hint">Shared with a link: you may look and download.</p>
          <table className="list"><tbody>
            {folder.folders.map((f) => <tr key={`d${f.id}`}><td className="name"><a href={`${base}/${f.id}`}>📁 {f.name}</a></td><td /></tr>)}
            {folder.files.map((f) => (
              <tr key={`f${f.id}`}>
                <td className="name"><button className="link" onClick={() => download(f.id)}>📄 {f.name}</button></td>
                <td className="size">{size(f.size)}</td>
              </tr>))}
            {folder.folders.length + folder.files.length === 0 && <tr><td className="hint">Empty.</td></tr>}
          </tbody></table>
        </section>}
      </main>
    </div>
  );
}
