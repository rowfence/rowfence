// @vitest-environment jsdom
// The React kit against the running app's routes (authzRoutes): a list's buttons in one call, <Can>, the
// headless share dialog, access requests, and the change feed that keeps them current.
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test } from "vitest";
import { AuthzProvider, Can, ShareDialog, useAccessRequest, usePerms } from "@rowstile/react";
import { SERVER, as, seed } from "./data";

beforeEach(seed);
afterEach(cleanup);

const nodeFetch = globalThis.fetch;
const asUser = (user: string): typeof fetch => (input, init) =>
  nodeFetch(String(input).startsWith("http") ? input : `${SERVER}${input}`, as(user, init as RequestInit));

function Buttons() {
  const perms = usePerms("project", [1, 2, 3]);
  if (perms.loading) return <p>loading</p>;
  return <ul>{[1, 2, 3].map((id) => <li key={id}>{id}:{perms(id).perms.join(",")}{perms(id).can("edit") && " [rename]"}</li>)}</ul>;
}

test("usePerms: one call for a list; <Can>", async () => {
  render(
    <AuthzProvider fetch={asUser("3")} live={false}>
      <Buttons />
      <Can type="project" id={1} perm="edit" fallback={<span>no edit on 1</span>}><span>edit on 1</span></Can>
      <Can type="project" id={3} perm="edit" fallback={<span>no edit on 3</span>}><span>edit on 3</span></Can>
    </AuthzProvider>,
  );
  await waitFor(() => expect(screen.getByText("1:edit,view [rename]")).toBeTruthy());
  expect(screen.getByText("2:")).toBeTruthy();                   // bo's project: cy may not see it
  expect(screen.getByText("3:view")).toBeTruthy();
  await waitFor(() => expect(screen.getByText("edit on 1")).toBeTruthy());
  expect(screen.getByText("no edit on 3")).toBeTruthy();
});

test("ShareDialog: share and unshare, as the database allows", async () => {
  let dialog: Parameters<Parameters<typeof ShareDialog>[0]["children"]>[0] | undefined;
  render(
    <AuthzProvider fetch={asUser("1")} live={false}>
      <ShareDialog type="project" id={1}>
        {(d) => {
          dialog = d;
          if (d.error) return <p>{d.error.message}</p>;
          return <p>{d.loading ? "loading" : `shared with ${d.shares.map((s) => s.subject_id).join(",") || "nobody"}`}</p>;
        }}
      </ShareDialog>
    </AuthzProvider>,
  );
  await waitFor(() => expect(screen.getByText("shared with nobody")).toBeTruthy());
  await act(() => dialog!.share("viewer", "user", 2));
  await waitFor(() => expect(screen.getByText("shared with 2")).toBeTruthy());
  expect(await (await nodeFetch(`${SERVER}/api/projects`, as("2"))).json()).toEqual([1, 2, 3]);
  await act(() => dialog!.unshare("viewer", "user", 2));
  await waitFor(() => expect(screen.getByText("shared with nobody")).toBeTruthy());
  expect(await (await nodeFetch(`${SERVER}/api/projects`, as("2"))).json()).toEqual([2, 3]);
});

test("ShareDialog: a user who may not share is refused, with the reason", async () => {
  let dialog: Parameters<Parameters<typeof ShareDialog>[0]["children"]>[0] | undefined;
  render(
    <AuthzProvider fetch={asUser("2")} live={false}>
      <ShareDialog type="project" id={3}>{(d) => { dialog = d; return <p>{d.loading ? "loading" : "ready"}</p>; }}</ShareDialog>
    </AuthzProvider>,
  );
  await waitFor(() => expect(screen.getByText("ready")).toBeTruthy());
  const e = await dialog!.share("viewer", "user", 2).catch((err) => err);
  expect(e.problem?.status).toBe(403);
});

// the answers are the signed-in user's: when the provider's user changes, the hooks ask again, and the
// earlier user's answers are not shown meanwhile
test("usePerms: another user, without a page load", async () => {
  let who = "3";
  const asWho: typeof fetch = (input, init) => asUser(who)(input, init);
  const page = (user: string) => (
    <AuthzProvider fetch={asWho} live={false} user={user}>
      <Can type="project" id={1} perm="edit" fallback={<span>no edit on 1</span>}><span>edit on 1</span></Can>
    </AuthzProvider>);
  const { rerender } = render(page("3"));
  await waitFor(() => expect(screen.getByText("edit on 1")).toBeTruthy());
  who = "2";
  rerender(page("2"));
  expect(screen.getByText("no edit on 1")).toBeTruthy();          // at once: cy's answer is forgotten
  await new Promise((r) => setTimeout(r, 300));
  expect(screen.getByText("no edit on 1")).toBeTruthy();
});

function Many() {
  const ids = Array.from({ length: 400 }, (_, i) => i + 1);
  const perms = usePerms("project", ids);
  return <p>{perms.loading ? "loading" : perms.error ? `failed: ${perms.error.message}` : `1:${perms(1).perms.join(",")} 400:${perms(400).perms.join(",")}`}</p>;
}

test("usePerms: a long list of ids", async () => {
  const posted: string[] = [];
  const counting: typeof fetch = (input, init) => {
    posted.push(`${init?.method ?? "GET"} ${String(input).split("?")[0]}`);
    return asUser("3")(input, init);
  };
  render(<AuthzProvider fetch={counting} live={false}><Many /></AuthzProvider>);
  await waitFor(() => expect(screen.getByText("1:edit,view 400:")).toBeTruthy());
  expect(posted).toEqual(["POST /api/authz/perms"]);
});

function Ask() {
  const r = useAccessRequest("project", 2);
  return <button onClick={() => r.request("viewer", "for the review").catch(() => undefined)}>{r.status}</button>;
}

test("useAccessRequest: asking for access", async () => {
  render(<AuthzProvider fetch={asUser("3")} live={false}><Ask /></AuthzProvider>);
  await act(async () => screen.getByText("idle").click());
  await waitFor(() => expect(screen.getByText("sent")).toBeTruthy());
});

test("live updates: the change feed says when access may have changed", async () => {
  const controller = new AbortController();
  const events = await nodeFetch(`${SERVER}/api/authz/events`, as("2", { signal: controller.signal }));
  expect(events.headers.get("content-type")).toContain("text/event-stream");
  const reader = events.body!.getReader();
  const seen: string[] = [];
  const reading = (async () => {
    const decoder = new TextDecoder();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      seen.push(decoder.decode(value));
      if (seen.join("").includes("event: changed")) return;
    }
  })();
  await new Promise((r) => setTimeout(r, 300));                 // the server is listening
  const share = await nodeFetch(`${SERVER}/api/authz/share`, as("1", {
    method: "POST", body: JSON.stringify({ type: "project", id: "1", relation: "viewer", subjectType: "user", subjectId: "2" }),
  }));
  expect(share.status).toBe(200);
  await Promise.race([reading, new Promise((_, no) => setTimeout(() => no(new Error("no change event: " + seen.join(""))), 10_000))]);
  expect(seen.join("")).toContain("event: changed");
  controller.abort();
});
