// @rowstile/next in this process, each way it can go: the servers test.sh starts run it too (conformance.test.ts),
// but what runs there isn't measured. Next's connection() is the test's own here: it answers as Next does inside a
// request, inside a cache, outside a request and inside after().
import pg from "pg";
import { afterAll, beforeEach, describe, expect, test, vi } from "vitest";
import { actingAs, NotFound, NotSignedIn, principal, Refused } from "@rowstile/client";
import { authz as rowstile } from "@rowstile/pg";
import { action, authzRoutes, checkAtStart, keepOutOfCaches, route } from "@rowstile/next";
import { db, pool } from "@/db";
import { APP, OWNER, seed } from "./data";

const { connection } = vi.hoisted(() => ({ connection: vi.fn(async (): Promise<void> => undefined) }));
vi.mock("next/server.js", () => ({ connection }));

beforeEach(async () => {
  connection.mockReset();
  connection.mockResolvedValue(undefined);
  await seed();
});
afterAll(async () => {
  await pool.end();
  await db.$disconnect();
});

const IN_CACHE = 'Route /notes used `connection()` inside "use cache". Accessing Dynamic data sources inside a cache scope is not supported.';

describe("signed-in reads are kept out of caches", () => {
  test("Next is asked for a dynamic render before a sign-in; nobody's reads may be cached", async () => {
    await keepOutOfCaches(principal(null));
    expect(connection).not.toHaveBeenCalled();
    await keepOutOfCaches(principal(1));                                      // inside a request: a dynamic render
    expect(connection).toHaveBeenCalledTimes(1);
    connection.mockRejectedValueOnce(new Error("`connection` was called outside a request scope."));
    await keepOutOfCaches(principal(1));                                      // a script, a worker: no render
    connection.mockRejectedValueOnce(new Error("Route /x used `connection()` inside `after()`."));
    await keepOutOfCaches(principal(1));                                      // after the response: no render
    connection.mockRejectedValueOnce(new Error(IN_CACHE));
    await expect(keepOutOfCaches(principal(1))).rejects.toThrow('inside "use cache"');
    connection.mockRejectedValueOnce("not an Error");
    await expect(keepOutOfCaches(principal(1))).rejects.toBe("not an Error");
  });

  test("inside a cache, a transaction signed in as someone fails instead of reading", async () => {
    const p = new pg.Pool({ connectionString: APP });
    try {
      connection.mockRejectedValue(new Error(IN_CACHE));
      const read = (who: string | null) => actingAs(who, () => rowstile(p).query("SELECT id FROM app.projects ORDER BY id"));
      await expect(read("1")).rejects.toThrow('inside "use cache"');
      expect((await read(null)).rows.map((r) => r.id)).toEqual([3]);       // the same for everyone: it may be cached
    } finally {
      await p.end();
    }
  });
});

test("checkAtStart: the server stops on a connection that skips row-level security, with why", async () => {
  const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
  const said = vi.spyOn(console, "error").mockImplementation(() => undefined);
  const owner = new pg.Pool({ connectionString: OWNER });
  try {
    await checkAtStart(rowstile(owner));
    expect(exit).toHaveBeenCalledWith(1);
    expect(said.mock.calls[0][0]).toMatch(/^rowstile: the app's database connection can't be used with rowstile: .*owners skip row-level security/);
    await checkAtStart({ check: async () => { throw "the database is down"; } });   // not an Error: said as it is
    expect(said.mock.calls[1][0]).toBe("rowstile: the database is down");
    exit.mockClear();
    await checkAtStart(db.$authz);                                           // the app's role: it starts
    expect(exit).not.toHaveBeenCalled();
  } finally {
    exit.mockRestore();
    said.mockRestore();
    await owner.end();
  }
});

describe("route handlers and server actions", () => {
  const rename = async (id: number) => {
    await db.note.update({ where: { id }, data: { body: "renamed" } });
    return id;
  };
  const notSignedIn = Object.assign(new Error("nobody signed in in this transaction"), { code: "28000" });

  test("route: a refusal is 403 with the reason, a hidden row 404; other errors are thrown", async () => {
    const PATCH = route(async (req: Request) => Response.json({ id: await rename(Number(new URL(req.url).searchParams.get("id"))) }));
    const patch = (who: string, id: number) => actingAs(who, () => PATCH(new Request(`http://app.test/notes?id=${id}`, { method: "PATCH" })));
    const refused = await patch("3", 1);
    expect([refused.status, refused.headers.get("content-type")]).toEqual([403, "application/problem+json"]);
    expect(await refused.json()).toMatchObject({ detail: "permission denied: user 3 may not update row 1 of app.notes", command: "update" });
    expect((await patch("2", 1)).status).toBe(404);
    expect((await patch("3", 4)).status).toBe(200);
    await expect(route(async () => { throw new Error("the app's"); })()).rejects.toThrow("the app's");
    await expect(route(async () => { throw notSignedIn; })()).rejects.toBeInstanceOf(NotSignedIn);
  });

  test("action: { ok, value } or the problem; other errors are thrown", async () => {
    const act = action(rename);
    expect(await actingAs("3", () => act(4))).toEqual({ ok: true, value: 4 });
    const refused = await actingAs("3", () => act(1));
    expect(!refused.ok && [refused.problem.status, refused.problem.command]).toEqual([403, "update"]);
    const hidden = await actingAs("2", () => act(1));
    expect(!hidden.ok && hidden.problem.status).toBe(404);
    await expect(action(async () => { throw new Error("the app's"); })()).rejects.toThrow("the app's");
    await expect(action(async () => { throw notSignedIn; })()).rejects.toBeInstanceOf(NotSignedIn);
  });

  // 16: what the call names isn't there (AZ708) is 404, a missing or wrong argument (AZ710) 400, each with the
  // database's words, as their pages say
  const calls = {
    // a share with someone who doesn't exist (Prisma's adapter keeps no hint for its SQLSTATE: the SDK says it)
    nobody: () => db.$authz.share("project", 1, "viewer", "user", 99),
    // an API key of ann's that isn't there: a refusal's SQLSTATE (42501), but no refusal
    noKey: () => db.$queryRaw`SELECT 1 AS ok FROM authz.revoke_api_key(${987654}::bigint)`,
    negative: () => db.$authz.list("project", "view", { limit: -1 }),
  };
  const notThere = (detail: string) =>
    ({ type: "https://rowstile.dev/problems/not-found", title: "Not Found", status: 404, detail, code: "AZ708" });
  const expected = {
    nobody: notThere("there is no user 99"),
    noKey: notThere("no API key 987654 of yours"),
    negative: { type: "https://rowstile.dev/problems/bad-argument", title: "Bad Request", status: 400,
                detail: "the page size must not be negative (got -1)", code: "AZ710" },
  };

  test("16: route: not there is 404, a wrong argument 400, with the database's words", async () => {
    for (const [name, call] of Object.entries(calls)) {
      const r = await actingAs("1", () => route(async () => { await call(); return new Response(null, { status: 204 }); })());
      expect([r.status, r.headers.get("content-type"), await r.json()], name)
        .toEqual([expected[name as keyof typeof calls].status, "application/problem+json", expected[name as keyof typeof calls]]);
    }
  });

  test("16: action: not there and a wrong argument come back as their problems", async () => {
    for (const [name, call] of Object.entries(calls)) {
      expect(await actingAs("1", () => action(call)()), name).toEqual({ ok: false, problem: expected[name as keyof typeof calls] });
    }
  });
});

describe("authzRoutes, for @rowstile/react", () => {
  const { GET, POST } = authzRoutes({ calls: db.$authz });
  const get = (who: string, path: string) => actingAs(who, () => GET(new Request(`http://app.test/api/authz/${path}`)));
  // (bytes, for a request with no content type at all: a string body is text/plain)
  const post = (who: string, path: string, body: object, type: string | null = "application/json") =>
    actingAs(who, () => POST(new Request(`http://app.test/api/authz/${path}`, {
      method: "POST", body: new TextEncoder().encode(JSON.stringify(body)), headers: type ? { "content-type": type } : {},
    })));

  test("GET: a list's permissions, the shares, and nothing else", async () => {
    expect(await (await get("3", "perms?type=project&ids=1&ids=3")).json()).toEqual({ "1": ["edit", "view"], "3": ["view"] });
    expect(await (await get("3", "perms")).json()).toEqual({});                       // no type, no ids
    expect(await (await get("1", "shares?type=project&id=1")).json()).toEqual([]);
    const noId = await get("1", "shares?type=project");
    expect([noId.status, (await noId.json()).code]).toEqual([403, "AZ705"]);      // a share of no object: none to see
    const unknown = await get("1", "nothing");
    expect([unknown.status, await unknown.json()]).toEqual([404, { title: "Not Found", status: 404 }]);
    expect((await actingAs("1", () => GET(new Request("http://app.test/")))).status).toBe(404);   // no route's name at all
    const events = await get("1", "events");                                    // no change feed given
    expect([events.status, (await events.json()).detail]).toEqual([404, "no change feed: authzRoutes({ changes })"]);
  });

  test("POST: JSON only; a long list, a share and its end, an access request", async () => {
    const form = await post("1", "share", { type: "project", id: "1" }, "application/x-www-form-urlencoded");
    expect(form.status).toBe(415);
    expect((await post("1", "share", { type: "project", id: "1" }, null)).status).toBe(415);   // no type at all
    expect(await (await post("3", "perms", { type: "project", ids: [1, 3] })).json()).toEqual({ "1": ["edit", "view"], "3": ["view"] });
    expect(await (await post("3", "perms", { type: "project", ids: "1" })).json()).toEqual({});   // not a list
    const share = { type: "project", id: "1", relation: "viewer", subjectType: "user", subjectId: "2" };
    expect(await (await post("1", "share", share)).json()).toEqual({ ok: true });
    expect((await (await get("1", "shares?type=project&id=1")).json()).map((s: { subject_id: string }) => s.subject_id)).toEqual(["2"]);
    expect(await (await post("1", "unshare", share)).json()).toEqual({ ok: true });
    const asked = await (await post("3", "request", { type: "project", id: "2", relation: "viewer", reason: "the review" })).json();
    expect(asked.id).toMatch(/^\d+$/);
    // a request without a reason: the database says what is missing (AZ710), which is the user's to fix: 400
    const why = await post("2", "request", { type: "project", id: "1", relation: "viewer" });
    expect([why.status, why.headers.get("content-type"), await why.json()]).toEqual([400, "application/problem+json", {
      type: "https://rowstile.dev/problems/bad-argument", title: "Bad Request", status: 400, detail: "say why you need it",
      code: "AZ710",
    }]);
    // 16: a share with someone who isn't there: 404, in the database's words
    const nobody = await post("1", "share", { ...share, subjectId: "99" });
    expect([nobody.status, await nobody.json()]).toEqual([404, {
      type: "https://rowstile.dev/problems/not-found", title: "Not Found", status: 404, detail: "there is no user 99",
      code: "AZ708",
    }]);
    // a share the policy doesn't declare (AZ706) is the app's mistake, not the user's: it stays an error
    await expect(post("1", "share", { ...share, relation: "member" })).rejects.toThrow("does not allow sharing project.member");
    expect((await post("1", "nothing", {})).status).toBe(404);
  });

  test("events: told of each change, pinged, and listening ends once when the page goes", async () => {
    vi.useFakeTimers();
    let listening = 0;
    let notify = () => {};
    const { GET: events } = authzRoutes({
      calls: db.$authz,
      changes: (onChange) => { listening += 1; notify = onChange; return () => { listening -= 1; }; },
    });
    try {
      const page = new AbortController();
      const response = await events(new Request("http://app.test/api/authz/events", { signal: page.signal }));
      expect(listening).toBe(1);                                                 // (as many as 1000 by default)
      const reader = response.body!.getReader();
      const text = async () => new TextDecoder().decode((await reader.read()).value);
      expect(await text()).toBe(": connected\n\n");
      notify();
      expect(await text()).toBe("event: changed\ndata: {}\n\n");
      vi.advanceTimersByTime(25_000);
      expect(await text()).toBe(": ping\n\n");
      await reader.cancel();                                                     // the page went: the stream is cancelled,
      expect(listening).toBe(0);
      page.abort();                                                              // and the request aborted
      notify();                                                                  // a feed that tells all the same
      vi.advanceTimersByTime(25_000);
      expect(listening).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

test("NotFound and Refused from a route keep what Prisma raised", async () => {
  const hidden = await actingAs("2", () => db.note.update({ where: { id: 1 }, data: { body: "x" } })).catch((e) => e);
  expect([hidden instanceof NotFound, (hidden as { cause?: { code?: string } }).cause?.code]).toEqual([true, "P2025"]);
  const refused = await actingAs("3", () => db.note.update({ where: { id: 1 }, data: { body: "x" } })).catch((e) => e);
  expect([refused instanceof Refused, (refused as { cause?: { code?: string } }).cause?.code]).toEqual([true, "P2025"]);
});
