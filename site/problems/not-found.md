# Not found (404)

`https://rowstile.dev/problems/not-found` is the `type` of the problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457))
the SDKs answer with when a row isn't there, or whoever the transaction acts for can't see it. Both get the
same answer.

```json
{
  "type": "https://rowstile.dev/problems/not-found",
  "title": "Not Found",
  "status": 404,
  "detail": "app.files 11 not found"
}
```

Where it comes from: `NotFound.problem()` in both SDKs; `rowstile.fastapi` answers with it
([FastAPI](../../docs/stacks/fastapi.md)), and so do `route()` and `action()` in `@rowstile/next`
([Next.js](../../docs/stacks/nextjs.md)) and `problemOf(e)` for any other framework
([Node](../../docs/stacks/node.md)). A write the user may not make, on a row they can see, is
[Refused](refused.md) instead.
