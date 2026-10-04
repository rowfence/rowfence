# Refused (403)

`https://rowfence.dev/problems/refused` is the `type` of the problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457))
the SDKs answer with when the database refused a write: a rule stopped an insert, an update or a delete, and
rowfence said which rule and why.

```json
{
  "type": "https://rowfence.dev/problems/refused",
  "title": "Forbidden",
  "status": 403,
  "detail": "the database's message",
  "table": "app.files",
  "command": "update",
  "why": ["the lines of the explanation"],
  "code": "AZ709"
}
```

- `table` and `command`: the rule that refused it (`null` when the database didn't say).
- `why`: the reason, as the database explained it.
- `code`: [AZ709](../../docs/errors/AZ709.md), a write refused by a rule.

Where it comes from: `Refused.problem()` in both SDKs; `rowfence.fastapi` answers with it
([FastAPI](../../docs/stacks/fastapi.md)), and so do `route()` and `action()` in `@rowfence/next`
([Next.js](../../docs/stacks/nextjs.md)) and `problemOf(e)` for any other framework
([Node](../../docs/stacks/node.md)).
