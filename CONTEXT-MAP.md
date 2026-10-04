# Context Map

## Contexts

- [rowstile](./core/CONTEXT.md): a policy language, its compiler (the `rowstile` command), and enforcement inside Postgres.
- File manager (`examples/filemanager/`): the first adopter. A standalone product for storing and sharing files (FastAPI backend, React frontend, RustFS object storage). Its glossary is created with its first term.
- Messenger (`examples/messenger/`): the second adopter, a WhatsApp-style app (chats, groups, invite links, blocking, bots) built to show what rowstile takes off an application. Same stack and same boundary as the file manager.

## Relationships

- **File manager, messenger → rowstile**: each is an ordinary user of rowstile. It writes its own policy file against its own tables, applies it from its migrations, and calls only the public surface (the `rowstile` command, the `authz` functions and settings, and the generated Python client). rowstile never names anything from the file manager.
- **Shared terms**: the file manager's folders and files are rowstile **objects**, its users and groups are **subjects**, and its sharing screens create **shares**. Use the rowstile words for those concepts in both contexts.
