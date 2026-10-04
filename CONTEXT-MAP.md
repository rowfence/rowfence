# Context Map

## Contexts

- [rowfence](./core/CONTEXT.md): a policy language, its compiler (the `rowfence` command), and enforcement inside Postgres.
- File manager (`examples/filemanager/`): the first adopter. A standalone product for storing and sharing files (FastAPI backend, React frontend, RustFS object storage). Its glossary is created with its first term.
- Messenger (`examples/messenger/`): the second adopter, a WhatsApp-style app (chats, groups, invite links, blocking, bots) built to show what rowfence takes off an application. Same stack and same boundary as the file manager.

## Relationships

- **File manager, messenger → rowfence**: each is an ordinary user of rowfence. It writes its own policy file against its own tables, applies it from its migrations, and calls only the public surface (the `rowfence` command, the `authz` functions and settings, and the generated Python client). rowfence never names anything from the file manager.
- **Shared terms**: the file manager's folders and files are rowfence **objects**, its users and groups are **subjects**, and its sharing screens create **shares**. Use the rowfence words for those concepts in both contexts.
