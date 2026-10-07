# Identity

Three ways to say who is asking, all per transaction:

1. **A trusted backend** calls `SELECT authz.act_as('user', '42')`. Simple, but anything
   that runs as the app role can then claim to be anyone.
2. **API keys** that users create for themselves (`authz.create_api_key`). Only a
   SHA-256 hash is stored. A key can carry **scopes**: `read` (built in) or the
   policy's own (`scope files = ...`) limit which commands and permissions the
   transaction gets. A read-only session can't share, approve, or mint broader keys.
   Pass the key as a parameter (`SELECT authz.login_key($1)`, as the SDKs and the generated clients do), not
   written into the statement, or it ends up in the server's statement log; the same for a JWT.
   `authz.login_key(key)` works in read-only transactions too (a replica), and requests with
   the same key never wait for each other: when a key was last used (`last_used_at`) is kept to
   the minute, and not by read-only transactions.
3. **JWTs** from your identity provider: `authz.login_jwt(token)` checks an HS256
   signature, a required `exp` and optional `nbf`, and the issuer and the audience once the settings
   `jwt_issuer` and `jwt_audience` name them (a token that names none is then refused); a `scope` claim limits
   the transaction. The settings are rows of `authz.settings`, which the owner writes and the app role
   can't read:

   ```sql
   INSERT INTO authz.settings VALUES ('jwt_secret', '...'), ('jwt_issuer', 'https://id.example')
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
   ```

   `jwt_secret` is required: without it `login_jwt` signs nobody in. It is the secret your identity
   provider signs with, and HS256 asks for 32 random bytes or more (RFC 7518): a short one can be
   guessed from any token. The other settings: `jwt_audience`, `jwt_user_claim` (the claim that holds
   the user's id, `sub` by default) and `jwt_type_claim` (below).

What a scope leaves a key able to do can be said in the policy's tests: a line with `with scope read`
is checked as a key limited to that scope would be
([the language's tests](language.md), [API keys with scopes](../cookbook/api-keys-with-scopes.md)).

**Services** (principal types) sign in the same three ways. The backend names the type
(`SELECT authz.act_as('service', '7')`);
`authz.create_api_key('deploy', '', NULL, 'service', '7')` makes service 7 a key, for someone
holding `manage_keys` on it (`can manage_keys = owner`); a JWT names the type in the claim the
setting `jwt_type_claim` says. While a service is signed in, `authz.uid()` is NULL and
`authz.principal()` returns `('service', '7')`; the audit trail and `created_by` say `service:7`.
`authz.who` lists users.

**Whoever signs in is a row of their type.** An id the type's table doesn't have (a user deleted since, an id
the app made up) is nobody: `authz.uid()` is NULL and `authz.principal()` returns no row, as for a row that
fails the type's `where`. So a deleted user's leftover `owner_id` grants nothing, and an app inserts a new
user's row before it signs in as them.

**Every sign-in is signed**. `act_as` and the logins put an HMAC in `authz.session`, over
who is signed in, the scopes, the backend and the transaction, with a key the app role can't read. The
settings are believed only with it, so nothing but `act_as` and the logins can change who is signed
in, widen a key's scopes, or leave view-as, on any Postgres: setting `authz.user_id` is an error, and so is
a signature from another transaction or connection. A transaction in which nobody signed in gets an error
too, not an empty result (`act_as(NULL, NULL)` says "nobody" on purpose). Sessions of the policy's owner
and superusers are believed without a signature (psql, migrations, tests). `core/tests/sessions.sh` checks all
of it, on the stock Postgres image.

Who may call `act_as`: the app role and its members (the policy grants it), so a compromised app can still
choose users. Keep the app role's credentials in the backend.
