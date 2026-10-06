-- Tenants (docs/cookbook/tenants.md): tickets numbered per organisation.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.orgs (id bigint PRIMARY KEY, name text);
CREATE TABLE app.org_members (org_id bigint NOT NULL REFERENCES app.orgs ON DELETE CASCADE,
                              user_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE,
                              role text NOT NULL DEFAULT 'member', PRIMARY KEY (org_id, user_id));
CREATE INDEX ON app.org_members (user_id);
CREATE TABLE app.tickets (org_id bigint NOT NULL REFERENCES app.orgs, id bigint NOT NULL,
                          assignee_id bigint REFERENCES app.users, title text, PRIMARY KEY (org_id, id));
CREATE INDEX ON app.tickets (assignee_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
GRANT INSERT, UPDATE, DELETE ON app.tickets TO app_user;
