-- A multi-tenant app (docs/cookbook/multi-tenant-app.md): organisations, their workspaces, the projects in them.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.orgs (id bigint PRIMARY KEY, name text);
CREATE TABLE app.org_members (org_id bigint NOT NULL REFERENCES app.orgs ON DELETE CASCADE,
                              user_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE,
                              role text NOT NULL DEFAULT 'member', PRIMARY KEY (org_id, user_id));
CREATE INDEX ON app.org_members (user_id);
CREATE TABLE app.workspaces (id bigserial PRIMARY KEY, org_id bigint NOT NULL REFERENCES app.orgs, name text);
CREATE INDEX ON app.workspaces (org_id);
CREATE TABLE app.workspace_members (workspace_id bigint NOT NULL REFERENCES app.workspaces ON DELETE CASCADE,
                                    user_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE,
                                    PRIMARY KEY (workspace_id, user_id));
CREATE INDEX ON app.workspace_members (user_id);
CREATE TABLE app.projects (id bigserial PRIMARY KEY, workspace_id bigint NOT NULL REFERENCES app.workspaces, name text);
CREATE INDEX ON app.projects (workspace_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
-- who is in an organisation or a workspace is not the app role's to write
GRANT INSERT, UPDATE, DELETE ON app.workspaces, app.projects TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user;
