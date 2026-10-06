-- Roles per organisation (docs/cookbook/roles-per-organization.md): admins, members and guests, and roles the
-- admins make.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.orgs (id bigint PRIMARY KEY, name text);
CREATE TABLE app.org_members (org_id bigint NOT NULL REFERENCES app.orgs ON DELETE CASCADE,
                              user_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE,
                              role text NOT NULL DEFAULT 'member', PRIMARY KEY (org_id, user_id));
CREATE INDEX ON app.org_members (user_id);
CREATE TABLE app.documents (id bigserial PRIMARY KEY, org_id bigint NOT NULL REFERENCES app.orgs,
                            owner_id bigint NOT NULL REFERENCES app.users, title text);
CREATE INDEX ON app.documents (org_id);
CREATE INDEX ON app.documents (owner_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
GRANT INSERT, UPDATE, DELETE ON app.documents TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user;
