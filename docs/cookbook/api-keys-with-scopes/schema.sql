-- API keys with scopes (docs/cookbook/api-keys-with-scopes.md): notes in projects, and keys that do less than
-- their user.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.projects (id bigserial PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, name text NOT NULL);
CREATE INDEX ON app.projects (owner_id);
CREATE TABLE app.project_members (project_id bigint NOT NULL REFERENCES app.projects,
                                  user_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE, PRIMARY KEY (project_id, user_id));
CREATE INDEX ON app.project_members (user_id);
CREATE TABLE app.notes (id bigserial PRIMARY KEY, project_id bigint NOT NULL REFERENCES app.projects,
                        author_id bigint NOT NULL REFERENCES app.users, body text NOT NULL);
CREATE INDEX ON app.notes (project_id);
CREATE INDEX ON app.notes (author_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
GRANT INSERT, UPDATE, DELETE ON app.notes TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user;
