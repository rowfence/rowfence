-- Folders that inherit (docs/cookbook/folders-that-inherit.md): folders inside folders.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.folders (id bigserial PRIMARY KEY, parent_id bigint REFERENCES app.folders,
                          owner_id bigint REFERENCES app.users, name text, inherit boolean NOT NULL DEFAULT true);
CREATE INDEX ON app.folders (parent_id);
CREATE INDEX ON app.folders (owner_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON app.users TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.folders TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user;
