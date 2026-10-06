-- Owner only (docs/cookbook/owner-only.md): notes, each belonging to one person.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.notes (id bigserial PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, body text);
CREATE INDEX ON app.notes (owner_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON app.users TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.notes TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user;
