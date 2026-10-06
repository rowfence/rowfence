-- Archived and deleted rows (docs/cookbook/archived-and-deleted.md): documents that can be archived, and put
-- in the trash without being removed.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.documents (id bigserial PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, title text,
                            archived boolean NOT NULL DEFAULT false, deleted_at timestamptz);
CREATE INDEX ON app.documents (owner_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
GRANT INSERT, UPDATE ON app.documents TO app_user;   -- no DELETE: rows are marked, never removed
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user;
