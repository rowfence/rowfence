-- Sharing like Google Docs (docs/cookbook/google-docs-sharing.md): private, shared with people, by link, public.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.documents (id bigserial PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, title text,
                            visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'public')));
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
