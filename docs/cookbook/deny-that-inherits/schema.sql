-- A deny that inherits (docs/cookbook/deny-that-inherits.md): wiki pages; a hidden page hides what is below it.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.pages (id bigserial PRIMARY KEY, parent_id bigint REFERENCES app.pages, title text,
                        hidden boolean NOT NULL DEFAULT false);
CREATE INDEX ON app.pages (parent_id);
CREATE TABLE app.page_readers (page_id bigint NOT NULL REFERENCES app.pages ON DELETE CASCADE,
                               user_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE, PRIMARY KEY (page_id, user_id));
CREATE INDEX ON app.page_readers (user_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
