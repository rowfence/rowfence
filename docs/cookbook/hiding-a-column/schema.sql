-- Hiding a column (docs/cookbook/hiding-a-column.md): a staff directory; salaries are not for everyone.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.employees (id bigserial PRIMARY KEY, user_id bigint NOT NULL REFERENCES app.users,
                            manager_id bigint REFERENCES app.users, title text, salary numeric);
CREATE INDEX ON app.employees (user_id);
CREATE INDEX ON app.employees (manager_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
-- the whole table: applying the policy takes SELECT on the masked column back
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
