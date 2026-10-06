-- Support and emergency access (docs/cookbook/support-and-emergency-access.md): customers' notes, and the
-- support agents assigned to each customer.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.support_assignments (customer_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE,
                                      agent_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE,
                                      PRIMARY KEY (customer_id, agent_id));
CREATE INDEX ON app.support_assignments (agent_id);
CREATE TABLE app.notes (id bigserial PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, body text);
CREATE INDEX ON app.notes (owner_id);

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
