-- Teams inside teams (docs/cookbook/teams-inside-teams.md): documents a team may read.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.teams (id bigint PRIMARY KEY, parent_id bigint REFERENCES app.teams, name text);
CREATE INDEX ON app.teams (parent_id);
CREATE TABLE app.team_members (team_id bigint NOT NULL REFERENCES app.teams ON DELETE CASCADE,
                               user_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE, PRIMARY KEY (team_id, user_id));
CREATE INDEX ON app.team_members (user_id);
CREATE TABLE app.documents (id bigserial PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, title text);
CREATE INDEX ON app.documents (owner_id);
CREATE TABLE app.document_teams (document_id bigint NOT NULL REFERENCES app.documents ON DELETE CASCADE,
                                 team_id bigint NOT NULL REFERENCES app.teams ON DELETE CASCADE, PRIMARY KEY (document_id, team_id));
CREATE INDEX ON app.document_teams (team_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
-- who is in a team, and which team reads what, are not the app role's to write: anyone could join anything
GRANT INSERT ON app.documents TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user;
