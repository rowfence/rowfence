-- composite_schema.sql: an app whose tables are keyed by (org_id, id), used by difftest.py
\set ON_ERROR_STOP on
SET client_min_messages = warning;
DROP SCHEMA IF EXISTS authz_gen, authz_int, authz, cx CASCADE;
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
END $$;
CREATE SCHEMA cx;
CREATE TABLE cx.users (id bigint PRIMARY KEY, manager_id bigint);
CREATE INDEX ON cx.users (manager_id);
CREATE TABLE cx.orgs (id bigint PRIMARY KEY);
CREATE TABLE cx.bots (id bigint PRIMARY KEY, owner_id bigint, active boolean NOT NULL DEFAULT true);
CREATE TABLE cx.org_admins (org_id bigint REFERENCES cx.orgs ON DELETE CASCADE, user_id bigint REFERENCES cx.users,
  PRIMARY KEY (org_id, user_id));
CREATE TABLE cx.teams (
  org_id      bigint,
  slug        text,                              -- spaces, commas and quotes: ids are quoted row text
  lead_id     bigint,
  parent_slug text,
  disbanded   boolean NOT NULL DEFAULT false,
  PRIMARY KEY (org_id, slug),
  -- link rows follow their team: renamed with it, gone with it (dangling links would still grant)
  FOREIGN KEY (org_id, parent_slug) REFERENCES cx.teams ON DELETE SET NULL (parent_slug) ON UPDATE CASCADE);
CREATE INDEX ON cx.teams (org_id, parent_slug);
CREATE TABLE cx.team_members (org_id bigint, team_slug text, user_id bigint, PRIMARY KEY (org_id, team_slug, user_id),
  FOREIGN KEY (org_id, team_slug) REFERENCES cx.teams ON DELETE CASCADE ON UPDATE CASCADE);
CREATE INDEX ON cx.team_members (user_id);
CREATE TABLE cx.team_bots (org_id bigint, team_slug text, bot_id bigint REFERENCES cx.bots ON DELETE CASCADE,
  PRIMARY KEY (org_id, team_slug, bot_id),
  FOREIGN KEY (org_id, team_slug) REFERENCES cx.teams ON DELETE CASCADE ON UPDATE CASCADE);
CREATE INDEX ON cx.team_bots (bot_id);
CREATE TABLE cx.projects (org_id bigint, id bigint, lead_id bigint, folder_id bigint, PRIMARY KEY (org_id, id));
CREATE INDEX ON cx.projects (org_id, folder_id);
CREATE TABLE cx.folders (
  org_id      bigint,
  id          bigint,
  owner_id    bigint,
  parent_type text,                              -- 'folder' or 'project'
  parent_id   bigint,
  PRIMARY KEY (org_id, id));
CREATE INDEX ON cx.folders (org_id, parent_id);
CREATE TABLE cx.folder_links (org_id bigint, child_id bigint, parent_id bigint, PRIMARY KEY (org_id, child_id, parent_id),
  FOREIGN KEY (org_id, child_id) REFERENCES cx.folders ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (org_id, parent_id) REFERENCES cx.folders ON DELETE CASCADE ON UPDATE CASCADE);
CREATE INDEX ON cx.folder_links (org_id, parent_id);
CREATE TABLE cx.folder_teams (org_id bigint, folder_id bigint, team_slug text, PRIMARY KEY (org_id, folder_id, team_slug),
  FOREIGN KEY (org_id, folder_id) REFERENCES cx.folders ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (org_id, team_slug) REFERENCES cx.teams ON DELETE CASCADE ON UPDATE CASCADE);
CREATE INDEX ON cx.folder_teams (org_id, team_slug);
CREATE TABLE cx.files (org_id bigint, id bigint, folder_id bigint, owner_id bigint, uploaded_by bigint,
  PRIMARY KEY (org_id, id));
CREATE INDEX ON cx.files (org_id, folder_id);
GRANT USAGE ON SCHEMA cx TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA cx TO app_user;
GRANT INSERT, UPDATE, DELETE ON cx.files, cx.folders TO app_user;
