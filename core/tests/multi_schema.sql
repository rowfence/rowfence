-- multi_schema.sql: a third app for difftest.py: UUID keys, suspended users and
-- orgs, archived folders, folders and projects nested in each other, documents
-- that live in either.
\set ON_ERROR_STOP on
SET client_min_messages = warning;
DROP SCHEMA IF EXISTS authz_gen, authz_int, authz, mt CASCADE;
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
END $$;
CREATE SCHEMA mt;
CREATE TABLE mt.users (id uuid PRIMARY KEY, active boolean NOT NULL DEFAULT true);
CREATE TABLE mt.orgs (id bigint PRIMARY KEY, suspended boolean NOT NULL DEFAULT false);
CREATE TABLE mt.org_members (
  org_id  bigint REFERENCES mt.orgs ON DELETE CASCADE,
  user_id uuid   REFERENCES mt.users ON DELETE CASCADE,
  role    text   NOT NULL DEFAULT 'member',
  PRIMARY KEY (org_id, user_id));
CREATE TABLE mt.teams (id bigint PRIMARY KEY);
CREATE TABLE mt.team_members (
  team_id bigint REFERENCES mt.teams ON DELETE CASCADE,
  user_id uuid   REFERENCES mt.users ON DELETE CASCADE,
  PRIMARY KEY (team_id, user_id));
CREATE TABLE mt.folders (
  id          bigint PRIMARY KEY,
  parent_type text,                 -- 'folder' or 'project'
  parent_id   bigint,
  owner_id    uuid REFERENCES mt.users ON DELETE SET NULL,
  locked      boolean NOT NULL DEFAULT false,
  archived    boolean NOT NULL DEFAULT false,
  org_id      bigint);                -- whose custom roles count on it
CREATE INDEX ON mt.folders (parent_id);
CREATE TABLE mt.projects (
  id        bigint PRIMARY KEY,
  org_id    bigint REFERENCES mt.orgs,
  folder_id bigint REFERENCES mt.folders ON DELETE SET NULL,
  lead_id   uuid REFERENCES mt.users ON DELETE SET NULL);
CREATE INDEX ON mt.projects (folder_id);
CREATE TABLE mt.docs (
  id             uuid PRIMARY KEY,
  container_type text NOT NULL,     -- 'folder' or 'project'
  container_id   bigint NOT NULL,
  author_id      uuid REFERENCES mt.users ON DELETE SET NULL,
  body           text NOT NULL DEFAULT 'the text');
GRANT USAGE ON SCHEMA mt TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA mt TO app_user;
GRANT INSERT, UPDATE, DELETE ON mt.docs TO app_user;
