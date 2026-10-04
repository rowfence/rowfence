-- alt_schema.sql: a second app, used by difftest.py to cover other shapes of policy
\set ON_ERROR_STOP on
SET client_min_messages = warning;
DROP SCHEMA IF EXISTS authz_gen, authz_int, authz, alt CASCADE;
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
END $$;
CREATE SCHEMA alt;
CREATE TABLE alt.users (id bigint PRIMARY KEY);
CREATE TABLE alt.groups (gid bigint PRIMARY KEY, owner_id bigint REFERENCES alt.users);
CREATE TABLE alt.group_members (
  group_id bigint REFERENCES alt.groups ON DELETE CASCADE,
  user_id  bigint REFERENCES alt.users,
  active   boolean NOT NULL DEFAULT true,
  PRIMARY KEY (group_id, user_id));
CREATE TABLE alt.projects (id bigint PRIMARY KEY, lead_id bigint REFERENCES alt.users);
CREATE TABLE alt.project_groups (
  project_id bigint REFERENCES alt.projects ON DELETE CASCADE,
  group_id   bigint REFERENCES alt.groups ON DELETE CASCADE,
  PRIMARY KEY (project_id, group_id));
CREATE TABLE alt.docs (                         -- the key is not called id
  doc_no     bigint PRIMARY KEY,
  owner_id   bigint REFERENCES alt.users,
  blocked_id bigint REFERENCES alt.users,       -- often NULL
  up         bigint REFERENCES alt.docs ON UPDATE CASCADE,
  project_id bigint REFERENCES alt.projects,
  locked     boolean NOT NULL DEFAULT false,
  created    timestamptz NOT NULL DEFAULT now());
CREATE INDEX ON alt.docs (up);
CREATE TABLE alt.doc_links (
  child  bigint REFERENCES alt.docs ON DELETE CASCADE ON UPDATE CASCADE,
  parent bigint REFERENCES alt.docs ON DELETE CASCADE ON UPDATE CASCADE,
  PRIMARY KEY (child, parent));
CREATE TABLE alt.doc_projects (
  doc_no  bigint REFERENCES alt.docs ON DELETE CASCADE ON UPDATE CASCADE,
  proj_id bigint REFERENCES alt.projects ON DELETE CASCADE,
  PRIMARY KEY (doc_no, proj_id));
CREATE TABLE alt.holds (target bigint PRIMARY KEY);   -- docs under legal hold
GRANT USAGE ON SCHEMA alt TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA alt TO app_user;
GRANT INSERT, UPDATE, DELETE ON alt.docs TO app_user;
