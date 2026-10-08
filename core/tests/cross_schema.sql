-- cross_schema.sql: folders inside folders or projects, projects placed in folders by a table (or by sharing), and
-- the frozen folders a condition reads (tests/cross.authz, difftest --gen cross). No foreign keys from the
-- placements or the frozen folders: their rows may name what is gone.
DO $r$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
END $r$;
DROP SCHEMA IF EXISTS cx CASCADE;
CREATE SCHEMA cx;
CREATE TABLE cx.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE cx.folders (
  id bigserial PRIMARY KEY,
  parent_type text CHECK (parent_type IN ('folder', 'project')),
  parent_id bigint,
  owner_id bigint REFERENCES cx.users,
  archived boolean NOT NULL DEFAULT false
);
CREATE TABLE cx.projects (id bigserial PRIMARY KEY, lead_id bigint REFERENCES cx.users);
CREATE TABLE cx.placements (
  project_id bigint NOT NULL,
  folder_id bigint NOT NULL,
  active boolean NOT NULL DEFAULT true,
  PRIMARY KEY (project_id, folder_id)
);
CREATE TABLE cx.frozen (folder_id bigint PRIMARY KEY);
-- regions and sites, which hold each other through these tables only
CREATE TABLE cx.regions (id bigserial PRIMARY KEY, chief_id bigint REFERENCES cx.users);
CREATE TABLE cx.sites (id bigserial PRIMARY KEY);
CREATE TABLE cx.site_links (
  region_id bigint NOT NULL, site_id bigint NOT NULL, active boolean NOT NULL DEFAULT true,
  PRIMARY KEY (region_id, site_id)
);
CREATE TABLE cx.region_links (region_id bigint NOT NULL, parent_id bigint NOT NULL, PRIMARY KEY (region_id, parent_id));
CREATE TABLE cx.site_regions (
  site_id bigint NOT NULL, region_id bigint NOT NULL, active boolean NOT NULL DEFAULT true,
  PRIMARY KEY (site_id, region_id)
);
CREATE INDEX ON cx.folders (parent_type, parent_id);
CREATE INDEX ON cx.folders (owner_id);
CREATE INDEX ON cx.projects (lead_id);
CREATE INDEX ON cx.placements (folder_id);
GRANT USAGE ON SCHEMA cx TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA cx TO app_user;
GRANT INSERT, UPDATE, DELETE ON cx.folders, cx.projects TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA cx TO app_user;
