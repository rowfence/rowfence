-- loop_schema.sql: tables whose foreign keys go round (tests/loop.authz, difftest --gen loop): an org's settings
-- name an email address, its domain names an org. Only orgs have owners; inheritance goes round the loop.
DO $r$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
END $r$;
DROP SCHEMA IF EXISTS lp CASCADE;
CREATE SCHEMA lp;
CREATE TABLE lp.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE lp.orgs (id bigserial PRIMARY KEY, owner_id bigint REFERENCES lp.users, settings_id bigint);
CREATE TABLE lp.settings (id bigserial PRIMARY KEY, email_id bigint);
CREATE TABLE lp.emails (id bigserial PRIMARY KEY, domain_id bigint, verified boolean NOT NULL DEFAULT true);
CREATE TABLE lp.domains (id bigserial PRIMARY KEY, org_id bigint REFERENCES lp.orgs ON DELETE SET NULL);
ALTER TABLE lp.orgs ADD FOREIGN KEY (settings_id) REFERENCES lp.settings ON DELETE SET NULL;
ALTER TABLE lp.settings ADD FOREIGN KEY (email_id) REFERENCES lp.emails ON DELETE SET NULL;
ALTER TABLE lp.emails ADD FOREIGN KEY (domain_id) REFERENCES lp.domains ON DELETE SET NULL;
CREATE INDEX ON lp.orgs (owner_id);
CREATE INDEX ON lp.orgs (settings_id);
CREATE INDEX ON lp.settings (email_id);
CREATE INDEX ON lp.emails (domain_id);
CREATE INDEX ON lp.domains (org_id);
GRANT USAGE ON SCHEMA lp TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA lp TO app_user;
GRANT INSERT, UPDATE, DELETE ON lp.orgs, lp.settings, lp.emails, lp.domains TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA lp TO app_user;
