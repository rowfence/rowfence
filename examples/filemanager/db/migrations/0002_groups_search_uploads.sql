-- 0002: groups managed in the app, search by name, and uploads straight from the browser to RustFS.

-- groups: whoever creates one owns it; owners and admins manage its members and sub-groups
ALTER TABLE fm.groups ADD COLUMN owner_id uuid REFERENCES fm.users;
ALTER TABLE fm.group_members ADD COLUMN id bigserial UNIQUE, ADD COLUMN is_admin boolean NOT NULL DEFAULT false;
GRANT INSERT, UPDATE, DELETE ON fm.groups, fm.group_members TO fm_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA fm TO fm_app;

-- search: names containing what was typed
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX files_name_trgm ON fm.files USING gin (name gin_trgm_ops);
CREATE INDEX folders_name_trgm ON fm.folders USING gin (name gin_trgm_ops);

-- a file uploaded straight to RustFS exists as a row first, ready once the bytes are there
ALTER TABLE fm.files ADD COLUMN ready boolean NOT NULL DEFAULT true;
