-- 0001: the file manager's tables. Run by db/migrate.py as the database owner, in one transaction.
CREATE SCHEMA fm;

CREATE TABLE fm.users (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email      text NOT NULL UNIQUE CHECK (email = lower(email)),
  name       text NOT NULL,
  is_support boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now());
-- kept apart from users, whom everyone signed in may look up (to share with them)
CREATE TABLE fm.credentials (
  user_id       uuid PRIMARY KEY REFERENCES fm.users ON DELETE CASCADE,
  password_hash text NOT NULL);
CREATE TABLE fm.sessions (
  token_hash text PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES fm.users ON DELETE CASCADE,
  expires_at timestamptz NOT NULL);
CREATE INDEX ON fm.sessions (user_id);

CREATE TABLE fm.groups (
  id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name      text NOT NULL,
  parent_id uuid REFERENCES fm.groups);
CREATE TABLE fm.group_members (
  group_id uuid NOT NULL REFERENCES fm.groups ON DELETE CASCADE,
  user_id  uuid NOT NULL REFERENCES fm.users ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id));
CREATE INDEX ON fm.group_members (user_id);
CREATE INDEX ON fm.groups (parent_id);

CREATE TABLE fm.folders (
  id         bigserial PRIMARY KEY,
  parent_id  bigint REFERENCES fm.folders ON UPDATE CASCADE,   -- empty a folder before deleting it
  owner_id   uuid NOT NULL REFERENCES fm.users,
  name       text NOT NULL CHECK (name <> '' AND strpos(name, '/') = 0),
  inherit    boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (parent_id, name));
CREATE INDEX ON fm.folders (parent_id);
CREATE INDEX ON fm.folders (owner_id);

CREATE TABLE fm.files (
  id           bigserial PRIMARY KEY,
  folder_id    bigint NOT NULL REFERENCES fm.folders ON UPDATE CASCADE,
  owner_id     uuid NOT NULL REFERENCES fm.users,
  name         text NOT NULL CHECK (name <> '' AND strpos(name, '/') = 0),
  size         bigint NOT NULL DEFAULT 0,
  content_type text NOT NULL DEFAULT 'application/octet-stream',
  object_key   uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),   -- the object in the bucket
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (folder_id, name));
CREATE INDEX ON fm.files (owner_id);

-- the app's role: row-level security applies to it (db/policy.authz); it signs people in itself
GRANT USAGE ON SCHEMA fm TO fm_app;
GRANT SELECT ON fm.users, fm.groups, fm.group_members TO fm_app;
GRANT SELECT ON fm.credentials TO fm_app;
GRANT SELECT, INSERT, DELETE ON fm.sessions TO fm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON fm.folders, fm.files TO fm_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA fm TO fm_app;

-- creating an account: the app role may read accounts but not write them, except through this
CREATE FUNCTION fm.sign_up(p_email text, p_name text, p_password_hash text)
RETURNS TABLE (id uuid, email text, name text, is_support boolean)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH u AS (INSERT INTO fm.users (email, name) VALUES (lower(p_email), p_name) RETURNING *),
       c AS (INSERT INTO fm.credentials (user_id, password_hash) SELECT u.id, p_password_hash FROM u)
  SELECT u.id, u.email, u.name, u.is_support FROM u $$;
REVOKE ALL ON FUNCTION fm.sign_up(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fm.sign_up(text, text, text) TO fm_app;
