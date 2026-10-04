-- 0003: share links. rowfence keeps only a hash of each link's token (the token is shown once); the app
-- remembers which links exist, to list and revoke them.
CREATE TABLE fm.share_links (
  id          bigserial PRIMARY KEY,
  kind        text NOT NULL CHECK (kind IN ('folder', 'file')),
  object_id   bigint NOT NULL,
  token_hash  text NOT NULL UNIQUE,
  created_by  uuid NOT NULL REFERENCES fm.users,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz);
CREATE INDEX ON fm.share_links (kind, object_id);
GRANT SELECT, INSERT, DELETE ON fm.share_links TO fm_app;
GRANT USAGE ON SEQUENCE fm.share_links_id_seq TO fm_app;
