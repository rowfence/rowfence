-- shares.sql: shares people made in the app, loaded after the policy is applied (bench/scale.sh):
-- 3 per 10 folders (to users or teams, viewer or editor) and 1 per 40 files (to users, viewer).
\set ON_ERROR_STOP on
SET client_min_messages = warning;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation)
SELECT 'folder', x.f, x.rel, x.st,
       CASE WHEN x.st = 'team' THEN 1 + floor(x.r * :teams)::int ELSE 1 + floor(x.r * :users)::int END,
       CASE WHEN x.st = 'team' THEN 'member' ELSE '' END
FROM (SELECT 1 + floor(random() * :folders)::bigint AS f,
             CASE WHEN random() < 0.5 THEN 'viewer' ELSE 'editor' END AS rel,
             CASE WHEN random() < 0.6 THEN 'team' ELSE 'user' END AS st,
             random() AS r
      FROM generate_series(1, :folders * 3 / 10)) x
ON CONFLICT DO NOTHING;
INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id)
SELECT 'file', 1 + floor(random() * :files)::bigint, 'viewer', 'user', 1 + floor(random() * :users)::int
FROM generate_series(1, :files / 40) ON CONFLICT DO NOTHING;
