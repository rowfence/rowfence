-- tree write: an org admin creates a folder inside a random folder, through row-level security
\set a random(1, 10)
\set p random(1, :nfolders)
BEGIN;
SET LOCAL ROLE app_user;
SELECT authz.act_as('user', :a::text);
INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, :p, :a, 'bench');
COMMIT;
