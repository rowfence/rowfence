-- open a folder (list its files), as a random org admin (who reaches every folder), through row-level security
\set u random(1, 10)
\set d random(1, :nfolders)
BEGIN;
SET LOCAL ROLE app_user;
SELECT authz.act_as('user', :u::text);
SELECT id, name FROM app.files WHERE folder_id = :d;
COMMIT;
