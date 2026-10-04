-- open one file, as a random org admin (who reaches every folder), through row-level security
\set u random(1, 10)
\set f random(1, :nfiles)
BEGIN;
SET LOCAL ROLE app_user;
SELECT authz.act_as('user', :u::text);
SELECT id, name, folder_id FROM app.files WHERE id = :f;
COMMIT;
