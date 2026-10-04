-- ask directly: may a random org admin edit a random file?
\set u random(1, 10)
\set f random(1, :nfiles)
BEGIN;
SET LOCAL ROLE app_user;
SELECT authz.act_as('user', :u::text);
SELECT authz.can('file', :f, 'edit');
COMMIT;
