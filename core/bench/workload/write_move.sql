-- tree write: an org admin moves a small folder (from level 12 down, about 100 below it at most) into any
-- folder, through
-- row-level security; a move that would put a folder inside itself is refused, as an app would refuse it
\set a random(1, 10)
\set m random(:small_first, :nfolders)
\set t random(1, :nfolders)
BEGIN;
SET LOCAL ROLE app_user;
SELECT authz.act_as('user', :a::text);
SELECT bench.try(format('UPDATE app.folders SET parent_id = %s WHERE id = %s', :t::bigint, :m::bigint));
COMMIT;
