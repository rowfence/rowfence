-- tree write: the backend links a small folder into a folder above level 12 (those never move and only
-- link upwards, so no folder ends up inside itself; the app role may not write links)
\set f random(:small_first, :nfolders)
\set t random(1, :small_first - 1)
SELECT bench.try(format('INSERT INTO app.folder_links VALUES (%s, %s) ON CONFLICT DO NOTHING', :f::bigint, :t::bigint));
