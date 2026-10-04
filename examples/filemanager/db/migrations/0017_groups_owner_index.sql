-- 0017: the index authz.lint() asks for (group.owner: the groups a person owns).
CREATE INDEX ON fm.groups (owner_id);
