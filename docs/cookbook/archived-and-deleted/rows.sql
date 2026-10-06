-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.documents (owner_id, title, archived, deleted_at) VALUES (1, 'Plans', false, NULL), (1, 'Last year', true, NULL), (1, 'In the trash', false, now());
