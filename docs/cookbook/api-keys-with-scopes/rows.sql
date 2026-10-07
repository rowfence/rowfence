-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.projects (id, owner_id, name) VALUES (1, 1, 'Plans'), (2, 2, 'Bo''s');
SELECT setval('app.projects_id_seq', 2);
INSERT INTO app.project_members VALUES (2, 1);
INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 1, 'ship it'), (2, 2, 'private'), (2, 1, 'from Ann');
