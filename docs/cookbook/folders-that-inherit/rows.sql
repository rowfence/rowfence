-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.folders (id, parent_id, owner_id, name) VALUES (1, NULL, 1, 'Top'), (2, 1, NULL, 'Sub'), (3, NULL, 2, 'Bo''s');
SELECT setval('app.folders_id_seq', 3);
