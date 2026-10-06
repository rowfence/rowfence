-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.pages (id, parent_id, title, hidden) VALUES (1, NULL, 'Handbook', false), (2, 1, 'Drafts', true), (3, 2, 'A draft', false), (4, 1, 'Holidays', false);
SELECT setval('app.pages_id_seq', 4);
INSERT INTO app.page_readers VALUES (1, 1);
