-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.orgs VALUES (1, 'Acme'), (2, 'Globex');
INSERT INTO app.org_members VALUES (1, 1, 'admin'), (2, 2, 'admin');
INSERT INTO app.workspaces (id, org_id, name) VALUES (1, 1, 'Design'), (2, 2, 'Research');
SELECT setval('app.workspaces_id_seq', 2);
INSERT INTO app.projects (workspace_id, name) VALUES (1, 'Website'), (2, 'Survey');
