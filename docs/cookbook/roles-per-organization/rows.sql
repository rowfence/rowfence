-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.orgs VALUES (1, 'Acme');
INSERT INTO app.org_members VALUES (1, 1, 'admin'), (1, 2, 'member');
INSERT INTO app.documents (org_id, owner_id, title) VALUES (1, 1, 'Handbook'), (1, 2, 'Bo''s notes');
