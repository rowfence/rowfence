-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.teams VALUES (1, NULL, 'Engineering'), (2, 1, 'Web');
INSERT INTO app.team_members VALUES (2, 1);
INSERT INTO app.documents (owner_id, title) VALUES (2, 'Plans');
INSERT INTO app.document_teams VALUES (1, 1);
