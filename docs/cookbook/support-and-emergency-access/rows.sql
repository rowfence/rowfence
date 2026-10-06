-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.support_assignments VALUES (1, 2);
INSERT INTO app.notes (owner_id, body) VALUES (1, 'Ann''s note'), (2, 'Bo''s note');
