-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.documents (owner_id, title, visibility) VALUES (1, 'Ann''s diary', 'private'), (2, 'Bo''s diary', 'private'), (2, 'Bo''s blog', 'public');
