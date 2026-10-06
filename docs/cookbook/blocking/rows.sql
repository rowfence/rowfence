-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.direct_messages (from_id, to_id, body) VALUES (1, 2, 'hi Bo'), (2, 1, 'hi Ann');
