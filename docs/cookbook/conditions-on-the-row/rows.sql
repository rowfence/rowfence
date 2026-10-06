-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.channels (id, name, announce) VALUES (1, 'general', false), (2, 'announcements', true);
SELECT setval('app.channels_id_seq', 2);
INSERT INTO app.channel_members VALUES (1, 1, false), (1, 2, false), (2, 1, false), (2, 2, true);
INSERT INTO app.posts (channel_id, author_id, body) VALUES (1, 1, 'hello'), (2, 2, 'the office is closed on Friday');
