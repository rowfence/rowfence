-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.services (id, name, owner_id) VALUES (1, 'weather', 1);
SELECT setval('app.services_id_seq', 1);
INSERT INTO app.channels (id, name) VALUES (1, 'general');
SELECT setval('app.channels_id_seq', 1);
INSERT INTO app.channel_members VALUES (1, 1);
INSERT INTO app.channel_bots VALUES (1, 1);
INSERT INTO app.posts (channel_id, bot_id, body) VALUES (1, 1, 'sunny');
