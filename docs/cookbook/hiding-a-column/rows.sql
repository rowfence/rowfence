-- A few rows to ask about in the playground (the tests bring their own).
INSERT INTO app.users VALUES (1, 'Ann'), (2, 'Bo');
INSERT INTO app.employees (user_id, manager_id, title, salary) VALUES (1, NULL, 'Director', 9000), (2, 1, 'Engineer', 5000);
