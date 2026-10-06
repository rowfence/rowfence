-- Bots and services (docs/cookbook/bots-and-services.md): bots that post where they were added.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.services (id bigserial PRIMARY KEY, name text NOT NULL, owner_id bigint NOT NULL REFERENCES app.users);
CREATE INDEX ON app.services (owner_id);
CREATE TABLE app.channels (id bigserial PRIMARY KEY, name text);
CREATE TABLE app.channel_members (channel_id bigint NOT NULL REFERENCES app.channels ON DELETE CASCADE,
                                  user_id bigint NOT NULL REFERENCES app.users ON DELETE CASCADE, PRIMARY KEY (channel_id, user_id));
CREATE INDEX ON app.channel_members (user_id);
CREATE TABLE app.channel_bots (channel_id bigint NOT NULL REFERENCES app.channels ON DELETE CASCADE,
                               service_id bigint NOT NULL REFERENCES app.services ON DELETE CASCADE, PRIMARY KEY (channel_id, service_id));
CREATE INDEX ON app.channel_bots (service_id);
CREATE TABLE app.posts (id bigserial PRIMARY KEY, channel_id bigint NOT NULL REFERENCES app.channels,
                        bot_id bigint NOT NULL REFERENCES app.services, body text);
CREATE INDEX ON app.posts (channel_id);
CREATE INDEX ON app.posts (bot_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
GRANT INSERT ON app.posts TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user;
