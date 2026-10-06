-- The tables of patterns.authz: one small app per pattern, side by side (a fixture for adversarial.sh).
CREATE SCHEMA cb;
CREATE TABLE cb.users (id bigint PRIMARY KEY, name text NOT NULL);

-- owner only
CREATE TABLE cb.notes (id bigserial PRIMARY KEY, owner_id bigint NOT NULL REFERENCES cb.users, body text);

-- teams inside teams
CREATE TABLE cb.teams (id bigint PRIMARY KEY, parent_id bigint REFERENCES cb.teams, name text);
CREATE TABLE cb.team_members (team_id bigint NOT NULL REFERENCES cb.teams ON DELETE CASCADE,
                              user_id bigint NOT NULL REFERENCES cb.users ON DELETE CASCADE, PRIMARY KEY (team_id, user_id));
CREATE INDEX ON cb.team_members (user_id);
CREATE INDEX ON cb.teams (parent_id);

-- folders that inherit, shared with people, teams and links
CREATE TABLE cb.folders (id bigserial PRIMARY KEY, parent_id bigint REFERENCES cb.folders,
                         owner_id bigint REFERENCES cb.users, name text, inherit boolean NOT NULL DEFAULT true);
CREATE INDEX ON cb.folders (parent_id);
CREATE INDEX ON cb.folders (owner_id);

-- wiki pages: a hidden page hides everything below it, from everyone
CREATE TABLE cb.pages (id bigserial PRIMARY KEY, parent_id bigint REFERENCES cb.pages, hidden boolean NOT NULL DEFAULT false);
CREATE TABLE cb.page_readers (page_id bigint NOT NULL REFERENCES cb.pages ON DELETE CASCADE,
                              user_id bigint NOT NULL REFERENCES cb.users ON DELETE CASCADE, PRIMARY KEY (page_id, user_id));
CREATE INDEX ON cb.pages (parent_id);
CREATE INDEX ON cb.page_readers (user_id);

-- tenants: tickets numbered per organisation
CREATE TABLE cb.orgs (id bigint PRIMARY KEY, name text);
CREATE TABLE cb.org_members (org_id bigint NOT NULL REFERENCES cb.orgs ON DELETE CASCADE,
                             user_id bigint NOT NULL REFERENCES cb.users ON DELETE CASCADE,
                             role text NOT NULL DEFAULT 'member', PRIMARY KEY (org_id, user_id));
CREATE INDEX ON cb.org_members (user_id);
CREATE TABLE cb.tickets (org_id bigint NOT NULL REFERENCES cb.orgs, id bigint NOT NULL,
                         assignee_id bigint REFERENCES cb.users, title text, PRIMARY KEY (org_id, id));
CREATE INDEX ON cb.tickets (assignee_id);

-- bots: services that sign in with their own keys
CREATE TABLE cb.services (id bigserial PRIMARY KEY, name text NOT NULL, owner_id bigint NOT NULL REFERENCES cb.users);
CREATE INDEX ON cb.services (owner_id);

-- channels: announcement channels, where only admins (and bots added to it) post
CREATE TABLE cb.channels (id bigserial PRIMARY KEY, announce boolean NOT NULL DEFAULT false);
CREATE TABLE cb.channel_members (channel_id bigint NOT NULL REFERENCES cb.channels ON DELETE CASCADE,
                                 user_id bigint NOT NULL REFERENCES cb.users ON DELETE CASCADE,
                                 admin boolean NOT NULL DEFAULT false, PRIMARY KEY (channel_id, user_id));
CREATE INDEX ON cb.channel_members (user_id);
CREATE TABLE cb.channel_bots (channel_id bigint NOT NULL REFERENCES cb.channels ON DELETE CASCADE,
                              service_id bigint NOT NULL REFERENCES cb.services ON DELETE CASCADE, PRIMARY KEY (channel_id, service_id));
CREATE INDEX ON cb.channel_bots (service_id);
CREATE TABLE cb.posts (id bigserial PRIMARY KEY, channel_id bigint NOT NULL REFERENCES cb.channels,
                       author_id bigint REFERENCES cb.users, bot_id bigint REFERENCES cb.services, body text);
CREATE INDEX ON cb.posts (channel_id);
CREATE INDEX ON cb.posts (author_id);
CREATE INDEX ON cb.posts (bot_id);

-- blocking: people who blocked you can't be written to
CREATE TABLE cb.blocks (blocker_id bigint NOT NULL REFERENCES cb.users, blocked_id bigint NOT NULL REFERENCES cb.users,
                        PRIMARY KEY (blocker_id, blocked_id));
CREATE INDEX ON cb.blocks (blocked_id);
CREATE TABLE cb.direct_messages (id bigserial PRIMARY KEY, from_id bigint NOT NULL REFERENCES cb.users,
                                 to_id bigint NOT NULL REFERENCES cb.users, body text);
CREATE INDEX ON cb.direct_messages (from_id);
CREATE INDEX ON cb.direct_messages (to_id);

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cb_app') THEN
    CREATE ROLE cb_app NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA cb TO cb_app;
GRANT SELECT ON ALL TABLES IN SCHEMA cb TO cb_app;
-- writes only where the policy has rules: membership tables written by the app would let anyone join anything
GRANT INSERT, UPDATE, DELETE ON cb.notes, cb.folders, cb.tickets, cb.posts, cb.direct_messages TO cb_app;
GRANT UPDATE (name) ON cb.users TO cb_app;                  -- your own row: the name
GRANT USAGE ON ALL SEQUENCES IN SCHEMA cb TO cb_app;
