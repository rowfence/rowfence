-- 0014: "you read what was said since you joined" goes by the chat's message number, not by time: a clock
-- that steps back made a message older than its sender's joining, and the post was refused. And the app
-- role no longer reads ms.credentials: signing in goes through ms.credentials_for() and ms.sign_up().

-- the chat's last message number when the person joined: they read the messages after it
ALTER TABLE ms.members ADD COLUMN joined_seq bigint NOT NULL DEFAULT 0;
UPDATE ms.members m SET joined_seq = coalesce(
  (SELECT max(x.seq) FROM ms.messages x WHERE x.chat_id = m.chat_id AND x.created_at < m.joined_at), 0);

-- set by the database, whatever the insert says (SECURITY DEFINER: it reads the chat's counter, like
-- ms.number_message)
CREATE FUNCTION ms.stamp_joined_seq() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  NEW.joined_seq := coalesce((SELECT c.last_seq FROM ms.chats c WHERE c.id = NEW.chat_id), 0);
  RETURN NEW;
END $f$;
CREATE TRIGGER stamp_joined_seq BEFORE INSERT ON ms.members FOR EACH ROW EXECUTE FUNCTION ms.stamp_joined_seq();
REVOKE ALL ON FUNCTION ms.stamp_joined_seq() FROM PUBLIC;

-- the number the signed-in person joined at (NULL: not a member)
-- (plpgsql: authz.uid() comes with the policy, applied after the migrations)
CREATE FUNCTION ms.joined_seq(p_chat bigint) RETURNS bigint
LANGUAGE plpgsql STABLE AS $$
BEGIN
  RETURN (SELECT m.joined_seq FROM ms.members m WHERE m.chat_id = p_chat AND m.user_id = authz.uid());
END $$;
GRANT EXECUTE ON FUNCTION ms.joined_seq(bigint) TO ms_app;

REVOKE ALL ON ms.credentials FROM ms_app;
