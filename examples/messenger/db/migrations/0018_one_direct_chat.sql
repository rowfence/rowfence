-- 0018: one direct chat for two people. The API looked for an old chat before making a new one, and nothing
-- stopped two requests at the same moment from making two.

-- the two people of each direct chat, in order. Written by the database when the second joins, and not the
-- app role's to read or write: it could otherwise take a pair's place
CREATE TABLE ms.direct_pairs (
  pair    uuid[] PRIMARY KEY CHECK (array_length(pair, 1) = 2),
  chat_id bigint NOT NULL UNIQUE REFERENCES ms.chats ON DELETE CASCADE);
REVOKE ALL ON ms.direct_pairs FROM ms_app;

-- the chats there are: the oldest of each pair keeps it (a later one for the same two stays, without a row)
INSERT INTO ms.direct_pairs (pair, chat_id)
SELECT DISTINCT ON (x.pair) x.pair, x.chat_id
FROM (SELECT m.chat_id, array_agg(m.user_id ORDER BY m.user_id) AS pair
      FROM ms.members m JOIN ms.chats d ON d.id = m.chat_id AND d.kind = 'direct'
      GROUP BY m.chat_id HAVING count(*) = 2) x
ORDER BY x.pair, x.chat_id;

-- (SECURITY DEFINER: it writes whoever adds the member, like ms.stamp_joined_seq)
CREATE FUNCTION ms.pair_direct() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_pair uuid[];
BEGIN
  IF (SELECT c.kind FROM ms.chats c WHERE c.id = NEW.chat_id) = 'direct' THEN
    SELECT array_agg(m.user_id ORDER BY m.user_id) INTO v_pair FROM ms.members m WHERE m.chat_id = NEW.chat_id;
    -- once for the chat: two members added by one statement both see the two of them here
    IF array_length(v_pair, 1) = 2 AND NOT EXISTS (SELECT 1 FROM ms.direct_pairs p WHERE p.chat_id = NEW.chat_id) THEN
      -- a second chat for the same two is refused here (23505): the API then answers with the first
      INSERT INTO ms.direct_pairs (pair, chat_id) VALUES (v_pair, NEW.chat_id);
    END IF;
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER pair_direct AFTER INSERT ON ms.members FOR EACH ROW EXECUTE FUNCTION ms.pair_direct();
REVOKE ALL ON FUNCTION ms.pair_direct() FROM PUBLIC;

-- a chat one of the two left is no longer the pair's: they may start another
CREATE FUNCTION ms.unpair_direct() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  DELETE FROM ms.direct_pairs p WHERE p.chat_id = OLD.chat_id;
  RETURN NULL;
END $f$;
CREATE TRIGGER unpair_direct AFTER DELETE ON ms.members FOR EACH ROW EXECUTE FUNCTION ms.unpair_direct();
REVOKE ALL ON FUNCTION ms.unpair_direct() FROM PUBLIC;
