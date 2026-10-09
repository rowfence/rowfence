#!/bin/bash
# governance.sh: the audit trail, the change feed, access requests, emergency access,
# access reviews, invariants, decision logs and previewing a policy change.
#   PGHOST=... PGPORT=... PGUSER=postgres tests/governance.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_governance}
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
check() {   # $1 label, $2 expected, $3 SQL (run as app_user)
  got=$(PSQL -c "SET ROLE app_user;" -c "$3" 2>&1 | tail -n 1)
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$2', got '$got'"; fails=$((fails + 1)); fi
}
admin() {   # $1 label, $2 expected, $3 SQL (run as the administrator)
  got=$(PSQL -c "$3" 2>&1 | tail -n 1)
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$2', got '$got'"; fails=$((fails + 1)); fi
}
as() { local u=$1; shift; PSQL -c "SET ROLE app_user; SET authz.user_id = '$u';" "$@" 2>&1 | tail -n 1; }
code() {
  psql -X -q -At -d "$DB" -v VERBOSITY=sqlstate "$@" 2>&1 | grep -o '^ERROR:  [0-9A-Z]*' | tail -n 1 | cut -c9- || true
}
. tests/words.sh
expect_code() {  # $1 label, $2 expected "SQLSTATE: the message's words" (or ok), rest: -c statements (as app_user unless the first is RESET ROLE)
  local label=$1 want=$2; shift 2
  got=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user" "$@" 2>&1 | grep '^ERROR:  ' | tail -n 1)
  got=${got#ERROR:  }; got=${got:-ok}
  if agrees "$label" "$want" "$got"; then echo "ok    $label"; else echo "FAIL  $label: expected $want, got $got"; fails=$((fails + 1)); fi
}

python3 compile_policy.py example/docs.authz > /tmp/authz_governance.sql || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance.sql >/dev/null || exit 1

echo "-- the audit trail"
as 5 -c "SELECT authz.share('folder', 2, 'viewer', 'user', 4)" >/dev/null
admin "a share is recorded, with who made it" "share|5|folder|2|viewer|user|4" \
  "SELECT action || '|' || user_id || '|' || object_type || '|' || object_id || '|' || relation || '|' || subject_type || '|' || subject_id
   FROM authz.audit ORDER BY id DESC LIMIT 1"
as 5 -c "SELECT authz.unshare('folder', 2, 'viewer', 'user', 4)" >/dev/null
admin "... and so is taking it back" "unshare|5" "SELECT action || '|' || user_id FROM authz.audit ORDER BY id DESC LIMIT 1"
PSQL -c "BEGIN" -c "SET LOCAL ROLE app_user" -c "SELECT authz.act_as('user', ' 05')" \
     -c "SELECT authz.share('folder', 2, 'viewer', 'user', 4)" -c "COMMIT" >/dev/null
admin "an id signed in as ' 05' is recorded as 5, as ids are stored" "share|5|5" \
  "SELECT a.action || '|' || a.user_id || '|' || s.created_by FROM authz.audit a, authz.shares s
   WHERE s.object_type = 'folder' AND s.object_id = '2' AND s.subject_id = '4' ORDER BY a.id DESC LIMIT 1"
as 5 -c "SELECT authz.unshare('folder', 2, 'viewer', 'user', 4)" >/dev/null
PSQL -c "INSERT INTO app.team_members VALUES (11, 3)" >/dev/null
admin "memberships kept in your tables are recorded too" "relate|team|11|member|user|3" \
  "SELECT action || '|' || object_type || '|' || object_id || '|' || relation || '|' || subject_type || '|' || subject_id
   FROM authz.audit ORDER BY id DESC LIMIT 1"
PSQL -c "DELETE FROM app.team_members WHERE team_id = 11 AND user_id = 3" >/dev/null
admin "... and their removal" "unrelate|team|11|3" \
  "SELECT action || '|' || object_type || '|' || object_id || '|' || subject_id FROM authz.audit ORDER BY id DESC LIMIT 1"
PSQL -c "BEGIN; SET LOCAL authz_ctx.reason = 'reorg'; UPDATE app.folders SET owner_id = 3 WHERE id = 4; COMMIT;" >/dev/null
admin "a changed owner column is recorded, with what it was and why" "relate|folder|4|owner|3|1|reorg" \
  "SELECT action || '|' || object_type || '|' || object_id || '|' || relation || '|' || subject_id || '|' || (detail->>'was') || '|' || reason
   FROM authz.audit ORDER BY id DESC LIMIT 1"
PSQL -c "UPDATE app.folders SET owner_id = 1 WHERE id = 4" >/dev/null
admin "an unrelated column change adds nothing" "0" \
  "WITH b AS (SELECT max(id) m FROM authz.audit), u AS (UPDATE app.folders SET name = 'Design' WHERE id = 4 RETURNING 1)
   SELECT count(*) FROM authz.audit, b WHERE id > b.m"
PSQL -c "UPDATE app.folders SET id = 40, owner_id = 3 WHERE id = 4" >/dev/null
admin "an owner change in the same UPDATE as a new key is recorded" "relate|40|owner|3" \
  "SELECT action || '|' || object_id || '|' || relation || '|' || subject_id FROM authz.audit
   WHERE object_type = 'folder' AND relation = 'owner' ORDER BY id DESC LIMIT 1"
PSQL -c "UPDATE app.folders SET id = 4, owner_id = 1 WHERE id = 40" >/dev/null
POS=$(PSQL -c "SELECT coalesce(max(pos), 0) FROM authz.changes")
PSQL -c "TRUNCATE app.folder_links" -c "INSERT INTO app.folder_links VALUES (21, 1)" >/dev/null
admin "emptying a link table is recorded" "truncate|folder" \
  "SELECT action || '|' || object_type FROM authz.audit WHERE action = 'truncate' ORDER BY id DESC LIMIT 1"
admin "... and announced for every folder" "{*}" \
  "SELECT object_ids::text FROM authz.changes WHERE pos > $POS AND object_type = 'folder' ORDER BY pos LIMIT 1"
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('folder', '999', 'viewer', 'user', '4')" >/dev/null
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance.sql >/dev/null
admin "shares dropped when the policy is applied (their row is gone) are recorded, with why" \
  "unshare|applying the policy: the row was deleted" \
  "SELECT action || '|' || reason FROM authz.audit WHERE object_id = '999' ORDER BY id DESC LIMIT 1"
expect_code "the trail cannot be edited, even by an administrator" "42501: the audit trail cannot be changed" -c "RESET ROLE" -c "DELETE FROM authz.audit"
expect_code "... or emptied" "42501: the audit trail cannot be changed" -c "RESET ROLE" -c "TRUNCATE authz.audit"
expect_code "the app role cannot read it" "42501: permission denied for table audit" -c "SELECT count(*) FROM authz.audit"

echo "-- the change feed"
POS=$(PSQL -c "SELECT coalesce(max(pos), 0) FROM authz.changes")
PSQL -c "UPDATE app.folders SET parent_id = 2 WHERE id = 4" >/dev/null
admin "moving a folder announces it (and what sits below it)" "t" \
  "SELECT bool_or(object_type = 'folder' AND '4' = ANY (object_ids)) FROM authz.changes_since($POS)"
admin "... with inheritance as the cause" "t" \
  "SELECT bool_or(cause = 'inheritance') FROM authz.changes_since($POS)"
PSQL -c "UPDATE app.folders SET parent_id = 3 WHERE id = 4" >/dev/null
got=$(psql -X -q -At -d "$DB" -c "LISTEN authz_changes" -c "SET ROLE app_user" -c "SET authz.user_id = 5" \
       -c "SELECT authz.share('file', 11, 'viewer', 'user', 4)" -c "SELECT 1" 2>&1)
case "$got" in *'notification "authz_changes"'*) echo "FAIL  the feed notified without notify_changes: $got"; fails=$((fails + 1));;
  *) echo "ok    by default the feed doesn't NOTIFY (it would queue every commit): consumers poll";; esac
PSQL -c "INSERT INTO authz.settings VALUES ('notify_changes', 'on')" >/dev/null
got=$(psql -X -q -At -d "$DB" -c "LISTEN authz_changes" -c "SET ROLE app_user" -c "SET authz.user_id = 5" \
       -c "SELECT authz.unshare('file', 11, 'viewer', 'user', 4)" -c "SELECT 1" 2>&1)
case "$got" in *'notification "authz_changes"'*) echo "ok    with notify_changes on, listeners hear of a change (NOTIFY authz_changes)";;
  *) echo "FAIL  notify: $got"; fails=$((fails + 1));; esac
PSQL -c "DELETE FROM authz.settings WHERE key = 'notify_changes'" >/dev/null
expect_code "the app role cannot read the feed" "42501: permission denied for function changes_since" -c "SELECT * FROM authz.changes_since(0)"


echo "-- emergency access (break glass)"
check "carol cannot see the prod keys" "f" "SET authz.user_id = 3; SELECT authz.can('file', 12, 'view')"
expect_code "a reason is required" "P0001: say why (it is kept in the audit trail)" -c "SET authz.user_id = 3" -c "SELECT authz.break_glass('folder', '6', 'viewer', '')"
expect_code "it lasts one day at most" "P0001: emergency access lasts more than nothing and one day at most" -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage', '2 days')"
expect_code "... and a duration must be given" "P0001: emergency access lasts more than nothing and one day at most" -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage', NULL)"
expect_code "... a positive one" "P0001: emergency access lasts more than nothing and one day at most" -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage', '-1 hour')"
expect_code "frank (Globex) cannot break the glass on an Acme folder" "42501: you cannot break the glass on folder 6" -c "SET authz.user_id = 6" \
  -c "SELECT authz.break_glass('folder', '6', 'viewer', 'outage')"
got=$(psql -X -q -At -d "$DB" -c "LISTEN authz_alerts" -c "SET ROLE app_user" -c "SET authz.user_id = 3" \
       -c "SELECT authz.break_glass('folder', '6', 'viewer', 'prod outage INC-7')" -c "SELECT 1" 2>&1)
case "$got" in *'notification "authz_alerts"'*) echo "ok    carol breaks the glass, and the alert goes out";;
  *) echo "FAIL  break glass: $got"; fails=$((fails + 1));; esac
check "... so she can see the keys" "t" "SET authz.user_id = 3; SELECT authz.can('file', 12, 'view')"
# (five minutes either way: the clock in a container may step back a few seconds between the two statements)
admin "... for an hour" "t" \
  "SELECT expires_at BETWEEN now() + interval '55 minutes' AND now() + interval '65 minutes' FROM authz.shares WHERE object_type = 'folder' AND object_id = '6' AND subject_id = '3'"
admin "the trail has it, with the reason" "break_glass|3|prod outage INC-7" \
  "SELECT action || '|' || user_id || '|' || reason FROM authz.audit WHERE action = 'break_glass' ORDER BY id DESC LIMIT 1"
# as the reference writes them, the id a number (docs/reference/app-code.md)
expect_code "the id may be a number, as for authz.can" ok -c "SET authz.user_id = 3" \
  -c "SELECT authz.break_glass('folder', 6, 'viewer', 'INC-7 outage', '1 hour')"
expect_code "... for a review too" ok -c "SET authz.user_id = 5" -c "BEGIN" -c "SELECT authz.start_review('folder', 3)" -c "ROLLBACK"
expect_code "... and for an owner's roles (the docs policy has none: refused, not unknown)" "42501: you cannot see roles of org 1" -c "SET authz.user_id = 5" \
  -c "SELECT * FROM authz.roles_of('org', 1)"

echo "-- access requests"
REQ=$(as 3 -c "SELECT authz.request_access('folder', 5, 'viewer', 'need the offer letter template', '7 days')")
[ -n "$REQ" ] && [ "$REQ" -gt 0 ] 2>/dev/null && echo "ok    carol asks to view Secrets" || { echo "FAIL  request: $REQ"; fails=$((fails + 1)); }
check "carol sees her own request" "t" "SET authz.user_id = 3; SELECT mine FROM authz.pending_requests() WHERE id = $REQ"
check "erin (who may share Secrets) sees it to decide" "1" "SET authz.user_id = 5; SELECT count(*) FROM authz.pending_requests() WHERE id = $REQ"
check "alice (who may not) does not" "0" "SET authz.user_id = 1; SELECT count(*) FROM authz.pending_requests() WHERE id = $REQ"
expect_code "alice cannot decide it" "42501: you cannot decide request 1" -c "SET authz.user_id = 1" -c "SELECT authz.decide_request($REQ, true)"
expect_code "alice cannot deny it either" "42501: you cannot decide request 1" -c "SET authz.user_id = 1" -c "SELECT authz.decide_request($REQ, false)"
expect_code "carol cannot approve her own request" "42501: you cannot decide your own request" -c "SET authz.user_id = 3" -c "SELECT authz.decide_request($REQ, true)"
expect_code "an answer is yes or no" "P0001: approve (true) or deny (false)" -c "SET authz.user_id = 5" -c "SELECT authz.decide_request($REQ, NULL)"
expect_code "... for a request still pending" "P0001: no pending request 999" -c "SET authz.user_id = 5" -c "SELECT authz.decide_request(999, true)"
expect_code "dave cannot withdraw carol's request" "P0001: no pending request $REQ of yours" -c "SET authz.user_id = 4" -c "SELECT authz.cancel_request($REQ)"
expect_code "a request says why" "P0001: say why you need it" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('folder', 6, 'viewer', '  ')"
expect_code "... and how long it may last is more than nothing" "P0001: the duration must be positive" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('folder', 6, 'viewer', 'please', '-1 day')"
check "before approval carol cannot view the offer letter" "f" "SET authz.user_id = 3; SELECT authz.can('file', 13, 'view')"
as 5 -c "SELECT authz.decide_request($REQ, true, 'ok for a week')" >/dev/null
check "after erin approves, she can" "t" "SET authz.user_id = 3; SELECT authz.can('file', 13, 'view')"
admin "the share ends after the requested week" "t" \
  "SELECT expires_at BETWEEN now() + interval '7 days' - interval '1 minute' AND now() + interval '7 days'
   FROM authz.shares WHERE object_type = 'folder' AND object_id = '5' AND subject_id = '3'"
admin "the request is closed, and says who approved it" "approved|5" "SELECT status || '|' || decided_by FROM authz.requests WHERE id = $REQ"
REQ2=$(as 4 -c "SELECT authz.request_access('folder', 6, 'viewer', 'curious')")
as 5 -c "SELECT authz.decide_request($REQ2, false, 'no')" >/dev/null
check "a denied request grants nothing" "f" "SET authz.user_id = 4; SELECT authz.can('folder', 6, 'view')"
REQ3=$(as 4 -c "SELECT authz.request_access('folder', 6, 'viewer', 'please')")
as 4 -c "SELECT authz.cancel_request($REQ3)" >/dev/null
admin "requests can be withdrawn" "cancelled" "SELECT status FROM authz.requests WHERE id = $REQ3"
expect_code "only relations the policy lets people share can be requested" "P0001: the policy does not allow sharing folder.owner with a user" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('folder', 6, 'owner', 'mine now')"
expect_code "... on types the policy has" "P0001: no type nosuchtype in the policy" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('nosuchtype', '1', 'role:1', 'boom')"
expect_code "... and roles that exist" "P0001: the policy does not allow sharing folder.role:999 with a user" -c "SET authz.user_id = 4" \
  -c "SELECT authz.request_access('folder', '6', 'role:999', 'boom')"
R999=$(as 4 -c "SELECT authz.request_access('folder', '999', 'viewer', 'boom')")
check "a request for a missing object reaches no approver" "0" "SET authz.user_id = 5; SELECT count(*) FROM authz.pending_requests() WHERE id = $R999"
as 4 -c "SELECT authz.cancel_request($R999)" >/dev/null
check "approvers can still list requests" "0" "SET authz.user_id = 5; SELECT count(*) FROM authz.pending_requests() WHERE requester = '4'"

echo "-- access reviews"
as 5 -c "SELECT authz.share('folder', 5, 'viewer', 'user', 4)" >/dev/null
expect_code "carol cannot review Secrets" "42501: you cannot review folder 5" -c "SET authz.user_id = 3" -c "SELECT authz.start_review('folder', '5')"
REV=$(as 5 -c "SELECT authz.start_review('folder', '5')")
check "erin's review lists every share on Secrets" "2" "SET authz.user_id = 5; SELECT count(*) FROM authz.review_items($REV)"
ITEM=$(as 5 -c "SELECT item FROM authz.review_items($REV) WHERE subject_id = '3'")
as 5 -c "SELECT authz.review_decide($REV, $ITEM, false)" >/dev/null
expect_code "carol cannot decide in it" "42501: you cannot decide in review 2" -c "SET authz.user_id = 3" -c "SELECT authz.review_decide($REV, $ITEM, true)"
expect_code "... nor read its items" "42501: you cannot see review $REV" -c "SET authz.user_id = 3" -c "SELECT * FROM authz.review_items($REV)"
expect_code "... nor close it" "42501: you cannot close review $REV" -c "SET authz.user_id = 3" -c "SELECT authz.close_review($REV)"
expect_code "erin decides on the items it has" "P0001: no item 999 in review $REV" -c "SET authz.user_id = 5" -c "SELECT authz.review_decide($REV, 999, false)"
check "closing the review revokes what was marked" "1" "SET authz.user_id = 5; SELECT authz.close_review($REV)"
check "... carol lost the offer letter" "f" "SET authz.user_id = 3; SELECT authz.can('file', 13, 'view')"
check "... dave (not decided) kept it" "t" "SET authz.user_id = 4; SELECT authz.can('file', 13, 'view')"
expect_code "a closed review cannot be changed" "42501: you cannot decide in review 2" -c "SET authz.user_id = 5" -c "SELECT authz.review_decide($REV, 1, false)"

echo "-- reviews respect 'shared by'"
sed -e 's/^  editor      : user, team#member shared$/  editor      : user, team#member, link shared by manage_editors/' \
    -e 's/^  can share = owner or org.admin or (parent.share and {inherit})$/&\n  can manage_editors = owner/' \
    example/docs.authz > /tmp/authz_governance_by.authz
grep -q "can manage_editors = owner" /tmp/authz_governance_by.authz && grep -q "shared by manage_editors" /tmp/authz_governance_by.authz ||
  { echo "FAIL  could not make the variant policy"; fails=$((fails + 1)); }
python3 compile_policy.py /tmp/authz_governance_by.authz > /tmp/authz_governance_by.sql &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance_by.sql >/dev/null
as 1 -c "SELECT authz.share('folder', 3, 'editor', 'user', 4)" >/dev/null
expect_code "erin (share, but not manage_editors) cannot unshare dave's editor share" "42501: you cannot unshare editor on folder 3 (needs manage_editors)" -c "SET authz.user_id = 5" \
  -c "SELECT authz.unshare('folder', 3, 'editor', 'user', 4)"
REV2=$(as 5 -c "SELECT authz.start_review('folder', '3')")
ITEM2=$(as 5 -c "SELECT item FROM authz.review_items($REV2) WHERE subject_id = '4' AND relation = 'editor'")
expect_code "... nor revoke it in a review" "42501: you cannot decide on editor in review 3 (you could not unshare it)" -c "SET authz.user_id = 5" -c "SELECT authz.review_decide($REV2, $ITEM2, false)"
check "... nor by closing the review with undecided items revoked" "0" "SET authz.user_id = 5; SELECT authz.close_review($REV2, true)"
check "dave is still an editor" "t" "SET authz.user_id = 4; SELECT authz.can('folder', 3, 'edit')"
as 1 -c "SELECT authz.create_link('folder', 3, 'editor')" >/dev/null
LINK=$(as 1 -c "SELECT id FROM authz.list_links('folder', 3)")
check "erin (share) sees the editors' link alice made" "$LINK|editor|1"   "SET authz.user_id = 5; SELECT id || '|' || relation || '|' || created_by FROM authz.list_links('folder', 3)"
expect_code "... but cannot turn it off (not manage_editors)" "42501: you cannot turn off link " -c "SET authz.user_id = 5"   -c "SELECT authz.revoke_link('folder', 3, '$LINK')"
expect_code "a read-only session turns no link off" "42501: this session is read-only (viewing as someone else, or a read-only token)" -c "SET authz.user_id = 1" -c "SET authz.scopes = 'read'"   -c "SELECT authz.revoke_link('folder', 3, '$LINK')"
admin "the link is still there" "1" "SELECT count(*) FROM authz.shares WHERE object_type = 'folder' AND object_id = '3' AND subject_type = 'link'"
as 1 -c "SELECT authz.revoke_link('folder', 3, '$LINK')" >/dev/null
admin "alice (manage_editors) turns it off, and the audit trail has it as an unshare of hers" "unshare|1|folder|3|editor|link"   "SELECT action || '|' || user_id || '|' || object_type || '|' || object_id || '|' || relation || '|' || subject_type
   FROM authz.audit ORDER BY id DESC LIMIT 1"
as 1 -c "SELECT authz.create_link('folder', 3, 'editor')" >/dev/null
admin "an administrator lists a link and turns it off" "0"   "SELECT authz.revoke_link('folder', 3, (SELECT id FROM authz.list_links('folder', 3))); SELECT count(*) FROM authz.list_links('folder', 3)"
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance.sql >/dev/null
as 1 -c "SELECT authz.unshare('folder', 3, 'editor', 'user', 4)" >/dev/null

echo "-- invariants"
admin "the example data keeps the invariant" "0" "SELECT count(*) FROM authz.check_invariants()"
PSQL -c "UPDATE app.folders SET owner_id = 6 WHERE id = 4" >/dev/null
admin "a Globex user owning an Acme folder breaks it" "6|{4}" \
  "SELECT user_id || '|' || object_ids::text FROM authz.check_invariants()"
got=$(psql -X -q -At -d "$DB" -f <(python3 compile_policy.py example/docs.authz --tests) 2>&1)
case "$got" in *"FAIL  invariant"*"policy test(s) failed"*) echo "ok    the policy tests fail on it";;
  *) echo "FAIL  policy tests with a broken invariant: $got"; fails=$((fails + 1));; esac
PSQL -c "UPDATE app.folders SET owner_id = 1 WHERE id = 4" >/dev/null
expect_code "the app role cannot run the invariant check" "42501: permission denied for function check_invariants" -c "SELECT * FROM authz.check_invariants()"

got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET client_min_messages = log" -c "SET authz_debug.log_decisions = on" \
       -c "SET authz.user_id = 1" -c "SELECT authz.can('file', E'11\\nauthz decision: forged', 'view')" 2>&1)
case "$got" in *$'\n'"authz decision: forged"*) echo "FAIL  a forged log line: $got"; fails=$((fails + 1));;
  *) echo "ok    ids cannot start a line of their own in the log";; esac
echo "-- decision logs"
got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET client_min_messages = log" -c "SET authz_debug.log_decisions = on" \
       -c "SET authz.user_id = 1" -c "SELECT authz.can('file', 11, 'view')" 2>&1)
case "$got" in *'authz decision: user="1" type="file" id="11" perm="view" -> true'*) echo "ok    each decision is logged when asked";;
  *) echo "FAIL  decision log: $got"; fails=$((fails + 1));; esac

echo "-- previewing a policy change"
TMPD=$(mktemp -d)
sed -e 's/^           or linked_into.view .*$//' -e 's/^  linked_into : folder *= .*$//' example/docs.authz > "$TMPD/nolinks.authz"
grep -q "linked_into" "$TMPD/nolinks.authz" && { echo "FAIL  could not make the policy without links"; fails=$((fails + 1)); }
COUNTS="SELECT (SELECT count(*) FROM authz.shares) || '|' || (SELECT count(*) FROM authz.audit) || '|' || (SELECT count(*) FROM authz.changes)"
BEFORE=$(PSQL -c "$COUNTS")
python3 compile_policy.py "$TMPD/nolinks.authz" --diff > "$TMPD/diff.sql" &&
out=$(PGOPTIONS="-c client_min_messages=error" psql -X -q -d "$DB" -f "$TMPD/diff.sql" 2>&1)
case "$out" in *"loses  | 5       | file        | permission view | 16"*) echo "ok    without links, erin would lose joint-plan.md";;
  *) echo "FAIL  diff: $out"; fails=$((fails + 1));; esac
case "$out" in *"loses  | 5       | app.files   | rows readable   | 16"*) echo "ok    ...and could no longer read its row";;
  *) echo "FAIL  diff rows: $out"; fails=$((fails + 1));; esac
case "$out" in *gains*) echo "FAIL  the diff shows gains: $out"; fails=$((fails + 1));; *) echo "ok    ...and nobody gains anything";; esac
check "the preview changed nothing" "t" "SET authz.user_id = 5; SELECT authz.can('file', 16, 'view')"
admin "... not even the trail or the feed" "$BEFORE" "$COUNTS"
out=$(python3 compile_policy.py "$TMPD/nolinks.authz" --diff --users 1,3 | PGOPTIONS="-c client_min_messages=error" psql -X -q -d "$DB" 2>&1)
case "$out" in *"| 5 "*|*ERROR*) echo "FAIL  --users 1,3 shows other users: $out"; fails=$((fails + 1));; *) echo "ok    --users limits the preview";; esac
rm -rf "$TMPD"

echo "-- ways around row-level security (authz.lint)"
admin "the example has no errors or warnings" "0" "SELECT count(*) FROM authz.lint() WHERE severity IN ('error', 'warning')"
# a rule for a command the app role has no privilege for never applies, and the statement fails with Postgres's
# own message: a warning that says what to grant. A privilege on one column is enough for an update
PSQL -c "REVOKE DELETE, UPDATE ON app.files FROM app_user" >/dev/null
admin "lint finds a delete rule the app role has no privilege for" "1" \
  "SELECT count(*) FROM authz.lint() WHERE severity = 'warning' AND object = 'app.files' AND problem LIKE 'the policy has a rule for delete, but app_user has no DELETE privilege%GRANT DELETE ON app.files TO app_user%'"
admin "... and an update rule" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.files' AND problem LIKE 'the policy has a rule for update,%'"
PSQL -c "GRANT UPDATE (name) ON app.files TO app_user" >/dev/null
admin "... not once it may update one column" "0" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.files' AND problem LIKE 'the policy has a rule for update,%'"
PSQL -c "REVOKE UPDATE (name) ON app.files FROM app_user" -c "GRANT DELETE, UPDATE ON app.files TO app_user" >/dev/null
admin "... and none with the privileges back" "0" "SELECT count(*) FROM authz.lint() WHERE problem LIKE 'the policy has a rule for %'"
# a relation named like a type that doesn't sign in (file.folder, folder.org) is nobody's mistake: no note
admin "lint has no note on a relation named like a type that doesn't sign in" "0" \
  "SELECT count(*) FROM authz.lint() WHERE problem LIKE 'is named like the type%'"
# without its column rule, whoever may edit a file may make themselves its owner: lint asks for a rule, and
# suggests the type's own share
grep -v "update id, owner_id, confidential" example/docs.authz > /tmp/authz_no_column_rule.authz
python3 compile_policy.py /tmp/authz_no_column_rule.authz > /tmp/authz_no_column_rule.sql &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_no_column_rule.sql >/dev/null
admin "lint finds a column that gives a relation and that an editor may change" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.files.owner_id' AND problem LIKE 'grants file.owner%add a rule such as \"update owner_id : share\"'"
# ...and has nothing to say when nobody may update the row at all
sed 's/^  update  *: edit$/  update : nobody/' /tmp/authz_no_column_rule.authz | grep -v "update folder_id after" > /tmp/authz_update_nobody.authz
python3 compile_policy.py /tmp/authz_update_nobody.authz > /tmp/authz_update_nobody.sql &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_update_nobody.sql >/dev/null
admin "...and none where the rule is \"update : nobody\"" "0" \
  "SELECT count(*) FROM authz.lint() WHERE object LIKE 'app.files.%' AND problem LIKE 'grants %'"
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance.sql >/dev/null
PSQL -c "GRANT TRUNCATE ON app.files TO app_user" \
     -c "CREATE VIEW app.all_files AS SELECT * FROM app.files" -c "GRANT SELECT ON app.all_files TO app_user" \
     -c "GRANT INSERT, TRUNCATE ON app.team_members TO app_user" \
     -c "CREATE UNIQUE INDEX files_name ON app.files (folder_id, name)" \
     -c "CREATE FUNCTION app.peek(bigint) RETURNS text LANGUAGE sql SECURITY DEFINER AS 'SELECT name FROM app.files WHERE id = \$1'" >/dev/null
lint() { PSQL -c "SELECT severity || ' ' || object FROM authz.lint() ORDER BY 1" | grep -c -- "$1"; }
for want in "error app.files" "error app.all_files" "error app.team_members" "info app.files_name" "info app.files_pkey" "warning app.peek(bigint)"; do
  [ "$(lint "^$want\$")" -ge 1 ] && echo "ok    lint finds: $want" || { echo "FAIL  lint misses: $want"; fails=$((fails + 1)); }
done
# a table beside the policy's that it doesn't name: said, while the app role may read it
PSQL -c "CREATE TABLE app.secrets (id int PRIMARY KEY, hash text)" -c "GRANT SELECT ON app.secrets TO app_user" >/dev/null
admin "lint finds a table the policy doesn't name, which the app role may read" "info" \
  "SELECT severity FROM authz.lint() WHERE object = 'app.secrets' AND problem LIKE '%the policy doesn''t name this table%'"
PSQL -c "REVOKE SELECT ON app.secrets FROM app_user" -c "GRANT SELECT (id) ON app.secrets TO app_user" >/dev/null
admin "... also when it may read one column of it" "1" "SELECT count(*) FROM authz.lint() WHERE object = 'app.secrets'"
PSQL -c "REVOKE SELECT (id) ON app.secrets FROM app_user" >/dev/null
admin "... and not once it may not" "0" "SELECT count(*) FROM authz.lint() WHERE object = 'app.secrets'"
admin "... nor a table the policy names (users has no rules: its own line)" "1" "SELECT count(*) FROM authz.lint() WHERE object = 'app.users'"
PSQL -c "DROP TABLE app.secrets" >/dev/null
# a policy made by hand on a governed table: Postgres joins permissive policies with OR, so it widens the rules
ALL=$(PSQL -c "SELECT count(*) FROM app.files"); SEES=$(as 4 -c "SELECT count(*) FROM app.files")
[ "$SEES" -lt "$ALL" ] && echo "ok    dave sees $SEES of the $ALL files" || { echo "FAIL  dave sees $SEES of $ALL files"; fails=$((fails + 1)); }
PGOPTIONS="-c client_min_messages=error" PSQL -c "DROP ROLE IF EXISTS authz_gov_other" -c "CREATE ROLE authz_gov_other" \
     -c "CREATE POLICY mine ON app.files FOR SELECT TO app_user USING (true)" \
     -c "CREATE POLICY everyone ON app.folders USING (true) WITH CHECK (true)" \
     -c "CREATE POLICY narrower ON app.folders AS RESTRICTIVE TO app_user USING (name <> 'x')" \
     -c "CREATE POLICY theirs ON app.files TO authz_gov_other USING (true)" >/dev/null
check "... and every file through a policy of the owner's making" "$ALL" "SET authz.user_id = 4; SELECT count(*) FROM app.files"
admin "lint finds it: an error, with the policy's name and how to drop it" "error" \
  "SELECT severity FROM authz.lint() WHERE object = 'app.files' AND problem LIKE 'the policy mine (select)%DROP POLICY mine ON app.files%'"
admin "... one for PUBLIC and every command too" "error" \
  "SELECT severity FROM authz.lint() WHERE object = 'app.folders' AND problem LIKE 'the policy everyone (every command)%'"
admin "... a restrictive one is a note" "info" \
  "SELECT severity FROM authz.lint() WHERE object = 'app.folders' AND problem LIKE 'the restrictive policy narrower%'"
admin "... one for a role the app role isn't in is nobody's way around" "0" \
  "SELECT count(*) FROM authz.lint() WHERE problem LIKE '%theirs%'"
PSQL -c "DROP POLICY mine ON app.files" -c "DROP POLICY theirs ON app.files" -c "DROP POLICY everyone ON app.folders" \
     -c "DROP POLICY narrower ON app.folders" -c "DROP ROLE authz_gov_other" >/dev/null
admin "... rowstile's own policies are not reported" "0" "SELECT count(*) FROM authz.lint() WHERE problem LIKE '%not rowstile''s%'"
PSQL -c "GRANT CREATE ON SCHEMA app TO app_user" -c "ALTER TABLE app.files OWNER TO app_user" >/dev/null
[ "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE object = 'app.files' AND problem LIKE 'is owned by%'")" = "1" ] &&
  echo "ok    lint finds: a governed table owned by the app role" || { echo "FAIL  lint misses the owner"; fails=$((fails + 1)); }
PSQL -c "ALTER TABLE app.files OWNER TO CURRENT_USER" -c "REVOKE CREATE ON SCHEMA app FROM app_user" >/dev/null
PSQL -c "ALTER TABLE app.files DISABLE ROW LEVEL SECURITY" >/dev/null
admin "lint finds row-level security off on a table with rules: an error" "1"   "SELECT count(*) FROM authz.lint() WHERE severity = 'error' AND object = 'app.files' AND problem LIKE 'row-level security is off%'"
PSQL -c "ALTER TABLE app.files ENABLE ROW LEVEL SECURITY" >/dev/null
expect_code "the app role cannot run lint" "42501: permission denied for function lint" -c "SELECT * FROM authz.lint()"
# without its 'after' rule, moving a folder isn't checked where it goes
grep -v "update parent_id after" example/docs.authz > /tmp/authz_no_after.authz
python3 compile_policy.py /tmp/authz_no_after.authz > /tmp/authz_no_after.sql &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_no_after.sql >/dev/null
admin "lint finds a move nothing checks the destination of" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.folders.parent_id' AND problem LIKE 'moves a row under another%'"
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance.sql >/dev/null
admin "...and none with the rule back" "0" \
  "SELECT count(*) FROM authz.lint() WHERE problem LIKE 'moves a row under another%'"
# a row keyed by two columns, moved by the pair: lint names the pair and the rule to add (it failed on the pair as
# one column's name, and so did applying such a policy)
PSQL -c "CREATE TABLE app.gov_boxes (org_id bigint, id bigint, parent_id bigint, owner_id bigint, PRIMARY KEY (org_id, id))" \
     -c "GRANT SELECT, UPDATE ON app.gov_boxes TO app_user" >/dev/null
{ sed '/^test$/,$d' example/docs.authz
  printf 'type box = app.gov_boxes (org_id, id)\n  parent : box  = [org_id, parent_id]\n  owner  : user = owner_id\n  can edit = owner or parent.edit\n'
  printf 'rules app.gov_boxes\n  select : edit\n  update : edit\n'; } > /tmp/authz_boxes.authz
python3 compile_policy.py /tmp/authz_boxes.authz > /tmp/authz_boxes.sql &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_boxes.sql >/dev/null
admin "lint finds a move by a pair of columns, and says the rule to add" "1" \
  "SELECT count(*) FROM authz.lint() WHERE object = 'app.gov_boxes.org_id, parent_id' AND problem LIKE '%add a rule such as \"update org_id, parent_id after : parent.edit\"'"
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f /tmp/authz_governance.sql >/dev/null
PSQL -c "DROP TABLE app.gov_boxes" >/dev/null

echo "-- retention"
POS=$(PSQL -c "SELECT max(pos) FROM authz.changes")
PSQL -c "UPDATE authz.changes SET at = now() - interval '10 days'" -c "INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, 1, 5, 'kept')" >/dev/null
admin "the feed keeps 7 days by default: older entries are trimmed" "t" "SELECT authz.trim_changes() > 0"
admin "... all of them" "f" "SELECT EXISTS (SELECT 1 FROM authz.changes WHERE pos <= $POS)"
admin "... newer ones stay" "t" "SELECT EXISTS (SELECT 1 FROM authz.changes WHERE pos > $POS)"
expect_code "a reader behind the trimmed part is told to read everything again" "55000: the change feed up to position " -c "RESET ROLE" \
  -c "SELECT * FROM authz.changes_since(0)"
admin "... a reader past it goes on" "t" "SELECT count(*) > 0 FROM authz.changes_since($POS)"
PSQL -c "INSERT INTO authz.settings VALUES ('changes_keep', '1 hour')" >/dev/null
admin "how long the feed keeps entries is a setting" "0" "SELECT authz.trim_changes()"
expect_code "trimming the audit trail needs a period" "P0001: say how long to keep the audit trail, e.g. authz.trim_audit(interval '2 years')" -c "RESET ROLE" -c "SELECT authz.trim_audit(NULL)"
admin "entries younger than the period stay" "0" "SELECT authz.trim_audit(interval '1 day')"
N=$(PSQL -c "SELECT count(*) FROM authz.audit")
admin "... older ones go" "$N" "SELECT authz.trim_audit(interval '0')"
admin "... and the trim is recorded" "trim_audit|$N" \
  "SELECT action || '|' || (detail ->> 'rows') FROM authz.audit ORDER BY id DESC LIMIT 1"
expect_code "the trail still cannot be edited otherwise" "42501: the audit trail cannot be changed" -c "RESET ROLE" -c "DELETE FROM authz.audit"
expect_code "... whatever the session sets" "42501: the audit trail cannot be changed" -c "RESET ROLE" -c "SET authz_int.trim_before = '2999-01-01'" \
  -c "DELETE FROM authz.audit"
admin "... and the trigger is on again after a trim" "O" \
  "SELECT tgenabled FROM pg_trigger WHERE tgrelid = 'authz.audit'::regclass AND tgname = 'authz_audit_append_only'"
expect_code "the app role cannot trim" "42501: permission denied for function trim_audit" -c "SELECT authz.trim_audit(interval '0')"
# emptying a governed table whose own columns hold relations (a file's folder and owner): last, the files are gone
POS=$(PSQL -c "SELECT coalesce(max(pos), 0) FROM authz.changes")
PSQL -c "TRUNCATE app.files" >/dev/null
admin "emptying a table whose columns hold relations is recorded" "truncate|app.files" \
  "SELECT action || '|' || (detail ->> 'table') FROM authz.audit WHERE action = 'truncate' AND object_type = 'file'"
admin "... and announced for every file" "1" \
  "SELECT count(*) FROM authz.changes WHERE pos > $POS AND object_type = 'file' AND object_ids = '{*}'"
admin "inheritance tables still match a rebuild" "t" "SELECT authz.verify()"
dropdb "$DB"
if [ $fails -eq 0 ]; then echo "governance: all passed"; else echo "governance: $fails failed"; exit 1; fi
