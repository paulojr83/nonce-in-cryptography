#!/usr/bin/env bash
# End-to-end verification of the nonce authentication flow.
#
#   API=http://localhost:4000/graphql ./scripts/e2e-verify.sh
#
# Exits non-zero if any check fails.

set -u
API="${API:-http://localhost:4000/graphql}"
EMAIL="${EMAIL:-user@example.com}"
PASSWORD="${PASSWORD:-DemoPassword123!}"

pass=0; fail=0
check() { # check <name> <condition-result>
  if [ "$2" = "0" ]; then printf '  PASS  %s\n' "$1"; pass=$((pass+1));
  else printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); fi
}
gql() { curl -s -m 10 -X POST "$API" -H 'Content-Type: application/json' "$@"; }
sha256() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
rand_hex() { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' 
'; }

# The verifier the server stores. The client computes it from what the user
# typed; neither side ever puts the password on the wire.
HA1=$(sha256 "$EMAIL:nonce-todo:$PASSWORD")

# Ask for a challenge, answer it with a digest. No ECDH here on purpose: this
# script is the client without a handshake, which is the path curl and GraphiQL
# take, and it keeps the nonce lifecycle readable in the terminal.
challenge() {
  gql -d "{\"query\":\"mutation{getNonce(username:\\\"$EMAIL\\\"){nonce}}\"}"
}

answer() { # answer <nonce> <cnonce> <digest>
  gql -d "{\"query\":\"mutation{login(username:\\\"$EMAIL\\\",nonce:\\\"$1\\\",cnonce:\\\"$2\\\",response:\\\"$3\\\"){token nonce session{id status} user{id email}}}\"}"
}

sign_in() {
  local ch nonce cnonce digest
  ch=$(challenge)
  nonce=$(field "$ch" nonce)
  cnonce=$(rand_hex)
  digest=$(sha256 "$HA1:$nonce:$cnonce")
  answer "$nonce" "$cnonce" "$digest"
}
gql_as() { local agent="$1"; shift; curl -s -m 10 -X POST "$API" -A "$agent" -H 'Content-Type: application/json' "$@"; }
field() { sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p" <<<"$1"; }

echo "== 1. Login =="
LOGIN=$(sign_in)
TOKEN=$(field "$LOGIN" token); NONCE=$(field "$LOGIN" nonce)
check "login returns a token"          "$([ -n "$TOKEN" ] && echo 0 || echo 1)"
check "login returns a nonce"          "$([ -n "$NONCE" ] && echo 0 || echo 1)"
check "session is ACTIVE"              "$(grep -q '"status":"ACTIVE"' <<<"$LOGIN" && echo 0 || echo 1)"
check "no verifier in the response"    "$(grep -q "$HA1" <<<"$LOGIN" && echo 1 || echo 0)"

echo "== 2. The login challenge is a nonce ==" 
CH=$(challenge); CH_NONCE=$(field "$CH" nonce)
CH_CNONCE=$(rand_hex); CH_DIGEST=$(sha256 "$HA1:$CH_NONCE:$CH_CNONCE")
FIRST=$(answer "$CH_NONCE" "$CH_CNONCE" "$CH_DIGEST")
check "the digest is accepted once"    "$([ -n "$(field "$FIRST" token)" ] && echo 0 || echo 1)"
AGAIN=$(answer "$CH_NONCE" "$CH_CNONCE" "$CH_DIGEST")
check "the same login cannot be replayed" "$(grep -q 'Invalid email or password' <<<"$AGAIN" && echo 0 || echo 1)"

CH2=$(challenge); CH2_NONCE=$(field "$CH2" nonce)
WRONG=$(answer "$CH2_NONCE" "$(rand_hex)" "$(sha256 "$(sha256 "$EMAIL:nonce-todo:wrong-password"):$CH2_NONCE:x")")
check "a wrong digest is refused"      "$(grep -q 'Invalid email or password' <<<"$WRONG" && echo 0 || echo 1)"

UNKNOWN=$(gql -d '{"query":"mutation{getNonce(username:\"nobody@example.com\"){nonce}}"}')
check "an unknown account still gets a challenge" "$([ -n "$(field "$UNKNOWN" nonce)" ] && echo 0 || echo 1)"

echo "== 3. Queries need no nonce =="
TODOS=$(gql -H "Authorization: Bearer $TOKEN" -d '{"query":"query{todos(first:10){totalCount pageInfo{hasNextPage endCursor}}}"}')
check "todos query succeeds"           "$(grep -q '"totalCount"' <<<"$TODOS" && echo 0 || echo 1)"
ME=$(gql -H "Authorization: Bearer $TOKEN" -d '{"query":"query{me{id email}}"}')
check "me query succeeds"              "$(grep -q "$EMAIL" <<<"$ME" && echo 0 || echo 1)"

echo "== 4. Mutation without a nonce is rejected =="
NO_NONCE=$(gql -H "Authorization: Bearer $TOKEN" -d '{"query":"mutation{createTodo(input:{title:\"no nonce\"}){todo{id}}}"}')
check "rejected with NONCE_MISSING"    "$(grep -q 'NONCE_MISSING' <<<"$NO_NONCE" && echo 0 || echo 1)"

echo "== 5. Mutation with a nonce succeeds and rotates =="
CREATE=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $NONCE" -d '{"query":"mutation{createTodo(input:{title:\"e2e todo\",description:\"created by the verification script\"}){todo{id title completed} nonce}}"}')
TODO_ID=$(field "$CREATE" id); NEW_NONCE=$(field "$CREATE" nonce)
check "todo created"                   "$([ -n "$TODO_ID" ] && echo 0 || echo 1)"
check "nonce rotated"                  "$([ "$NEW_NONCE" != "$NONCE" ] && [ -n "$NEW_NONCE" ] && echo 0 || echo 1)"

echo "== 6. Replaying the consumed nonce fails =="
REPLAY=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $NONCE" -d '{"query":"mutation{createTodo(input:{title:\"replay\"}){todo{id}}}"}')
check "rejected as already used"       "$(grep -q 'NONCE_ALREADY_USED' <<<"$REPLAY" && echo 0 || echo 1)"

echo "== 7. Update rotates again =="
UPDATE=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $NEW_NONCE" -d "{\"query\":\"mutation{updateTodo(id:\\\"$TODO_ID\\\",input:{completed:true}){todo{id completed} nonce}}\"}")
UPD_NONCE=$(field "$UPDATE" nonce)
check "todo marked complete"           "$(grep -q '"completed":true' <<<"$UPDATE" && echo 0 || echo 1)"
check "nonce rotated again"            "$([ "$UPD_NONCE" != "$NEW_NONCE" ] && [ -n "$UPD_NONCE" ] && echo 0 || echo 1)"

echo "== 8. An invalid nonce is refused =="
FORGED=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $(printf 'f%.0s' {1..64})" -d '{"query":"mutation{createTodo(input:{title:\"forged\"}){todo{id}}}"}')
check "rejected as invalid"            "$(grep -q 'NONCE_INVALID' <<<"$FORGED" && echo 0 || echo 1)"

echo "== 9. Delete rotates and removes =="
DELETE=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $UPD_NONCE" -d "{\"query\":\"mutation{deleteTodo(id:\\\"$TODO_ID\\\"){todo{id} nonce}}\"}")
DEL_NONCE=$(field "$DELETE" nonce)
check "delete succeeded"               "$(grep -q "$TODO_ID" <<<"$DELETE" && echo 0 || echo 1)"
GONE=$(gql -H "Authorization: Bearer $TOKEN" -d "{\"query\":\"query{getTodo(id:\\\"$TODO_ID\\\"){id}}\"}")
check "todo is gone"                   "$(grep -q 'TODO_NOT_FOUND' <<<"$GONE" && echo 0 || echo 1)"

echo "== 10. One nonce authorises one operation =="
CUR=$DEL_NONCE
MULTI=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $CUR" -d '{"query":"mutation{ a: createTodo(input:{title:\"multi a\"}){todo{id}} b: createTodo(input:{title:\"multi b\"}){todo{id}} }"}')
check "two mutations on one nonce refused" "$(grep -q 'NONCE_MULTIPLE_OPERATIONS' <<<"$MULTI" && echo 0 || echo 1)"
check "neither mutation ran"            "$(grep -q '"todo"' <<<"$MULTI" && echo 1 || echo 0)"
SURVIVED=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $CUR" -d '{"query":"mutation{createTodo(input:{title:\"after the refusal\"}){todo{id} nonce}}"}')
SURV_ID=$(field "$SURVIVED" id); CUR=$(field "$SURVIVED" nonce)
check "the refusal did not spend the nonce" "$([ -n "$SURV_ID" ] && echo 0 || echo 1)"
CLEAN=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $CUR" -d "{\"query\":\"mutation{deleteTodo(id:\\\"$SURV_ID\\\"){todo{id} nonce}}\"}")
CUR=$(field "$CLEAN" nonce)

echo "== 11. A failed mutation still hands back a nonce =="
FAILED=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $CUR" -d '{"query":"mutation{createTodo(input:{title:\"   \"}){todo{id} nonce}}"}')
REPLACEMENT=$(field "$FAILED" nonce)
check "the mutation failed on its own rule" "$(grep -q 'Todo title is required' <<<"$FAILED" && echo 0 || echo 1)"
check "a replacement nonce came back"    "$([ -n "$REPLACEMENT" ] && [ "$REPLACEMENT" != "$CUR" ] && echo 0 || echo 1)"
RECOVERED=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $REPLACEMENT" -d '{"query":"mutation{createTodo(input:{title:\"recovered\"}){todo{id} nonce}}"}')
REC_ID=$(field "$RECOVERED" id); CUR=$(field "$RECOVERED" nonce)
check "the replacement works"            "$([ -n "$REC_ID" ] && echo 0 || echo 1)"
CLEAN=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $CUR" -d "{\"query\":\"mutation{deleteTodo(id:\\\"$REC_ID\\\"){todo{id} nonce}}\"}")
CUR=$(field "$CLEAN" nonce)

echo "== 12. A nonce belongs to one session =="
OTHER=$(sign_in)
OTHER_TOKEN=$(field "$OTHER" token); OTHER_NONCE=$(field "$OTHER" nonce)
CROSS=$(gql -H "Authorization: Bearer $OTHER_TOKEN" -H "X-NONCE: $CUR" -d '{"query":"mutation{createTodo(input:{title:\"wrong session\"}){todo{id}}}"}')
check "a nonce from another session is refused" "$(grep -q 'NONCE_BINDING_MISMATCH' <<<"$CROSS" && echo 0 || echo 1)"
gql -H "Authorization: Bearer $OTHER_TOKEN" -H "X-NONCE: $OTHER_NONCE" -d '{"query":"mutation{logout{success}}"}' > /dev/null

echo "== 13. A nonce belongs to one client =="
OTHER_AGENT=$(gql_as 'not-the-client/1.0' -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $CUR" -d '{"query":"mutation{createTodo(input:{title:\"wrong agent\"}){todo{id}}}"}')
check "a nonce from another client is refused" "$(grep -q 'NONCE_BINDING_MISMATCH' <<<"$OTHER_AGENT" && echo 0 || echo 1)"

echo "== 14. A client without a nonce can get one =="
ANON_REFRESH=$(gql -d '{"query":"mutation{refreshNonce{nonce}}"}')
check "refreshNonce requires a session"  "$(grep -q 'Authentication required' <<<"$ANON_REFRESH" && echo 0 || echo 1)"
REFRESHED=$(gql -H "Authorization: Bearer $TOKEN" -d '{"query":"mutation{refreshNonce{nonce}}"}')
FRESH=$(field "$REFRESHED" nonce)
check "refreshNonce issues one"          "$([ -n "$FRESH" ] && echo 0 || echo 1)"

echo "== 15. Unauthenticated access is refused =="
ANON=$(gql -d '{"query":"query{me{id}}"}')
check "me requires authentication"     "$(grep -q 'Authentication required' <<<"$ANON" && echo 0 || echo 1)"

echo "== 16. Logout revokes the session =="
LOGOUT=$(gql -H "Authorization: Bearer $TOKEN" -H "X-NONCE: $FRESH" -d '{"query":"mutation{logout{success}}"}')
check "the refreshed nonce works"      "$(grep -q '"success":true' <<<"$LOGOUT" && echo 0 || echo 1)"
AFTER=$(gql -H "Authorization: Bearer $TOKEN" -d '{"query":"query{me{id}}"}')
check "old token no longer works"      "$(grep -q 'no longer active' <<<"$AFTER" && echo 0 || echo 1)"

echo
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
