# API Reference

GraphQL endpoint: `POST /graphql` (default `http://localhost:4000/graphql`).

All examples below were captured against the running server.

---

## Authentication and nonce handling

`Authorization: Bearer <token>` goes on every authenticated call, sealed or not.

The nonce has two ways in:

| Where | When |
| --- | --- |
| Inside the envelope, as a `nonce` field | A client with a channel. Nothing is visible on the wire. |
| `X-NONCE` header | A client without one — curl, GraphiQL, the verification script. `X-CSRF-TOKEN` is accepted as an alias. |
| `$nonce` or `$input.nonce` variable | Same, for callers that would rather put it in the body. |

The rules the server applies:

- **Queries show a nonce but never consume it.** `me`, `todos` and `getTodo`
  are refused without one (`NONCE_MISSING`), and the same nonce serves as many
  reads as you like - only a mutation retires it.
  Everything is checked unless the server exempts it in
  `NONCE_DISABLED_OPERATIONS`; it names the exemptions in its startup log.
- **Mutations consume exactly one nonce** and return a replacement in the
  response payload. Store it and use it for the next mutation.
- **One protected mutation per request.** GraphQL will happily execute several
  root fields in one document; a single nonce does not authorise them all. A
  request selecting two protected mutations is rejected with
  `NONCE_MULTIPLE_OPERATIONS` and **nothing runs and nothing is consumed**.
- **A failed mutation still returns a nonce.** The nonce is consumed before the
  resolver runs, so when a mutation then fails on its own rules the replacement
  arrives in the error's `extensions.nonce`. Read it from there as well as from
  the payload, or the client is left holding a spent token.
- The `nonce` field inside `CreateTodoInput` / `UpdateTodoInput` and the `nonce`
  argument on `deleteTodo` are optional, and read only when nothing else carried
  a nonce.
- **Todo content is stored as it arrives.** The server does not encrypt it and
  could not read it any less than it does: `db.json` holds plain text. The
  protection is on the wire, not at rest.

---

## The encrypted channel

A client that completes the handshake at sign-in sends and receives envelopes
instead of JSON:

```json
{
  "v": 1,
  "nid": "3c8b5ce03a5ea6282b07e5afe905cf41b99fde41f69a0aac86a108735e43f2ad",
  "iv": "Sewi3wnWNg9jZQgT",
  "ct": "1PFFIOwzT0ylOljbAthhQvCixZgDIjorR0Bq8htN/dFxPaff…"
}
```

- `nid` is `sha256(nonce)` - which nonce keys this message, and the only field
  that is not secret. It is what the server already stores, so naming it here
  gives away nothing new.
- `ct` holds the whole GraphQL request: `query`, `variables`, `operationName`,
  and the raw `nonce`. The server lifts the nonce out after decrypting and hands
  it to the replay check, so it never travels in a header.
- The reply comes back in the same shape, including the rotated nonce.

How the keys work:

| Step | |
| --- | --- |
| Secret | ECDH P-256 at sign-in. Neither side transmits it. |
| Message key | `HKDF-SHA256(secret, salt = nid, info = "nonce-transport-v1\|req"` or `"…\|res")` |
| Cipher | AES-256-GCM, 12 random bytes of IV, `nid` as additional authenticated data |

A request that is not an envelope is passed through untouched, and answered in
the clear. That is how curl, GraphiQL and `scripts/e2e-verify.sh` work; the
examples below are all written that way.

Failures to open anything - a wrong key, a flipped byte, a nonce the server does
not know - come back as `TRANSPORT_UNREADABLE` (400) with no detail about which.

---

## Mutations

### getNonce

The challenge, and the key agreement. Public: a client with no credentials
cannot authenticate in order to ask for the thing it needs to authenticate.

```graphql
mutation GetNonce($username: String!, $clientPublicKey: String) {
  getNonce(username: $username, clientPublicKey: $clientPublicKey) {
    nonce
    serverPublicKey
  }
}
```

```json
{
  "data": {
    "getNonce": {
      "nonce": "4048d1e1720631a22caa9b8ac9ce72b94b623b5a11f64d3e9a5814b2f9a847f5",
      "serverPublicKey": "BKq1xk3eZ9…"
    }
  }
}
```

- The challenge is a nonce: single use, two-minute TTL, spent by the login that
  answers it whether that login succeeds or fails.
- `clientPublicKey` is a raw P-256 public point, base64. Send one and the reply
  carries the server's, and every later message can be sealed. Omit it and the
  session simply has no channel.
- An account that does not exist gets a challenge too. Anything else would turn
  this into a way to find out who has an account here.

---

### login

Answers a challenge. The password is not a parameter.

```graphql
mutation Login($username: String!, $nonce: String!, $cnonce: String!, $response: String!) {
  login(username: $username, nonce: $nonce, cnonce: $cnonce, response: $response) {
    user { id email createdAt }
    session { id userId expiresAt status }
    token
    nonce
  }
}
```

What the client computes:

```
ha1      = sha256( username : nonce-todo : password )
response = sha256( ha1 : nonce : cnonce )
```

`cnonce` is the client's own nonce, so the server does not get to choose every
input to the digest. `nonce` is the challenge being answered - the server needs
it back to find the challenge and to recompute the hash, the same way RFC 2617
sends it back in the `Authorization` header.

Response:

```json
{
  "data": {
    "login": {
      "user": { "id": "user_demo", "email": "user@example.com" },
      "session": { "id": "session_38f67b66-…", "status": "ACTIVE" },
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "nonce": "6274962af1578eb1df9e4b6130f85d48c2318c606635cbbfa1d..."
    }
  }
}
```

For a client that sent a public key to `getNonce`, all of that arrives sealed:
the token and the first nonce are never in the open.

Every failure - unknown account, no open challenge, the wrong challenge, a bad
digest - answers the same way:

```json
{
  "errors": [
    {
      "message": "Invalid email or password",
      "extensions": { "error_code": "INVALID_CREDENTIALS", "http": { "status": 401 } }
    }
  ],
  "data": null
}
```

Replaying a captured login gets that answer too: the challenge it carries was
spent the first time.

---

### createTodo

```graphql
mutation CreateTodo($input: CreateTodoInput!) {
  createTodo(input: $input) {
    todo { id title description completed createdAt updatedAt }
    nonce
  }
}
```

```bash
curl -X POST http://localhost:4000/graphql \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-NONCE: $NONCE" \
  -d '{"query":"mutation{createTodo(input:{title:\"Buy milk\",description:\"Semi-skimmed\"}){todo{id title completed} nonce}}"}'
```

```json
{
  "data": {
    "createTodo": {
      "todo": {
        "id": "todo_998ae0c2-2494-488e-a22e-d02cfcf78f90",
        "title": "Buy milk",
        "completed": false
      },
      "nonce": "f255f4e49ab3bc38a1364181935bebf799d980d4378a56f53fb9478c60707e90"
    }
  }
}
```

The returned `nonce` replaces the one just spent.

---

### updateTodo

Only fields present in `input` change; omitted fields keep their values.

```graphql
mutation UpdateTodo($id: ID!, $input: UpdateTodoInput!) {
  updateTodo(id: $id, input: $input) {
    todo { id title description completed updatedAt }
    nonce
  }
}
```

```json
{
  "data": {
    "updateTodo": {
      "todo": { "id": "todo_f42f3c97", "title": "Walk the dog", "completed": true },
      "nonce": "1b2a2c893c8c16d9834463d51030a62c858a80043c30095444bc54e55d4b0848"
    }
  }
}
```

A todo belonging to another user reports `TODO_NOT_FOUND` (404) rather than a
permission error, so the response does not confirm that the id exists.

---

### deleteTodo

```graphql
mutation DeleteTodo($id: ID!) {
  deleteTodo(id: $id) {
    todo { id }
    nonce
  }
}
```

```json
{
  "data": {
    "deleteTodo": {
      "todo": { "id": "todo_f42f3c97" },
      "nonce": "ca6aae74a0eb61eabe2080a68d8ce2e069ab7e717808576257e5bb043cecac52"
    }
  }
}
```

The deleted todo is returned so the client can confirm what was removed.

---

### refreshNonce

Issues a fresh nonce for the current session. Authenticated, but it takes no
nonce of its own - a client asking for a nonce is by definition a client without
a usable one, and requiring one here would make every spent or expired nonce a
dead end ending in a forced sign-in.

```graphql
mutation RefreshNonce {
  refreshNonce { nonce }
}
```

```json
{
  "data": {
    "refreshNonce": {
      "nonce": "6bea3421f3cfef40b73455509048ff0de5bd0c8602345c930154c99b545ca5bf"
    }
  }
}
```

It issues only to the caller's own session, and changes nothing else, so no
replay can profit from it.

---

### logout

Revokes the session and the nonces issued to **that session**. The user's other
sessions keep working - signing out of one tab does not break another.

```graphql
mutation Logout {
  logout { success message }
}
```

```json
{ "data": { "logout": { "success": true, "message": "Logged out successfully" } } }
```

Afterwards the JWT stops working immediately, before its own expiry:

```json
{
  "errors": [{ "message": "Your session is no longer active. Please log in again" }],
  "data": { "me": null }
}
```

---

## Queries

### me

```graphql
query GetMe { me { id email createdAt } }
```

```json
{ "data": { "me": { "id": "user_demo", "email": "user@example.com" } } }
```

### todos

Relay-style cursor pagination, ordered oldest first. `first` defaults to 10 and
is capped at 100.

```graphql
query GetTodos($first: Int, $after: String) {
  todos(first: $first, after: $after) {
    totalCount
    edges {
      cursor
      node { id title description completed createdAt updatedAt }
    }
    pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
  }
}
```

```json
{
  "data": {
    "todos": {
      "totalCount": 2,
      "edges": [
        {
          "node": { "id": "todo_998ae0c2", "title": "Buy milk", "completed": false },
          "cursor": "dG9kbzp0b2RvXzk5OGFlMGMy"
        }
      ],
      "pageInfo": { "hasNextPage": true, "endCursor": "dG9kbzp0b2RvXzk5OGFlMGMy" }
    }
  }
}
```

Pass `endCursor` back as `after` for the next page. An unrecognised cursor is
rejected with `Invalid pagination cursor` rather than silently restarting at
page one.

### getTodo

```graphql
query GetTodo($id: ID!) { getTodo(id: $id) { id title completed } }
```

Returns `TODO_NOT_FOUND` (404) for a missing todo *or* one owned by someone else.

---

## Error responses

Every error carries the same three fields in `extensions`:

```json
{
  "error_code": "NONCE_EXPIRED",
  "suggested_action": "Your session has expired. Please refresh and try again",
  "http": { "status": 401 }
}
```

### Nonce errors

| `error_code`             | Status | Cause                                     |
| ------------------------ | ------ | ----------------------------------------- |
| `NONCE_MISSING`          | 403    | No `X-NONCE` header on a mutation         |
| `NONCE_INVALID`          | 401    | Nonce was never issued by this server     |
| `NONCE_EXPIRED`          | 401    | Past its TTL (default 5 minutes)          |
| `NONCE_ALREADY_USED`     | 403    | Replay of a consumed nonce                |
| `NONCE_BINDING_MISMATCH` | 403    | Bound to a different user, session or client |
| `NONCE_RACE_CONDITION`   | 409    | Concurrent request consumed it first      |
| `NONCE_MULTIPLE_OPERATIONS` | 403 | Several protected mutations in one request |

### Transport errors

| `error_code`           | Status | Cause                                        |
| ---------------------- | ------ | -------------------------------------------- |
| `TRANSPORT_UNREADABLE` | 400    | A sealed request that would not open: wrong key, tampered bytes, or a nonce this server does not know |

It arrives in the clear - there is no key to seal it with - and says nothing
about which of those it was.

Missing nonce:

```json
{
  "errors": [
    {
      "message": "CSRF token missing. Please refresh the page and try again.",
      "path": ["createTodo"],
      "extensions": {
        "error_code": "NONCE_MISSING",
        "suggested_action": "Include a valid CSRF token in your request",
        "http": { "status": 403 }
      }
    }
  ]
}
```

Replayed nonce:

```json
{
  "errors": [
    {
      "message": "This request has already been processed. Please try again with a new request.",
      "extensions": {
        "error_code": "NONCE_ALREADY_USED",
        "suggested_action": "Try again with a new request",
        "http": { "status": 403 }
      }
    }
  ]
}
```

### Auth errors

| `error_code`          | Status | Cause                                  |
| --------------------- | ------ | -------------------------------------- |
| `NOT_AUTHENTICATED`   | 401    | Missing or unusable token              |
| `INVALID_TOKEN`       | 401    | Bad signature, wrong format, no claims |
| `TOKEN_EXPIRED`       | 401    | Expired token, or a revoked session    |
| `INVALID_CREDENTIALS` | 401    | Wrong email or password                |
| `TODO_NOT_FOUND`      | 404    | Missing, or owned by someone else      |

---

## Client integration pattern

The reference implementation is
[`client/src/crypto/channel.ts`](../client/src/crypto/channel.ts) and
[`transport.ts`](../client/src/crypto/transport.ts). The shape of it:

```ts
// once, at sign-in
const { publicKey, complete } = await startHandshake();
const { nonce: challenge, serverPublicKey } = await getNonce(username, publicKey);
const secret = await complete(serverPublicKey);          // never transmitted

const ha1 = await sha256Hex(`${username}:nonce-todo:${password}`);
const digest = await sha256Hex(`${ha1}:${challenge}:${cnonce}`);
const { token, nonce } = await sealedPost(challenge, secret, loginRequest(digest));

// every request after that
async function call(query, variables, { isMutation }) {
  const nid = await sha256Hex(nonce);                    // salts this message's key
  const body = { query, variables, nonce };              // the nonce rides inside
  const reply = await post(await seal(JSON.stringify(body), secret, nid), token);
  const json = JSON.parse(await open(reply, secret));

  // Always keep a rotated nonce, even alongside errors: a mutation that
  // consumed its nonce and then failed returns the replacement in extensions
  const rotated =
    Object.values(json.data ?? {})[0]?.nonce ??
    json.errors?.find((error) => error.extensions?.nonce)?.extensions?.nonce;
  if (rotated) nonce = rotated;

  const code = json.errors?.[0]?.extensions?.error_code;
  if (code === 'NONCE_EXPIRED' || code === 'NONCE_RACE_CONDITION') {
    // Recoverable: retry once with the fresh nonce
  }

  return json;
}
```

Retry only `NONCE_EXPIRED` and `NONCE_RACE_CONDITION`. The others cannot succeed
on a retry and looping on them only burns the user's retry budget.

When there is no nonce left to retry with - the client never had one, or lost
it - call `refreshNonce` rather than sending the user back to the login form.
It is the one authenticated request that may have to go out in the clear, and
the one that carries nothing worth hiding.
