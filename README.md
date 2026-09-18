# Nonce in Cryptography — a working demonstration

A todo app whose state-changing operations are protected by **single-use
cryptographic nonces**. It exists to show one idea concretely:

> A token that is valid exactly once cannot be replayed.

Every mutation must present a nonce that the server issued, has never seen used,
has not expired, and that belongs to this caller — their user, their session,
their client. Using it consumes it and returns a fresh one. Replaying it fails,
and so does spending one nonce on two operations.

---

## Quick start

Requires Node.js 18+.

```bash
npm install
```

Start the database (json-server):

```bash
npm run db --workspace=server
```

Then the API and the web app:

```bash
npm run dev
```

- Web app: <http://localhost:3000>
- API: <http://localhost:4000/graphql>
- Database: <http://localhost:3001>

Sign in with `user@example.com` / `DemoPassword123!`. The demo account is seeded
automatically on first start.

The API also runs without json-server — it warns and keeps everything in memory,
which is fine for a quick look but loses state on restart.

---

## The seven properties of a nonce

Most live in [`nonce-service.ts`](server/src/services/nonce-service.ts); the last
one is a property of the *request*, so it lives in
[`nonce-validation-middleware.ts`](server/src/middleware/nonce-validation-middleware.ts).
Every one of them is exercised by [`e2e-verify.sh`](scripts/e2e-verify.sh)
against the running server.

| # | Property | How it is enforced | Failure |
| - | -------- | ------------------ | ------- |
| 1 | **Unpredictable** | `crypto.randomBytes(NONCE_LENGTH)` — 256 bits by default | — |
| 2 | **Never stored raw** | Only `sha256(nonce)` is persisted | — |
| 3 | **Single use** | `used` flag checked on every validation | `NONCE_ALREADY_USED` (403) |
| 4 | **Expires** | `NONCE_TTL` (5 min), then a cleanup job deletes it | `NONCE_EXPIRED` (401) |
| 5 | **Bound to a caller** | Checked against `user_id`, `session_id` and the client's user agent | `NONCE_BINDING_MISMATCH` (403) |
| 6 | **Atomically consumed** | Compare-and-set, so only one concurrent request wins | `NONCE_RACE_CONDITION` (409) |
| 7 | **Authorises one operation** | A request selecting several protected mutations is refused whole | `NONCE_MULTIPLE_OPERATIONS` (403) |

Property 6 is worth a caveat: twelve simultaneous requests on one nonce do leave
exactly one winner, but the losers answer `NONCE_ALREADY_USED`, not the 409.
Reaching that code needs two requests to pass validation before either consumes,
and an in-memory repository leaves nothing but microtasks in that gap - Node
will not interleave another request there. The compare-and-set is what makes the
outcome deterministic; the 409 is what it will answer once a repository does
real I/O in that gap.

Property 7 is the one a GraphQL server has to add for itself. A single request
can select any number of root fields, and the executor runs them all — so
without it, one nonce would cover `a: createTodo … b: createTodo …` and "used
once" would mean once per *request* rather than once per *operation*.

---

## The flow

```
  Browser                                   Server
     │                                         │
     │  getNonce(user, clientPublicKey)        │
     │────────────────────────────────────────▶│  issue challenge C (a nonce)
     │                                         │  agree secret S over ECDH
     │◀────────────────────────────────────────│  keep S on C
     │   C, serverPublicKey                    │
     │                                         │
     │  derive S                               │
     │  digest = sha256(HA1 : C : cnonce)      │
     │                                         │
     │  ┌ sealed with S, salted by C ────────┐ │
     │  │ login(user, C, cnonce, digest)     │ │
     │  └────────────────────────────────────┘ │
     │────────────────────────────────────────▶│  consume C - right or wrong
     │                                         │  recompute the digest from HA1
     │                                         │  create session, carry S
     │                                         │  issue nonce N1
     │◀────────────────────────────────────────│  ┌ sealed ──────────────────┐
     │   token, N1  (only after opening)       │  │ token, N1                │
     │                                         │  └──────────────────────────┘
     │  ┌ sealed with S, salted by N1 ───────┐ │
     │  │ createTodo(...), nonce: N1         │ │
     │  └────────────────────────────────────┘ │
     │────────────────────────────────────────▶│  open it, lift N1 out
     │                                         │  N1 known? unused? not expired?
     │                                         │  bound to this caller?
     │                                         │  consume N1 (atomic)
     │◀────────────────────────────────────────│  create todo, issue N2, seal
     │   todo, N2  (only after opening)        │
     │                                         │
     │  the same sealed request again          │
     │────────────────────────────────────────▶│  N1 already consumed
     │◀────────────────────────────────────────│  403 NONCE_ALREADY_USED
```

**The password is never sent.** Sign-in is challenge-response: the client
answers the server's nonce with `sha256(HA1 : nonce : cnonce)`, and the server
recomputes it from a stored verifier. Capturing that exchange buys nothing - the
challenge is a nonce, spent by the attempt that answers it, right or wrong.

**Queries never consume a nonce.** A read that spent one would break the
rotation every mutation depends on.

**A failed mutation still hands back a nonce.** Consumption happens before the
resolver runs — that is what makes it atomic — so a mutation that then fails on
its own rules (an empty title, a todo that is not yours) would otherwise leave
the caller holding a spent token. The replacement rides along in the error's
`extensions.nonce`.

**A client with no nonce is not stuck.** `refreshNonce` issues one for the
session the caller is already authenticated for. It is the one mutation that
takes no nonce, because requiring one would be a deadlock: the clients that need
it are exactly the clients that have none.

On the client, no component ever touches a nonce: the Relay network layer
injects the current one and stores the rotated one — from the payload, from the
response extensions, or from an error's extensions
([`nonce-middleware.ts`](client/src/relay/nonce-middleware.ts)).

---

## What travels, and what it looks like

```
  what you type        mensagem que nao pode aparecer
  POST /graphql        {"v":1,"nid":"3c8b5ce03a5e…","iv":"Sewi3wnWNg9jZQgT","ct":"1PFFIOwzT0ylOljb…"}
  the reply            {"v":1,"nid":"3c8b5ce03a5e…","iv":"OxfWYfhgy8R+HjQ5","ct":"nF3pQ0rTbKk8Yd2x…"}
  db.json              mensagem que nao pode aparecer
  the component        mensagem que nao pode aparecer
```

Stored in the clear, carried encrypted. The database is readable by anyone who
can read the database - that was never what this protects - and the network is
not.

**How the key is agreed.** Sign-in carries an ECDH P-256 public key; the server
answers with its own and both sides compute the same 32 bytes. Nothing that
secret is derived from ever crosses the wire, which is the part a key derived
from the nonce alone could not manage: the nonce has to travel for the replay
check, so anyone reading it would hold the key with the message it protects.

**What the nonce does here.** It salts the key. Each message's key is
`HKDF(secret, salt = sha256(nonce), info = direction)`, so a key covers one
exchange and no more - the same "used once" rule the replay protection runs on,
applied to key material. Request and reply take different keys from the same
salt, so neither can be replayed as the other. The salt is the nonce's hash and
not the nonce, because the server stores only the hash and should not need the
raw value to read a message; an HKDF salt does not have to be secret.

**Why the IV is still random.** A query does not consume its nonce, so several
messages can legitimately share one. An IV derived from the nonce would then
repeat under a single key, and a repeated IV is the one mistake AES-GCM cannot
survive. The IV is 12 random bytes in the envelope; the nonce's hash goes in as
additional authenticated data, so a message cannot be moved onto another nonce
without breaking the tag.

**The nonce rides inside.** The raw nonce is in the ciphertext, not in a header,
and is lifted out server-side after decryption. So the value the replay check
needs is never visible, and neither is the rotated one coming back.

**Plain JSON still works.** A request that is not an envelope is passed through
untouched, which is how curl, GraphiQL and `e2e-verify.sh` still work. That is a
deliberate door, not an oversight: a demonstration you cannot poke at with curl
teaches less.

### What this is not

- **Not a replacement for TLS.** ECDH with no certificate stops a passive
  listener, not an active one who substitutes their own public key for the
  server's. Proving the key belongs to the server is exactly what certificates
  do, and nothing here substitutes for them.
- **Not invisible to your own DevTools** in any meaningful sense. Your browser
  holds the secret; the ciphertext in the Network tab is the same ciphertext an
  attacker would see, which is the point.
- **HA1 is password-equivalent.** Challenge-response means the server stores a
  value it can recompute a digest from, so whoever steals the database can
  authenticate as that user. They still cannot learn the password or reuse it
  elsewhere, but bcrypt would not have let them in at all. That is the price of
  a server that can verify a digest it did not choose the inputs for.
- **The secret sits in sessionStorage**, readable by script on this origin -
  the same exposure as the session token it lives beside.

---

## See it for yourself

With everything running, three scripts.

The nonce lifecycle, in the clear, where every step is readable in a terminal:

```bash
API=http://localhost:4000/graphql bash scripts/e2e-verify.sh
```

Thirty-two checks: a login replayed, a wrong digest, an unknown account that
still gets a challenge, a replayed nonce, a forged one, a nonce from another
session, one from another client, two mutations offered one nonce, a mutation
that fails after consuming its nonce, and a client recovering from having none.

The encrypted channel, from a client that completes the handshake:

```bash
node scripts/verify-sealed-channel.js
```

Sixteen checks that nothing readable crosses the wire in either direction - not
the password digest, not the todo, not the nonce it spent, not the one coming
back - and that a flipped byte or a substituted nonce breaks the tag.

Every way a protected mutation can fail:

```bash
node scripts/verify-update-failures.js
```

Fourteen checks over `updateTodo`, grouped by *when* it goes wrong: before the
nonce is looked at, because of the nonce, and after the nonce was already spent.
That last group is the one worth watching - the caller leaves holding a usable
replacement either way, or the failure would cost them the session.

**Watch the rotation.** Sign in, create a todo, then open
`server/data/db.json` and look at `nonces`: the consumed one has `used: true`
and `consumed_at` set, with the fresh one beside it. Only hashes are there —
the nonce itself is never written down.

**Watch it survive a restart.** Stop the API (leave json-server running) and
start it again. The token you were holding still works, and a nonce you already
spent is still refused: the consumed state was persisted. The channel does not
survive it - the agreed secret lives with the session in memory and in
db.json — so sign in again to get a new one.

**Watch the wire.** Open DevTools on the app, create a todo, and look at the
POST: `{"v":1,"nid":…,"iv":…,"ct":…}` going out and the same shape coming back.
Then open `server/data/db.json` and read the todo you just wrote, in plain text.

---

## What is in the box

```
server/src/
  services/nonce-service.ts             <- issue, validate, consume, expire
  services/digest-service.ts            <- the challenge-response verifier
  crypto/transport-cipher.ts            <- the server half of the channel
  middleware/transport-middleware.ts    <- opens a request before GraphQL sees it
  middleware/nonce-validation-middleware.ts  <- decides what is protected, consumes the nonce
  resolvers/todo-resolvers.ts           <- enforces the middleware's verdict
  services/auth-service.ts              <- sessions, so a nonce has something to bind to
  data/                                 <- repositories + write-through to json-server
  jobs/nonce-cleanup-job.ts             <- deletes nonces that expired long ago

client/src/
  crypto/transport.ts                   <- ECDH, HKDF, AES-256-GCM per message
  crypto/channel.ts                     <- seals a request, opens the reply
  crypto/login-handshake.ts             <- getNonce, digest, key agreement
  relay/nonce-middleware.ts             <- injects and rotates the nonce
  relay/refresh-nonce.ts                <- asks the server for one when there is none
  contexts/NonceContext.tsx             <- holds the current nonce
  hooks/useNonceMutation.ts             <- retries the two recoverable failures
  components/NonceErrorBoundary.tsx     <- one recovery path per error code
```

Storage is in-memory, mirrored to `db.json` through json-server. Memory stays
primary because the compare-and-set in property 6 has no equivalent in
json-server — making it the source of truth would quietly break replay
protection.

---

## Error codes

| Code | HTTP | Meaning | Recovery |
| ---- | ---- | ------- | -------- |
| `NONCE_MISSING` | 403 | No nonce sent | `refreshNonce`, then retry |
| `NONCE_INVALID` | 401 | Never issued by this server | `refreshNonce`, then retry |
| `NONCE_EXPIRED` | 401 | Past its TTL | **Retried automatically** |
| `NONCE_ALREADY_USED` | 403 | Replay | None — the request may already have run |
| `NONCE_BINDING_MISMATCH` | 403 | Wrong user, session or client | None — sign in again |
| `NONCE_RACE_CONDITION` | 409 | Lost a concurrent consume | **Retried automatically** |
| `NONCE_MULTIPLE_OPERATIONS` | 403 | One nonce offered for several mutations | None — send them one at a time |
| `TRANSPORT_UNREADABLE` | 400 | A sealed request that would not open | None — sign in again for a new channel |

Only the two marked automatic are retried by the network layer: they are the
ones where the same request, with a fresh nonce, is still the right request. The
next two need a nonce the client does not have, which is what `refreshNonce` is
for — the user clicks a button rather than being sent back to the login form.
The last three cannot succeed on a retry at all. Full examples in
[docs/API.md](docs/API.md).

---

## Configuration

Nothing is required — every value has a working default. The ones worth knowing:

| Variable | Default | Why you would change it |
| -------- | ------- | ----------------------- |
| `NONCE_TTL` | `300000` (5 min) | Shorter narrows the replay window |
| `NONCE_LENGTH` | `32` | Bytes of entropy per nonce (minimum 32) |
| `SESSION_TTL` | `86400000` (24h) | How long a login lasts |
| `DATABASE_URL` | `http://localhost:3001` | Where json-server is |
| `JWT_SECRET` | dev default | **Required in production**, min 32 chars |

---

## Checking it still works

There is no unit suite. The verification is the three scripts above, driving the
real server over HTTP — for a property like "this nonce belongs to another
session", "the title never appears on the wire" or "one of twelve wins", a check
against the running system is the one that proves anything.

Types and lint on top of them:

```bash
npm run build && npm run lint
```

---

## This is a demonstration, not a product

Deliberately left out, because none of it teaches anything about nonces: audit
logging, caching, rate limiting, production config validation, Docker, and
deployment tooling.

The costs of the channel and of digest auth are listed under
[What this is not](#what-this-is-not), and they are the real ones. Two more
things you would need before trusting this anywhere real:

1. **Reads come from memory**, so a second instance would not see the first
   one's nonces. The repositories would need to read from the database too.
2. **The compare-and-set is per process.** Across instances the same nonce could
   be consumed twice. A real database does this with
   `UPDATE ... WHERE used = false` and treats "0 rows affected" as the race.
