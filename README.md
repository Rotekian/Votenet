# VoteNet — Anonymous Onion-Routed Voting

A desktop voting system where an admin creates polls, verified voters receive
**bearer** vote tokens they can **trade peer-to-peer**, and votes are cast over
**onion-routed** paths so the server cannot link a vote to the voter. Double-spend
attempts trigger a **cascade**: the token is invalidated, the invalidation is
broadcast to every client, and affected voters are issued fresh tokens until
everyone who wants to vote has done so.

```
 admin ──create poll──▶ server ──release──▶ issues bearer tokens
                                              │
 voters ◀──── token issued (bearer, owner-free) ─┘
   │
   ├── trade token P2P (server-blind, end-to-end encrypted) ──▶ peer
   │
   └── cast vote ──onion path: peer→peer→exit──▶ server
                    (server records vote against the token, not the voter)
                          │
                 double-spend? ──▶ invalidate token + broadcast cascade
                                  └── reissue fresh tokens until all voted
```

## Quick start

```bash
pip install -r requirements.txt
```

In one terminal, start the server:

```bash
python -m votenet.server
```

In separate terminals, launch clients (one per user):

```bash
python -m votenet.client
```

On Windows you can use `run_server.bat` / `run_client.bat`. Launch several
clients and sign in with different accounts.

### Seeded accounts

| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin    | admin |
| alice    | alice    | voter |
| bob      | bob      | voter |
| carol    | carol    | voter |
| dave     | dave     | voter |
| eve      | eve      | voter |

## Scenario walkthrough

1. **Admin creates a poll.** Sign in as `admin`, click **+ New poll**, enter a
   title, description, and at least two options, then **Create poll**. You'll be
   asked whether to open the voting window immediately — say yes.

2. **Voters receive tokens.** Each voter who is online when the window opens
   receives a **bearer** vote token (visible in the dashboard's "My tokens"
   column and on the poll detail screen). The token carries no owner field.

3. **Trade tokens (optional).** A voter can open the **Trade** screen, pick one
   of their tokens and a recipient peer, and send either a **REAL** trade
   (genuine signed token; the recipient verifies the server signature and runs
   an anonymous `CheckSpendable` query before accepting) or a **CHAFF** trade
   (knowingly swapped fake tokens to generate anonymizing noise).

4. **Cast a vote.** A voter holding a token opens the poll, selects an option,
   and hits **Vote**. The client builds a 2–3 hop onion path through other
   online peers and sends the wrapped vote as an opaque `Relay` blob. Each peer
   peels a layer and forwards blindly; the exit peer submits the inner payload
   to the server. The server records the vote against the **token**, not the
   exit node's connection, and replies with a `VoteResponse` matched by a
   one-time nonce.

5. **Cascade (if a token is double-spent).** If a stale or duplicated copy of a
   token is submitted after it has already been spent, the server rejects it
   with `ALREADY_SPENT`, marks the token **invalidated**, and broadcasts
   `TokenInvalidated` to *every* client. Every client holding that token drops
   it; affected voters request a reissue and receive a **fresh** token for the
   next sub-round, then vote again. This continues until everyone who wants to
   vote has an accepted vote.

6. **Results.** When all interested voters have voted (or the round budget
   expires), the server tallies accepted votes and publishes **totals**,
   **percentages**, and **turnout**. Every client sees the same results on the
   poll screen, with a simple bar chart.

## How anonymity is achieved

* **Bearer tokens.** A `VoteToken` carries `{token_id, poll_id, window_id,
  issued_at, expires_at}` plus a server Ed25519 signature — and **no owner
  field**. Possession of a correctly-signed, unspent, non-invalidated token is
  the right to cast one vote. This is what makes trades untrackable: there is
  nothing on the token to track.

* **Peer-to-peer trades, server-blind.** All trade traffic flows through
  opaque, end-to-end-encrypted `Relay` blobs that the server forwards without
  inspecting. The server cannot read trade contents and cannot tell that a
  relayed blob *is* a trade.

* **Onion-routed votes.** A vote is wrapped in layered encryption addressed to
  a chain of peer hops; the server only relays opaque blobs between clients and
  receives the final payload from the exit node. Because the token may have
  been traded away before being spent, the server cannot conclude that the user
  it *issued* a token to is the one who *spent* it.

* **Bad actors are contained.** A fake token fails the (publicly verifiable)
  server signature check instantly. An already-spent token fails an anonymous
  `CheckSpendable` query before a trade completes. A stale/duplicated token is
  healed by the cascade: spend is first-come-first-served, and the loser of the
  race gets a reissued token. The worst a bad actor can cause is a reissue —
  never a permanently stolen vote.

* **Cascade authorization.** The server records which user it issued each token
  to in an **issuance ledger**. This ledger is used *only* to authorize
  invalidations (so a malicious client cannot broadcast a fake cascade to
  disrupt others' votes). It is never used to bind a *spent* vote to a user.

### Honest limitations (v1)

These are deliberate scope decisions for the first version:

* **The issuance link is broken probabilistically, not cryptographically.**
  Without blind signatures, the server retains `token_id → user` in the
  issuance ledger. Trade mixing + chaff make it *unlikely* — not impossible —
  that the issued user is the spender. Upgrading to blind signatures later is
  structurally supported (the token interface is owner-free) but out of scope
  for v1.

* **In-memory state.** Nothing is persisted; the demo runs entirely in RAM and
  resets on server restart.

* **Single-server deployment.** Designed for one machine or one server; not a
  distributed/federated system.

* **In-band server key learning.** A client learns the server's Ed25519 public
  key from the `SERVER_PUBKEY` message sent after login. A production system
  would pin the server key out-of-band (e.g. via TLS pinning or a trust anchor).

## Architecture

```
votenet/
  config.py           host/port, timings, seeded accounts
  crypto.py           Ed25519, X25519, ChaCha20Poly1305, canonical JSON
  messages.py         wire protocol: Message envelope + MsgType enum
  tokens.py           bearer VoteToken + server signature
  onion.py            hybrid onion: build path, wrap/peel layers, Ed25519↔X25519
  trade.py            REAL/CHAFF P2P trade offers + sealed payload encryption
  server/
    store.py          in-memory state (users, polls, windows, ledgers, peer dir)
    handlers.py       per-message handlers; the cascade lives in handle_submit_vote
    server.py         asyncio start_server + per-connection loop + window loop
    runner.py         `python -m votenet.server`
  client/
    net.py            asyncio loop in a background thread; queue bridge to GUI
    controller.py     client FSM: held tokens, peers, cascade reactions
    api.py            GUI-facing actions: login, vote, trade, create/release
    runner.py         `python -m votenet.client`
    ui/               tkinter views: login, dashboard, admin, poll, trade, log
tests/
    test_crypto.py    signing, AEAD, X25519 agreement
    test_tokens.py    bearer token sign/verify/tamper; no-owner-field invariant
    test_onion.py     multi-hop wrap/peel; wrong-recipient/tamper rejection
    test_trade.py     REAL verifies / CHAFF skips / forged-token rejection
    test_server_fsm.py  create→release→vote→double-spend→cascade→tally
    test_live_protocol.py  full wire path incl. real onion vote + cascade broadcast
```

### The cascade, in detail

The cascade is the heart of the spec: when a token is rejected as already-spent,
every client must learn to drop that token so no one holds a dead token, and
affected voters must be issued replacements. The flow:

1. A holder submits a vote with token **X**.
2. The server verifies X's signature, window, and spend status.
   * If **unspent** → record the vote, mark X spent in `spend_ledger`, reply
     `VoteResponse{ACCEPTED}`. The holder marks the token spent. Done.
   * If **already spent** (a stale/duplicated copy, or a retry) → add X to
     `invalidated`, reply `REJECTED{ALREADY_SPENT}`, and **broadcast
     `TokenInvalidated{X}`** to all clients.
3. Every client receiving the broadcast drops any local copy of X. A client
   whose earlier *accepted* vote used X invalidates its own copy too.
4. Affected holders request a reissue by presenting the invalidated token's id;
   the server's window loop issues a **fresh** token (new `token_id`, new
   signature) for the next sub-round.
5. Repeat until no pending reissues remain → window closes → results published.

Because tokens are bearer instruments, a reissue is granted to anyone holding a
correctly-signed copy of the invalidated token — whether they got it by original
issuance or by trade. This is what lets the cascade heal trades too.

## Testing

```bash
pip install -r requirements.txt
python -m pytest
```

The suite covers the crypto primitives, bearer-token invariants, onion routing,
the P2P trade layer, the server FSM (including the full cascade flow), and a
set of live-socket tests that spin up a real server and exercise the onion vote
path and the double-spend cascade over actual TCP connections.

## Dependencies

* **Python 3.10+**
* [`cryptography`](https://cryptography.io) — Ed25519, X25519, ChaCha20Poly1305
* `tkinter` — ships with CPython on Windows/macOS; on Linux install `python3-tk`
* `pytest`, `pytest-asyncio` — test only
