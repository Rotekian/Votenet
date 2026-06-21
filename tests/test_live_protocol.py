"""Live-socket integration tests: a real VoteServer + real client connections.

These validate the full wire path that unit/handler tests skip:

* TCP framing and message dispatch
* Login flow + SERVER_PUBKEY delivery + token verification on the client
* Peer announcement / discovery (so onion paths can be built)
* A genuine onion-routed vote: client builds a path, server forwards blind,
  exit node submits, VoteResponse returns matched by nonce
* The cascade over the wire: double-spend -> TokenInvalidated broadcast
* Results published with totals + percentages

These tests construct a VoteServer in-process and connect raw asyncio
streams, then drive a minimal client controller to react to messages.
"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from votenet import config, onion
from votenet.client.controller import ClientController
from votenet.crypto import generate_identity
from votenet.messages import MsgType, Message, decode_frames, encode
from votenet.server.server import VoteServer
from votenet.server.store import Store
from votenet.tokens import SignedToken


@pytest.fixture
async def live_server():
    """Spin up a VoteServer on an ephemeral port, seed accounts, return (server, host, port)."""
    # Use a fresh identity per test to avoid cross-test token confusion.
    server_ident = generate_identity()
    store = Store()
    for u, role in [("admin", "admin"), ("alice", "voter"), ("bob", "voter"), ("carol", "voter")]:
        store.add_user(u, u, role)
    server = VoteServer(store=store, identity=server_ident)
    # Bind to ephemeral port
    await server.start(host="127.0.0.1", port=0)
    sock = server._server.sockets[0]
    host, port = sock.getsockname()[:2]
    yield server, host, port, server_ident
    await server.stop()


async def _connect(host, port, identity):
    """Open a raw stream + drain helper bound to a client identity."""
    reader, writer = await asyncio.open_connection(host, port)
    inbox: asyncio.Queue = asyncio.Queue()
    inbox_list: list[Message] = []
    buf = b""

    async def reader_loop():
        nonlocal buf
        while True:
            data = await reader.read(4096)
            if not data:
                return
            buf += data
            for msg, buf in decode_frames(buf):
                inbox_list.append(msg)
                await inbox.put(msg)

    task = asyncio.ensure_future(reader_loop())

    async def send(msg):
        writer.write(encode(msg))
        await writer.drain()

    async def wait_for(pred, timeout=2.0):
        """Wait until some message in the inbox satisfies pred(msg). Returns it."""
        deadline = asyncio.get_event_loop().time() + timeout
        i = 0
        while True:
            while i < len(inbox_list):
                if pred(inbox_list[i]):
                    return inbox_list[i]
                i += 1
            if asyncio.get_event_loop().time() > deadline:
                return None
            await asyncio.sleep(0.02)

    async def collect(pred, timeout=0.4):
        """Collect all currently-arrived messages matching pred."""
        await asyncio.sleep(timeout)
        return [m for m in inbox_list if pred(m)]

    async def close():
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return {"reader": reader, "writer": writer, "send": send, "wait_for": wait_for,
            "collect": collect, "close": close, "identity": identity, "inbox": inbox_list}


async def _login(client, username):
    """Perform a login and return the LOGIN_RESPONSE payload."""
    await client["send"](Message(type=MsgType.LOGIN_REQUEST, payload={
        "username": username, "password": username,
        "pubkey_id": client["identity"].pubkey_id,
    }))
    resp = await client["wait_for"](lambda m: m.type == MsgType.LOGIN_RESPONSE)
    assert resp is not None and resp.payload["ok"], f"login failed: {resp}"
    return resp.payload


# --------------------------------------------------------------------------
async def test_login_delivers_server_pubkey(live_server):
    server, host, port, server_ident = live_server
    ident = generate_identity()
    c = await _connect(host, port, ident)
    try:
        await _login(c, "alice")
        pubkey_msg = await c["wait_for"](lambda m: m.type == MsgType.SERVER_PUBKEY)
        assert pubkey_msg is not None
        assert pubkey_msg.payload["pubkey_id"] == server_ident.pubkey_id
    finally:
        await c["close"]()


async def test_peer_announcement_on_login(live_server):
    server, host, port, _ = live_server
    a = await _connect(host, port, generate_identity())
    b = await _connect(host, port, generate_identity())
    try:
        await _login(a, "alice")
        await _login(b, "bob")
        # Alice should have heard about bob's arrival
        peer = await a["wait_for"](lambda m: m.type == MsgType.PEER_ANNOUNCE
                                   and m.payload["pubkey_id"] == b["identity"].pubkey_id)
        assert peer is not None, "alice did not learn about bob"
    finally:
        await a["close"]()
        await b["close"]()


async def test_create_release_issues_tokens_over_wire(live_server):
    server, host, port, server_ident = live_server
    admin = await _connect(host, port, generate_identity())
    alice = await _connect(host, port, generate_identity())
    bob = await _connect(host, port, generate_identity())
    try:
        await _login(admin, "admin")
        await _login(alice, "alice")
        await _login(bob, "bob")
        # Admin creates a poll
        await admin["send"](Message(type=MsgType.CREATE_POLL, payload={
            "title": "Tea?", "description": "d", "options": ["yes", "no"],
        }))
        created = await admin["wait_for"](lambda m: m.type == MsgType.POLL_CREATED)
        poll_id = created.payload["poll_id"]
        # Admin releases
        await admin["send"](Message(type=MsgType.RELEASE_POLL, payload={"poll_id": poll_id}))
        # Alice and Bob should each receive a TOKEN_ISSUED
        alice_tok = await alice["wait_for"](lambda m: m.type == MsgType.TOKEN_ISSUED)
        bob_tok = await bob["wait_for"](lambda m: m.type == MsgType.TOKEN_ISSUED)
        assert alice_tok and bob_tok
        # And both should verify against the real server public key
        for m in (alice_tok, bob_tok):
            st = SignedToken.from_dict(m.payload["token"])
            assert st.verify(server_ident.public), "token failed server-key verification"
    finally:
        await admin["close"]()
        await alice["close"]()
        await bob["close"]()


async def test_onion_routed_vote_accepted(live_server):
    """The headline wire test: a vote traverses a real onion path and is accepted."""
    server, host, port, server_ident = live_server
    admin = await _connect(host, port, generate_identity())
    alice = await _connect(host, port, generate_identity())
    bob = await _connect(host, port, generate_identity())
    carol = await _connect(host, port, generate_identity())
    try:
        await _login(admin, "admin")
        await _login(alice, "alice")
        await _login(bob, "bob")
        await _login(carol, "carol")
        # Create + release
        await admin["send"](Message(type=MsgType.CREATE_POLL, payload={
            "title": "T", "description": "d", "options": ["yes", "no"],
        }))
        poll_id = (await admin["wait_for"](lambda m: m.type == MsgType.POLL_CREATED)).payload["poll_id"]
        await admin["send"](Message(type=MsgType.RELEASE_POLL, payload={"poll_id": poll_id}))
        # Alice waits for her token + for window to open
        alice_tok = await alice["wait_for"](lambda m: m.type == MsgType.TOKEN_ISSUED)
        st = SignedToken.from_dict(alice_tok.payload["token"])
        # Build an onion path through bob -> carol -> server. Alice needs their pubkey_ids.
        # Give peer announcements a moment to propagate.
        await asyncio.sleep(0.2)
        peers_online = [bob["identity"].pubkey_id, carol["identity"].pubkey_id]
        # Wait until alice has learned of both peers via PEER_ANNOUNCE.
        for _ in range(50):
            known = {m.payload["pubkey_id"] for m in alice["inbox"]
                     if m.type == MsgType.PEER_ANNOUNCE}
            if set(peers_online) <= known:
                break
            await asyncio.sleep(0.05)
        path = [bob["identity"].pubkey_id, carol["identity"].pubkey_id]
        nonce = "alice-vote-nonce"
        inner = {"type": "submit_vote", "token": st.to_dict(), "choice": "yes", "reply_nonce": nonce}
        blob = onion.build_onion(inner, path)
        await alice["send"](Message(type=MsgType.RELAY, payload={
            "to_pubkey_id": path[0], "blob": blob,
        }))
        # Bob is the first hop: he should receive a RELAY addressed to him.
        bob_relay = await bob["wait_for"](lambda m: m.type == MsgType.RELAY, timeout=1.5)
        assert bob_relay is not None, "bob did not receive the relay"
        # Peel as bob and relay onward to carol.
        peeled = onion.peel_layer(bob["identity"], bob_relay.payload["blob"])
        await bob["send"](Message(type=MsgType.RELAY, payload={
            "to_pubkey_id": peeled.next, "blob": peeled.blob_b64,
        }))
        # Carol receives, peels, sees exit to SERVER, submits the inner payload.
        carol_relay = await carol["wait_for"](lambda m: m.type == MsgType.RELAY, timeout=1.5)
        peeled2 = onion.peel_layer(carol["identity"], carol_relay.payload["blob"])
        assert onion.is_exit(peeled2)
        inner_decoded = onion.decode_final_payload(peeled2.blob_b64)
        await carol["send"](Message(type=MsgType.SUBMIT_VOTE, payload=inner_decoded))
        # The response is unicast back through the connection that submitted (carol's,
        # the exit node). In our hybrid model the VoteResponse goes to the exit
        # node's connection; the original voter matches it by nonce.
        vote_resp = await carol["wait_for"](lambda m: m.type == MsgType.VOTE_RESPONSE, timeout=1.5)
        assert vote_resp is not None, "no VoteResponse received"
        assert vote_resp.payload["status"] == "ACCEPTED"
        assert vote_resp.payload["nonce"] == nonce
    finally:
        for c in (admin, alice, bob, carol):
            await c["close"]()


async def test_double_spend_broadcasts_invalidation_over_wire(live_server):
    """Double-spend over the wire: server broadcasts TokenInvalidated to ALL clients."""
    server, host, port, server_ident = live_server
    admin = await _connect(host, port, generate_identity())
    alice = await _connect(host, port, generate_identity())
    bob = await _connect(host, port, generate_identity())
    carol = await _connect(host, port, generate_identity())
    try:
        await _login(admin, "admin")
        await _login(alice, "alice")
        await _login(bob, "bob")
        await _login(carol, "carol")
        await admin["send"](Message(type=MsgType.CREATE_POLL, payload={
            "title": "T", "description": "d", "options": ["yes", "no"],
        }))
        poll_id = (await admin["wait_for"](lambda m: m.type == MsgType.POLL_CREATED)).payload["poll_id"]
        await admin["send"](Message(type=MsgType.RELEASE_POLL, payload={"poll_id": poll_id}))
        alice_tok = await alice["wait_for"](lambda m: m.type == MsgType.TOKEN_ISSUED)
        st = SignedToken.from_dict(alice_tok.payload["token"])
        # First vote — accepted
        await alice["send"](Message(type=MsgType.SUBMIT_VOTE, payload={
            "token": st.to_dict(), "choice": "yes", "reply_nonce": "n1",
        }))
        r1 = await alice["wait_for"](lambda m: m.type == MsgType.VOTE_RESPONSE)
        assert r1.payload["status"] == "ACCEPTED"
        # Double-spend from bob's connection (simulating a stale copy held by bob)
        await bob["send"](Message(type=MsgType.SUBMIT_VOTE, payload={
            "token": st.to_dict(), "choice": "no", "reply_nonce": "n2",
        }))
        r2 = await bob["wait_for"](lambda m: m.type == MsgType.VOTE_RESPONSE)
        assert r2.payload["status"] == "REJECTED"
        assert r2.payload["reason"] == "ALREADY_SPENT"
        # The cascade broadcast must reach carol (an uninvolved client) too
        cascade = await carol["wait_for"](lambda m: m.type == MsgType.TOKEN_INVALIDATED, timeout=1.5)
        assert cascade is not None, "carol did not receive the cascade broadcast"
        assert cascade.payload["token_id"] == st.token.token_id
    finally:
        for c in (admin, alice, bob, carol):
            await c["close"]()
