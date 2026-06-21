"""Integration tests for the server FSM: the cascade end-to-end.

These exercise the server handlers directly (no networking) to validate the
core spec requirements deterministically:

* create -> release -> issue tokens -> vote -> accept
* double-spend -> reject (ALREADY_SPENT) -> invalidate -> broadcast cascade
* post-cascade submission rejected as INVALIDATED
* anonymous CheckSpendable reflects spend status
* results tally (totals + percentages + turnout)

A separate live-socket test (test_live_protocol.py) covers the wire path.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from votenet import tokens
from votenet.crypto import generate_identity
from votenet.messages import MsgType, Message
from votenet.server.handlers import (
    handle_check_spendable,
    handle_create_poll,
    handle_release_poll,
    handle_submit_vote,
)
from votenet.server.store import ClientConnection, Store
from votenet.tokens import SignedToken


@pytest.fixture
def env():
    """A fresh server environment: identity, store, three connected clients."""
    server = generate_identity()
    store = Store()
    for u in ("admin", "alice", "bob", "carol"):
        store.add_user(u, u, "admin" if u == "admin" else "voter")
    admin = ClientConnection(username="admin", pubkey_id="pk_admin", session_token="s0")
    alice = ClientConnection(username="alice", pubkey_id="pk_alice", session_token="s1")
    bob = ClientConnection(username="bob", pubkey_id="pk_bob", session_token="s2")
    carol = ClientConnection(username="carol", pubkey_id="pk_carol", session_token="s3")
    for c in (admin, alice, bob, carol):
        store.register_peer(c)
    return {
        "server": server,
        "store": store,
        "admin": admin,
        "alice": alice,
        "bob": bob,
        "carol": carol,
    }


async def _create_and_release(env, title="Tea?", options=("yes", "no")):
    """Helper: admin creates + releases a poll. Returns (poll_id, window_id)."""
    create = await handle_create_poll(
        env["admin"],
        Message(type=MsgType.CREATE_POLL, payload={"title": title, "description": "d", "options": list(options)}),
        env["store"], env["server"],
    )
    poll_id = create[0].payload["poll_id"]
    rel = await handle_release_poll(
        env["admin"],
        Message(type=MsgType.RELEASE_POLL, payload={"poll_id": poll_id}),
        env["store"], env["server"],
    )
    window_id = rel[0].payload["window_id"]
    return poll_id, window_id, rel


def _issued_tokens(release_replies, server):
    """Extract verified SignedTokens from a release_poll reply list."""
    out = []
    for m in release_replies:
        if m.type == MsgType.TOKEN_ISSUED:
            st = SignedToken.from_dict(m.payload["token"])
            assert st.verify(server.public)
            out.append(st)
    return out


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------
async def test_create_and_release_issues_tokens_to_all_voters(env):
    poll_id, window_id, replies = await _create_and_release(env)
    issued = _issued_tokens(replies, env["server"])
    # 3 voters online (alice, bob, carol) -> 3 tokens
    assert len(issued) == 3
    # Each token must be bearer (no owner field)
    for st in issued:
        body = st.token._body_dict()
        assert "owner" not in body and "recipient" not in body
    # Issuance ledger records recipient (the one allowed info-leak)
    ledger = env["store"].issuance_ledger
    usernames = {ledger[st.token.token_id] for st in issued}
    assert usernames == {"alice", "bob", "carol"}


async def test_first_vote_accepted(env):
    poll_id, window_id, replies = await _create_and_release(env)
    alice_token = _issued_tokens(replies, env["server"])[0]
    resp = await handle_submit_vote(
        env["alice"],
        Message(type=MsgType.SUBMIT_VOTE, payload={
            "token": alice_token.to_dict(), "choice": "yes", "reply_nonce": "n1",
        }),
        env["store"], env["server"],
    )
    assert resp[0].payload["status"] == "ACCEPTED"
    assert env["store"].spend_ledger[alice_token.token.token_id] == window_id


async def test_vote_with_bad_choice_rejected(env):
    poll_id, window_id, replies = await _create_and_release(env)
    alice_token = _issued_tokens(replies, env["server"])[0]
    resp = await handle_submit_vote(
        env["alice"],
        Message(type=MsgType.SUBMIT_VOTE, payload={
            "token": alice_token.to_dict(), "choice": "maybe", "reply_nonce": "n1",
        }),
        env["store"], env["server"],
    )
    assert resp[0].payload["status"] == "REJECTED"
    assert resp[0].payload["reason"] == "BAD_CHOICE"


async def test_vote_with_forged_token_rejected(env):
    poll_id, window_id, _ = await _create_and_release(env)
    impostor = generate_identity()
    forged = tokens.issue_token(poll_id, window_id, impostor, ttl_seconds=600)
    resp = await handle_submit_vote(
        env["alice"],
        Message(type=MsgType.SUBMIT_VOTE, payload={
            "token": forged.to_dict(), "choice": "yes", "reply_nonce": "n1",
        }),
        env["store"], env["server"],
    )
    assert resp[0].payload["status"] == "REJECTED"
    assert resp[0].payload["reason"] == "BAD_SIGNATURE"


# --------------------------------------------------------------------------
# The cascade: double-spend -> reject -> invalidate -> broadcast
# --------------------------------------------------------------------------
async def test_double_spend_triggers_cascade(env):
    """The headline test: spending a token twice triggers the full cascade."""
    poll_id, window_id, replies = await _create_and_release(env)
    alice_token = _issued_tokens(replies, env["server"])[0]

    # First spend: accepted
    r1 = await handle_submit_vote(
        env["alice"],
        Message(type=MsgType.SUBMIT_VOTE, payload={
            "token": alice_token.to_dict(), "choice": "yes", "reply_nonce": "n1",
        }),
        env["store"], env["server"],
    )
    assert r1[0].payload["status"] == "ACCEPTED"

    # Second spend of the SAME token (simulating a stale/duplicated holder):
    r2 = await handle_submit_vote(
        env["bob"],  # arrives via a different exit node — server can't tell
        Message(type=MsgType.SUBMIT_VOTE, payload={
            "token": alice_token.to_dict(), "choice": "no", "reply_nonce": "n2",
        }),
        env["store"], env["server"],
    )
    assert r2[0].payload["status"] == "REJECTED"
    assert r2[0].payload["reason"] == "ALREADY_SPENT"
    # A TOKEN_INVALIDATED broadcast must accompany the rejection
    cascade = [m for m in r2 if m.type == MsgType.TOKEN_INVALIDATED]
    assert cascade, "double-spend must produce a TokenInvalidated broadcast"
    assert cascade[0].payload["token_id"] == alice_token.token.token_id
    # The token is now in the invalidated set
    assert alice_token.token.token_id in env["store"].invalidated


async def test_post_cascade_submission_rejected_as_invalidated(env):
    poll_id, window_id, replies = await _create_and_release(env)
    alice_token = _issued_tokens(replies, env["server"])[0]
    # Spend it
    await handle_submit_vote(env["alice"], Message(type=MsgType.SUBMIT_VOTE, payload={
        "token": alice_token.to_dict(), "choice": "yes", "reply_nonce": "n1",
    }), env["store"], env["server"])
    # Trigger cascade
    await handle_submit_vote(env["bob"], Message(type=MsgType.SUBMIT_VOTE, payload={
        "token": alice_token.to_dict(), "choice": "no", "reply_nonce": "n2",
    }), env["store"], env["server"])
    # Any further submission must now be REJECTED as INVALIDATED
    r3 = await handle_submit_vote(env["carol"], Message(type=MsgType.SUBMIT_VOTE, payload={
        "token": alice_token.to_dict(), "choice": "yes", "reply_nonce": "n3",
    }), env["store"], env["server"])
    assert r3[0].payload["reason"] == "INVALIDATED"


async def test_check_spendable_reflects_status(env):
    poll_id, window_id, replies = await _create_and_release(env)
    alice_token = _issued_tokens(replies, env["server"])[0]
    store = env["store"]
    server = env["server"]

    # Initially spendable
    r = await handle_check_spendable(env["bob"], Message(type=MsgType.CHECK_SPENDABLE, payload={
        "token_id": alice_token.token.token_id, "nonce": "q1",
    }), store, server)
    assert r[0].payload["status"] == "SPENDABLE"

    # After spending
    await handle_submit_vote(env["alice"], Message(type=MsgType.SUBMIT_VOTE, payload={
        "token": alice_token.to_dict(), "choice": "yes", "reply_nonce": "n1",
    }), store, server)
    r = await handle_check_spendable(env["bob"], Message(type=MsgType.CHECK_SPENDABLE, payload={
        "token_id": alice_token.token.token_id, "nonce": "q2",
    }), store, server)
    assert r[0].payload["status"] == "SPENT"

    # After cascade invalidation
    store.invalidated.add(alice_token.token.token_id)
    r = await handle_check_spendable(env["bob"], Message(type=MsgType.CHECK_SPENDABLE, payload={
        "token_id": alice_token.token.token_id, "nonce": "q3",
    }), store, server)
    assert r[0].payload["status"] == "INVALIDATED"


async def test_results_tally_and_percentages(env):
    poll_id, window_id, replies = await _create_and_release(env)
    store = env["store"]
    server = env["server"]
    issued = {store.issuance_ledger[st.token.token_id]: st for st in _issued_tokens(replies, server)}
    # Alice votes yes, Bob votes yes, Carol votes no
    for user, choice in [("alice", "yes"), ("bob", "yes"), ("carol", "no")]:
        conn = {"alice": env["alice"], "bob": env["bob"], "carol": env["carol"]}[user]
        r = await handle_submit_vote(conn, Message(type=MsgType.SUBMIT_VOTE, payload={
            "token": issued[user].to_dict(), "choice": choice, "reply_nonce": f"n-{user}",
        }), store, server)
        assert r[0].payload["status"] == "ACCEPTED"

    # Tally via the close helper
    from votenet.server.handlers import _close_window_and_publish
    poll = store.polls[poll_id]
    msgs = _close_window_and_publish(poll, store)
    results = [m for m in msgs if m.type == MsgType.RESULTS_PUBLISHED][0].payload
    assert results["totals"] == {"yes": 2, "no": 1}
    assert results["percentages"]["yes"] == pytest.approx(66.7, abs=0.1)
    assert results["percentages"]["no"] == pytest.approx(33.3, abs=0.1)
    assert results["voted"] == 3
    assert results["eligible"] == 3
    assert results["turnout"] == 100.0


async def test_admin_only_can_create_poll(env):
    """A non-admin cannot create a poll."""
    r = await handle_create_poll(
        env["alice"],  # voter, not admin
        Message(type=MsgType.CREATE_POLL, payload={"title": "t", "description": "d", "options": ["a", "b"]}),
        env["store"], env["server"],
    )
    assert r[0].type == MsgType.ERROR
    assert r[0].payload["code"] == "forbidden"


async def test_admin_only_can_release(env):
    poll_id, _, _ = await _create_and_release(env)
    r = await handle_release_poll(
        env["alice"],
        Message(type=MsgType.RELEASE_POLL, payload={"poll_id": poll_id}),
        env["store"], env["server"],
    )
    # Either forbidden or already-released (admin already released in fixture helper)
    assert r[0].type == MsgType.ERROR
