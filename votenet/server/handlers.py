"""Server-side message handlers.

Each handler takes the live :class:`ClientConnection`, the incoming
:class:`Message`, the shared :class:`Store`, the server :class:`Identity`, and
returns a list of outbound :class:`Message` instances (or an awaitable
producing one). Handlers are coroutines so they can broadcast and await drains.

The single most important handler is :func:`handle_submit_vote`, which
implements the double-spend detection and cascade trigger.
"""

from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable, Dict, List, Optional

from .. import config
from ..crypto import Identity, b64, random_hex
from ..messages import MsgType, Message, error
from ..tokens import SignedToken, issue_token
from ..config import TOKEN_TTL_SECONDS, WINDOW_ROUND_SECONDS
from .store import ClientConnection, Poll, Store, Window


# Type alias for clarity
Handler = Callable[[ClientConnection, Message, Store, Identity], Awaitable[List[Message]]]


def _now() -> int:
    return int(time.time())


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
async def handle_login(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    p = msg.payload
    username = p.get("username", "")
    password = p.get("password", "")
    user = store.verify_credentials(username, password)
    if user is None:
        return [msg.reply(MsgType.LOGIN_RESPONSE, {"ok": False, "error": "bad credentials"})]

    # Bind the connection: store username + session. The client's pubkey_id is
    # set on a separate Challenge flow — but we accept it inline here if the
    # client sent its public key (it always does at login).
    conn.username = username
    conn.session_token = store.create_session(username)
    if p.get("pubkey_id"):
        conn.pubkey_id = p["pubkey_id"]
        store.register_peer(conn)
        # Tell everyone (including the new peer) who's online. Also hand the
        # client our server public key so it can verify all signed tokens.
        return [
            msg.reply(MsgType.LOGIN_RESPONSE, {
                "ok": True,
                "session_token": conn.session_token,
                "role": user.role,
                "username": username,
            }),
            Message(type=MsgType.SERVER_PUBKEY, payload={
                "pubkey_id": server.pubkey_id,
                "pubkey_b64": b64(server.pubkey_bytes),
            }),
            Message(type=MsgType.PEER_ANNOUNCE, payload={"pubkey_id": conn.pubkey_id, "username": username}),
        ]
    # No pubkey_id supplied — still log in but no peer directory entry.
    return [msg.reply(MsgType.LOGIN_RESPONSE, {
        "ok": True,
        "session_token": conn.session_token,
        "role": user.role,
        "username": username,
    })]


async def handle_list_peers(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    peers = [
        {"pubkey_id": pk, "username": c.username}
        for pk, c in store.peer_directory.items()
        if c.username and pk != conn.pubkey_id
    ]
    return [msg.reply(MsgType.PEERS_LIST, {"peers": peers})]


# --------------------------------------------------------------------------
# Polls (admin-gated)
# --------------------------------------------------------------------------
async def handle_create_poll(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    if not _is_admin(conn, store):
        return [msg.reply(MsgType.ERROR, {"code": "forbidden", "detail": "admin only"})]
    p = msg.payload
    title = (p.get("title") or "").strip()
    description = (p.get("description") or "").strip()
    options = [o.strip() for o in (p.get("options") or []) if str(o).strip()]
    if not title or len(options) < 2:
        return [msg.reply(MsgType.ERROR, {"code": "invalid", "detail": "need title + >=2 options"})]
    poll_id = random_hex(8)
    store.polls[poll_id] = Poll(
        poll_id=poll_id,
        title=title,
        description=description,
        options=options,
        created_by=conn.username or "",
    )
    return [msg.reply(MsgType.POLL_CREATED, {"poll_id": poll_id, "title": title})]


async def handle_list_polls(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    polls = [
        {
            "poll_id": pid,
            "title": pl.title,
            "description": pl.description,
            "options": pl.options,
            "released": pl.released,
            "closed": pl.closed,
            "window_id": pl.window_id,
        }
        for pid, pl in store.polls.items()
    ]
    return [msg.reply(MsgType.POLLS_LIST, {"polls": polls})]


async def handle_release_poll(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    """Open a voting window for a poll. Returns a WINDOW_OPENED broadcast."""
    if not _is_admin(conn, store):
        return [msg.reply(MsgType.ERROR, {"code": "forbidden", "detail": "admin only"})]
    poll_id = msg.payload.get("poll_id")
    poll = store.polls.get(poll_id)
    if poll is None:
        return [msg.reply(MsgType.ERROR, {"code": "no_such_poll"})]
    if poll.released:
        return [msg.reply(MsgType.ERROR, {"code": "already_released"})]

    now = _now()
    window_id = random_hex(8)
    poll.released = True
    poll.window_id = window_id
    window = Window(
        window_id=window_id,
        poll_id=poll_id,
        opened_at=now,
        expires_at=now + WINDOW_ROUND_SECONDS * config.MAX_ROUNDS + 60,
        round=1,
    )
    store.windows[window_id] = window
    store.votes_by_token.setdefault(poll_id, {})

    # Initial interest set = all voters currently online with a pubkey.
    # Voters who log in later will also be issued a token on ListPeers/etc.
    window.interested = {
        c.username for c in store.peer_directory.values()
        if c.username and store.users.get(c.username, None) and store.users[c.username].role == "voter"
    }
    # Issue one bearer token per interested voter.
    issued_messages = _issue_tokens_for(window, store, server)

    return [
        msg.reply(MsgType.OK, {"window_id": window_id}),
        Message(type=MsgType.WINDOW_OPENED, payload={
            "poll_id": poll_id,
            "window_id": window_id,
            "expires_at": window.expires_at,
            "round": window.round,
            "title": poll.title,
            "description": poll.description,
            "options": poll.options,
        }),
        *issued_messages,
    ]


async def handle_close_poll(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    """Force-close a poll and publish results. Used by the window loop too."""
    poll_id = msg.payload.get("poll_id")
    poll = store.polls.get(poll_id)
    if poll is None:
        return [msg.reply(MsgType.ERROR, {"code": "no_such_poll"})]
    if not _is_admin(conn, store) and not msg.payload.get("_internal"):
        return [msg.reply(MsgType.ERROR, {"code": "forbidden", "detail": "admin only"})]
    return _close_window_and_publish(poll, store)


# --------------------------------------------------------------------------
# Anonymous spendability check (via onion path; no auth required)
# --------------------------------------------------------------------------
async def handle_check_spendable(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    """Reply SPENDABLE/SPENT/INVALIDATED for a token id. No identity attached.

    This runs on whatever connection delivers the innermost onion payload —
    by design that's an exit node, not the original querier, so the server
    learns nothing about who's asking.
    """
    token_id = msg.payload.get("token_id")
    nonce = msg.payload.get("nonce")
    status = store.is_spendable(token_id) if token_id else "SPENT"
    return [msg.reply(MsgType.SPENDABLE_RESULT, {"nonce": nonce, "status": status, "token_id": token_id})]


# --------------------------------------------------------------------------
# Relaying (hybrid onion): forward an opaque blob to another peer, blind.
# --------------------------------------------------------------------------
async def handle_relay(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    to_id = msg.payload.get("to_pubkey_id")
    blob = msg.payload.get("blob")
    target = store.peer_directory.get(to_id)
    if target is None:
        # Unknown peer. If the "to" is SERVER, this might be a final hop
        # that arrived directly — handle the inner payload inline.
        if to_id == "SERVER" or to_id is None:
            return await _handle_inner_blob(conn, msg, store, server, blob)
        return [msg.reply(MsgType.ERROR, {"code": "no_such_peer", "detail": to_id})]
    # Forward blind. The recipient will peel its layer and either relay again
    # or submit the inner payload. We carry the original reply_to so the
    # sender can correlate, but the recipient sends its OWN message (a fresh
    # Relay or a SubmitVote), not a reply — so we drop reply_to here.
    await target.send(Message(type=MsgType.RELAY, payload={"to_pubkey_id": to_id, "blob": blob, "from_relay": True}))
    return []  # nothing to send back to the relaying hop


async def _handle_inner_blob(conn: ClientConnection, msg: Message, store: Store, server: Identity, blob: Optional[str]) -> List[Message]:
    """A relay reached the server as the exit. Decode and dispatch the inner msg."""
    from .. import onion

    if not blob:
        return [msg.reply(MsgType.ERROR, {"code": "empty_inner"})]
    try:
        inner = onion.decode_final_payload(blob)
    except Exception:
        return [msg.reply(MsgType.ERROR, {"code": "bad_inner"})]
    inner_type = inner.get("type")
    if inner_type == "submit_vote":
        # Re-wrap as a SubmitVote message so the standard handler runs. We
        # synthesize a Message with the inner payload + the same reply chain.
        synth = Message(type=MsgType.SUBMIT_VOTE, payload=inner, id=msg.id, reply_to=msg.reply_to)
        return await handle_submit_vote(conn, synth, store, server)
    if inner_type == "check_spendable":
        synth = Message(type=MsgType.CHECK_SPENDABLE, payload=inner, id=msg.id, reply_to=msg.reply_to)
        return await handle_check_spendable(conn, synth, store, server)
    return [msg.reply(MsgType.ERROR, {"code": "unknown_inner", "detail": inner_type})]


# --------------------------------------------------------------------------
# Voting — the heart of the cascade
# --------------------------------------------------------------------------
async def handle_submit_vote(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    """Process a vote submission (arrived either directly or via onion exit).

    The vote is bound to the **token**, not to ``conn``. The exit node is just
    the messenger. Verification + cascade logic lives here.
    """
    p = msg.payload
    token_dict = p.get("token")
    choice = p.get("choice")
    reply_nonce = p.get("reply_nonce")
    if not token_dict or not choice or not reply_nonce:
        return [msg.reply(MsgType.VOTE_RESPONSE, {
            "nonce": reply_nonce, "status": "REJECTED", "reason": "MALFORMED",
        })]

    st = SignedToken.from_dict(token_dict)
    # 1. Signature check
    if not st.verify(server.public):
        return _reject(conn, msg, reply_nonce, st.token.token_id, "BAD_SIGNATURE", store)
    token_id = st.token.token_id
    poll_id = st.token.poll_id
    window_id = st.token.window_id
    window = store.windows.get(window_id)
    poll = store.polls.get(poll_id)
    # 2. Window state
    if window is None or window.closed or poll is None or poll.closed:
        return _reject(conn, msg, reply_nonce, token_id, "WINDOW_CLOSED", store)
    if choice not in poll.options:
        return _reject(conn, msg, reply_nonce, token_id, "BAD_CHOICE", store)
    # 3. Spend status — the cascade trigger
    status = store.is_spendable(token_id)
    if status == "INVALIDATED":
        return _reject(conn, msg, reply_nonce, token_id, "INVALIDATED", store)
    if status == "SPENT":
        # Double-spend! Invalidate this token and broadcast the cascade.
        broadcast = _invalidate_token(token_id, store)
        return _reject(conn, msg, reply_nonce, token_id, "ALREADY_SPENT", store, extra=broadcast)

    # 4. ACCEPT — record the vote, mark spent.
    store.spend_ledger[token_id] = window_id
    store.votes_by_token.setdefault(poll_id, {})[token_id] = choice
    # The user bound to this token (via the issuance ledger) now has a valid
    # vote in this window — but we DON'T say which user in the reply.
    issuer = store.issuance_ledger.get(token_id)
    if issuer:
        window.voted_ok.add(issuer)
        window.pending_reissue.discard(issuer)
    return [msg.reply(MsgType.VOTE_RESPONSE, {"nonce": reply_nonce, "status": "ACCEPTED", "token_id": token_id})]


# --------------------------------------------------------------------------
# Reissue request (bearer right: present an invalidated, signed token copy)
# --------------------------------------------------------------------------
async def handle_reissue_request(conn: ClientConnection, msg: Message, store: Store, server: Identity) -> List[Message]:
    """A client holding an invalidated token requests a fresh one.

    Because tokens are bearer instruments, anyone presenting a correctly-
    signed *copy* of an invalidated token is entitled to a replacement —
    whether they got it by original issuance or by trade. This is what keeps
    the cascade healing trades too.
    """
    p = msg.payload
    token_dict = p.get("token")
    if not token_dict:
        return [msg.reply(MsgType.ERROR, {"code": "no_token"})]
    st = SignedToken.from_dict(token_dict)
    if not st.verify(server.public):
        return [msg.reply(MsgType.ERROR, {"code": "bad_signature"})]
    old_id = st.token.token_id
    if old_id not in store.invalidated:
        # Token isn't invalidated; nothing to reissue.
        return [msg.reply(MsgType.ERROR, {"code": "not_invalidated"})]
    window = store.windows.get(st.token.window_id)
    if window is None or window.closed:
        return [msg.reply(MsgType.ERROR, {"code": "window_closed"})]
    # Mark this holder (by session) as interested for the next sub-round.
    if conn.username:
        window.pending_reissue.add(conn.username)
    return [msg.reply(MsgType.OK, {"queued": True, "round": window.round + 1})]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _is_admin(conn: ClientConnection, store: Store) -> bool:
    if not conn.username:
        return False
    u = store.users.get(conn.username)
    return u is not None and u.role == "admin"


def _issue_tokens_for(window: Window, store: Store, server: Identity) -> List[Message]:
    """Issue one bearer token to each interested user not yet voted.

    Records ``token_id -> username`` in the issuance ledger and pushes a
    TOKEN_ISSUED message to each recipient's connection.
    """
    out: List[Message] = []
    for username in sorted(window.interested - window.voted_ok):
        conn = _conn_for_username(store, username)
        if conn is None:
            continue
        st = issue_token(window.poll_id, window.window_id, server, TOKEN_TTL_SECONDS)
        store.issuance_ledger[st.token.token_id] = username
        window.issued_tokens.add(st.token.token_id)
        out.append(Message(type=MsgType.TOKEN_ISSUED, payload={"token": st.to_dict()}, id=random_hex(8)))
        # We can't await here (sync helper); attach the target so the caller sends.
        out[-1]._target_conn = conn  # type: ignore[attr-defined]
    return out


def _conn_for_username(store: Store, username: str) -> Optional[ClientConnection]:
    for conn in store.peer_directory.values():
        if conn.username == username:
            return conn
    return None


def _invalidate_token(token_id: str, store: Store) -> Message:
    """Mark a token invalidated and produce the cascade broadcast."""
    store.invalidated.add(token_id)
    return Message(type=MsgType.TOKEN_INVALIDATED, payload={"token_id": token_id}, id=random_hex(8))


def _reject(
    conn: ClientConnection,
    msg: Message,
    nonce: Optional[str],
    token_id: str,
    reason: str,
    store: Store,
    extra: Optional[Message] = None,
) -> List[Message]:
    out = [msg.reply(MsgType.VOTE_RESPONSE, {
        "nonce": nonce, "status": "REJECTED", "reason": reason, "token_id": token_id,
    })]
    if extra is not None:
        out.append(extra)
    return out


def _close_window_and_publish(poll: Poll, store: Store) -> List[Message]:
    """Tally accepted votes and broadcast RESULTS_PUBLISHED."""
    poll.closed = True
    window = store.windows.get(poll.window_id) if poll.window_id else None
    if window:
        window.closed = True
    tokens_for_poll = store.votes_by_token.get(poll.poll_id, {})
    totals: Dict[str, int] = {opt: 0 for opt in poll.options}
    for choice in tokens_for_poll.values():
        totals[choice] = totals.get(choice, 0) + 1
    n_voted = sum(totals.values())
    pct = {opt: (round(100.0 * c / n_voted, 1) if n_voted else 0.0) for opt, c in totals.items()}
    n_eligible = len(window.interested) if window else 0
    turnout = round(100.0 * n_voted / n_eligible, 1) if (window and n_eligible) else 0.0
    return [
        Message(type=MsgType.WINDOW_CLOSED, payload={"poll_id": poll.poll_id, "window_id": poll.window_id}),
        Message(type=MsgType.RESULTS_PUBLISHED, payload={
            "poll_id": poll.poll_id,
            "title": poll.title,
            "totals": totals,
            "percentages": pct,
            "turnout": turnout,
            "voted": n_voted,
            "eligible": n_eligible,
            "options": poll.options,
        }),
    ]


# --------------------------------------------------------------------------
# Dispatch table
# --------------------------------------------------------------------------
HANDLERS: Dict[MsgType, Handler] = {
    MsgType.LOGIN_REQUEST: handle_login,
    MsgType.LIST_PEERS: handle_list_peers,
    MsgType.CREATE_POLL: handle_create_poll,
    MsgType.LIST_POLLS: handle_list_polls,
    MsgType.RELEASE_POLL: handle_release_poll,
    MsgType.CLOSE_POLL: handle_close_poll,
    MsgType.CHECK_SPENDABLE: handle_check_spendable,
    MsgType.RELAY: handle_relay,
    MsgType.SUBMIT_VOTE: handle_submit_vote,
    MsgType.REISSUE_REQUEST: handle_reissue_request,
}
