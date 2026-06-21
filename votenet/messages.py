"""Wire protocol for VoteNet.

Every message is a single line of JSON terminated by ``\\n``. The envelope is::

    {"id": "<uuid>", "type": "<MsgType>", "payload": {...}, "reply_to"?: "<id>"}

``id`` lets a caller correlate an async reply with a request. ``reply_to`` is
set on responses. ``payload`` shape depends on ``type``; see :class:`MsgType`.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class MsgType(str, Enum):
    """All message types on the wire. Values are the wire strings."""

    # --- Auth ---
    LOGIN_REQUEST = "login_request"
    LOGIN_RESPONSE = "login_response"
    SERVER_PUBKEY = "server_pubkey"    # server -> client: Ed25519 pubkey for token verification
    CHALLENGE = "challenge"            # server → client: prove you hold the key
    CHALLENGE_RESPONSE = "challenge_response"

    # --- Peer discovery ---
    PEER_ANNOUNCE = "peer_announce"    # server → all: a peer is online
    PEER_LEAVE = "peer_leave"
    LIST_PEERS = "list_peers"
    PEERS_LIST = "peers_list"

    # --- Polls (admin-gated) ---
    CREATE_POLL = "create_poll"
    POLL_CREATED = "poll_created"
    LIST_POLLS = "list_polls"
    POLLS_LIST = "polls_list"
    RELEASE_POLL = "release_poll"
    CLOSE_POLL = "close_poll"

    # --- Window lifecycle (broadcast) ---
    WINDOW_OPENED = "window_opened"    # {poll_id, window_id, expires_at, round}
    WINDOW_CLOSED = "window_closed"
    RESULTS_PUBLISHED = "results_published"

    # --- Tokens ---
    TOKEN_ISSUED = "token_issued"      # {token} bearer token for this window
    TOKEN_INVALIDATED = "token_invalidated"  # broadcast cascade
    CHECK_SPENDABLE = "check_spendable"      # anonymous query
    SPENDABLE_RESULT = "spendable_result"
    REISSUE_REQUEST = "reissue_request"      # present invalidated token for fresh one

    # --- Relay (hybrid: server forwards opaque blobs blind) ---
    RELAY = "relay"                          # {to_pubkey_id, blob}

    # --- Voting ---
    SUBMIT_VOTE = "submit_vote"        # {token, choice, reply_nonce}
    VOTE_RESPONSE = "vote_response"    # {nonce, status, reason?, token_id}

    # --- Errors / generic ---
    ERROR = "error"
    OK = "ok"


@dataclass
class Message:
    """A single wire message."""

    type: MsgType
    payload: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    reply_to: Optional[str] = None

    def to_json(self) -> str:
        env: Dict[str, Any] = {"id": self.id, "type": self.type.value, "payload": self.payload}
        if self.reply_to is not None:
            env["reply_to"] = self.reply_to
        return json.dumps(env, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> "Message":
        env = json.loads(line)
        return cls(
            type=MsgType(env["type"]),
            payload=env.get("payload", {}),
            id=env.get("id", uuid.uuid4().hex[:16]),
            reply_to=env.get("reply_to"),
        )

    def reply(self, type_: MsgType, payload: Optional[Dict[str, Any]] = None) -> "Message":
        """Build a response message correlated to this one via ``reply_to``."""
        return Message(type=type_, payload=payload or {}, reply_to=self.id)


def encode(msg: Message) -> bytes:
    """Serialize a :class:`Message` to a newline-terminated wire frame."""
    return (msg.to_json() + "\n").encode("utf-8")


def decode_frames(buffer: bytes):
    """Yield ``(Message, remaining_bytes)`` for each complete frame in ``buffer``.

    Returns the leftover bytes that don't yet form a complete line so callers
    can carry them into the next read.
    """
    remaining = buffer
    while b"\n" in remaining:
        line, remaining = remaining.split(b"\n", 1)
        if not line.strip():
            continue
        yield Message.from_json(line.decode("utf-8")), remaining


def error(reply_to: Optional[str], code: str, detail: str = "") -> Message:
    """Convenience constructor for an error message."""
    return Message(
        type=MsgType.ERROR,
        payload={"code": code, "detail": detail},
        reply_to=reply_to,
    )
