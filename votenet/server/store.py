"""In-memory server state for VoteNet.

Holds all the maps the server consults while running a poll window:

* ``users`` / ``sessions`` — seeded accounts and the live session tokens.
* ``polls`` — created polls (title, description, options).
* ``windows`` — open voting windows keyed by ``window_id``.
* ``issuance_ledger`` — ``{token_id -> username}``. **The one place the server
  links a token to a user**, used solely to authorize cascade invalidations.
  Never used to bind a *spent* vote to a user.
* ``spend_ledger`` — ``{token_id -> window_id}``. The authoritative record of
  which tokens have been spent (double-spend detection).
* ``invalidated`` — ``set[token_id]``. Tokens that must no longer be honored.
* ``votes`` — ``{poll_id -> {option -> count}}`` plus per-token dedup.
* ``peer_directory`` — ``{pubkey_id -> ClientConnection}`` for relay routing.

Nothing here is persisted; the demo runs entirely in RAM.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from ..messages import Message


@dataclass
class User:
    username: str
    password: str  # plaintext — demo only
    role: str  # "admin" or "voter"


@dataclass
class Poll:
    poll_id: str
    title: str
    description: str
    options: List[str]
    created_by: str
    released: bool = False
    closed: bool = False
    # set when released
    window_id: Optional[str] = None


@dataclass
class Window:
    """A voting window for one poll. May run several sub-rounds (cascade)."""

    window_id: str
    poll_id: str
    opened_at: int
    expires_at: int
    round: int = 0
    # usernames that have expressed interest and should receive/keep a token
    interested: Set[str] = field(default_factory=set)
    # usernames that have an ACCEPTED vote in this window
    voted_ok: Set[str] = field(default_factory=set)
    # usernames awaiting a reissued token this sub-round
    pending_reissue: Set[str] = field(default_factory=set)
    # tokens issued for this window (for cleanup / validity checks)
    issued_tokens: Set[str] = field(default_factory=set)
    # tokens reissued in the current sub-round (carry interest forward)
    closed: bool = False


@dataclass
class ClientConnection:
    """A live TCP connection. Held in the peer directory while connected."""

    username: Optional[str] = None
    pubkey_id: Optional[str] = None
    writer: Any = None  # asyncio.StreamWriter
    session_token: Optional[str] = None

    @property
    def authenticated(self) -> bool:
        return self.username is not None and self.session_token is not None

    async def send(self, msg: "Message") -> None:
        from ..messages import encode

        if self.writer is None or self.writer.is_closing():
            return
        self.writer.write(encode(msg))
        try:
            await self.writer.drain()
        except Exception:
            # connection broken; the read loop will reap it
            pass


class Store:
    """All mutable server state. Single instance per server process."""

    def __init__(self) -> None:
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, str] = {}  # session_token -> username
        self.polls: Dict[str, Poll] = {}
        self.windows: Dict[str, Window] = {}
        self.issuance_ledger: Dict[str, str] = {}  # token_id -> username
        self.spend_ledger: Dict[str, str] = {}  # token_id -> window_id
        self.invalidated: Set[str] = set()
        # poll_id -> {token_id: option} so we can remove a vote if its token is
        # later invalidated during the window (and re-tally).
        self.votes_by_token: Dict[str, Dict[str, str]] = {}
        # peer directory: pubkey_id -> ClientConnection
        self.peer_directory: Dict[str, "ClientConnection"] = {}

    # ------------------------------------------------------------------
    # Users / sessions
    # ------------------------------------------------------------------
    def add_user(self, username: str, password: str, role: str) -> None:
        self.users[username] = User(username=username, password=password, role=role)

    def verify_credentials(self, username: str, password: str) -> Optional[User]:
        u = self.users.get(username)
        if u is not None and u.password == password:
            return u
        return None

    def create_session(self, username: str) -> str:
        from ..crypto import random_hex

        token = random_hex(24)
        self.sessions[token] = username
        return token

    def username_for_session(self, session_token: str) -> Optional[str]:
        return self.sessions.get(session_token)

    def user_for_pubkey(self, pubkey_id: str) -> Optional[User]:
        # Look up by the connection bound to this pubkey.
        conn = self.peer_directory.get(pubkey_id)
        if conn and conn.username:
            return self.users.get(conn.username)
        return None

    # ------------------------------------------------------------------
    # Token spend semantics
    # ------------------------------------------------------------------
    def is_spendable(self, token_id: str) -> str:
        """Return 'SPENDABLE', 'SPENT', or 'INVALIDATED'."""
        if token_id in self.invalidated:
            return "INVALIDATED"
        if token_id in self.spend_ledger:
            return "SPENT"
        return "SPENDABLE"

    # ------------------------------------------------------------------
    # Peer directory
    # ------------------------------------------------------------------
    def register_peer(self, conn: "ClientConnection") -> None:
        if conn.pubkey_id:
            self.peer_directory[conn.pubkey_id] = conn

    def unregister_peer(self, conn: "ClientConnection") -> None:
        if conn.pubkey_id and self.peer_directory.get(conn.pubkey_id) is conn:
            del self.peer_directory[conn.pubkey_id]

    def online_peer_ids(self) -> List[str]:
        return list(self.peer_directory.keys())
