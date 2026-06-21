"""High-level actions the GUI invokes, all synchronous from its perspective.

Each method packages a :class:`Message` and either awaits a reply (via
``ClientNet._request_reply``) or fires-and-forgets. Onion-routed vote
submission and P2P trade framing live here, built on :mod:`votenet.onion` and
:mod:`votenet.trade`.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .. import config, onion, trade
from ..crypto import random_hex
from ..messages import Message, MsgType
from ..tokens import SignedToken
from .controller import ClientController
from .net import ClientNet

log = logging.getLogger("votenet.client.api")


class ClientAPI:
    def __init__(self, net: ClientNet, controller: ClientController) -> None:
        self.net = net
        self.controller = controller

    # ------------------------------------------------------------------
    # Connection / login
    # ------------------------------------------------------------------
    def login(self, host: str, port: int, username: str, password: str) -> Dict[str, Any]:
        result = self.net.connect_and_login(host, port, username, password)
        self.controller.username = result.get("username")
        self.controller.role = result.get("role")
        # Ask the server for the current poll + peer snapshots.
        self.net.send(Message(type=MsgType.LIST_POLLS))
        self.net.send(Message(type=MsgType.LIST_PEERS))
        return result

    # ------------------------------------------------------------------
    # Poll management (admin)
    # ------------------------------------------------------------------
    def create_poll(self, title: str, description: str, options: List[str]) -> Optional[str]:
        """Create a poll. Returns the new poll_id, or None on error."""
        req = Message(type=MsgType.CREATE_POLL, payload={
            "title": title, "description": description, "options": options,
        })
        reply = self._request(req)
        if reply and reply.type == MsgType.POLL_CREATED:
            return reply.payload.get("poll_id")
        return None

    def release_poll(self, poll_id: str) -> bool:
        """Open the voting window for a poll."""
        req = Message(type=MsgType.RELEASE_POLL, payload={"poll_id": poll_id})
        reply = self._request(req)
        return reply is not None and reply.type == MsgType.OK

    def close_poll(self, poll_id: str) -> bool:
        req = Message(type=MsgType.CLOSE_POLL, payload={"poll_id": poll_id})
        reply = self._request(req)
        return reply is not None and reply.type in (MsgType.RESULTS_PUBLISHED, MsgType.OK)

    def refresh_polls(self) -> None:
        self.net.send(Message(type=MsgType.LIST_POLLS))

    # ------------------------------------------------------------------
    # Voting (onion-routed, anonymous)
    # ------------------------------------------------------------------
    def cast_vote(self, poll_id: str, choice: str) -> str:
        """Cast a vote for ``choice`` on ``poll_id`` using one of my held tokens.

        Builds an onion path through 2-3 online peers, wraps the
        ``SubmitVote`` payload, and sends it as a Relay to the first hop. The
        server records the vote against the **token**, not our connection.

        Returns the ``reply_nonce`` so the GUI can correlate the eventual
        VoteResponse. Raises ``RuntimeError`` if we hold no token or no peers
        are available for a path.
        """
        token = self._pick_token_for(poll_id)
        if token is None:
            raise RuntimeError("no held token for this poll")
        peers = list(self.controller.online_peers.keys())
        if not peers:
            raise RuntimeError("no online peers to build an onion path")
        path = onion.pick_path(self.net.identity.pubkey_id, peers,
                               config.MIN_ONION_HOPS, config.MAX_ONION_HOPS)
        nonce = random_hex(8)
        inner_payload = {
            "type": "submit_vote",
            "token": token.to_dict(),
            "choice": choice,
            "reply_nonce": nonce,
        }
        blob = onion.build_onion(inner_payload, path)
        # Remember what we're waiting for so the GUI can show context.
        self.controller._pending_votes[nonce] = {
            "token_id": token.token.token_id,
            "choice": choice,
            "poll_id": poll_id,
        }
        self.net.send(Message(type=MsgType.RELAY, payload={
            "to_pubkey_id": path[0],
            "blob": blob,
        }))
        return nonce

    def _pick_token_for(self, poll_id: str) -> Optional[SignedToken]:
        for st in self.controller.held_tokens.values():
            if st.token.poll_id == poll_id:
                return st
        return None

    # ------------------------------------------------------------------
    # P2P trades (REAL / CHAFF)
    # ------------------------------------------------------------------
    def offer_trade(self, my_token: SignedToken, recipient_pubkey_id: str,
                    kind: trade.TradeKind) -> str:
        """Send a trade PROPOSE to a peer and register it as pending.

        REAL: includes the genuine signed token; the recipient verifies it
        before accepting, then sends back its own counter token. CHAFF: both
        parties knowingly exchange noise — no verification.

        Returns the ``offer_id`` so the caller can correlate the eventual ACCEPT.
        """
        offer_id = random_hex(8)
        if kind == trade.TradeKind.REAL:
            tmsg = trade.TradeMessage(
                action=trade.TradeAction.PROPOSE,
                offer_id=offer_id,
                from_pubkey_id=self.net.identity.pubkey_id,
                to_pubkey_id=recipient_pubkey_id,
                kind=kind,
                token=my_token.to_dict(),
            )
        else:  # CHAFF
            tmsg = trade.TradeMessage(
                action=trade.TradeAction.PROPOSE,
                offer_id=offer_id,
                from_pubkey_id=self.net.identity.pubkey_id,
                to_pubkey_id=recipient_pubkey_id,
                kind=kind,
                chaff_blob=trade.make_chaff(),
            )
        self.controller._pending_trades[offer_id] = {"kind": kind.value,
                                                      "to": recipient_pubkey_id}
        blob = trade.seal_trade_payload(self.net.identity, recipient_pubkey_id,
                                        tmsg.to_payload())
        self.net.send(Message(type=MsgType.RELAY, payload={
            "to_pubkey_id": recipient_pubkey_id,
            "blob": blob,
        }))
        return offer_id

    def offer_chaff(self, recipient_pubkey_id: str) -> str:
        """Send a CHAFF PROPOSE (no held token needed). Used by the AutoTrader."""
        return self.offer_trade(my_token=None,  # type: ignore[arg-type]
                                recipient_pubkey_id=recipient_pubkey_id,
                                kind=trade.TradeKind.CHAFF)

    def check_spendable(self, token_id: str) -> str:
        """Anonymous CheckSpendable query via the onion path.

        Returns 'SPENDABLE', 'SPENT', 'INVALIDATED', or 'UNKNOWN' if no reply.
        """
        peers = list(self.controller.online_peers.keys())
        if not peers:
            return "UNKNOWN"
        path = onion.pick_path(self.net.identity.pubkey_id, peers, 1, config.MAX_ONION_HOPS)
        nonce = random_hex(8)
        inner = {"type": "check_spendable", "token_id": token_id, "nonce": nonce}
        blob = onion.build_onion(inner, path)
        self.net.send(Message(type=MsgType.RELAY, payload={
            "to_pubkey_id": path[0], "blob": blob,
        }))
        return nonce  # caller watches for SPENDABLE_RESULT with this nonce

    # ------------------------------------------------------------------
    # Plumbing
    # ------------------------------------------------------------------
    def _request(self, msg: Message) -> Optional[Message]:
        """Send a message and await its reply (blocking the GUI briefly)."""
        if self.net._loop is None:
            return None
        coro = self.net._request_reply(msg, timeout=6.0)
        fut = asyncio.run_coroutine_threadsafe(coro, self.net._loop)  # type: ignore[arg-type]
        try:
            return fut.result(timeout=8)
        except Exception:
            log.exception("request %s failed", msg.type)
            return None
