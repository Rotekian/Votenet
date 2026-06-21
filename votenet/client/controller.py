"""Client-side state machine.

The controller owns all client state and reacts to every inbound
:class:`Message` delivered by :class:`ClientNet`. It is the bridge between raw
network messages and the GUI: views read state from the controller and the
controller emits high-level notifications (via callbacks) the GUI subscribes
to.

Key state:

* ``held_tokens`` — ``{token_id -> SignedToken}`` I currently possess (by
  issuance or trade). Possession = right to spend.
* ``spent_tokens`` — token_ids I've successfully voted with.
* ``awaiting_reissue`` — token_ids I held that got invalidated; I'm owed a
  replacement for the next sub-round.
* ``online_peers`` — ``{pubkey_id -> username}`` for path building & trades.
* ``polls`` — ``{poll_id -> poll_dict}`` cached from LIST_POLLS broadcasts.
* ``open_windows`` — ``{poll_id -> window_dict}``.
* ``results`` — ``{poll_id -> results_dict}``.
* ``server_public`` — the Ed25519 public key learned from the first signed
  token; used to verify every subsequent token + onion exit.

The cascade reactions live here:

* ``VoteResponse REJECTED``  -> invalidate that token locally (drop from
  ``held_tokens``), surface a notification. (The server's broadcast will also
  arrive; this is idempotent.)
* ``TokenInvalidated{id}``    -> drop the token if I hold it; if I had cast a
  vote with it that was ACCEPTED, that vote is now void and I request a
  reissue so I can vote again in the next sub-round.
* ``VoteResponse ACCEPTED``   -> mark the token spent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..crypto import public_from_id
from ..messages import Message, MsgType
from ..tokens import SignedToken
from .. import onion as _onion  # for sending reissue via onion (optional)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

log = logging.getLogger("votenet.client.controller")


@dataclass
class Notification:
    """A high-level event surfaced to the GUI."""

    kind: str          # "info", "vote", "trade", "cascade", "results", "error"
    title: str
    detail: str = ""


class ClientController:
    def __init__(self, net: "Any") -> None:
        self.net = net
        # State
        self.held_tokens: Dict[str, SignedToken] = {}
        self.spent_tokens: set[str] = set()
        self.awaiting_reissue: set[str] = set()  # invalidated token_ids I'm owed a replacement for
        self.online_peers: Dict[str, str] = {}   # pubkey_id -> username
        self.polls: Dict[str, Dict[str, Any]] = {}
        self.open_windows: Dict[str, Dict[str, Any]] = {}  # poll_id -> window
        self.results: Dict[str, Dict[str, Any]] = {}       # poll_id -> results
        self.username: Optional[str] = None
        self.role: Optional[str] = None
        self.server_public: Optional[Ed25519PublicKey] = None
        # token_ids that were issued directly to me by the server. A client is
        # "anonymized" once it holds at least one token that is NOT in this set
        # (i.e. it has traded away its original). Tracked so the AutoTrader
        # stops proposing once the client is anonymized — but the client keeps
        # ACCEPTING incoming trades so others can anonymize against it.
        self.original_token_ids: set[str] = set()
        # Pending vote replies we're watching (nonce -> choice/token_id)
        self._pending_votes: Dict[str, Dict[str, str]] = {}
        # Pending outbound PROPOSEs awaiting an ACCEPT (offer_id -> TradeMessage)
        self._pending_trades: Dict[str, Dict[str, Any]] = {}
        # When True, incoming trade PROPOSEs are auto-accepted (toggled with the
        # auto-trade switch). Manual trades always surface a notification.
        self.auto_accept_trades = False
        # GUI notification callback
        self.on_notify: Optional[Callable[[Notification], None]] = None
        self.on_state_change: Optional[Callable[[], None]] = None

    # ------------------------------------------------------------------
    # Wiring
    # ------------------------------------------------------------------
    def attach(self) -> None:
        """Subscribe to network messages."""
        self.net.add_listener(self.handle_message)

    def _notify(self, n: Notification) -> None:
        if self.on_notify:
            try:
                self.on_notify(n)
            except Exception:
                log.exception("notify callback raised")

    def _changed(self) -> None:
        if self.on_state_change:
            try:
                self.on_state_change()
            except Exception:
                log.exception("state change callback raised")

    # ------------------------------------------------------------------
    # Message dispatch
    # ------------------------------------------------------------------
    def handle_message(self, msg: Message) -> None:
        handler = {
            MsgType.SERVER_PUBKEY: self._on_server_pubkey,
            MsgType.PEER_ANNOUNCE: self._on_peer_announce,
            MsgType.PEER_LEAVE: self._on_peer_leave,
            MsgType.PEERS_LIST: self._on_peers_list,
            MsgType.POLLS_LIST: self._on_polls_list,
            MsgType.POLL_CREATED: self._on_poll_created,
            MsgType.WINDOW_OPENED: self._on_window_opened,
            MsgType.WINDOW_CLOSED: self._on_window_closed,
            MsgType.TOKEN_ISSUED: self._on_token_issued,
            MsgType.TOKEN_INVALIDATED: self._on_token_invalidated,
            MsgType.VOTE_RESPONSE: self._on_vote_response,
            MsgType.RESULTS_PUBLISHED: self._on_results_published,
            MsgType.SPENDABLE_RESULT: self._on_spendable_result,
            MsgType.RELAY: self._on_relay,
            MsgType.ERROR: self._on_error,
        }.get(msg.type)
        if handler is None:
            log.debug("unhandled message type %s", msg.type)
            return
        try:
            handler(msg)
        except Exception:
            log.exception("handler %s failed", msg.type)
        self._changed()

    # --- Server pubkey (learn once, verify forever) ---------------------
    def _on_server_pubkey(self, msg: Message) -> None:
        from ..crypto import unb64, public_from_bytes
        raw = unb64(msg.payload["pubkey_b64"])
        self.server_public = public_from_bytes(raw)
        # Re-verify any tokens we already hold against the now-known key.
        for tid, st in list(self.held_tokens.items()):
            if not st.verify(self.server_public):
                self.held_tokens.pop(tid, None)
                self._notify(Notification("error", "Token failed verification", tid[:8]))

    # --- Peer discovery -------------------------------------------------
    def _on_peer_announce(self, msg: Message) -> None:
        pid = msg.payload.get("pubkey_id")
        uname = msg.payload.get("username")
        if pid:
            self.online_peers[pid] = uname or pid[:8]

    def _on_peer_leave(self, msg: Message) -> None:
        pid = msg.payload.get("pubkey_id")
        if pid:
            self.online_peers.pop(pid, None)

    def _on_peers_list(self, msg: Message) -> None:
        for peer in msg.payload.get("peers", []):
            self.online_peers[peer["pubkey_id"]] = peer.get("username") or peer["pubkey_id"][:8]

    # --- Polls ----------------------------------------------------------
    def _on_polls_list(self, msg: Message) -> None:
        for p in msg.payload.get("polls", []):
            self.polls[p["poll_id"]] = p

    def _on_poll_created(self, msg: Message) -> None:
        # A new poll was created (maybe by us). Refresh the list.
        self.net.send(Message(type=MsgType.LIST_POLLS))

    # --- Window lifecycle ----------------------------------------------
    def _on_window_opened(self, msg: Message) -> None:
        poll_id = msg.payload["poll_id"]
        self.open_windows[poll_id] = msg.payload
        self.polls.setdefault(poll_id, {}).update({
            "title": msg.payload.get("title"),
            "description": msg.payload.get("description"),
            "options": msg.payload.get("options", []),
            "window_id": msg.payload.get("window_id"),
        })
        self._notify(Notification("info", "Poll opened", msg.payload.get("title", poll_id)))

    def _on_window_closed(self, msg: Message) -> None:
        poll_id = msg.payload.get("poll_id")
        self.open_windows.pop(poll_id, None)

    # --- Tokens ---------------------------------------------------------
    def _on_token_issued(self, msg: Message) -> None:
        st = SignedToken.from_dict(msg.payload["token"])
        # Verify the server signature before accepting.
        if self.server_public is not None and not st.verify(self.server_public):
            self._notify(Notification("error", "Rejected token", "bad server signature"))
            return
        self.held_tokens[st.token.token_id] = st
        # Tokens issued directly to me by the server are my "originals". A
        # client is anonymized once it holds a token that is NOT an original.
        self.original_token_ids.add(st.token.token_id)
        self.awaiting_reissue.discard(st.token.token_id)
        self._notify(Notification("info", "Vote token issued",
                                  f"for poll {st.token.poll_id[:8]}"))

    def has_anonymized(self) -> bool:
        """True iff I hold at least one token I did NOT receive by direct issuance.

        This is the trigger for the AutoTrader to stop *proposing* (one swap
        is enough to anonymize me). Accepting continues regardless so that
        other, not-yet-anonymized clients can shed their originals against me.
        """
        held = set(self.held_tokens.keys())
        return bool(held) and not held.issubset(self.original_token_ids)

    def _on_token_invalidated(self, msg: Message) -> None:
        """Cascade broadcast: drop the token everywhere, request reissue."""
        tid = msg.payload["token_id"]
        was_held = tid in self.held_tokens
        had_voted = tid in self.spent_tokens
        self.held_tokens.pop(tid, None)
        self.spent_tokens.discard(tid)
        self.original_token_ids.discard(tid)
        if was_held or had_voted:
            # I had this token (held or already voted). Per the spec, my vote
            # is invalidated and I'm owed a fresh token next sub-round.
            self.awaiting_reissue.add(tid)
            self._notify(Notification("cascade", "Token invalidated",
                                      f"A vote token ({tid[:8]}) was invalidated. "
                                      "You'll receive a replacement."))
            # Ask the server for a replacement. We need a signed copy of the
            # invalidated token to present — but we just dropped it. So we
            # remember the invalidated id and rely on the next TOKEN_ISSUED.
            # (The server's window loop reissues to anyone in pending_reissue.)
            self._request_reissue(tid)
        else:
            self._notify(Notification("cascade", "Token invalidated (cascade)",
                                      f"Token {tid[:8]} cascade — not one of yours."))

    def _request_reissue(self, invalidated_token_id: str) -> None:
        """Send a REISSUE_REQUEST for the next sub-round.

        We don't have the signed copy anymore (we dropped it on invalidation),
        so we send the bare token_id. The server's window loop already has us
        in its pending_reissue set when it triggered the cascade, so this is a
        belt-and-braces reminder.
        """
        # Look up which window this token belonged to via open_windows.
        window_id = None
        for w in self.open_windows.values():
            window_id = w.get("window_id")
            break  # any open window — there should be exactly one active poll
        self.net.send(Message(type=MsgType.REISSUE_REQUEST, payload={
            "token_id": invalidated_token_id,
            "window_id": window_id,
            "username": self.username,
        }))

    # --- Voting ---------------------------------------------------------
    def _on_vote_response(self, msg: Message) -> None:
        status = msg.payload.get("status")
        token_id = msg.payload.get("token_id")
        reason = msg.payload.get("reason")
        nonce = msg.payload.get("nonce")
        if status == "ACCEPTED":
            if token_id:
                self.spent_tokens.add(token_id)
                self.held_tokens.pop(token_id, None)
            self._notify(Notification("vote", "Vote accepted", "Your vote was recorded."))
        else:  # REJECTED
            # Per spec: on rejection, invalidate the original token locally.
            if token_id:
                self.held_tokens.pop(token_id, None)
                self.awaiting_reissue.add(token_id)
                self._request_reissue(token_id)
            self._notify(Notification("vote", "Vote rejected",
                                      f"reason: {reason}. Your token was invalidated; "
                                      "a replacement will be issued."))

    def _on_results_published(self, msg: Message) -> None:
        poll_id = msg.payload["poll_id"]
        self.results[poll_id] = msg.payload
        totals = msg.payload.get("totals", {})
        summary = ", ".join(f"{k}={v}" for k, v in totals.items())
        self._notify(Notification("results", "Results published", summary))

    # --- Anonymous spendability query reply ----------------------------
    def _on_spendable_result(self, msg: Message) -> None:
        # Routed back through the onion path; surfaced as a notification.
        status = msg.payload.get("status")
        tid = msg.payload.get("token_id")
        self._notify(Notification("info", "Token check", f"{tid[:8] if tid else '?'}: {status}"))

    # --- Relay (onion hop or trade) ------------------------------------
    def _on_relay(self, msg: Message) -> None:
        """We received an opaque blob. Peel our layer and act.

        Three cases:
          1. The blob is an onion layer for us -> peel; if ``next`` is a peer,
             relay onward; if ``next`` is SERVER, submit the inner payload.
          2. The blob is an encrypted trade offer/accept addressed to us ->
             decrypt and surface to the trade UI.
          3. The blob is a relay-back reply (e.g. VoteResponse traveling the
             reverse path) -> match by nonce.
        """
        blob = msg.payload.get("blob")
        if not blob:
            return
        # Try peeling as an onion layer first.
        try:
            peeled = _onion.peel_layer(self.net.identity, blob)
        except Exception:
            # Not an onion layer for us — try opening as a trade payload.
            self._maybe_handle_trade_blob(blob)
            return
        if _onion.is_exit(peeled):
            # We're the exit node: decode the inner payload and submit it to
            # the server on the sender's behalf. The server replies via a
            # reply_nonce; we route that back along the path.
            inner = _onion.decode_final_payload(peeled.blob_b64)
            self._submit_inner_to_server(inner)
        else:
            # Relay onward to the next peer.
            self.net.send(Message(type=MsgType.RELAY, payload={
                "to_pubkey_id": peeled.next,
                "blob": peeled.blob_b64,
            }))

    def _submit_inner_to_server(self, inner: Dict[str, Any]) -> None:
        """As the exit node, forward the inner payload to the server.

        We attach the original reply_nonce so the *originating* voter (not us)
        learns the result when it comes back as a VoteResponse matched by nonce.
        """
        inner_type = inner.get("type")
        if inner_type == "submit_vote":
            self.net.send(Message(type=MsgType.SUBMIT_VOTE, payload=inner))
        elif inner_type == "check_spendable":
            self.net.send(Message(type=MsgType.CHECK_SPENDABLE, payload=inner))
        else:
            log.debug("exit node ignoring inner type %s", inner_type)

    def _maybe_handle_trade_blob(self, blob: str) -> None:
        """Handle an incoming sealed trade message addressed to us.

        Implements the 1:1 swap protocol:

        * PROPOSE  -> decide whether to accept (auto or manual), then send an
                     ACCEPT back with our own counter item, adopting theirs.
        * ACCEPT   -> we initiated this trade; adopt the counter item they sent
                     back and complete the swap.
        """
        from .. import trade
        try:
            payload = trade.open_trade_payload(self.net.identity, blob)
        except Exception:
            return  # not for us
        # Only the new multi-step trade messages carry a "msg": "trade" flag.
        if payload.get("msg") != "trade":
            # Legacy single-shot offer (manual mode): just notify.
            kind = payload.get("kind")
            if kind in (trade.TradeKind.REAL.value, trade.TradeKind.CHAFF.value):
                offer = trade.TradeOffer.from_payload(payload)
                self._notify(Notification("trade", "Trade offer received",
                                          f"{offer.kind} from {offer.from_pubkey_id[:8]}"))
            return

        tmsg = trade.TradeMessage.from_payload(payload)
        if tmsg.action == trade.TradeAction.PROPOSE:
            self._handle_propose(tmsg)
        elif tmsg.action == trade.TradeAction.ACCEPT:
            self._handle_accept(tmsg)

    def _handle_propose(self, tmsg: "Any") -> None:
        """We received a PROPOSE. Verify (REAL), adopt, send back an ACCEPT.

        Only auto-accepts when ``auto_accept_trades`` is set (toggled by the
        AutoTrader). In manual mode we merely notify and let the user act.
        This is what lets the user disable auto-trading and not be drawn into
        swaps they didn't initiate.
        """
        from .. import trade
        # If this PROPOSE wasn't addressed to us, ignore.
        if tmsg.to_pubkey_id != self.net.identity.pubkey_id:
            return
        if not self.auto_accept_trades:
            # Manual mode: surface the offer but don't act automatically.
            self._notify(Notification("trade", "Trade offer received (manual)",
                                      f"{tmsg.kind.value} from {tmsg.from_pubkey_id[:8]} — "
                                      "enable auto-trade to accept."))
            return
        accepted_item: Optional[str] = None  # token_id we adopted, if REAL
        if tmsg.kind == trade.TradeKind.REAL:
            if tmsg.token is None or self.server_public is None:
                self._notify(Notification("trade", "Trade rejected",
                                          "REAL offer missing token or unknown server key"))
                return
            st = SignedToken.from_dict(tmsg.token)
            if not st.verify(self.server_public):
                self._notify(Notification("trade", "Trade rejected",
                                          "REAL token failed server signature verification"))
                return
            # Adopt their token.
            self.held_tokens[st.token.token_id] = st
            accepted_item = st.token.token_id
            self._notify(Notification("trade", "Trade accepted (REAL)",
                                      f"Adopted token {st.token.token_id[:8]} from "
                                      f"{tmsg.from_pubkey_id[:8]}"))
        else:  # CHAFF
            self._notify(Notification("trade", "Chaff trade received",
                                      f"noise round with {tmsg.from_pubkey_id[:8]}"))

        # Send an ACCEPT back with our own counter item. _pick_counter_token
        # prefers shedding an original so accepting also anonymizes us.
        counter_token = self._pick_counter_token(exclude=accepted_item)
        if counter_token is None and tmsg.kind == trade.TradeKind.REAL:
            # We accepted their token but have none to give back. This is fine:
            # a 1:1 swap is symmetric only when both hold a token. We complete
            # the receive without sending a counter — net effect: we gained a
            # token, peer gave one away. This still mixes holdings usefully.
            self._notify(Notification("trade", "Trade one-way",
                                      "Received a token but have none to send back."))
            return
        # Build the ACCEPT and send it back via a sealed relay.
        accept_msg = trade.TradeMessage(
            action=trade.TradeAction.ACCEPT,
            offer_id=tmsg.offer_id,
            from_pubkey_id=self.net.identity.pubkey_id,
            to_pubkey_id=tmsg.from_pubkey_id,
            kind=tmsg.kind,
            token=counter_token.to_dict() if counter_token else None,
            chaff_blob=trade.make_chaff() if (tmsg.kind == trade.TradeKind.CHAFF) else None,
        )
        blob = trade.seal_trade_payload(self.net.identity, tmsg.from_pubkey_id,
                                        accept_msg.to_payload())
        self.net.send(Message(type=MsgType.RELAY, payload={
            "to_pubkey_id": tmsg.from_pubkey_id, "blob": blob,
        }))
        # For REAL: if we sent our own token, drop it locally (it's theirs now).
        if counter_token is not None and tmsg.kind == trade.TradeKind.REAL:
            self.held_tokens.pop(counter_token.token.token_id, None)

    def _handle_accept(self, tmsg: "Any") -> None:
        """Our PROPOSE was accepted. Adopt the counter item they returned."""
        from .. import trade
        pending = self._pending_trades.pop(tmsg.offer_id, None)
        if tmsg.kind == trade.TradeKind.REAL:
            if tmsg.token is None or self.server_public is None:
                return
            st = SignedToken.from_dict(tmsg.token)
            if not st.verify(self.server_public):
                self._notify(Notification("trade", "Trade ACCEPT rejected",
                                          "counter token failed verification"))
                return
            self.held_tokens[st.token.token_id] = st
            self._notify(Notification("trade", "Trade complete (REAL)",
                                      f"Received token {st.token.token_id[:8]} from "
                                      f"{tmsg.from_pubkey_id[:8]}"))
        else:  # CHAFF
            self._notify(Notification("trade", "Chaff round complete",
                                      f"noise swap with {tmsg.from_pubkey_id[:8]}"))

    def _pick_counter_token(self, exclude: Optional[str]) -> Optional[SignedToken]:
        """Pick a held token to offer as the counter side of a REAL swap.

        Prefers to shed an *original* (server-issued-to-me) token: doing so
        anonymizes us (we keep the peer's non-original token, drop our own
        original), and gives the peer a token they didn't issue either. This
        makes both accepting and proposing converge everyone toward anonymity.
        """
        candidates = [st for tid, st in self.held_tokens.items() if tid != exclude]
        if not candidates:
            return None
        # Prefer originals so we shed the token most identifying to us.
        originals = [st for st in candidates if st.token.token_id in self.original_token_ids]
        return (originals or candidates)[0]

    # --- Errors ---------------------------------------------------------
    def _on_error(self, msg: Message) -> None:
        self._notify(Notification("error", "Server error",
                                  f"{msg.payload.get('code')}: {msg.payload.get('detail', '')}"))

    # ------------------------------------------------------------------
    # Queries for the GUI
    # ------------------------------------------------------------------
    def tokens_for_poll(self, poll_id: str) -> List[SignedToken]:
        return [st for st in self.held_tokens.values() if st.token.poll_id == poll_id]

    def has_open_window(self, poll_id: str) -> bool:
        return poll_id in self.open_windows

    def is_admin(self) -> bool:
        return self.role == "admin"

    def online_peer_list(self) -> List[tuple[str, str]]:
        return [(pid, name) for pid, name in self.online_peers.items()]
