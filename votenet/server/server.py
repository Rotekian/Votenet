"""The VoteNet asyncio server.

Responsibilities:

* ``start_server`` accepts TCP connections, one :class:`ClientConnection` each.
* A per-connection read loop decodes frames and dispatches to handlers.
* A single background **window loop** task watches each open window, advancing
  sub-rounds on the configured cadence and reissuing tokens for any holder
  whose vote was rejected in the previous sub-round — until every interested
  voter has an ACCEPTED vote, or ``MAX_ROUNDS``/expiry is hit.
* Broadcasts (WINDOW_OPENED, TOKEN_ISSUED, TOKEN_INVALIDATED, RESULTS_PUBLISHED)
  are fanned out to all authenticated connections.

The window loop is the engine that makes the cascade healing observable: a
rejected vote invalidates the token (broadcast), and the loop reissues a fresh
token to the affected holder for the next sub-round so they can vote again.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Optional

from .. import config
from ..crypto import Identity, generate_identity, load_identity, random_hex, save_identity
from ..messages import MsgType, Message, decode_frames, error
from .handlers import HANDLERS, _close_window_and_publish, _issue_tokens_for, _invalidate_token
from .store import ClientConnection, Store

log = logging.getLogger("votenet.server")


class VoteServer:
    def __init__(self, store: Optional[Store] = None, identity: Optional[Identity] = None) -> None:
        self.store = store or Store()
        self.identity = identity or generate_identity()
        self._server: Optional[asyncio.AbstractServer] = None
        self._window_task: Optional[asyncio.Task] = None
        # connections still in handshake (no pubkey yet) tracked separately
        self._anonymous_conns: List[ClientConnection] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self, host: str = config.HOST, port: int = config.PORT) -> None:
        self._server = await asyncio.start_server(self._handle_conn, host, port)
        self._window_task = asyncio.create_task(self._window_loop(), name="window-loop")
        addrs = ", ".join(str(s.getsockname()) for s in (self._server.sockets or []))
        log.info("VoteNet server listening on %s", addrs)
        log.info("Server pubkey_id: %s", self.identity.pubkey_id)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._window_task:
            self._window_task.cancel()
            try:
                await self._window_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    # ------------------------------------------------------------------
    # Per-connection read loop
    # ------------------------------------------------------------------
    async def _handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = ClientConnection(writer=writer)
        self._anonymous_conns.append(conn)
        buf = b""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                buf += data
                for msg, buf in decode_frames(buf):
                    await self._dispatch(conn, msg)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception:
            log.exception("error in connection read loop")
        finally:
            await self._cleanup(conn)

    async def _dispatch(self, conn: ClientConnection, msg: Message) -> None:
        handler = HANDLERS.get(msg.type)
        if handler is None:
            await conn.send(error(msg.id, "unknown_type", msg.type.value))
            return
        try:
            replies = await handler(conn, msg, self.store, self.identity)
        except Exception as e:
            log.exception("handler %s raised", msg.type.value)
            await conn.send(error(msg.id, "handler_error", str(e)))
            return
        # Send the direct replies back to the originator.
        for r in replies:
            target = getattr(r, "_target_conn", None) or conn
            await target.send(r)
        # Some replies are broadcasts (WINDOW_OPENED, TOKEN_INVALIDATED,
        # RESULTS_PUBLISHED, PEER_ANNOUNCE, PEER_LEAVE). Fan those out.
        broadcast_types = {
            MsgType.WINDOW_OPENED, MsgType.TOKEN_INVALIDATED,
            MsgType.RESULTS_PUBLISHED, MsgType.WINDOW_CLOSED,
            MsgType.PEER_ANNOUNCE, MsgType.PEER_LEAVE,
        }
        for r in replies:
            if r.type in broadcast_types:
                await self._broadcast(r, exclude=None)
        # TOKEN_ISSUED is NOT a broadcast: it's addressed to one recipient via
        # the _target_conn attribute, so it was already sent above.

    async def _broadcast(self, msg: Message, exclude: Optional[ClientConnection]) -> None:
        targets = list(self.store.peer_directory.values())
        for c in targets:
            if c is exclude or not c.authenticated:
                continue
            await c.send(msg)

    async def _cleanup(self, conn: ClientConnection) -> None:
        if conn in self._anonymous_conns:
            self._anonymous_conns.remove(conn)
        if conn.pubkey_id:
            self.store.unregister_peer(conn)
            # Announce departure so peers prune their path options.
            await self._broadcast(
                Message(type=MsgType.PEER_LEAVE, payload={"pubkey_id": conn.pubkey_id}),
                exclude=None,
            )
        try:
            conn.writer.close()
            await conn.writer.wait_closed()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Window loop — advances sub-rounds and heals cascades
    # ------------------------------------------------------------------
    async def _window_loop(self) -> None:
        """Periodically advance each open window.

        Every ``WINDOW_ROUND_SECONDS`` we look at each open window: if some
        interested voters haven't yet voted OK and some are queued for
        reissue, we bump the round and issue fresh tokens to them. When
        everyone interested has voted (or rounds exhaust / expiry hits), we
        close the window and publish results.
        """
        while True:
            try:
                await asyncio.sleep(1)
                for window in list(self.store.windows.values()):
                    if window.closed:
                        continue
                    await self._maybe_advance_window(window)
            except asyncio.CancelledError:
                break
            except Exception:
                log.exception("window loop iteration failed")

    async def _maybe_advance_window(self, window) -> None:  # type: ignore[no-untyped-def]
        now = int(time.time())
        poll = self.store.polls.get(window.poll_id)
        if poll is None:
            window.closed = True
            return
        # Closing conditions:
        everyone_voted = window.interested and window.interested <= window.voted_ok
        rounds_exhausted = window.round >= config.MAX_ROUNDS
        expired = now >= window.expires_at
        if everyone_voted or rounds_exhausted or expired:
            msgs = _close_window_and_publish(poll, self.store)
            for m in msgs:
                await self._broadcast(m, exclude=None)
            return
        # Time to advance a sub-round?
        elapsed_this_round = now - window.opened_at
        round_deadline = window.round * config.WINDOW_ROUND_SECONDS
        if elapsed_this_round < round_deadline:
            return  # still inside the current round
        # Advance.
        window.round += 1
        # Promote pending reissues into a fresh issuance round.
        if window.pending_reissue:
            # Carry interest forward: those users are still interested.
            window.interested |= window.pending_reissue
            new_messages = _issue_tokens_for(window, self.store, self.identity)
            for m in new_messages:
                target = getattr(m, "_target_conn", None)
                if target is not None:
                    await target.send(m)
            window.pending_reissue.clear()
