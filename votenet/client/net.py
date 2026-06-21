"""Networking thread bridge for the VoteNet client.

Problem: tkinter must run in the main thread, and asyncio must run in a
single thread. We solve it by running the asyncio loop in a **background
daemon thread** and exposing a small synchronous API to the GUI.

* Outbound: the GUI thread enqueues :class:`Message` objects on
  ``outgoing``; the asyncio loop drains it and writes each to the socket.
* Inbound: the asyncio loop enqueues incoming :class:`Message` objects on
  ``incoming``; the GUI polls them with ``root.after(50, ...)``
* Requests that need a reply (e.g. login) use an asyncio Future stored in
  ``_pending``, keyed by ``reply_to`` correlation.

This keeps all socket I/O off the GUI thread while letting the GUI drive
actions through plain method calls on :class:`ClientNet`.
"""

from __future__ import annotations

import asyncio
import logging
import queue
import threading
import uuid
from typing import Any, Callable, Dict, Optional

from .. import config
from ..crypto import Identity, generate_identity, load_identity, save_identity
from ..messages import Message, MsgType, decode_frames, encode

log = logging.getLogger("votenet.client.net")


class ClientNet:
    """The threaded network client. Owned by the GUI thread."""

    def __init__(self, identity: Optional[Identity] = None) -> None:
        self.identity = identity or load_or_create_identity()
        self.host = config.HOST
        self.port = config.PORT
        # cross-thread queues
        self.incoming: "queue.Queue[Message]" = queue.Queue()
        self._outgoing: "queue.Queue[Message]" = queue.Queue()
        # correlation: id -> Future (asyncio side)
        self._pending: Dict[str, asyncio.Future] = {}
        # GUI-side subscribers for state events
        self._listeners: list[Callable[[Message], None]] = []
        # asyncio plumbing
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self.connected = threading.Event()
        self.username: Optional[str] = None
        self.role: Optional[str] = None

    # ------------------------------------------------------------------
    # Listener registration (GUI calls this from main thread)
    # ------------------------------------------------------------------
    def add_listener(self, fn: Callable[[Message], None]) -> None:
        self._listeners.append(fn)

    def poll_incoming(self) -> list[Message]:
        """Drain any inbound messages. Called by the GUI via after()."""
        msgs: list[Message] = []
        while True:
            try:
                msgs.append(self.incoming.get_nowait())
            except queue.Empty:
                break
        return msgs

    def notify_listeners(self, msg: Message) -> None:
        """Push a message to all GUI listeners (main thread)."""
        for fn in self._listeners:
            try:
                fn(msg)
            except Exception:
                log.exception("listener raised")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Spawn the background asyncio thread (does not connect yet)."""
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="votenet-net")
        self._thread.start()

    def stop(self) -> None:
        if self._loop is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop).result(timeout=2)
        except Exception:
            # Teardown race (e.g. loop already stopping). Force-stop as fallback.
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        self._loop = None
        self._thread = None

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    async def _shutdown(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._loop.stop()

    # ------------------------------------------------------------------
    # Connection + login (called from GUI thread, returns via Future)
    # ------------------------------------------------------------------
    def connect_and_login(self, host: str, port: int, username: str, password: str) -> Any:
        """Connect (if needed) and log in. Returns the LOGIN_RESPONSE payload.

        Blocks the GUI thread briefly while awaiting the response. Raises
        ConnectionError on transport failure or ValueError on bad credentials.
        """
        self.host = host
        self.port = port
        coro = self._connect_and_login(username, password)
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)  # type: ignore[arg-type]
        return fut.result(timeout=10)

    async def _connect_and_login(self, username: str, password: str) -> Dict[str, Any]:
        if self._writer is None or self._writer.is_closing():
            self._reader, self._writer = await asyncio.open_connection(self.host, self.port)
            self.connected.set()
            asyncio.ensure_future(self._read_loop(), loop=self._loop)
        # Send login with our pubkey_id so the server registers us in the peer dir.
        req = Message(type=MsgType.LOGIN_REQUEST, payload={
            "username": username,
            "password": password,
            "pubkey_id": self.identity.pubkey_id,
        })
        reply = await self._request_reply(req)
        if not reply or not reply.payload.get("ok"):
            raise ValueError(reply.payload.get("error", "login failed") if reply else "no reply")
        self.username = reply.payload.get("username")
        self.role = reply.payload.get("role")
        return reply.payload

    async def _request_reply(self, msg: Message, timeout: float = 8.0) -> Optional[Message]:
        """Send a message and await the reply correlated by id."""
        assert self._loop is not None
        fut: asyncio.Future = self._loop.create_future()
        self._pending[msg.id] = fut
        self._send_now(msg)
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self._pending.pop(msg.id, None)
            return None

    def _send_now(self, msg: Message) -> None:
        """Enqueue a message for the writer to drain."""
        self._outgoing.put_nowait(msg)
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._pump_outgoing)

    def _pump_outgoing(self) -> None:
        """Drain the outgoing queue onto the wire (asyncio thread)."""
        assert self._loop is not None
        while True:
            try:
                msg = self._outgoing.get_nowait()
            except queue.Empty:
                return
            asyncio.ensure_future(self._write(msg), loop=self._loop)

    async def _write(self, msg: Message) -> None:
        if self._writer is None or self._writer.is_closing():
            return
        try:
            self._writer.write(encode(msg))
            await self._writer.drain()
        except Exception:
            log.exception("write failed")
            self.connected.clear()

    async def _read_loop(self) -> None:
        """Read frames forever, dispatching replies and forwarding to GUI."""
        assert self._reader is not None
        buf = b""
        try:
            while True:
                data = await self._reader.read(4096)
                if not data:
                    break
                buf += data
                for msg, buf in decode_frames(buf):
                    self._dispatch_inbound(msg)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception:
            log.exception("read loop failed")
        finally:
            self.connected.clear()

    def _dispatch_inbound(self, msg: Message) -> None:
        # 1. Resolve any pending request future.
        fut = self._pending.pop(msg.reply_to, None)
        if fut is not None and not fut.done():
            fut.set_result(msg)
            return  # request replies are consumed by the requester
        # 2. Otherwise deliver to the GUI via the incoming queue.
        self.incoming.put(msg)

    # ------------------------------------------------------------------
    # Fire-and-forget sends (no reply expected) — for relays, votes, etc.
    # ------------------------------------------------------------------
    def send(self, msg: Message) -> None:
        """Send a message without awaiting a reply."""
        self._send_now(msg)

    # ------------------------------------------------------------------
    # Server pubkey — fetched once after login so we can verify tokens.
    # ------------------------------------------------------------------
    # The server's public key isn't shipped in a dedicated message in v1; we
    # trust the LOGIN_RESPONSE channel (TLS or localhost assumed). The client
    # learns it from the first server-signed token it receives, verifying all
    # subsequent tokens against that key. See controller.py.


def load_or_create_identity() -> Identity:
    """Load the client's long-term identity, creating one on first run."""
    from ..config import IDENTITY_PATH
    if IDENTITY_PATH.exists():
        return load_identity(IDENTITY_PATH)
    ident = generate_identity()
    save_identity(ident, IDENTITY_PATH)
    return ident
