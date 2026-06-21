"""``python -m votenet.server`` entry point.

Seeds the demo accounts, loads (or generates) the server identity, and runs
the asyncio server forever. Prints the account list and server address on
startup so you know how to connect clients.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from .. import config
from ..crypto import Identity, generate_identity, load_identity, save_identity
from ..config import HOST, PORT, IDENTITY_PATH, SEED_ACCOUNTS, VOTENET_DIR
from .server import VoteServer
from .store import Store


def _build_store() -> Store:
    store = Store()
    for username, password, role in SEED_ACCOUNTS:
        store.add_user(username, password, role)
    return store


def _load_server_identity() -> Identity:
    server_path = VOTENET_DIR / "server.pem"
    if server_path.exists():
        return load_identity(server_path)
    ident = generate_identity()
    save_identity(ident, server_path)
    return ident


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    store = _build_store()
    identity = _load_server_identity()
    server = VoteServer(store=store, identity=identity)

    print("=" * 64)
    print(" VoteNet server")
    print("=" * 64)
    print(f"  Address : {HOST}:{PORT}")
    print(f"  Server pubkey_id: {identity.pubkey_id}")
    print()
    print("  Seeded accounts (username / password / role):")
    for u, pw, role in SEED_ACCOUNTS:
        print(f"    {u:<8} / {pw:<8} / {role}")
    print()
    print("  Launch clients with:  python -m votenet.client")
    print("=" * 64)
    print()

    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
