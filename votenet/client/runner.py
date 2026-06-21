"""``python -m votenet.client`` entry point — launches the tkinter GUI."""

from __future__ import annotations

import logging
import sys

from .. import config
from .ui.app import VoteNetApp


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    print("=" * 64)
    print(" VoteNet client")
    print("=" * 64)
    print(f"  Default server: {config.HOST}:{config.PORT}")
    print(f"  Seeded accounts: admin/admin, alice/alice, bob/bob,")
    print(f"                   carol/carol, dave/dave, eve/eve")
    print("=" * 64)
    print()
    try:
        app = VoteNetApp()
        app.run()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
