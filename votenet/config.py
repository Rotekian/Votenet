"""Static configuration for the VoteNet demo.

All values are demo-friendly defaults suitable for running the server and
several client instances on a single machine. Adjust freely for multi-host use.
"""

from __future__ import annotations

import os
from pathlib import Path

# --- Network ---------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 53171  # arbitrary unprivileged port

# --- Identity storage ------------------------------------------------------
VOTENET_DIR = Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".votenet"
IDENTITY_PATH = VOTENET_DIR / "identity.pem"

# --- Window timing (seconds) ----------------------------------------------
# A voting window stays open this long per sub-round before the server reviews
# reissues. The cascade loop continues until every interested holder has an
# ACCEPTED vote or MAX_ROUNDS is hit.
WINDOW_ROUND_SECONDS = 20
MAX_ROUNDS = 8

# --- Onion path ------------------------------------------------------------
MIN_ONION_HOPS = 2
MAX_ONION_HOPS = 3

# --- Auto-trading ----------------------------------------------------------
# When auto-trading is toggled on, a client proposes trades on this cadence
# (seconds between attempts). Roughly half of auto-proposals are CHAFF to
# generate anonymizing noise, the rest are REAL swaps of held tokens.
AUTO_TRADE_INTERVAL_SECONDS = 3.0
AUTO_TRADE_CHAFF_PROBABILITY = 0.5  # fraction of auto-trades that are CHAFF


# --- Seeded accounts -------------------------------------------------------
# (username, password, role). role is "admin" or "voter". The server prints
# this list on startup so you know how to log in.
SEED_ACCOUNTS = [
    ("admin", "admin", "admin"),
    ("alice", "alice", "voter"),
    ("bob", "bob", "voter"),
    ("carol", "carol", "voter"),
    ("dave", "dave", "voter"),
    ("eve", "eve", "voter"),
]

# --- Token validity --------------------------------------------------------
TOKEN_TTL_SECONDS = 60 * 10  # a token lives for ~ten minutes once issued

# --- Fingerprint helpers --------------------------------------------------
FINGERPRINT_LEN = 12  # hex chars of the public key shown in the UI
