"""Peer-to-peer bearer-token trades.

Trades are **fully peer-to-peer**: the server only relays opaque,
end-to-end-encrypted blobs between two clients and can neither read trade
contents nor tell that a relayed blob *is* a trade. This is what keeps trades
untrackable.

Two trade kinds:

* ``REAL`` — the offerer sends a genuine, server-signed bearer token. The
  recipient verifies the signature and runs an anonymous ``CheckSpendable``
  query (via the onion path) before accepting, so it cannot be handed an
  already-spent or invalidated token. If both checks pass, the two parties
  swap tokens. Fake tokens fail signature verification instantly.

* ``CHAFF`` — both parties knowingly exchange fabricated, non-verifying
  tokens purely to generate traffic indistinguishable from real trades,
  diluting any relay/path observer's signal. Verification is intentionally
  skipped.

Bad-actor handling: because possession of a valid token is the right to
spend, a counterparty who reneges (sends nothing valid) cannot steal a vote —
the rightful holder can always race to spend first. The worst a bad actor
achieves is triggering a reissue for the aggrieved party.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

from . import crypto
from .crypto import (
    Identity,
    aead_decrypt,
    aead_encrypt,
    b64,
    derive_shared,
    generate_ephemeral,
    public_from_id,
    unb64,
)
from .tokens import SignedToken
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


class TradeKind(str, Enum):
    """REAL = genuine token swap; CHAFF = deliberate fake-token noise."""

    REAL = "real"
    CHAFF = "chaff"


@dataclass
class TradeOffer:
    """A single offer from one peer to another.

    For ``REAL`` trades ``token`` is a genuine :class:`SignedToken`. For
    ``CHAFF`` trades ``token`` is None and ``chaff_blob`` carries fake data.
    """

    kind: TradeKind
    from_pubkey_id: str
    to_pubkey_id: str
    offer_id: str  # nonce correlating offer <-> accept
    token: Optional[Dict[str, Any]] = None  # SignedToken.to_dict(), REAL only
    chaff_blob: Optional[str] = None  # opaque fake bytes, CHAFF only

    def to_payload(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "kind": self.kind.value,
            "from": self.from_pubkey_id,
            "to": self.to_pubkey_id,
            "offer_id": self.offer_id,
        }
        if self.token is not None:
            d["token"] = self.token
        if self.chaff_blob is not None:
            d["chaff_blob"] = self.chaff_blob
        return d

    @classmethod
    def from_payload(cls, d: Dict[str, Any]) -> "TradeOffer":
        return cls(
            kind=TradeKind(d["kind"]),
            from_pubkey_id=d["from"],
            to_pubkey_id=d["to"],
            offer_id=d["offer_id"],
            token=d.get("token"),
            chaff_blob=d.get("chaff_blob"),
        )


class TradeAction(str, Enum):
    """Steps of the 1:1 swap protocol, carried inside a sealed trade message."""

    PROPOSE = "propose"   # A -> B: here is my token/chaff; want to trade?
    ACCEPT = "accept"     # B -> A: yes; here is my counter token; I've adopted yours.
    COMPLETE = "complete"  # internal: A adopts B's counter token.


@dataclass
class TradeMessage:
    """A sealed trade protocol message exchanged between two peers.

    Wraps a :class:`TradeOffer` (or a counter-offer in the ACCEPT step) plus the
    action discriminator. The whole thing is end-to-end encrypted to the peer.
    """

    action: TradeAction
    offer_id: str
    from_pubkey_id: str
    to_pubkey_id: str
    kind: TradeKind
    # In PROPOSE this is the proposer's token/chaff; in ACCEPT it is the
    # accepter's counter token/chaff.
    token: Optional[Dict[str, Any]] = None
    chaff_blob: Optional[str] = None

    def to_payload(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "msg": "trade",  # discriminator so receivers can tell trade msgs apart
            "action": self.action.value,
            "offer_id": self.offer_id,
            "from": self.from_pubkey_id,
            "to": self.to_pubkey_id,
            "kind": self.kind.value,
        }
        if self.token is not None:
            d["token"] = self.token
        if self.chaff_blob is not None:
            d["chaff_blob"] = self.chaff_blob
        return d

    @classmethod
    def from_payload(cls, d: Dict[str, Any]) -> "TradeMessage":
        return cls(
            action=TradeAction(d["action"]),
            offer_id=d["offer_id"],
            from_pubkey_id=d["from"],
            to_pubkey_id=d["to"],
            kind=TradeKind(d["kind"]),
            token=d.get("token"),
            chaff_blob=d.get("chaff_blob"),
        )


# --------------------------------------------------------------------------
# End-to-end encryption between two trading peers
# --------------------------------------------------------------------------
# The trade payload is encrypted to the recipient's long-term public key using
# an ephemeral X25519 keypair. The server relays the ciphertext blindly.
def seal_trade_payload(
    sender_identity: Identity,
    recipient_pubkey_id: str,
    payload: Dict[str, Any],
) -> str:
    """Encrypt ``payload`` (a trade offer/accept) for ``recipient_pubkey_id``.

    Returns a base64 blob suitable for carrying inside a ``Relay`` envelope.
    """
    pair = generate_ephemeral()
    recipient_ed = public_from_id(recipient_pubkey_id)
    # Reuse the Ed25519->X25519 conversion defined for onion layers.
    from .onion import ed25519_to_x25519_public

    recipient_x = ed25519_to_x25519_public(recipient_ed)
    key = derive_shared(pair.private, recipient_x)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ct = aead_encrypt(key, plaintext)
    envelope = {"eph": b64(pair.public_bytes), "ct": b64(ct)}
    return b64(json.dumps(envelope, separators=(",", ":")).encode())


def open_trade_payload(
    recipient_identity: Identity,
    blob_b64: str,
) -> Dict[str, Any]:
    """Inverse of :func:`seal_trade_payload`. Raises ``ValueError`` on failure."""
    from cryptography.exceptions import InvalidTag
    from .onion import _ed_priv_to_x25519

    envelope = json.loads(unb64(blob_b64).decode())
    eph_pub = X25519PublicKey.from_public_bytes(unb64(envelope["eph"]))
    x_priv = _ed_priv_to_x25519(recipient_identity)
    key = derive_shared(x_priv, eph_pub)
    try:
        plaintext = aead_decrypt(key, unb64(envelope["ct"]))
    except InvalidTag as e:
        raise ValueError("trade payload not for us (or tampered)") from e
    return json.loads(plaintext.decode())


# --------------------------------------------------------------------------
# Verification helpers (recipient side, REAL trades)
# --------------------------------------------------------------------------
def verify_offered_token(offer: TradeOffer, server_public: Ed25519PublicKey) -> Optional[SignedToken]:
    """For a REAL offer, return the verified :class:`SignedToken` or None.

    Returns None if the offer is CHAFF (caller decides whether that's an error)
    or if the token fails signature verification.
    """
    if offer.kind != TradeKind.REAL or offer.token is None:
        return None
    st = SignedToken.from_dict(offer.token)
    return st if st.verify(server_public) else None


def make_chaff() -> str:
    """Generate opaque fake bytes for a CHAFF trade offer."""
    return crypto.random_hex(32)
