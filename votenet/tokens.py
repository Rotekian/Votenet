"""Bearer vote tokens.

A :class:`VoteToken` carries **no owner/recipient field**. Possession of a
correctly-signed, unspent, non-invalidated token is the right to cast one
vote. This is what makes peer-to-peer trades untrackable: there is nothing on
the token to track.

The token's canonical-JSON body is signed by the server's Ed25519 key, so its
validity is publicly verifiable by anyone — a critical property for safe P2P
trades, since a buyer can confirm a token is genuine before accepting it.

Note (anonymity limitation): the server records which *user* it issued a token
to in its issuance ledger. That ledger is used **only** to authorize cascade
invalidations — it never binds a *spent* vote to that user (see README,
"Anonymity properties & honest limitations").
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

from . import crypto
from .crypto import Identity, b64, canonical_json, random_hex, unb64, verify_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(frozen=True)
class VoteToken:
    """A server-signed bearer token granting one vote.

    Fields are intentionally minimal: ``token_id`` is a random 16-byte hex,
    ``poll_id`` / ``window_id`` bind it to a specific poll window, and
    ``expires_at`` bounds its lifetime. There is **no** owner field.
    """

    token_id: str
    poll_id: str
    window_id: str
    issued_at: int
    expires_at: int

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def to_signed(self, server_identity: Identity) -> "SignedToken":
        """Sign this token with the server identity, returning a SignedToken."""
        body = canonical_json(self._body_dict())
        signature = server_identity.private.sign(body)
        return SignedToken(token=self, signature=b64(signature))

    def _body_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "poll_id": self.poll_id,
            "window_id": self.window_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class SignedToken:
    """A :class:`VoteToken` plus its server signature, ready for transport."""

    token: VoteToken
    signature: str  # base64 Ed25519 signature over the canonical token body

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def verify(self, server_public: Ed25519PublicKey) -> bool:
        """Return True iff the signature is valid for ``server_public``."""
        try:
            body = canonical_json(self.token._body_dict())
            return verify_signature(server_public, unb64(self.signature), body)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": asdict(self.token),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignedToken":
        t = d["token"]
        return cls(
            token=VoteToken(
                token_id=t["token_id"],
                poll_id=t["poll_id"],
                window_id=t["window_id"],
                issued_at=t["issued_at"],
                expires_at=t["expires_at"],
            ),
            signature=d["signature"],
        )


# --------------------------------------------------------------------------
# Factory
# --------------------------------------------------------------------------
def issue_token(
    poll_id: str,
    window_id: str,
    server_identity: Identity,
    ttl_seconds: int,
    token_id: Optional[str] = None,
) -> SignedToken:
    """Create and sign a fresh bearer token for ``poll_id`` / ``window_id``."""
    now = int(time.time())
    return VoteToken(
        token_id=token_id or random_hex(16),
        poll_id=poll_id,
        window_id=window_id,
        issued_at=now,
        expires_at=now + ttl_seconds,
    ).to_signed(server_identity)
