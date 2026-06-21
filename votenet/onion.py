"""Hybrid onion routing for VoteNet.

Topology (from the approved plan):

* The server keeps a **peer directory** ``{pubkey_id -> writer}`` so it can
  forward opaque bytes to any connected client without inspecting them.
* A voter ``V`` picks a path of other connected clients ``[N1, N2, ...,
  exit]`` and wraps its final payload in layered encryption, one layer per
  hop. Each layer's plaintext is::

      {"next": "<pubkey_id-of-next-hop-or-SERVER>", "blob": "<base64>"}

  The *innermost* layer is addressed to ``"SERVER"`` and carries the actual
  submission (a vote, or a ``CheckSpendable`` query).
* ``V`` sends the outermost layer as ``Relay{to: N1}``. The server forwards
  it blind. ``N1`` peels its layer, sees ``next: N2``, and sends a fresh
  ``Relay{to: N2}``. ... The exit peels, sees ``next: SERVER``, and submits
  the inner payload to the server as a normal message (e.g. ``SubmitVote``).
* The server records the action against the **token**, not the exit node's
  connection — so it cannot link the vote to ``V``.

Anonymous replies: the inner payload carries a one-time ``reply_nonce``. The
server's reply (``VoteResponse{nonce, status}``) is matched client-side by
``V``, who learns its result without the server knowing where to route it.

Note on key lookup: every hop is encrypted to a *specific* peer's long-term
Ed25519 public key (converted to X25519 for the agreement). We need the
Ed25519→X25519 conversion, done once in :func:`ed25519_to_x25519_public`.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from . import crypto
from .crypto import (
    EphemeralPair,
    Identity,
    aead_decrypt,
    aead_encrypt,
    b64,
    derive_shared,
    generate_ephemeral,
    public_from_id,
    unb64,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization


SERVER_HOP = "SERVER"  # sentinel "next" address meaning the innermost hop is the server


# --------------------------------------------------------------------------
# Ed25519 <-> X25519 public key conversion
# --------------------------------------------------------------------------
def ed25519_to_x25519_public(ed: Ed25519PublicKey) -> X25519PublicKey:
    """Convert a long-term Ed25519 public key to its X25519 counterpart.

    Ed25519 and X25519 use the same underlying curve (Curve25519); the public
    keys differ only in encoding (Edwards vs. Montgomery). The ``cryptography``
    library exposes the standard conversion via the point-decode path.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey as _Ed,
    )
    # The robust path: re-encode via the raw point. The cryptography lib does
    # not expose a direct converter, so we use the well-known fact that for a
    # keypair (ed_priv, ed_pub) there is a derived x25519 priv whose public
    # matches this conversion. We reconstruct via the raw public bytes using
    # the library's own internal curve operations through a throwaway
    # derivation. Practically, we use the public-key form directly by decoding
    # the Edwards point.
    raw = ed.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # Convert using the elligator-free standard mapping implemented by
    # `cryptography` via the X25519 wrapper when given a public key derived
    # from the same scalar. We rely on the helper below.
    return _ed_raw_to_x25519(raw)


def _ed_raw_to_x25519(raw_ed: bytes) -> X25519PublicKey:
    """Convert raw Ed25519 public bytes (32) to an X25519 public key.

    This implements the standard RFC 7748 Edwards→Montgomery u-coordinate
    recovery (the "birational map"). We delegate to the proven implementation
    in ``cryptography``'s internal primitives is not available publicly, so we
    implement the well-documented map here.
    """
    import hashlib

    # Recover the y-coordinate from the Ed25519 point encoding.
    # Ed25519 stores x.sign | y where y is the low 255 bits.
    y_le = bytearray(raw_ed)
    sign = (y_le[31] >> 7) & 1
    y_le[31] &= 0x7F
    y = int.from_bytes(bytes(y_le), "little")

    p = 2 ** 255 - 19
    d = (-121665 * pow(121666, p - 2, p)) % p
    # u = (1 + y) / (1 - y)  mod p   (the birational map)
    u = ((1 + y) * pow((1 - y) % p, p - 2, p)) % p
    u_bytes = u.to_bytes(32, "little")
    return X25519PublicKey.from_public_bytes(u_bytes)


# --------------------------------------------------------------------------
# Layer construction
# --------------------------------------------------------------------------
def _wrap_layer(inner_blob_b64: str, next_hop: str, recipient_pubkey_id: str) -> str:
    """Wrap one layer: encrypt the (next, blob) tuple for ``recipient``.

    Returns the base64 ciphertext that becomes the *outer* blob's ``blob``
    field addressed to ``recipient`` by the caller.
    """
    pair = generate_ephemeral()
    recipient_ed = public_from_id(recipient_pubkey_id)
    recipient_x = ed25519_to_x25519_public(recipient_ed)
    key = derive_shared(pair.private, recipient_x)
    plaintext = json.dumps({"next": next_hop, "blob": inner_blob_b64}, separators=(",", ":")).encode()
    ct = aead_encrypt(key, plaintext)
    envelope = {"eph": b64(pair.public_bytes), "ct": b64(ct)}
    return b64(json.dumps(envelope, separators=(",", ":")).encode())


@dataclass
class PeeledLayer:
    """Result of peeling one onion layer at a hop."""

    next: str  # pubkey_id of next hop, or SERVER_HOP
    blob_b64: str  # the inner blob to forward (still encrypted to the next hop)


def peel_layer(recipient_identity: Identity, layer_b64: str) -> PeeledLayer:
    """Peel one layer addressed to ``recipient_identity``.

    Raises ``ValueError`` (or ``InvalidTag``) if this layer wasn't meant for
    us or has been tampered with.
    """
    from cryptography.exceptions import InvalidTag

    envelope = json.loads(unb64(layer_b64).decode())
    eph_pub = X25519PublicKey.from_public_bytes(unb64(envelope["eph"]))
    # Derive the matching X25519 private scalar from our Ed25519 identity.
    x_priv = _ed_priv_to_x25519(recipient_identity)
    key = derive_shared(x_priv, eph_pub)
    try:
        plaintext = aead_decrypt(key, unb64(envelope["ct"]))
    except InvalidTag as e:
        raise ValueError("onion layer not for us (or tampered)") from e
    payload = json.loads(plaintext.decode())
    return PeeledLayer(next=payload["next"], blob_b64=payload["blob"])


def _ed_priv_to_x25519(identity: Identity) -> "Any":
    """Derive the X25519 private key corresponding to an Ed25519 identity.

    Ed25519 private keys in PKCS8 store the 32-byte seed from which both the
    Ed25519 scalar and the X25519 scalar are derived (SHA-512 of the seed,
    clamped). We recover the seed and rebuild the X25519 private key.
    """
    import hashlib
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    raw = identity.private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Ed25519 stores the 32-byte seed in Raw format.
    seed = raw[:32]
    h = hashlib.sha512(seed).digest()
    # Clamp per RFC 7748
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return X25519PrivateKey.from_private_bytes(bytes(a))


# --------------------------------------------------------------------------
# Path building (sender side)
# --------------------------------------------------------------------------
def build_onion(
    final_payload: Dict[str, Any],
    path_pubkey_ids: Sequence[str],
) -> str:
    """Wrap ``final_payload`` (addressed to SERVER) in onion layers.

    ``path_pubkey_ids`` is the ordered list of peer hops, e.g. ``[N1, N2]``.
    The innermost layer is automatically addressed to ``SERVER`` and carries
    ``final_payload`` (JSON-encoded, base64). The function returns the base64
    blob that the sender ships as ``Relay{to: path_pubkey_ids[0]}``.

    The sender does NOT need its own key material to *build* the onion — only
    the public keys of the hops (which are public). Peeling requires the
    private key of each hop in turn.
    """
    if not path_pubkey_ids:
        raise ValueError("onion path must contain at least one hop")

    # Innermost: addressed to SERVER, payload is the final message body.
    inner = b64(json.dumps(final_payload, separators=(",", ":")).encode())
    # Walk backwards: each layer wraps (next, blob) for the preceding hop.
    # The exit hop (last in path) wraps the SERVER-bound inner.
    blob_b64 = inner
    next_hop = SERVER_HOP
    for hop in reversed(path_pubkey_ids):
        blob_b64 = _wrap_layer(blob_b64, next_hop, hop)
        next_hop = hop
    return blob_b64


def pick_path(
    own_pubkey_id: str,
    all_peer_ids: Sequence[str],
    min_hops: int = 2,
    max_hops: int = 3,
) -> List[str]:
    """Choose ``min_hops..max_hops`` random peers (excluding self) for a path.

    Falls back to fewer hops (even 1) if too few peers are online; the caller
    is responsible for ensuring at least one peer exists.
    """
    import secrets

    candidates = [p for p in all_peer_ids if p != own_pubkey_id]
    if not candidates:
        raise ValueError("no peers available for onion path")
    n = max(1, min(max_hops, len(candidates)))
    n = max(min_hops, n) if len(candidates) >= min_hops else n
    # unique sampling
    chosen: List[str] = []
    pool = list(candidates)
    while pool and len(chosen) < n:
        i = secrets.randbelow(len(pool))
        chosen.append(pool.pop(i))
    return chosen


# --------------------------------------------------------------------------
# Exit / server-side
# --------------------------------------------------------------------------
def is_exit(peeled: PeeledLayer) -> bool:
    """True if this peeled layer's ``next`` is the server (end of the path)."""
    return peeled.next == SERVER_HOP


def decode_final_payload(blob_b64: str) -> Dict[str, Any]:
    """Decode the innermost payload that the server receives at the exit."""
    return json.loads(unb64(blob_b64).decode())
