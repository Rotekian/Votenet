"""Cryptographic primitives for VoteNet.

This module wraps the three primitives the system needs:

* **Ed25519** long-term identity keys. Every server and client has one. The
  hex fingerprint of the public key is the network-wide ``pubkey_id`` and is
  used for peer discovery, relay addressing, and signing challenges.
* **X25519** ephemeral key agreement, used to derive per-layer symmetric keys
  for onion encryption and for encrypting peer-to-peer trade messages.
* **ChaCha20Poly1305** authenticated encryption for those layers/messages.

Everything operates on ``bytes``; callers are responsible for base64 encoding
when transporting over JSON (see :mod:`votenet.messages`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature, InvalidTag


# --------------------------------------------------------------------------
# Base64 helpers
# --------------------------------------------------------------------------
def b64(data: bytes) -> str:
    """Encode bytes to a base64 string for JSON transport."""
    return base64.b64encode(data).decode("ascii")


def unb64(s: str) -> bytes:
    """Decode a base64 string back to bytes."""
    return base64.b64decode(s.encode("ascii"))


def random_hex(n_bytes: int = 16) -> str:
    """Return ``n_bytes`` of cryptographically random data as hex."""
    return os.urandom(n_bytes).hex()


# --------------------------------------------------------------------------
# Canonical JSON (stable serialization so signatures are reproducible)
# --------------------------------------------------------------------------
def canonical_json(obj: Any) -> bytes:
    """Serialize ``obj`` to deterministic, sorted-keys JSON with no spaces.

    Determinism is essential: a signature covers these bytes on both sides, so
    the byte layout must be identical regardless of dict insertion order.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------
# Identity keys (Ed25519)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Identity:
    """A long-term Ed25519 identity keypair."""

    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @property
    def pubkey_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def pubkey_id(self) -> str:
        """Short hex fingerprint used as the network-wide identifier."""
        return self.pubkey_bytes.hex()


def generate_identity() -> Identity:
    """Generate a fresh Ed25519 :class:`Identity`."""
    priv = Ed25519PrivateKey.generate()
    return Identity(private=priv, public=priv.public_key())


def load_identity(path: "os.PathLike[str] | str", password: bytes | None = None) -> Identity:
    """Load an :class:`Identity` from a PEM file, generating one if absent."""
    path = Path(path)
    if path.exists():
        data = path.read_bytes()
        priv = serialization.load_pem_private_key(data, password=password)
        assert isinstance(priv, Ed25519PrivateKey)
        return Identity(private=priv, public=priv.public_key())
    return generate_identity()


def save_identity(identity: Identity, path: "os.PathLike[str] | str") -> None:
    """Persist an :class:`Identity` to a PEM file (unencrypted — demo only)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = identity.private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def public_from_bytes(raw: bytes) -> Ed25519PublicKey:
    """Reconstruct an Ed25519 public key from raw 32-byte form."""
    return Ed25519PublicKey.from_public_bytes(raw)


def public_from_id(pubkey_id: str) -> Ed25519PublicKey:
    """Reconstruct an Ed25519 public key from its hex ``pubkey_id``."""
    return public_from_bytes(bytes.fromhex(pubkey_id))


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------
def sign(identity: Identity, data: bytes) -> bytes:
    """Sign ``data`` with ``identity``'s private key."""
    return identity.private.sign(data)


def verify_signature(public: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """Return True if ``signature`` over ``data`` is valid for ``public``."""
    try:
        public.verify(signature, data)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# Symmetric AEAD (ChaCha20Poly1305)
# --------------------------------------------------------------------------
def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt ``plaintext`` with ChaCha20Poly1305. ``key`` must be 32 bytes."""
    if len(key) != 32:
        raise ValueError("AEAD key must be 32 bytes")
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    return nonce + cipher.encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Inverse of :func:`aead_encrypt`. Raises :class:`InvalidTag` on tamper."""
    if len(key) != 32:
        raise ValueError("AEAD key must be 32 bytes")
    if len(blob) < 12:
        raise InvalidTag("ciphertext too short")
    nonce, ciphertext = blob[:12], blob[12:]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, aad)


# --------------------------------------------------------------------------
# X25519 key agreement — for onion layers and P2P trade encryption
# --------------------------------------------------------------------------
@dataclass
class EphemeralPair:
    """An ephemeral X25519 keypair used for one encryption."""

    private: X25519PrivateKey
    public: X25519PublicKey

    @property
    def public_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def generate_ephemeral() -> EphemeralPair:
    priv = X25519PrivateKey.generate()
    return EphemeralPair(private=priv, public=priv.public_key())


def x25519_public_from_bytes(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)


def derive_shared(private: X25519PrivateKey, peer_public: X25519PublicKey) -> bytes:
    """Derive a 32-byte symmetric key from an X25519 exchange.

    We derive directly from the shared secret — adequate for this demo. A
    production system would feed this through HKDF; the function name keeps
    that intent explicit.
    """
    shared = private.exchange(peer_public)
    # Simple key derivation: we still want 32 stable bytes. SHA-256 of the
    # shared secret gives us that. (A production system would use HKDF.)
    return hashlib.sha256(b"votenet-x25519-v1" + shared).digest()
