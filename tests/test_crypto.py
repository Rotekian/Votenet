"""Tests for the crypto primitives: signing, AEAD, X25519 agreement."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from votenet import crypto
from votenet.crypto import (
    Identity,
    aead_decrypt,
    aead_encrypt,
    canonical_json,
    derive_shared,
    generate_ephemeral,
    generate_identity,
    sign,
    verify_signature,
    public_from_id,
    b64,
    unb64,
)


def test_sign_verify_roundtrip():
    ident = generate_identity()
    sig = sign(ident, b"message")
    assert verify_signature(ident.public, sig, b"message")


def test_sign_verify_wrong_key_rejected():
    a = generate_identity()
    b = generate_identity()
    sig = sign(a, b"message")
    assert not verify_signature(b.public, sig, b"message")


def test_sign_verify_tampered_message_rejected():
    ident = generate_identity()
    sig = sign(ident, b"message")
    assert not verify_signature(ident.public, sig, b"MESSAGE")


def test_aead_roundtrip():
    key = b"0" * 32
    ct = aead_encrypt(key, b"plaintext", aad=b"context")
    assert aead_decrypt(key, ct, b"context") == b"plaintext"


def test_aead_tamper_rejected():
    key = b"0" * 32
    ct = bytearray(aead_encrypt(key, b"plaintext", aad=b"context"))
    ct[-1] ^= 0xFF  # flip a bit
    with pytest.raises(InvalidTag):
        aead_decrypt(key, bytes(ct), b"context")


def test_aead_wrong_aad_rejected():
    key = b"0" * 32
    ct = aead_encrypt(key, b"plaintext", aad=b"context")
    with pytest.raises(InvalidTag):
        aead_decrypt(key, ct, b"different")


def test_aead_wrong_key_rejected():
    ct = aead_encrypt(b"0" * 32, b"plaintext")
    with pytest.raises(InvalidTag):
        aead_decrypt(b"1" * 32, ct)


def test_x25519_shared_secret_agreement():
    a = generate_ephemeral()
    b = generate_ephemeral()
    s1 = derive_shared(a.private, b.public)
    s2 = derive_shared(b.private, a.public)
    assert s1 == s2
    assert len(s1) == 32


def test_canonical_json_is_deterministic():
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b


def test_pubkey_id_roundtrip():
    ident = generate_identity()
    pub = public_from_id(ident.pubkey_id)
    assert pub.public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    ) == ident.pubkey_bytes


def test_b64_roundtrip():
    data = os.urandom(64)
    assert unb64(b64(data)) == data
