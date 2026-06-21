"""Tests for bearer vote tokens."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from votenet import tokens
from votenet.crypto import generate_identity
from votenet.tokens import SignedToken, VoteToken, issue_token


def test_token_signs_and_verifies():
    server = generate_identity()
    st = issue_token("poll1", "win1", server, ttl_seconds=600)
    assert st.verify(server.public)


def test_token_rejects_wrong_server_key():
    server = generate_identity()
    other = generate_identity()
    st = issue_token("poll1", "win1", server, ttl_seconds=600)
    assert not st.verify(other.public)


def test_token_tamper_rejected():
    server = generate_identity()
    st = issue_token("poll1", "win1", server, ttl_seconds=600)
    d = st.to_dict()
    d["token"]["poll_id"] = "tampered"
    assert not SignedToken.from_dict(d).verify(server.public)


def test_token_signature_tamper_rejected():
    server = generate_identity()
    st = issue_token("poll1", "win1", server, ttl_seconds=600)
    d = st.to_dict()
    # Flip a byte in the base64 signature.
    sig = bytearray(d["signature"], "ascii")
    if sig[0] == ord("A"):
        sig[0] = ord("B")
    else:
        sig[0] = ord("A")
    d["signature"] = sig.decode("ascii")
    assert not SignedToken.from_dict(d).verify(server.public)


def test_token_has_no_owner_field():
    """Bearer tokens must NOT carry an owner/recipient field."""
    server = generate_identity()
    st = issue_token("poll1", "win1", server, ttl_seconds=600)
    body = st.token.to_signed(server).token._body_dict()
    forbidden = {"owner", "recipient", "user", "username", "holder"}
    assert not (forbidden & set(body.keys())), \
        f"bearer token must not carry owner info, found {forbidden & set(body.keys())}"


def test_token_dict_roundtrip():
    server = generate_identity()
    st = issue_token("poll1", "win1", server, ttl_seconds=600)
    d = st.to_dict()
    st2 = SignedToken.from_dict(d)
    assert st2.token.token_id == st.token.token_id
    assert st2.token.poll_id == st.token.poll_id
    assert st2.verify(server.public)


def test_token_ids_are_unique():
    server = generate_identity()
    ids = {issue_token("p", "w", server, 600).token.token_id for _ in range(50)}
    assert len(ids) == 50
