"""Tests for hybrid onion routing."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from votenet import onion
from votenet.crypto import generate_identity
from votenet.onion import (
    SERVER_HOP,
    build_onion,
    decode_final_payload,
    is_exit,
    peel_layer,
    pick_path,
)


def test_two_hop_onion_roundtrip():
    """V -> N1 -> N2 -> SERVER. Each hop peels correctly."""
    n1 = generate_identity()
    n2 = generate_identity()
    final_payload = {"type": "submit_vote", "token_id": "abc123", "choice": "yes", "reply_nonce": "n42"}
    blob = build_onion(final_payload, [n1.pubkey_id, n2.pubkey_id])

    # N1 peels
    p1 = peel_layer(n1, blob)
    assert p1.next == n2.pubkey_id
    # N2 peels
    p2 = peel_layer(n2, p1.blob_b64)
    assert is_exit(p2)
    # Server decodes
    inner = decode_final_payload(p2.blob_b64)
    assert inner == final_payload


def test_three_hop_onion_roundtrip():
    a, b, c = (generate_identity() for _ in range(3))
    payload = {"type": "check_spendable", "token_id": "xyz", "nonce": "n1"}
    path = [a.pubkey_id, b.pubkey_id, c.pubkey_id]
    blob = build_onion(payload, path)

    p = peel_layer(a, blob)
    assert p.next == b.pubkey_id
    p = peel_layer(b, p.blob_b64)
    assert p.next == c.pubkey_id
    p = peel_layer(c, p.blob_b64)
    assert is_exit(p)
    assert decode_final_payload(p.blob_b64) == payload


def test_wrong_recipient_cannot_peel():
    n1 = generate_identity()
    intruder = generate_identity()
    blob = build_onion({"x": 1}, [n1.pubkey_id])
    with pytest.raises(ValueError):
        peel_layer(intruder, blob)


def test_tampered_layer_rejected():
    n1 = generate_identity()
    blob = build_onion({"x": 1}, [n1.pubkey_id])
    tampered = blob[:-4] + "AAAA"
    with pytest.raises(Exception):
        peel_layer(n1, tampered)


def test_pick_path_excludes_self():
    peers = [f"peer{i}" for i in range(5)]
    chosen = pick_path("self", peers, min_hops=2, max_hops=3)
    assert "self" not in chosen
    assert len(chosen) >= 2
    assert len(set(chosen)) == len(chosen)  # no duplicates


def test_pick_path_few_peers():
    """With only one peer available, we still get a viable (1-hop) path."""
    chosen = pick_path("self", ["only_peer"], min_hops=2, max_hops=3)
    assert chosen == ["only_peer"]


def test_pick_path_empty_raises():
    with pytest.raises(ValueError):
        pick_path("self", [], min_hops=2, max_hops=3)


def test_single_hop_to_server():
    """A one-hop path still reaches the server as the exit."""
    n1 = generate_identity()
    payload = {"type": "submit_vote", "token_id": "t", "choice": "c", "reply_nonce": "n"}
    blob = build_onion(payload, [n1.pubkey_id])
    p = peel_layer(n1, blob)
    assert is_exit(p)
    assert decode_final_payload(p.blob_b64) == payload


def test_server_hop_sentinel():
    assert SERVER_HOP == "SERVER"
