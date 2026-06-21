"""Tests for the P2P trade layer: REAL/CHAFF offers + sealed payloads."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from votenet import trade
from votenet.crypto import generate_identity
from votenet.tokens import issue_token
from votenet.trade import TradeKind, TradeOffer, open_trade_payload, seal_trade_payload, verify_offered_token


def test_real_offer_verifies():
    server = generate_identity()
    holder = generate_identity()
    recipient = generate_identity()
    st = issue_token("poll1", "win1", server, ttl_seconds=600)
    offer = TradeOffer(
        kind=TradeKind.REAL,
        from_pubkey_id=holder.pubkey_id,
        to_pubkey_id=recipient.pubkey_id,
        offer_id="offer1",
        token=st.to_dict(),
    )
    verified = verify_offered_token(offer, server.public)
    assert verified is not None
    assert verified.token.token_id == st.token.token_id


def test_real_offer_rejects_forged_token():
    """A token not signed by the server fails verification."""
    impostor = generate_identity()  # pretends to be the server
    holder = generate_identity()
    recipient = generate_identity()
    st = issue_token("poll1", "win1", impostor, ttl_seconds=600)
    offer = TradeOffer(
        kind=TradeKind.REAL,
        from_pubkey_id=holder.pubkey_id,
        to_pubkey_id=recipient.pubkey_id,
        offer_id="offer1",
        token=st.to_dict(),
    )
    real_server = generate_identity()
    assert verify_offered_token(offer, real_server.public) is None


def test_real_offer_rejects_tampered_token():
    server = generate_identity()
    holder = generate_identity()
    recipient = generate_identity()
    st = issue_token("poll1", "win1", server, ttl_seconds=600)
    d = st.to_dict()
    d["token"]["window_id"] = "different_window"
    offer = TradeOffer(
        kind=TradeKind.REAL,
        from_pubkey_id=holder.pubkey_id,
        to_pubkey_id=recipient.pubkey_id,
        offer_id="offer1",
        token=d,
    )
    assert verify_offered_token(offer, server.public) is None


def test_chaff_offer_skips_verification():
    """CHAFF offers carry no verifiable token by design."""
    holder = generate_identity()
    recipient = generate_identity()
    offer = TradeOffer(
        kind=TradeKind.CHAFF,
        from_pubkey_id=holder.pubkey_id,
        to_pubkey_id=recipient.pubkey_id,
        offer_id="offer1",
        chaff_blob=trade.make_chaff(),
    )
    server = generate_identity()
    # verify_offered_token returns None for CHAFF (caller knows it's noise).
    assert verify_offered_token(offer, server.public) is None


def test_sealed_trade_payload_roundtrip():
    sender = generate_identity()
    recipient = generate_identity()
    payload = {"kind": "real", "from": sender.pubkey_id, "to": recipient.pubkey_id, "offer_id": "o1"}
    blob = seal_trade_payload(sender, recipient.pubkey_id, payload)
    recovered = open_trade_payload(recipient, blob)
    assert recovered == payload


def test_sealed_trade_payload_wrong_recipient_rejected():
    sender = generate_identity()
    recipient = generate_identity()
    intruder = generate_identity()
    blob = seal_trade_payload(sender, recipient.pubkey_id, {"secret": 1})
    with pytest.raises(ValueError):
        open_trade_payload(intruder, blob)


def test_trade_offer_payload_roundtrip():
    server = generate_identity()
    a = generate_identity()
    b = generate_identity()
    st = issue_token("p", "w", server, 600)
    offer = TradeOffer(
        kind=TradeKind.REAL,
        from_pubkey_id=a.pubkey_id,
        to_pubkey_id=b.pubkey_id,
        offer_id="o1",
        token=st.to_dict(),
    )
    payload = offer.to_payload()
    restored = TradeOffer.from_payload(payload)
    assert restored.kind == TradeKind.REAL
    assert restored.from_pubkey_id == a.pubkey_id
    assert restored.token == st.to_dict()


def test_chaff_blob_is_random():
    blobs = {trade.make_chaff() for _ in range(20)}
    assert len(blobs) == 20
