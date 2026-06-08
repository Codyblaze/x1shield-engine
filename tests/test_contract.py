"""Contract tests locking the request shape the gateway must send.

These guard against the regression where the Node gateway posted a bare
fingerprint instead of the {walletAddress, fingerprint} envelope the engine
requires (extra="forbid"), which silently failed every heuristics-path verify.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

VALID_WALLET = "0xabc0000000000000000000000000000000000001"
FINGERPRINT = {
    "transactions": [],
    "funding_sources": [],
    "interaction_sequence": ["connect", "approve", "swap"],
}


def test_accepts_gateway_envelope():
    resp = client.post(
        "/api/v1/analyze",
        json={"walletAddress": VALID_WALLET, "fingerprint": FINGERPRINT},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert "is_human" in body
    assert "risk_score" in body
    assert body["walletAddress"] == VALID_WALLET


def test_rejects_bare_fingerprint():
    # The old (buggy) gateway shape: fingerprint posted as the whole body.
    resp = client.post("/api/v1/analyze", json=FINGERPRINT)

    assert resp.status_code == 422
