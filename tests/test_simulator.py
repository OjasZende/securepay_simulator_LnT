import base64

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from app import core
from app.main import app
from app.pki import create_certificates, inspect_certificates


@pytest.fixture
def demo(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA", tmp_path / "data")
    monkeypatch.setattr(core, "SECRET", tmp_path / "secrets")
    monkeypatch.setattr(core, "DB", core.DATA / "demo.sqlite3")
    monkeypatch.setattr(core, "KEY", core.SECRET / "data-key.bin")
    monkeypatch.setattr(core, "PASSWORD_HASH", core.SECRET / "admin-hash.txt")
    password = core.initialize()
    create_certificates(core.SECRET)
    return TestClient(app, base_url="https://testserver"), ("admin", password)


def test_encrypted_storage_and_tampering(demo):
    client, auth = demo
    with core.connection() as db:
        stored = db.execute("SELECT email_encrypted FROM customers LIMIT 1").fetchone()[0]
    assert "asha@example.test" not in stored
    assert core.decrypt(stored) == "asha@example.test"
    raw = bytearray(base64.urlsafe_b64decode(stored))
    raw[-1] ^= 1
    with pytest.raises(InvalidTag):
        core.decrypt(base64.urlsafe_b64encode(raw).decode())
    assert client.get("/api/customers", auth=auth).status_code == 200


def test_access_minimization_and_measurement(demo):
    client, auth = demo
    assert client.get("/api/overview").status_code == 401
    assert client.get("/api/overview", auth=("admin", "wrong")).status_code == 401
    overview = client.get("/api/overview", auth=auth).json()
    assert overview["passed"] == overview["total"]
    assert overview["report"]["encryption_coverage_percent"] == 100
    assert overview["report"]["unnecessary_fields_stored"] == []
    assert overview["report"]["baseline"]["unnecessary_fields"] == 5
    assert overview["report"]["baseline"]["plaintext_emails"] == 2
    assert overview["report"]["protected"]["plaintext_emails"] == 0
    assert overview["report"]["audit_coverage_percent"] == 100
    assert overview["certificate"]["valid"]
    assert overview["certificate"]["receipt_signature_verified"]
    assert client.post("/api/payments", auth=auth, json={
        "customer_id": 1, "amount_cents": 100, "last4": "4242", "cvv": "123"
    }).status_code == 422
    assert client.post("/api/payments", auth=auth, json={
        "customer_id": 1, "amount_cents": 100, "last4": "4242"
    }).status_code == 201
    report = core.audit_report()
    assert report["transactions"] == 3
    assert report["audit_events"] == 3


def test_http_api_is_rejected(demo):
    client = TestClient(app, base_url="http://testserver")
    assert client.get("/api/overview").status_code == 426


def test_plaintext_vs_protected_and_customer_creation(demo):
    client, auth = demo
    overview = client.get("/api/overview", auth=auth).json()
    assert len(overview["comparison"]) == 4
    # Create a new dummy customer and verify their email is encrypted at rest
    res = client.post("/api/customers", auth=auth, json={"name": "Priya Demo", "email": "priya@example.test"})
    assert res.status_code == 201
    created = res.json()
    assert "priya@example.test" not in created["email_encrypted"]
    assert core.decrypt(created["email_encrypted"]) == "priya@example.test"
    # Excess fields in customer creation must be rejected (HTTP 422)
    bad_cust = client.post("/api/customers", auth=auth, json={
        "name": "Bad Demo", "email": "bad@example.test", "phone": "9999999999"
    })
    assert bad_cust.status_code == 422


def test_interactive_encryption_and_pki_simulation(demo):
    client, auth = demo
    # Clean encryption test
    enc_ok = client.post("/api/encryption-demo", auth=auth, json={"plaintext": "secret@example.test", "tamper": False}).json()
    assert enc_ok["decrypted_match"] is True
    assert enc_ok["integrity_status"] == "VERIFIED"

    # Tampered encryption test
    enc_bad = client.post("/api/encryption-demo", auth=auth, json={"plaintext": "secret@example.test", "tamper": True}).json()
    assert enc_bad["decrypted_match"] is False
    assert enc_bad["integrity_status"] == "TAMPER_BLOCKED_INVALID_TAG"

    # Clean PKI communication simulation
    pki_ok = client.post("/api/pki-simulate", auth=auth, json={"message": "PAY|cust:1|amt:50000", "tamper": False}).json()
    assert pki_ok["cert_chain_verified"] is True
    assert pki_ok["channel_integrity_verified"] is True
    assert pki_ok["receipt_signature_verified"] is True
    assert pki_ok["status"] == "SECURE_DELIVERY"

    # Tampered PKI communication simulation (MITM attack)
    pki_bad = client.post("/api/pki-simulate", auth=auth, json={"message": "PAY|cust:1|amt:50000", "tamper": True}).json()
    assert pki_bad["channel_integrity_verified"] is False
    assert pki_bad["receipt_signature_verified"] is False
    assert pki_bad["status"] == "BLOCKED_TAMPER_DETECTED"


def test_password_policy_and_privacy_module(demo):
    client, auth = demo
    weak = client.post("/api/password-check", auth=auth, json={"password": "password123"}).json()
    assert weak["strong"] is False

    strong = client.post("/api/password-check", auth=auth, json={"password": "Secur3Pay#FinTech!2026"}).json()
    assert strong["strong"] is True
    assert strong["argon2id_hash_sample"].startswith("$argon2")

    # Privacy module inspection
    priv = client.get("/api/privacy", auth=auth).json()
    assert priv["summary"]["compliant"] is True
    assert priv["summary"]["unnecessary_stored_count"] == 0

    # Bloated payload rejected by privacy analyzer
    bloated = client.post("/api/privacy/check-payload", auth=auth, json={
        "payload": {"customer_id": 1, "amount_cents": 5000, "last4": "4242", "phone": "12345", "cvv": "999"}
    }).json()
    assert bloated["accepted_by_simulator"] is False
    assert len(bloated["unnecessary_personal_fields"]) == 1
    assert len(bloated["prohibited_pci_fields"]) == 1

    # Minimal payload accepted by privacy analyzer
    minimal = client.post("/api/privacy/check-payload", auth=auth, json={
        "payload": {"customer_id": 1, "amount_cents": 5000, "last4": "4242"}
    }).json()
    assert minimal["accepted_by_simulator"] is True

