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
