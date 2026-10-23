"""Storage and security controls. Every record in this app is fictional."""
import base64
import os
import secrets
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from pwdlib import PasswordHash

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
SECRET = ROOT / ".secrets"
DB = DATA / "securepay.sqlite3"
KEY = SECRET / "data-key.bin"
PASSWORD_HASH = SECRET / "admin-hash.txt"
password_hasher = PasswordHash.recommended()

FIELDS = [
    {"field": "customer name", "class": "Personal", "purpose": "identify a fictional customer", "stored": True, "protection": "access controlled"},
    {"field": "email", "class": "Personal", "purpose": "send a fictional receipt", "stored": True, "protection": "AES-GCM encrypted"},
    {"field": "phone", "class": "Personal", "purpose": "not required", "stored": False, "protection": "not collected"},
    {"field": "full card number", "class": "Cardholder data", "purpose": "not required for simulation", "stored": False, "protection": "token and last four only"},
    {"field": "CVV / PIN", "class": "Sensitive authentication", "purpose": "not required for simulation", "stored": False, "protection": "never collected or stored"},
    {"field": "date of birth / address", "class": "Personal", "purpose": "not required", "stored": False, "protection": "not collected"},
    {"field": "transaction amount", "class": "Financial", "purpose": "payment record", "stored": True, "protection": "access controlled"},
    {"field": "password", "class": "Credential", "purpose": "demo administrator login", "stored": True, "protection": "Argon2id hash"},
]

EXCESS_FIELDS = ("phone", "address", "birth_date", "pan", "cvv")
PRIVACY_RISKS = [
    {"field": "phone / address / birth date", "risk": "More personal details would be exposed in a breach", "decision": "Do not collect"},
    {"field": "full card number", "risk": "Expands payment data exposure and compliance scope", "decision": "Use token and last four"},
    {"field": "CVV / PIN", "risk": "Sensitive authentication data must not be retained after authorization", "decision": "Never collect in this demo"},
]


def connection():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def encrypt(value: str) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(KEY.read_bytes()).encrypt(nonce, value.encode(), b"customer-email")
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt(value: str) -> str:
    raw = base64.urlsafe_b64decode(value)
    return AESGCM(KEY.read_bytes()).decrypt(raw[:12], raw[12:], b"customer-email").decode()


def initialize() -> str:
    DATA.mkdir(exist_ok=True)
    SECRET.mkdir(exist_ok=True)
    if DB.exists() or KEY.exists() or PASSWORD_HASH.exists():
        raise RuntimeError("Demo already initialized. Existing data and keys were preserved.")
    password = secrets.token_urlsafe(18)
    KEY.write_bytes(AESGCM.generate_key(bit_length=256))
    PASSWORD_HASH.write_text(password_hasher.hash(password), encoding="utf-8")
    with connection() as db:
        db.executescript("""
            CREATE TABLE customers (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, email_encrypted TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE transactions (
                id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id),
                amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
                currency TEXT NOT NULL DEFAULT 'INR',
                payment_token TEXT NOT NULL, last4 TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'approved',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY, event TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)
        customers = [("Asha Demo", "asha@example.test"), ("Ravi Demo", "ravi@example.test")]
        for name, email in customers:
            db.execute("INSERT INTO customers(name,email_encrypted) VALUES (?,?)", (name, encrypt(email)))
        db.execute("INSERT INTO transactions(customer_id,amount_cents,payment_token,last4) VALUES (?,?,?,?)",
                   (1, 129900, "tok_demo_001", "4242"))
        db.execute("INSERT INTO transactions(customer_id,amount_cents,payment_token,last4) VALUES (?,?,?,?)",
                   (2, 45900, "tok_demo_002", "1881"))
        db.executemany("INSERT INTO audit_events(event) VALUES (?)", [("payment_created",), ("payment_created",)])
    return password


def verify_password(candidate: str) -> bool:
    return password_hasher.verify(candidate, PASSWORD_HASH.read_text(encoding="utf-8"))


def customers():
    with connection() as db:
        rows = db.execute("SELECT id,name,email_encrypted,created_at FROM customers ORDER BY id").fetchall()
    return [{"id": r["id"], "name": r["name"], "email": decrypt(r["email_encrypted"]),
             "created_at": r["created_at"]} for r in rows]


def transactions():
    with connection() as db:
        rows = db.execute("""SELECT t.*, c.name FROM transactions t JOIN customers c
                             ON c.id=t.customer_id ORDER BY t.id DESC""").fetchall()
    return [dict(r) for r in rows]


def create_payment(customer_id: int, amount_cents: int, last4: str):
    token = "tok_demo_" + secrets.token_hex(8)
    with connection() as db:
        if not db.execute("SELECT 1 FROM customers WHERE id=?", (customer_id,)).fetchone():
            raise ValueError("Unknown customer")
        cursor = db.execute("""INSERT INTO transactions(customer_id,amount_cents,payment_token,last4)
                               VALUES (?,?,?,?)""", (customer_id, amount_cents, token, last4))
        db.execute("INSERT INTO audit_events(event) VALUES (?)", ("payment_created",))
    return {"id": cursor.lastrowid, "payment_token": token, "status": "approved"}


def audit_report():
    with connection() as db:
        customer_count = db.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
        stored_emails = [r[0] for r in db.execute("SELECT email_encrypted FROM customers")]
        encrypted_count = 0
        for value in stored_emails:
            try:
                if "@" not in value and "@" in decrypt(value):
                    encrypted_count += 1
            except (ValueError, UnicodeError, InvalidTag):
                pass
        tx_count = db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        audit_count = db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        db_columns = [r[1].lower() for table in ("customers", "transactions")
                      for r in db.execute(f"PRAGMA table_info({table})")]
    unnecessary = [f for f in EXCESS_FIELDS if f in db_columns]
    sensitive_auth_stored = any(f in db_columns for f in ("cvv", "pin"))
    # An intentionally overcollecting design is assembled only in memory, measured,
    # then discarded. No plaintext comparison database is created.
    baseline_records = [dict(name=r["name"], email=decrypt(r["email_encrypted"]),
                             phone="DEMO-PHONE", address="DEMO-ADDRESS",
                             birth_date="DEMO-DOB", pan="DEMO-CARD", cvv="DEMO-CVV")
                        for r in _raw_customers()]
    baseline_excess = len(set(baseline_records[0]) & set(EXCESS_FIELDS)) if baseline_records else 0
    return {
        "customers": customer_count, "transactions": tx_count,
        "encrypted_emails": encrypted_count, "encryption_coverage_percent":
            round(100 * encrypted_count / customer_count) if customer_count else 100,
        "unnecessary_fields_stored": unnecessary, "sensitive_auth_data_stored": sensitive_auth_stored,
        "audit_events": audit_count, "audit_coverage_percent": round(100 * audit_count / tx_count) if tx_count else 100,
        "key_separated": KEY.exists() and KEY.parent != DB.parent and len(KEY.read_bytes()) == 32,
        "password_hashed": PASSWORD_HASH.exists() and PASSWORD_HASH.read_text(encoding="utf-8").startswith("$argon2"),
        "baseline": {"plaintext_emails": sum("@" in r["email"] for r in baseline_records),
                     "encrypted_emails": 0, "unnecessary_fields": baseline_excess,
                     "description": "Measured in-memory overcollection example; never persisted"},
        "protected": {"plaintext_emails": int("email" in db_columns) * customer_count,
                      "encrypted_emails": encrypted_count, "unnecessary_fields": len(unnecessary)},
    }


def _raw_customers():
    with connection() as db:
        return db.execute("SELECT name,email_encrypted FROM customers").fetchall()
