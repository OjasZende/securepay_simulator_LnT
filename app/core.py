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


def initialize(reset: bool = False) -> str:
    DATA.mkdir(exist_ok=True)
    SECRET.mkdir(exist_ok=True)
    if reset:
        for path in (DB, KEY, PASSWORD_HASH):
            if path.exists():
                path.unlink()
    elif DB.exists() or KEY.exists() or PASSWORD_HASH.exists():
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
        customers_seed = [("Asha Demo", "asha@example.test"), ("Ravi Demo", "ravi@example.test")]
        for name, email in customers_seed:
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
             "email_encrypted": r["email_encrypted"], "created_at": r["created_at"]} for r in rows]


def create_customer(name: str, email: str) -> dict:
    encrypted_email = encrypt(email)
    with connection() as db:
        cursor = db.execute("INSERT INTO customers(name,email_encrypted) VALUES (?,?)", (name, encrypted_email))
    return {"id": cursor.lastrowid, "name": name, "email": email, "email_encrypted": encrypted_email}


def transactions():
    from app.pki import sign_data
    with connection() as db:
        rows = db.execute("""SELECT t.*, c.name FROM transactions t JOIN customers c
                             ON c.id=t.customer_id ORDER BY t.id DESC""").fetchall()
    result = []
    for r in rows:
        item = dict(r)
        receipt_bytes = f"tx:{item['id']}|cust:{item['customer_id']}|amt:{item['amount_cents']}|tok:{item['payment_token']}".encode()
        item["receipt_signature"] = sign_data(SECRET, receipt_bytes)
        result.append(item)
    return result


def audit_events():
    with connection() as db:
        rows = db.execute("SELECT id, event, created_at FROM audit_events ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def create_payment(customer_id: int, amount_cents: int, last4: str):
    from app.pki import sign_data
    token = "tok_demo_" + secrets.token_hex(8)
    with connection() as db:
        if not db.execute("SELECT 1 FROM customers WHERE id=?", (customer_id,)).fetchone():
            raise ValueError("Unknown customer")
        cursor = db.execute("""INSERT INTO transactions(customer_id,amount_cents,payment_token,last4)
                               VALUES (?,?,?,?)""", (customer_id, amount_cents, token, last4))
        db.execute("INSERT INTO audit_events(event) VALUES (?)", ("payment_created",))
    tx_id = cursor.lastrowid
    receipt_bytes = f"tx:{tx_id}|cust:{customer_id}|amt:{amount_cents}|tok:{token}".encode()
    return {
        "id": tx_id, "payment_token": token, "status": "approved",
        "receipt_signature": sign_data(SECRET, receipt_bytes),
    }


def inspect_encryption(sample: str = "demo@example.test", tamper: bool = False) -> dict:
    ciphertext = encrypt(sample)
    raw = bytearray(base64.urlsafe_b64decode(ciphertext))
    nonce_hex = bytes(raw[:12]).hex()
    tag_hex = bytes(raw[-16:]).hex()
    body_hex = bytes(raw[12:-16]).hex()
    if tamper:
        raw[-1] ^= 0x01
    tampered_b64 = base64.urlsafe_b64encode(bytes(raw)).decode()
    try:
        decrypted = decrypt(tampered_b64)
        decrypted_match = decrypted == sample
        integrity_status = "VERIFIED"
    except InvalidTag:
        decrypted = None
        decrypted_match = False
        integrity_status = "TAMPER_BLOCKED_INVALID_TAG"
    return {
        "fictional_plaintext": sample,
        "stored_form": tampered_b64 if tamper else ciphertext,
        "decrypted_plaintext": decrypted,
        "decrypted_match": decrypted_match,
        "tamper_simulated": tamper,
        "integrity_status": integrity_status,
        "nonce_hex": nonce_hex,
        "ciphertext_hex": body_hex,
        "auth_tag_hex": tag_hex,
        "aad": "customer-email",
        "algorithm": "AES-256-GCM",
        "key_bits": 256,
        "key_separated": KEY.exists() and KEY.parent != DB.parent,
        "note": "Sample exists only for this response; it is not saved.",
    }


def evaluate_password_strength(candidate: str) -> dict:
    weak_common = {"password", "123456", "12345678", "admin", "admin123", "qwerty", "welcome", "letmein"}
    checks = {
        "min_length_12": len(candidate) >= 12,
        "has_uppercase": any(c.isupper() for c in candidate),
        "has_lowercase": any(c.islower() for c in candidate),
        "has_digit": any(c.isdigit() for c in candidate),
        "has_special": any(not c.isalnum() for c in candidate),
        "not_common_weak": candidate.lower() not in weak_common,
    }
    score = sum(checks.values())
    passed = all(checks.values())
    sample_hash = password_hasher.hash(candidate)
    return {
        "plaintext_length": len(candidate),
        "checks": checks,
        "score": f"{score}/6",
        "strong": passed,
        "verdict": "STRONG (Meets PCI-DSS Req 8 Policy)" if passed else "WEAK (Vulnerable to brute-force/dictionary attack)",
        "argon2id_hash_sample": sample_hash,
        "algorithm": "Argon2id (Salted, Memory-Hard)",
    }


def plaintext_vs_protected_comparison() -> list[dict]:
    stored_cust = _raw_customers()
    sample_cipher = stored_cust[0]["email_encrypted"] if stored_cust else encrypt("asha@example.test")
    stored_hash = PASSWORD_HASH.read_text(encoding="utf-8")[:56] + "..." if PASSWORD_HASH.exists() else "$argon2id$..."
    return [
        {
            "category": "Customer Details (PII)",
            "threat": "Database breach & excessive personal data collection",
            "plaintext_unprotected": 'name="Asha Demo", email="asha@example.test", phone="+91-9876543210", dob="1999-05-14", address="12 MG Road"',
            "protected_in_simulator": f'name="Asha Demo", email_encrypted="{sample_cipher[:36]}...", phone/dob/address=NOT_COLLECTED',
            "control": "AES-256-GCM encryption at rest with 96-bit random nonce + Data Minimization",
        },
        {
            "category": "Payment Card Data (CHD / SAD)",
            "threat": "Card skimming, PAN theft & illegal CVV retention",
            "plaintext_unprotected": 'pan="4111-1111-1111-4242", cvv="123", expiry="12/28", pin="9999"',
            "protected_in_simulator": 'payment_token="tok_demo_001", last4="4242", cvv/pin=REJECTED (HTTP 422)',
            "control": "PCI-DSS Req 3 Tokenization + Strict Schema Rejection of CVV/PAN",
        },
        {
            "category": "Authentication Credentials",
            "threat": "Weak passwords, credential stuffing & plaintext password leaks",
            "plaintext_unprotected": 'username="admin", password="password123" (stored in plaintext or unsalted MD5/SHA1)',
            "protected_in_simulator": f'username="admin", password_hash="{stored_hash}" (144-bit entropy secret)',
            "control": "PCI-DSS Req 8 Argon2id memory-hard salted hashing + high-entropy credential",
        },
        {
            "category": "Communication & Transaction Records",
            "threat": "Man-in-the-Middle (MITM) sniffing, spoofing & repudiation",
            "plaintext_unprotected": "Plain HTTP POST /api/payments (cleartext wire traffic, unsigned receipt, no audit log)",
            "protected_in_simulator": "HTTPS (TLS + Local CA X.509 RSA-3072 Cert) + HTTP 426 enforcement + RSA-SHA256 Signed Receipt + Audit Log",
            "control": "PCI-DSS Req 4 & 10 PKI Certificate Trust, TLS Encryption & Immutable Audit Trail",
        },
    ]


def analyze_payload_privacy(payload: dict) -> dict:
    allowed_fields = {
        "customer_id": "Links payment to an existing fictional customer record",
        "name": "Identifies customer for account display",
        "email": "Required to send payment receipt (stored AES-256-GCM encrypted)",
        "amount_cents": "Required to record transaction value",
        "currency": "Required to denominate transaction value",
        "last4": "Allows customer to recognize card without storing full PAN",
    }
    prohibited_pci = {
        "pan": "Full Primary Account Number (PAN) expands PCI-DSS scope; replaced by payment token",
        "card_number": "Full card number must not be stored in plaintext; use token + last4",
        "cvv": "Sensitive Authentication Data (SAD) — PCI-DSS Req 3.3 strictly prohibits storage after authorization",
        "cvc": "Sensitive Authentication Data (SAD) — prohibited by PCI-DSS Req 3.3",
        "pin": "Sensitive Authentication Data (SAD) — PIN/PIN block storage is prohibited by PCI-DSS Req 3.3",
        "track_data": "Full magnetic stripe / chip track data is prohibited by PCI-DSS Req 3.3",
    }
    unnecessary_pii = {
        "phone": "Unnecessary personal data for payment simulation; increases breach impact",
        "address": "Physical address is not required for digital payment simulation",
        "birth_date": "Date of birth is high-risk identity data not needed for payment processing",
        "dob": "Date of birth is unnecessary personal data",
        "ssn": "Government ID / SSN is unnecessary and high-risk personal data",
        "aadhaar": "National ID is unnecessary and high-risk personal data",
        "geolocation": "Precise location tracking is unnecessary for payment processing",
    }
    necessary_found = []
    unnecessary_found = []
    prohibited_found = []
    for key in payload:
        k = key.lower().strip()
        if k in allowed_fields:
            necessary_found.append({"field": key, "classification": "Necessary & Permitted", "reason": allowed_fields[k]})
        elif k in prohibited_pci:
            prohibited_found.append({"field": key, "classification": "Prohibited (PCI-DSS Req 3)", "reason": prohibited_pci[k]})
        elif k in unnecessary_pii:
            unnecessary_found.append({"field": key, "classification": "Unnecessary Personal Data", "reason": unnecessary_pii[k]})
        else:
            unnecessary_found.append({"field": key, "classification": "Unnecessary / Unrecognized Field", "reason": "Not required for stated payment purpose; rejected by schema minimization"})
    accepted = not unnecessary_found and not prohibited_found
    return {
        "accepted_by_simulator": accepted,
        "necessary_fields": necessary_found,
        "unnecessary_personal_fields": unnecessary_found,
        "prohibited_pci_fields": prohibited_found,
        "verdict": "COMPLIANT: Only minimal necessary data provided." if accepted else "REJECTED: Contains unnecessary personal data or prohibited PCI-DSS fields.",
    }


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
        table_schemas = {
            table: [r[1] for r in db.execute(f"PRAGMA table_info({table})")]
            for table in ("customers", "transactions", "audit_events")
        }
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
        "table_schemas": table_schemas,
        "baseline": {"plaintext_emails": sum("@" in r["email"] for r in baseline_records),
                     "encrypted_emails": 0, "unnecessary_fields": baseline_excess,
                     "description": "Measured in-memory overcollection example; never persisted"},
        "protected": {"plaintext_emails": int("email" in db_columns) * customer_count,
                      "encrypted_emails": encrypted_count, "unnecessary_fields": len(unnecessary)},
    }


def _raw_customers():
    with connection() as db:
        return db.execute("SELECT name,email_encrypted FROM customers").fetchall()

