import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, ConfigDict, Field

from app import core
from app.pki import inspect_certificates, simulate_pki_communication

app = FastAPI(title="SecurePay Simulator", description="Local educational demo using fictional data")
basic = HTTPBasic()
WEB = Path(__file__).resolve().parents[1] / "web"


@app.middleware("http")
async def require_https_for_api(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.scheme != "https":
        return JSONResponse(status_code=426, content={"detail": "Use HTTPS for payment and customer APIs"})
    return await call_next(request)


def require_admin(credentials: HTTPBasicCredentials = Depends(basic)):
    if not core.DB.exists() or not core.PASSWORD_HASH.exists():
        raise HTTPException(status_code=503, detail="Run python -m app.setup first")
    username_ok = secrets.compare_digest(credentials.username, "admin")
    password_ok = core.verify_password(credentials.password)
    if not (username_ok and password_ok):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid demo credentials", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


class Payment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    customer_id: int
    amount_cents: int = Field(gt=0, le=1_000_000_00)
    last4: str = Field(pattern=r"^\d{4}$")


class CustomerCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=80)
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class EncryptionTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plaintext: str = Field(default="demo@example.test", min_length=1, max_length=256)
    tamper: bool = False


class PkiSimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(default="PAY|cust:1|amt:19900|currency:INR|last4:4242", min_length=1, max_length=256)
    tamper: bool = False


class PasswordCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=128)


class PrivacyPayloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload: dict


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(WEB / "index.html")


@app.get("/style.css", include_in_schema=False)
def style():
    return FileResponse(WEB / "style.css", media_type="text/css")


@app.get("/app.js", include_in_schema=False)
def script():
    return FileResponse(WEB / "app.js", media_type="text/javascript")


@app.get("/api/overview")
def overview(request: Request, _=Depends(require_admin)):
    report = core.audit_report()
    cert = inspect_certificates(core.SECRET)
    controls = [
        {
            "id": "data-minimization",
            "principle": "PCI DSS 3.2 & 3.3 / Privacy",
            "label": "Store only needed account data; never store CVV/PIN or full PAN",
            "threat": "Excessive collection of personal data & illegal SAD retention",
            "control_detail": "Tokenizes payment method (tok_demo_* + last 4 digits) and blocks CVV, PIN, phone, DOB, and address.",
            "evidence": f"Unnecessary columns stored: {len(report['unnecessary_fields_stored'])}, SAD stored: {report['sensitive_auth_data_stored']}",
            "pass": not report["unnecessary_fields_stored"] and not report["sensitive_auth_data_stored"],
        },
        {
            "id": "stored-data",
            "principle": "PCI DSS 3.5 & 3.6",
            "label": "Protect stored customer email & isolate cryptographic keys",
            "threat": "Exposure of plain-text customer records & poor key management",
            "control_detail": "Encrypts customer email with AES-256-GCM (random 96-bit nonce + AAD) and stores the 256-bit key in .secrets/ separate from SQLite.",
            "evidence": f"Encrypted emails: {report['encryption_coverage_percent']}%, Key isolated: {report['key_separated']}",
            "pass": report["encryption_coverage_percent"] == 100 and report["key_separated"],
        },
        {
            "id": "transmission",
            "principle": "PCI DSS 4.2",
            "label": "Valid PKI certificate & mandatory HTTPS transport",
            "threat": "Insecure communication & Man-in-the-Middle (MITM) interception",
            "control_detail": "Rejects plain HTTP with 426 Upgrade Required; uses local Root CA signed X.509 RSA-3072 server certificate and signed receipts.",
            "evidence": f"Scheme: {request.url.scheme.upper()}, Cert valid: {cert['valid']}, Signed receipt: {cert['receipt_signature_verified']}",
            "pass": cert["valid"] and request.url.scheme == "https",
        },
        {
            "id": "secure-input",
            "principle": "PCI DSS 6.2",
            "label": "Strict schema validation & injection prevention",
            "threat": "Malformed payloads, mass assignment & SQL injection",
            "control_detail": "Pydantic extra='forbid' rejects unexpected fields (e.g. CVV/PAN) with HTTP 422; SQLite queries use bound parameters.",
            "evidence": "Strict input schema active on /api/payments and /api/customers",
            "pass": True,
        },
        {
            "id": "access",
            "principle": "PCI DSS 7.2 & 8.3",
            "label": "Authenticated admin access & Argon2id password hashing",
            "threat": "Unauthorized access & weak or plaintext passwords",
            "control_detail": "Requires HTTP Basic Auth on all APIs, verifies username with constant-time compare_digest, and stores admin password as Argon2id hash.",
            "evidence": f"Argon2id hash verified: {report['password_hashed']}",
            "pass": report["password_hashed"],
        },
        {
            "id": "logging",
            "principle": "PCI DSS 10.2",
            "label": "Payment audit events enabled and synchronized",
            "threat": "Unmonitored transactions & lack of forensic audit trail",
            "control_detail": "Records an immutable timestamped audit_events entry for every simulated payment transaction.",
            "evidence": f"Audit coverage: {report['audit_coverage_percent']}% ({report['audit_events']}/{report['transactions']} tx)",
            "pass": report["audit_coverage_percent"] == 100,
        },
    ]
    return {
        "report": report,
        "certificate": cert,
        "controls": controls,
        "comparison": core.plaintext_vs_protected_comparison(),
        "passed": sum(item["pass"] for item in controls),
        "total": len(controls),
        "note": "Educational control checks; not a PCI DSS assessment or certification.",
    }


@app.get("/api/customers")
def customers(_=Depends(require_admin)):
    return core.customers()


@app.post("/api/customers", status_code=201)
def add_customer(payload: CustomerCreate, _=Depends(require_admin)):
    return core.create_customer(payload.name.strip(), payload.email.strip())


@app.get("/api/transactions")
def transactions(_=Depends(require_admin)):
    return core.transactions()


@app.get("/api/audit-logs")
def audit_logs(_=Depends(require_admin)):
    return core.audit_events()


@app.post("/api/payments", status_code=201)
def payment(payload: Payment, _=Depends(require_admin)):
    try:
        return core.create_payment(payload.customer_id, payload.amount_cents, payload.last4)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/privacy")
def privacy(_=Depends(require_admin)):
    report = core.audit_report()
    collected = [f for f in core.FIELDS if f["stored"]]
    rejected = [f for f in core.FIELDS if not f["stored"]]
    return {
        "inventory": core.FIELDS,
        "risks": core.PRIVACY_RISKS,
        "findings": report["unnecessary_fields_stored"],
        "table_schemas": report["table_schemas"],
        "summary": {
            "collected_count": len(collected),
            "not_collected_count": len(rejected),
            "unnecessary_stored_count": len(report["unnecessary_fields_stored"]),
            "sensitive_auth_stored": report["sensitive_auth_data_stored"],
            "compliant": not report["unnecessary_fields_stored"] and not report["sensitive_auth_data_stored"],
        },
    }


@app.post("/api/privacy/check-payload")
def check_privacy_payload(req: PrivacyPayloadRequest, _=Depends(require_admin)):
    return core.analyze_payload_privacy(req.payload)


@app.get("/api/encryption-demo")
def encryption_demo(_=Depends(require_admin)):
    return core.inspect_encryption("demo@example.test", tamper=False)


@app.post("/api/encryption-demo")
def encryption_demo_interactive(req: EncryptionTestRequest, _=Depends(require_admin)):
    return core.inspect_encryption(req.plaintext, tamper=req.tamper)


@app.post("/api/pki-simulate")
def pki_simulate(req: PkiSimRequest, _=Depends(require_admin)):
    return simulate_pki_communication(core.SECRET, req.message, tamper=req.tamper)


@app.post("/api/password-check")
def password_check(req: PasswordCheckRequest, _=Depends(require_admin)):
    return core.evaluate_password_strength(req.password)

