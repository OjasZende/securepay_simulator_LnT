import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, ConfigDict, Field

from app import core
from app.pki import inspect_certificates

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
        {"id": "data-minimization", "principle": "PCI DSS 3 / privacy", "label": "Store only needed account data",
         "pass": not report["unnecessary_fields_stored"] and not report["sensitive_auth_data_stored"]},
        {"id": "stored-data", "principle": "PCI DSS 3", "label": "Protect stored customer email",
         "pass": report["encryption_coverage_percent"] == 100 and report["key_separated"]},
        {"id": "transmission", "principle": "PCI DSS 4", "label": "Valid local server certificate",
         "pass": cert["valid"] and request.url.scheme == "https"},
        {"id": "access", "principle": "PCI DSS 7 and 8", "label": "Admin authentication required",
         "pass": report["password_hashed"]},
        {"id": "logging", "principle": "PCI DSS 10", "label": "Payment audit events enabled",
         "pass": report["audit_coverage_percent"] == 100},
    ]
    return {"report": report, "certificate": cert, "controls": controls,
            "passed": sum(item["pass"] for item in controls), "total": len(controls),
            "note": "Educational control checks; not a PCI DSS assessment or certification."}


@app.get("/api/customers")
def customers(_=Depends(require_admin)):
    return core.customers()


@app.get("/api/transactions")
def transactions(_=Depends(require_admin)):
    return core.transactions()


@app.post("/api/payments", status_code=201)
def payment(payload: Payment, _=Depends(require_admin)):
    try:
        return core.create_payment(payload.customer_id, payload.amount_cents, payload.last4)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/privacy")
def privacy(_=Depends(require_admin)):
    return {"inventory": core.FIELDS, "risks": core.PRIVACY_RISKS,
            "findings": core.audit_report()["unnecessary_fields_stored"]}


@app.get("/api/encryption-demo")
def encryption_demo(_=Depends(require_admin)):
    sample = "demo@example.test"
    ciphertext = core.encrypt(sample)
    return {"fictional_plaintext": sample, "stored_form": ciphertext,
            "decrypted_match": core.decrypt(ciphertext) == sample,
            "algorithm": "AES-256-GCM", "note": "Sample exists only for this response; it is not saved."}
