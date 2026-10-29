# SecurePay Simulator (Problem Statement 03)

A **local educational FinTech payment simulator** using fictional records. It demonstrates how a FinTech payment system protects sensitive customer and payment data using encryption (`AES-256-GCM`) and Public Key Infrastructure (`PKI`), satisfies key **PCI-DSS v4.0** security principles, protects credentials with **Argon2id**, and minimizes data-privacy risks. It is **not** a real payment processor or a formal PCI-DSS certification tool.

## Problem Statement Coverage

| Requirement | Implementation in SecurePay Simulator |
|---|---|
| **Dummy customer & transaction data** | Seeded fictional customers (`customers` table) and payment records (`transactions` table) in SQLite (`data/securepay.sqlite3`), plus interactive creation of customers and payments. |
| **Plain-text vs. protected data** | Side-by-side comparison across Customer PII, Cardholder/Authentication Data, Credentials, and Network Transport, plus live database inspection showing decrypted emails alongside stored `AES-256-GCM` ciphertext and before/after metrics. |
| **Basic encryption & key management** | `AES-256-GCM` authenticated encryption with 96-bit random nonces, 128-bit integrity tags, Additional Authenticated Data (`AAD`), interactive bit-flip tamper detection, and 256-bit key isolation in `.secrets/data-key.bin`. |
| **PKI-based secure communication** | Local Root CA (`ca.pem`) signing a server X.509 certificate (`server.pem`, RSA-3072) with SANs for `localhost`/`127.0.0.1`, mandatory HTTPS enforcement (`HTTP 426`), `app.verify_tls` verification, and an interactive 5-step PKI channel simulator (`RSA-OAEP` key exchange + `AES-256-GCM` channel + `RSA-SHA256` signed transaction receipts). |
| **Selected PCI-DSS principles** | Live automated checks mapped to **PCI-DSS Req 3.2/3.3** (no SAD/CVV storage, tokenization), **Req 3.5/3.6** (encryption at rest & key separation), **Req 4.2** (PKI & TLS transport), **Req 6.2** (strict input validation & parameterized SQL), **Req 7.2 & 8.3** (authenticated admin access, password policy & Argon2id hashing), and **Req 10.2** (100% transaction audit trail). |
| **Simple privacy module** | Classifies what personal/financial data is collected, why each field is collected, live SQLite schema inspection proving zero excess columns (`phone`, `address`, `birth_date`, `pan`, `cvv`), and an interactive **Privacy Payload Inspector** that flags unnecessary PII and prohibited PCI fields. |

## Setup & Run

On Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m app.setup
```

> **Tip:** If the demo was already initialized and you want to generate a fresh one-time administrator password, keys, and certificates, run:
> ```powershell
> .\.venv\Scripts\python.exe -m app.setup --reset
> ```

**Copy the one-time admin password shown by setup.** It is stored only as a salted Argon2id hash in `.secrets/admin-hash.txt`.

Start the HTTPS server:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8443 --ssl-keyfile .secrets/server-key.pem --ssl-certfile .secrets/server.pem
```

Open **https://127.0.0.1:8443** and log in with password from setup (username is `admin`). To verify the TLS handshake and X.509 certificate chain against the local Root CA (`.secrets/ca.pem`) from another terminal:

```powershell
.\.venv\Scripts\python.exe -m app.verify_tls
```

## Run Automated Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```
