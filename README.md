# SecurePay Simulator

A **local educational payment simulator** using fictional records. It demonstrates encryption at rest, a local PKI and HTTPS handshake, password hashing, selected PCI DSS security principles, privacy minimization, and measurable dashboard checks. It is **not** a payment processor or a PCI DSS certification tool.

## Requirements

- Python 3.13+
- The packages in `requirements.txt`

On Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m app.setup
```

**Copy the one-time admin password shown by setup.** It is not recoverable from the stored Argon2id hash. Setup generates fictional customers, an AES-256-GCM key, a local CA, and a server certificate. The SQLite database and all secrets remain in ignored local folders.

Run the HTTPS app:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8443 --ssl-keyfile .secrets/server-key.pem --ssl-certfile .secrets/server.pem
```

Open **https://127.0.0.1:8443** and log in as `admin`. The browser will warn about the local demo CA because it is not in the operating system trust store. For a verified trust demonstration, keep the server running and execute in another terminal:

```powershell
.\.venv\Scripts\python.exe -m app.verify_tls
```

The verification script trusts only `.secrets/ca.pem` and checks the HTTPS certificate and hostname. Do not install this demo CA in your system trust store. `/docs` provides the FastAPI API reference.

## What to demonstrate

1. **Sensitive data:** The privacy inventory classifies personal, cardholder, sensitive authentication, financial, and credential fields. It lists each field's purpose, whether it is stored, and its protection.
2. **Stored data:** Customer emails are AES-GCM ciphertext in SQLite; the dashboard shows a fictional plaintext sample and its encrypted form. The random nonce and authentication tag allow tampering to be detected.
3. **PKI:** A local CA signs the server certificate. The dashboard checks its signature, dates and hostname, and demonstrates a signed receipt checked with the public key. The private key stays server-side.
4. **Transmission:** Payment and customer APIs reject plain HTTP. Run the app over HTTPS and use `app.verify_tls` to prove certificate-based trust.
5. **Selected PCI DSS principles:** The dashboard maps controls to requirements 3, 4, 7, 8 and 10. Checks inspect encrypted records, key separation, password hashing, HTTPS, and payment audit coverage. They are illustrative checks, not a full assessment.
6. **Privacy:** The database stores no full card number, CVV, PIN, phone, birth date or address. Payment requests accept only a fictional customer's ID, amount and last four digits. A random token represents the payment method. The privacy panel explains the risks of unnecessary collection.
7. **Measurement:** The before counts are measured from a temporary, overcollecting fictional record set assembled in memory. The after counts are measured from SQLite. The before records are never persisted.

## Run checks

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Use fictional data only. Passwords are hashed, not encrypted. Keep `.secrets/` and `data/` private; they are excluded from Git. Local key files and a self-issued CA are appropriate for this demonstration, not production key management.

Reference: [PCI DSS v4.0.1](https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1) and [PCI SSC guidance on sensitive authentication data](https://www.pcisecuritystandards.org/faqs/1154/).
