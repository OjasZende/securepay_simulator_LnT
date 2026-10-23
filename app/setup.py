"""Run once: python -m app.setup"""
from app import core
from app.pki import create_certificates


def main():
    password = core.initialize()
    create_certificates(core.SECRET)
    print("SecurePay demo initialized with fictional records.")
    print("Dashboard login: admin")
    print("One-time generated password:", password)
    print("Save the password locally. It is stored only as an Argon2id hash.")
    print("Start HTTPS: .\\.venv\\Scripts\\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8443 --ssl-keyfile .secrets/server-key.pem --ssl-certfile .secrets/server.pem")


if __name__ == "__main__":
    main()
