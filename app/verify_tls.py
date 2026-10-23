"""Verify that the live local HTTPS service chains to our demo CA."""
import ssl
import urllib.request

from app.core import SECRET


def main():
    context = ssl.create_default_context(cafile=str(SECRET / "ca.pem"))
    with urllib.request.urlopen("https://127.0.0.1:8443/", context=context, timeout=5) as response:
        print("Trusted CA, valid hostname and HTTPS handshake:", response.status)


if __name__ == "__main__":
    main()
