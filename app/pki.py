"""Local-only CA and server certificate for the PKI demonstration."""
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


def create_certificates(secret_dir: Path) -> None:
    secret_dir.mkdir(parents=True, exist_ok=True)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecurePay Demo Local CA")])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    ca_cert = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_cert = (
        x509.CertificateBuilder().subject_name(server_name).issuer_name(ca_name)
        .public_key(server_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(IPv4Address("127.0.0.1"))
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=True, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (secret_dir / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (secret_dir / "server.pem").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    (secret_dir / "server-key.pem").write_bytes(server_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))


def inspect_certificates(secret_dir: Path) -> dict:
    ca = x509.load_pem_x509_certificate((secret_dir / "ca.pem").read_bytes())
    server = x509.load_pem_x509_certificate((secret_dir / "server.pem").read_bytes())
    key = serialization.load_pem_private_key((secret_dir / "server-key.pem").read_bytes(), password=None)
    ca.public_key().verify(server.signature, server.tbs_certificate_bytes,
                           padding.PKCS1v15(), server.signature_hash_algorithm)
    names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    now = datetime.now(timezone.utc)
    valid = (ca.subject == server.issuer and server.not_valid_before_utc <= now <= server.not_valid_after_utc
             and "localhost" in names.get_values_for_type(x509.DNSName)
             and IPv4Address("127.0.0.1") in names.get_values_for_type(x509.IPAddress))
    message = b"securepay-demo-receipt"
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    server.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    return {
        "valid": valid, "issuer": ca.subject.rfc4514_string(),
        "subject": server.subject.rfc4514_string(),
        "expires": server.not_valid_after_utc.isoformat(),
        "signature_verified": True, "receipt_signature_verified": True,
        "public_key_type": "RSA 3072", "private_key_exposed": False,
    }
