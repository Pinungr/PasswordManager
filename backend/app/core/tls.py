import os
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def tls_paths(data: Path, host_mode: str, *, initialize: bool = False) -> tuple[Path, Path, Path]:
    mounted = (
        Path(os.environ.get("SECUREVAULT_TLS_CERT_FILE", "/tls/tls-cert.pem")),
        Path(os.environ.get("SECUREVAULT_TLS_KEY_FILE", "/tls/tls-key.pem")),
        Path(os.environ.get("SECUREVAULT_TLS_CA_FILE", "/tls/tls-ca.pem")),
    )
    if all(path.is_file() for path in mounted):
        return mounted
    if host_mode != "local" or any(path.exists() for path in mounted):
        raise RuntimeError("Supply a complete TLS certificate, private key, and CA bundle.")

    directory = data / "tls"
    if initialize and not directory.exists():
        create_local_tls(directory)
    return directory / "tls-cert.pem", directory / "tls-key.pem", directory / "tls-ca.pem"


def create_local_tls(directory: Path) -> None:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    server_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pinaki SecureVault Local CA")])
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    moment = datetime.now(UTC)

    def certificate(subject, key, days):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(moment - timedelta(minutes=5))
            .not_valid_after(moment + timedelta(days=days))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        )

    ca = (
        certificate(ca_name, ca_key, 1825)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server = (
        certificate(server_name, server_key, 1825)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ip_address("127.0.0.1")),
                x509.IPAddress(ip_address("::1")),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Publish the three files together so a stopped first boot can retry cleanly.
    with TemporaryDirectory(dir=directory.parent, prefix=".tls-") as temporary:
        generated = Path(temporary)
        (generated / "tls-ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (generated / "tls-cert.pem").write_bytes(server.public_bytes(serialization.Encoding.PEM))
        (generated / "tls-key.pem").write_bytes(
            server_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        generated.rename(directory)
