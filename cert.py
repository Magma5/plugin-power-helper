from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
from yaml import safe_load

with open('config.yml') as f:
    config = safe_load(f)

ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, config['issuer_common_name']),
])

cert = (x509.CertificateBuilder()
    .subject_name(x509.Name([]))
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=700))
).sign(ca_key, hashes.SHA256())

with open(config['ca_key_file'], 'wb') as ca_key_file:
    ca_key_file.write(ca_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    ))

with open(config['key_file'], 'wb') as key_file:
    key_file.write(key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    ))

with open(config['cert_file'], "wb") as cert_file:
    cert_file.write(cert.public_bytes(Encoding.PEM))
