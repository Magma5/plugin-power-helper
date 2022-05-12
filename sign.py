from yaml import safe_load
from sys import stderr
import json
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.hazmat.primitives import hashes
from base64 import b64encode
import hashlib

def get_cert_hash(cert):
    def padding(b):
        return f"0001{'ff' * (512 - len(b) // 2 - 3)}00{b}"

    sha256_magic = '3031300D060960864801650304020105000420'

    sha = hashlib.sha256()
    sha.update(cert.tbs_certificate_bytes)

    return int.from_bytes(bytes.fromhex(padding(sha256_magic + sha.hexdigest())),
        byteorder='big',
        signed=False)

with open('config.yml') as f:
    config = safe_load(f)

with open(config['key_file'], 'rb') as f:
    key: rsa.RSAPrivateKey = load_pem_private_key(f.read(), password=None)

with open(config['cert_file'], 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read())

data = config['data']
data_compact = json.dumps(data, separators=(',', ':'))

data_signature = key.sign(data_compact.encode('utf-8'), padding.PKCS1v15(), hashes.SHA1())

output_data = data | {
    'data_b64': b64encode(data_compact.encode('utf-8')).decode('utf-8'),
    'data_signature_b64': b64encode(data_signature).decode('utf-8'),
    'cert_b64': b64encode(cert.public_bytes(Encoding.DER)).decode('utf-8'),
    'cert_hash': get_cert_hash(cert),
    'cert_signature': int.from_bytes(cert.signature, byteorder='big', signed=False)
}

for output_file, template in config['output'].items():
    with open(output_file, 'w') as output:
        output.write(template.format(**output_data))
        print('Saved', output_file, file=stderr)
