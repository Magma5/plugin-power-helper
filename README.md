# plugin-power helper

A script that can generate signed data and use with [plugin-power](https://github.com/ja-netfilter/plugin-power)

## Introduction

* `cert.py` will generate a 4096-bit RSA key (CA signing key), a 2048-bit RSA key (data signing key) and a certificate. The certificate will have the `issuer` CN configured as `issuer_common_name` config value.

* `sign.py` will sign the data given in the config (convert to compact JSON first) using the private key and output the value into files configured in `config.yml`.

## Output template variables

* All values given in `data`.
* `data_b64` The data converted to compact JSON and base64 encoded.
* `data_signature_b64` The data converted to compact JSON and signature generated by the private key, base64 encoded.
* `cert_b64` Certificate itself encoded in DER format and base64 encoded.
* `cert_hash` Integer value of the hash of the certificate, used to generate the cert_signature.
* `cert_signature` Integer value of the certificate's signature.

## Use with plugin-power

To spoof the certificate to be signed by another (legit) CA, find the modulus (integer) of the real CA certificate, and configure `output` as follows (replace `[ca public key modulus]` with the actual value):

```
output:
  power.conf: |
    [Result]
    EQUAL,{cert_signature},65537,[ca public key modulus]->{cert_hash}
```

Then it will save a power.conf that can be used with plugin-power.
