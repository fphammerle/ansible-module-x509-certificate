#!/usr/bin/python

DOCUMENTATION = """
---
module: x509_certificate
short_description: Create X.509 certificates.
requirements:
- cryptography (python 2)
author: Fabian Peter Hammerle
"""

from ansible.module_utils.basic import AnsibleModule

from cryptography import utils
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import os

def random_serial_number():
    """ https://cryptography.io/en/latest/_modules/cryptography/x509/base/#random_serial_number """
    return utils.int_from_bytes(os.urandom(20), "big") >> 1

def create_key(path):
    return rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 4096,
            backend = default_backend(),
            )

def save_key(path, key):
    with open(path, 'wb') as f:
        f.write(key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption(),
            ))
    os.chmod(path, 0600)

def save_cert(path, cert):
    with open(path, 'wb') as f:
        f.write(cert.public_bytes(
            encoding = serialization.Encoding.PEM,
            ))
    os.chmod(path, 0600)

def load_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(
                data = f.read(),
                password = None,
                backend = default_backend(),
                )

def load_cert(path):
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(
                data = f.read(),
                backend = default_backend(),
                )

def create_name(common_name, organization_name = None):
    attr = []
    if organization_name:
        attr.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name))
    attr.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attr)

def main(argv):

    module = AnsibleModule(
        argument_spec = {
            'cert_path': {'required': True, 'type': 'str'},
            'common_name': {'required': True, 'type': 'str'},
            'key_path': {'required': True, 'type': 'str'},
            'organization_name': {'required': False, 'type': 'str', 'default': None},
            }
        )

    changed = False

    if os.path.exists(module.params['key_path']):
        key = load_key(module.params['key_path'])
    else:
        key = create_key(module.params['key_path'])
        save_key(path = module.params['key_path'], key = key)
        changed = True

    if os.path.exists(module.params['cert_path']):
        cert = load_cert(module.params['cert_path'])
    else:
        issuer = create_name(
            common_name = module.params['common_name'].decode('utf-8'),
            organization_name = module.params['organization_name'].decode('utf-8')
                if module.params['organization_name'] else None,
            )
        cert_builder = (
            x509.CertificateBuilder()
             .subject_name(issuer)
             .issuer_name(issuer)
             .public_key(key.public_key())
             .serial_number(random_serial_number())
             .not_valid_before(datetime.datetime.utcnow())
             .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days = 356 * 10))
             )
        cert = cert_builder.sign(
                private_key = key,
                algorithm = hashes.SHA256(),
                backend = default_backend(),
                )
        save_cert(path = module.params['cert_path'], cert = cert)
        changed = True

    module.exit_json(
            changed = changed,
            cert_path =  module.params['cert_path'],
            key_path = module.params['key_path'],
            subject_common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            )

    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))