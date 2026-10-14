"""
PKI Trust Chain Dataset Generator
Generates a controlled PKI hierarchy with intentionally flawed certificates
for testing the analysis platform.
"""

import os
import datetime
import csv
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import ipaddress

DATASET_DIR = os.path.join(os.path.dirname(__file__), '..', 'dataset')
ROOT_DIR    = os.path.join(DATASET_DIR, 'roots')
INT_DIR     = os.path.join(DATASET_DIR, 'intermediates')
LEAF_DIR    = os.path.join(DATASET_DIR, 'leaf')

for d in [ROOT_DIR, INT_DIR, LEAF_DIR]:
    os.makedirs(d, exist_ok=True)

NOW = datetime.datetime.now(datetime.timezone.utc)
METADATA_ROWS = []

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def gen_rsa_key(size=2048):
    return rsa.generate_private_key(
        public_exponent=65537, key_size=size, backend=default_backend()
    )

def save_cert(cert, path):
    with open(path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def save_key(key, path):
    with open(path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

def add_meta2(filename, cert, cert_type, subject_cn, issuer_cn, note=""):
    METADATA_ROWS.append({
        'filename': filename,
        'type': cert_type,
        'subject_cn': subject_cn,
        'issuer_cn': issuer_cn,
        'valid_from': cert.not_valid_before_utc.date().isoformat(),
        'valid_until': cert.not_valid_after_utc.date().isoformat(),
        'note': note,
    })

def builder_base(subject_name, issuer_name, serial, not_before, not_after):
    return (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

# ─────────────────────────────────────────────────────────────────────────────
# Root CA 1  (main trust anchor)
# ─────────────────────────────────────────────────────────────────────────────
print("Generating Root CA 1 ...")
root1_key  = gen_rsa_key(4096)
root1_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI PKI Lab"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Root Authority"),
    x509.NameAttribute(NameOID.COMMON_NAME, "AI PKI Root CA"),
])
root1_cert = (
    builder_base(root1_name, root1_name, x509.random_serial_number(),
                 NOW - datetime.timedelta(days=365*2),
                 NOW + datetime.timedelta(days=365*10))
    .public_key(root1_key.public_key())
    .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(root1_key.public_key()), critical=False)
    .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                  content_commitment=False, key_encipherment=False,
                                  data_encipherment=False, key_agreement=False,
                                  encipher_only=False, decipher_only=False), critical=True)
    .sign(root1_key, hashes.SHA256(), default_backend())
)
save_cert(root1_cert, os.path.join(ROOT_DIR, 'root_ca_01.pem'))
save_key(root1_key,   os.path.join(ROOT_DIR, 'root_ca_01.key'))
add_meta2('roots/root_ca_01.pem', root1_cert, 'root', 'AI PKI Root CA', 'AI PKI Root CA', 'Primary trust anchor')

# ─────────────────────────────────────────────────────────────────────────────
# Root CA 2  (secondary)
# ─────────────────────────────────────────────────────────────────────────────
print("Generating Root CA 2 ...")
root2_key  = gen_rsa_key(2048)
root2_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI PKI Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, "AI PKI Secondary Root CA"),
])
root2_cert = (
    builder_base(root2_name, root2_name, x509.random_serial_number(),
                 NOW - datetime.timedelta(days=365),
                 NOW + datetime.timedelta(days=365*5))
    .public_key(root2_key.public_key())
    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(root2_key.public_key()), critical=False)
    .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                  content_commitment=False, key_encipherment=False,
                                  data_encipherment=False, key_agreement=False,
                                  encipher_only=False, decipher_only=False), critical=True)
    .sign(root2_key, hashes.SHA256(), default_backend())
)
save_cert(root2_cert, os.path.join(ROOT_DIR, 'root_ca_02.pem'))
save_key(root2_key,   os.path.join(ROOT_DIR, 'root_ca_02.key'))
add_meta2('roots/root_ca_02.pem', root2_cert, 'root', 'AI PKI Secondary Root CA', 'AI PKI Secondary Root CA', 'Secondary trust anchor')

# ─────────────────────────────────────────────────────────────────────────────
# Intermediate CA 1  (under Root CA 1)
# ─────────────────────────────────────────────────────────────────────────────
print("Generating Intermediate CA 1 ...")
int1_key  = gen_rsa_key(2048)
int1_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI PKI Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, "AI Intermediate CA 1"),
])
aki1 = x509.AuthorityKeyIdentifier.from_issuer_public_key(root1_key.public_key())
int1_cert = (
    builder_base(int1_name, root1_name, x509.random_serial_number(),
                 NOW - datetime.timedelta(days=180),
                 NOW + datetime.timedelta(days=365*3))
    .public_key(int1_key.public_key())
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(int1_key.public_key()), critical=False)
    .add_extension(aki1, critical=False)
    .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                  content_commitment=False, key_encipherment=False,
                                  data_encipherment=False, key_agreement=False,
                                  encipher_only=False, decipher_only=False), critical=True)
    .sign(root1_key, hashes.SHA256(), default_backend())
)
save_cert(int1_cert, os.path.join(INT_DIR, 'intermediate_01.pem'))
save_key(int1_key,   os.path.join(INT_DIR, 'intermediate_01.key'))
add_meta2('intermediates/intermediate_01.pem', int1_cert, 'intermediate', 'AI Intermediate CA 1', 'AI PKI Root CA', 'Signs AI services group A')

# ─────────────────────────────────────────────────────────────────────────────
# Intermediate CA 2  (under Root CA 1)
# ─────────────────────────────────────────────────────────────────────────────
print("Generating Intermediate CA 2 ...")
int2_key  = gen_rsa_key(2048)
int2_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI PKI Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, "AI Intermediate CA 2"),
])
aki2 = x509.AuthorityKeyIdentifier.from_issuer_public_key(root1_key.public_key())
int2_cert = (
    builder_base(int2_name, root1_name, x509.random_serial_number(),
                 NOW - datetime.timedelta(days=90),
                 NOW + datetime.timedelta(days=365*2))
    .public_key(int2_key.public_key())
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(int2_key.public_key()), critical=False)
    .add_extension(aki2, critical=False)
    .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                  content_commitment=False, key_encipherment=False,
                                  data_encipherment=False, key_agreement=False,
                                  encipher_only=False, decipher_only=False), critical=True)
    .sign(root1_key, hashes.SHA256(), default_backend())
)
save_cert(int2_cert, os.path.join(INT_DIR, 'intermediate_02.pem'))
save_key(int2_key,   os.path.join(INT_DIR, 'intermediate_02.key'))
add_meta2('intermediates/intermediate_02.pem', int2_cert, 'intermediate', 'AI Intermediate CA 2', 'AI PKI Root CA', 'Signs AI services group B')

# ─────────────────────────────────────────────────────────────────────────────
# Intermediate CA 3  EXPIRED  (under Root CA 2)
# ─────────────────────────────────────────────────────────────────────────────
print("Generating Intermediate CA 3 (EXPIRED) ...")
int3_key  = gen_rsa_key(2048)
int3_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI PKI Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, "AI Intermediate CA 3 (Expired)"),
])
aki3 = x509.AuthorityKeyIdentifier.from_issuer_public_key(root2_key.public_key())
int3_cert = (
    builder_base(int3_name, root2_name, x509.random_serial_number(),
                 NOW - datetime.timedelta(days=730),
                 NOW - datetime.timedelta(days=30))
    .public_key(int3_key.public_key())
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(int3_key.public_key()), critical=False)
    .add_extension(aki3, critical=False)
    .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                  content_commitment=False, key_encipherment=False,
                                  data_encipherment=False, key_agreement=False,
                                  encipher_only=False, decipher_only=False), critical=True)
    .sign(root2_key, hashes.SHA256(), default_backend())
)
save_cert(int3_cert, os.path.join(INT_DIR, 'intermediate_03_expired.pem'))
save_key(int3_key,   os.path.join(INT_DIR, 'intermediate_03_expired.key'))
add_meta2('intermediates/intermediate_03_expired.pem', int3_cert, 'intermediate',
          'AI Intermediate CA 3 (Expired)', 'AI PKI Secondary Root CA', 'EXPIRED intermediate for broken-chain tests')

# ─────────────────────────────────────────────────────────────────────────────
# Helper: build leaf cert
# ─────────────────────────────────────────────────────────────────────────────
def make_leaf(cn, sans, issuer_cert, issuer_key, not_before, not_after, key_size=2048):
    key = gen_rsa_key(key_size)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI Services Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    san_list = []
    for s in sans:
        try:
            san_list.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            san_list.append(x509.DNSName(s))
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key())
    cert = (
        builder_base(name, issuer_cert.subject, x509.random_serial_number(),
                     not_before, not_after)
        .public_key(key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(aki, critical=False)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                                      content_commitment=False, key_encipherment=True,
                                      data_encipherment=False, key_agreement=False,
                                      encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(issuer_key, hashes.SHA256(), default_backend())
    )
    return cert, key

# ─────────────────────────────────────────────────────────────────────────────
# Leaf certificates
# ─────────────────────────────────────────────────────────────────────────────

print("Generating leaf: inference-api (VALID) ...")
cert, key = make_leaf('inference.ai.company.com',
    ['inference.ai.company.com', 'inference-api.ai.company.com'],
    int1_cert, int1_key, NOW - datetime.timedelta(days=60), NOW + datetime.timedelta(days=305))
save_cert(cert, os.path.join(LEAF_DIR, 'service_01_inference.pem'))
save_key(key,   os.path.join(LEAF_DIR, 'service_01_inference.key'))
add_meta2('leaf/service_01_inference.pem', cert, 'leaf',
          'inference.ai.company.com', 'AI Intermediate CA 1', 'VALID - Inference API')

print("Generating leaf: model-registry (VALID) ...")
cert, key = make_leaf('models.ai.company.com', ['models.ai.company.com'],
    int1_cert, int1_key, NOW - datetime.timedelta(days=30), NOW + datetime.timedelta(days=335))
save_cert(cert, os.path.join(LEAF_DIR, 'service_02_model_registry.pem'))
save_key(key,   os.path.join(LEAF_DIR, 'service_02_model_registry.key'))
add_meta2('leaf/service_02_model_registry.pem', cert, 'leaf',
          'models.ai.company.com', 'AI Intermediate CA 1', 'VALID - Model Registry')

print("Generating leaf: training-api (EXPIRING SOON) ...")
cert, key = make_leaf('training.ai.company.com', ['training.ai.company.com'],
    int2_cert, int2_key, NOW - datetime.timedelta(days=347), NOW + datetime.timedelta(days=18))
save_cert(cert, os.path.join(LEAF_DIR, 'service_03_training.pem'))
save_key(key,   os.path.join(LEAF_DIR, 'service_03_training.key'))
add_meta2('leaf/service_03_training.pem', cert, 'leaf',
          'training.ai.company.com', 'AI Intermediate CA 2', 'WARNING - Expires in 18 days')

print("Generating leaf: vector-db (EXPIRED) ...")
cert, key = make_leaf('vector.ai.company.com', ['vector.ai.company.com'],
    int2_cert, int2_key, NOW - datetime.timedelta(days=400), NOW - datetime.timedelta(days=35))
save_cert(cert, os.path.join(LEAF_DIR, 'service_04_vector_db.pem'))
save_key(key,   os.path.join(LEAF_DIR, 'service_04_vector_db.key'))
add_meta2('leaf/service_04_vector_db.pem', cert, 'leaf',
          'vector.ai.company.com', 'AI Intermediate CA 2', 'CRITICAL - EXPIRED 35 days ago')

print("Generating leaf: monitoring (WEAK KEY 1024) ...")
cert, key = make_leaf('monitoring.ai.company.com', ['monitoring.ai.company.com'],
    int1_cert, int1_key, NOW - datetime.timedelta(days=10), NOW + datetime.timedelta(days=355),
    key_size=1024)
save_cert(cert, os.path.join(LEAF_DIR, 'service_05_monitoring.pem'))
save_key(key,   os.path.join(LEAF_DIR, 'service_05_monitoring.key'))
add_meta2('leaf/service_05_monitoring.pem', cert, 'leaf',
          'monitoring.ai.company.com', 'AI Intermediate CA 1', 'HIGH - Weak RSA 1024 key')

print("Generating leaf: data-pipeline (SAN MISMATCH) ...")
cert, key = make_leaf('data-pipeline.ai.company.com', ['wrong-host.other.com'],
    int2_cert, int2_key, NOW - datetime.timedelta(days=5), NOW + datetime.timedelta(days=360))
save_cert(cert, os.path.join(LEAF_DIR, 'service_06_data_pipeline.pem'))
save_key(key,   os.path.join(LEAF_DIR, 'service_06_data_pipeline.key'))
add_meta2('leaf/service_06_data_pipeline.pem', cert, 'leaf',
          'data-pipeline.ai.company.com', 'AI Intermediate CA 2', 'HIGH - SAN hostname mismatch')

print("Generating leaf: feature-store (BROKEN CHAIN / unknown issuer) ...")
orphan_key  = gen_rsa_key(2048)
orphan_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unknown External CA")])
orphan_cert = (
    builder_base(orphan_name, orphan_name, x509.random_serial_number(),
                 NOW - datetime.timedelta(days=365), NOW + datetime.timedelta(days=365))
    .public_key(orphan_key.public_key())
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(orphan_key.public_key()), critical=False)
    .sign(orphan_key, hashes.SHA256(), default_backend())
)
cert, key = make_leaf('feature-store.ai.company.com', ['feature-store.ai.company.com'],
    orphan_cert, orphan_key, NOW - datetime.timedelta(days=5), NOW + datetime.timedelta(days=360))
save_cert(cert, os.path.join(LEAF_DIR, 'service_07_feature_store.pem'))
save_key(key,   os.path.join(LEAF_DIR, 'service_07_feature_store.key'))
add_meta2('leaf/service_07_feature_store.pem', cert, 'leaf',
          'feature-store.ai.company.com', 'Unknown External CA', 'CRITICAL - Broken chain, unknown issuer')

print("Generating leaf: orchestrator-api (VALID) ...")
cert, key = make_leaf('orchestrator.ai.company.com',
    ['orchestrator.ai.company.com', 'orch-api.ai.company.com'],
    int2_cert, int2_key, NOW - datetime.timedelta(days=20), NOW + datetime.timedelta(days=345))
save_cert(cert, os.path.join(LEAF_DIR, 'service_08_orchestrator.pem'))
save_key(key,   os.path.join(LEAF_DIR, 'service_08_orchestrator.key'))
add_meta2('leaf/service_08_orchestrator.pem', cert, 'leaf',
          'orchestrator.ai.company.com', 'AI Intermediate CA 2', 'VALID - Orchestrator API')

print("Generating leaf: legacy-api (EXPIRED INTERMEDIATE) ...")
cert, key = make_leaf('legacy.ai.company.com', ['legacy.ai.company.com'],
    int3_cert, int3_key, NOW - datetime.timedelta(days=200), NOW + datetime.timedelta(days=165))
save_cert(cert, os.path.join(LEAF_DIR, 'service_09_legacy.pem'))
save_key(key,   os.path.join(LEAF_DIR, 'service_09_legacy.key'))
add_meta2('leaf/service_09_legacy.pem', cert, 'leaf',
          'legacy.ai.company.com', 'AI Intermediate CA 3 (Expired)', 'CRITICAL - Intermediate CA expired')

# Write metadata.csv
csv_path = os.path.join(DATASET_DIR, 'metadata.csv')
with open(csv_path, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['filename','type','subject_cn','issuer_cn',
                                           'valid_from','valid_until','note'])
    writer.writeheader()
    writer.writerows(METADATA_ROWS)

print(f"\nDataset generated: {DATASET_DIR}")
print("  Roots: 2  |  Intermediates: 3  |  Leaves: 9")
