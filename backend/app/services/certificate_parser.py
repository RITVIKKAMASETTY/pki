"""
Certificate Parser Service
Extracts all relevant metadata from X.509 PEM certificates.
"""

from __future__ import annotations

import hashlib
from typing import Optional
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import NameOID, ExtensionOID

from ..models.schemas import CertificateInfo


def load_pem(pem_data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_data)


def _get_cn(name: x509.Name) -> str:
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return str(name)


def _key_info(pub_key) -> tuple[str, int]:
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        return "EC", pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        return "DSA", pub_key.key_size
    return "Unknown", 0


def _get_extension_safe(cert: x509.Certificate, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def parse_certificate(pem_data: bytes, filename: str = "") -> CertificateInfo:
    cert = load_pem(pem_data)
    now = datetime.now(timezone.utc)

    subject_cn = _get_cn(cert.subject)
    issuer_cn  = _get_cn(cert.issuer)

    pub_key = cert.public_key()
    key_algo, key_size = _key_info(pub_key)

    sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    sig_algo_full = cert.signature_algorithm_oid.dotted_string

    # Fingerprints
    sha256_fp = cert.fingerprint(hashes.SHA256()).hex(":")
    sha1_fp   = cert.fingerprint(hashes.SHA1()).hex(":")

    # Validity
    nv_before = cert.not_valid_before_utc
    nv_after  = cert.not_valid_after_utc
    is_expired = now > nv_after
    days_remaining = (nv_after - now).days if not is_expired else -(now - nv_after).days

    # Basic Constraints
    bc = _get_extension_safe(cert, ExtensionOID.BASIC_CONSTRAINTS)
    is_ca = bc.ca if bc else False
    path_length = bc.path_length if bc else None

    # Key Usage
    ku_ext = _get_extension_safe(cert, ExtensionOID.KEY_USAGE)
    key_usage = []
    if ku_ext:
        attrs = ["digital_signature","content_commitment","key_encipherment",
                 "data_encipherment","key_agreement","key_cert_sign","crl_sign"]
        for a in attrs:
            try:
                if getattr(ku_ext, a):
                    key_usage.append(a)
            except Exception:
                pass

    # Extended Key Usage
    eku_ext = _get_extension_safe(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    extended_key_usage = [oid.dotted_string for oid in eku_ext] if eku_ext else []

    # SANs
    san_ext = _get_extension_safe(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    sans = []
    if san_ext:
        for name in san_ext:
            if isinstance(name, x509.DNSName):
                sans.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                sans.append(f"IP:{name.value}")
            elif isinstance(name, x509.RFC822Name):
                sans.append(f"email:{name.value}")
            else:
                sans.append(str(name.value))

    # AKI / SKI
    aki_ext = _get_extension_safe(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    authority_key_id = aki_ext.key_identifier.hex(":") if (aki_ext and aki_ext.key_identifier) else None

    ski_ext = _get_extension_safe(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    subject_key_id = ski_ext.key_identifier.hex(":") if ski_ext else None

    return CertificateInfo(
        filename=filename,
        subject=str(cert.subject),
        subject_cn=subject_cn,
        issuer=str(cert.issuer),
        issuer_cn=issuer_cn,
        serial_number=hex(cert.serial_number),
        version=cert.version.value + 1,
        valid_from=nv_before,
        valid_until=nv_after,
        is_expired=is_expired,
        days_remaining=days_remaining,
        public_key_algorithm=key_algo,
        public_key_size=key_size,
        signature_algorithm=sig_algo,
        signature_algorithm_oid=sig_algo_full,
        is_ca=is_ca,
        path_length=path_length,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        subject_alternative_names=sans,
        authority_key_identifier=authority_key_id,
        subject_key_identifier=subject_key_id,
        fingerprint_sha256=sha256_fp,
        fingerprint_sha1=sha1_fp,
        pem_data=pem_data.decode("utf-8"),
    )
