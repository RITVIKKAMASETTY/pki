"""
Trust Chain Builder
Constructs and validates certificate chains using issuer/subject matching
and Authority/Subject Key Identifier linking.
"""

from __future__ import annotations

from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from ..models.schemas import CertificateInfo, TrustChainResult, ChainLink


def _aki_to_hex(cert_info: CertificateInfo) -> Optional[str]:
    return cert_info.authority_key_identifier

def _ski_to_hex(cert_info: CertificateInfo) -> Optional[str]:
    return cert_info.subject_key_identifier


def _certs_match(child: CertificateInfo, parent: CertificateInfo) -> bool:
    """
    Determine if parent issued child.
    Primary:   Subject Key Identifier of parent == Authority Key Identifier of child
    Fallback:  issuer_cn of child == subject_cn of parent
    """
    child_aki = _aki_to_hex(child)
    parent_ski = _ski_to_hex(parent)

    if child_aki and parent_ski:
        # Normalize separators
        c_aki = child_aki.replace(":", "").lower()
        p_ski = parent_ski.replace(":", "").lower()
        return c_aki == p_ski

    # Fallback: name match
    return child.issuer_cn.strip() == parent.subject_cn.strip()


def verify_signature(child_pem: bytes, parent_pem: bytes) -> bool:
    """
    Cryptographically verify that parent signed child.
    Returns True on success, False on failure.
    """
    try:
        child_cert  = x509.load_pem_x509_certificate(child_pem)
        parent_cert = x509.load_pem_x509_certificate(parent_pem)
        parent_key  = parent_cert.public_key()
        parent_key.verify(
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child_cert.signature_hash_algorithm,
        )
        return True
    except (InvalidSignature, Exception):
        return False


def build_chain(
    leaf: CertificateInfo,
    all_certs: list[CertificateInfo],
    max_depth: int = 10,
) -> TrustChainResult:
    """
    Walk up the issuer chain from leaf until we reach a self-signed root
    or exhaust the available certificates.
    """
    chain: list[ChainLink] = []
    issues: list[str] = []
    current = leaf
    visited: set[str] = set()
    root_cn: Optional[str] = None

    # Index certs by subject_cn for quick lookup
    by_cn: dict[str, list[CertificateInfo]] = {}
    for c in all_certs:
        by_cn.setdefault(c.subject_cn, []).append(c)

    for _ in range(max_depth):
        fp = current.fingerprint_sha256
        if fp in visited:
            issues.append(f"Cycle detected at {current.subject_cn}")
            break
        visited.add(fp)

        is_self_signed = current.subject_cn == current.issuer_cn
        link = ChainLink(
            subject_cn=current.subject_cn,
            issuer_cn=current.issuer_cn,
            certificate_type=current.certificate_type if hasattr(current, 'certificate_type') else ('root' if is_self_signed else 'unknown'),
            is_valid=not current.is_expired,
        )
        chain.append(link)

        if current.is_expired:
            issues.append(f"Certificate '{current.subject_cn}' is EXPIRED")

        if is_self_signed:
            root_cn = current.subject_cn
            break

        # Find parent
        issuer_cn = current.issuer_cn
        candidates = by_cn.get(issuer_cn, [])
        parent: Optional[CertificateInfo] = None
        for c in candidates:
            if _certs_match(current, c):
                parent = c
                break
        if not candidates:
            # Try broader search
            for c in all_certs:
                if _certs_match(current, c):
                    parent = c
                    break

        if parent is None:
            issues.append(f"Issuer not found: '{issuer_cn}' for '{current.subject_cn}'")
            break

        # Verify signature
        try:
            child_pem  = current.pem_data.encode()
            parent_pem = parent.pem_data.encode()
            if not verify_signature(child_pem, parent_pem):
                issues.append(f"Signature verification FAILED: '{current.subject_cn}' not signed by '{parent.subject_cn}'")
        except Exception as e:
            issues.append(f"Signature check error: {e}")

        current = parent

    is_complete = root_cn is not None
    is_valid    = is_complete and len(issues) == 0

    return TrustChainResult(
        leaf_cn=leaf.subject_cn,
        chain=chain,
        root_cn=root_cn,
        is_complete=is_complete,
        is_valid=is_valid,
        issues=issues,
    )
