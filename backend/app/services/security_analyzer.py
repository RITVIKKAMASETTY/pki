"""
Security Analyzer — Rule-based engine that evaluates certificate health.
Produces structured findings with severity and recommendations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..models.schemas import (
    CertificateInfo, TrustChainResult, SecurityFinding, AnalysisResult
)

# Severity order
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
EXPIRY_WARNING_DAYS = 30
EXPIRY_CRITICAL_DAYS = 7


def _overall_risk(findings: list[SecurityFinding]) -> str:
    if not findings:
        return "LOW"
    min_sev = min(findings, key=lambda f: SEVERITY_ORDER[f.severity])
    return min_sev.severity


def analyze(
    cert: CertificateInfo,
    chain_result: Optional[TrustChainResult],
    known_root_cns: Optional[set[str]] = None,
) -> AnalysisResult:
    findings: list[SecurityFinding] = []
    now = datetime.now(timezone.utc)

    # ── Rule 1: Expired certificate ───────────────────────────────────────────
    if cert.is_expired:
        findings.append(SecurityFinding(
            finding_type="EXPIRED",
            severity="CRITICAL",
            description=f"Certificate expired {abs(cert.days_remaining)} days ago "
                        f"(was valid until {cert.valid_until.date()}).",
            recommendation="Revoke and reissue the certificate immediately. Any service "
                           "depending on this certificate may be presenting a broken chain "
                           "to clients.",
        ))

    # ── Rule 2: Expiring soon ─────────────────────────────────────────────────
    elif 0 < cert.days_remaining <= EXPIRY_WARNING_DAYS:
        severity = "CRITICAL" if cert.days_remaining <= EXPIRY_CRITICAL_DAYS else "MEDIUM"
        findings.append(SecurityFinding(
            finding_type="EXPIRING_SOON",
            severity=severity,
            description=f"Certificate expires in {cert.days_remaining} days "
                        f"({cert.valid_until.date()}).",
            recommendation="Renew the certificate before expiration to avoid service disruption. "
                           "Automate renewal with ACME/Let's Encrypt or internal CA tooling.",
        ))

    # ── Rule 3: Weak RSA key < 2048 ──────────────────────────────────────────
    if cert.public_key_algorithm == "RSA" and cert.public_key_size < 2048:
        findings.append(SecurityFinding(
            finding_type="WEAK_KEY",
            severity="HIGH",
            description=f"RSA key size is {cert.public_key_size} bits. "
                        "Keys below 2048 bits are considered cryptographically weak.",
            recommendation="Reissue the certificate with at least RSA-2048, "
                           "or migrate to ECDSA P-256 for equivalent security with smaller keys.",
        ))

    # ── Rule 4: SHA-1 signature ───────────────────────────────────────────────
    if "sha1" in cert.signature_algorithm.lower():
        findings.append(SecurityFinding(
            finding_type="WEAK_SIGNATURE",
            severity="HIGH",
            description="Certificate uses SHA-1 as the signature hash algorithm. "
                        "SHA-1 is cryptographically broken and deprecated.",
            recommendation="Reissue the certificate with SHA-256 or stronger. "
                           "Major browsers and TLS stacks reject SHA-1 certificates.",
        ))

    # ── Rule 5: SAN hostname mismatch ────────────────────────────────────────
    if not cert.is_ca:
        cn = cert.subject_cn
        dns_sans = [s.replace("DNS:", "") for s in cert.subject_alternative_names if s.startswith("DNS:")]
        if not dns_sans:
            findings.append(SecurityFinding(
                finding_type="NO_SAN",
                severity="HIGH",
                description="Certificate has no Subject Alternative Name (SAN) DNS entries. "
                            "Modern TLS requires SANs; the CN is ignored by browsers.",
                recommendation="Reissue the certificate with appropriate SAN entries "
                               "matching all hostnames the service is accessed by.",
            ))
        else:
            # Check if CN is covered by any SAN
            cn_lower = cn.lower()
            covered = any(
                cn_lower == s.lower() or
                (s.startswith("*.") and cn_lower.endswith(s[1:].lower()))
                for s in dns_sans
            )
            if not covered:
                findings.append(SecurityFinding(
                    finding_type="SAN_MISMATCH",
                    severity="HIGH",
                    description=f"Common Name '{cn}' is NOT listed in Subject Alternative Names "
                                f"({', '.join(dns_sans)}).",
                    recommendation="Reissue the certificate and ensure the CN (or intended hostnames) "
                                   "appear in the SAN DNS list.",
                ))

    # ── Rule 6: Broken trust chain ────────────────────────────────────────────
    if chain_result and not chain_result.is_complete:
        findings.append(SecurityFinding(
            finding_type="BROKEN_CHAIN",
            severity="CRITICAL",
            description="Trust chain is INCOMPLETE — one or more issuer certificates are missing. "
                        f"Issues: {'; '.join(chain_result.issues)}",
            recommendation="Ensure all intermediate CA certificates are available and correctly "
                           "installed on the server. Configure the TLS server to send the full chain.",
        ))

    # ── Rule 7: Untrusted root ────────────────────────────────────────────────
    if chain_result and chain_result.is_complete and known_root_cns:
        if chain_result.root_cn and chain_result.root_cn not in known_root_cns:
            findings.append(SecurityFinding(
                finding_type="UNTRUSTED_ROOT",
                severity="CRITICAL",
                description=f"Root CA '{chain_result.root_cn}' is NOT in the trusted root store.",
                recommendation="Import the root CA certificate into the trusted store, or reissue "
                               "the certificate from a trusted CA.",
            ))

    # ── Rule 8: Chain signature/validity errors ───────────────────────────────
    if chain_result and chain_result.is_complete:
        chain_errors = [i for i in chain_result.issues
                        if "signature" in i.lower() or "expired" in i.lower()]
        for err in chain_errors:
            findings.append(SecurityFinding(
                finding_type="CHAIN_ERROR",
                severity="CRITICAL",
                description=f"Trust chain validation error: {err}",
                recommendation="Investigate the failing certificate in the chain. "
                               "Reissue certificates with proper signatures.",
            ))

    # ── Rule 9: CA cert used as leaf ─────────────────────────────────────────
    if cert.is_ca and "key_cert_sign" in cert.key_usage:
        has_server_auth = any("1.3.6.1.5.5.7.3.1" in eku for eku in cert.extended_key_usage)
        if has_server_auth:
            findings.append(SecurityFinding(
                finding_type="CA_AS_LEAF",
                severity="MEDIUM",
                description="A CA certificate has Extended Key Usage 'Server Authentication'. "
                            "CA certificates should not be used directly as leaf certificates.",
                recommendation="Issue a separate leaf certificate from this CA for server use.",
            ))

    # ── Rule 10: RSA key > 4096 (performance note) ───────────────────────────
    if cert.public_key_algorithm == "RSA" and cert.public_key_size > 4096:
        findings.append(SecurityFinding(
            finding_type="OVERSIZED_KEY",
            severity="INFO",
            description=f"RSA key is {cert.public_key_size} bits. Very large RSA keys can cause "
                        "performance issues during TLS handshakes.",
            recommendation="Consider ECDSA P-384 as a more efficient alternative for high-security requirements.",
        ))

    return AnalysisResult(
        certificate_cn=cert.subject_cn,
        overall_risk=_overall_risk(findings) if findings else "TRUSTED",
        findings=findings,
        chain_result=chain_result,
    )
