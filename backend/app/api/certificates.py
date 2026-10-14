"""Certificates API routes."""

from __future__ import annotations

import json
import os
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from ..database.models import Certificate, Finding, TrustChain, AIServiceRecord, get_db
from ..services.certificate_parser import parse_certificate
from ..services.chain_builder import build_chain
from ..services.security_analyzer import analyze
from ..models.schemas import (
    CertificateDB, CertificateInfo, TrustChainResult, AnalysisResult, SecurityFinding
)

router = APIRouter(prefix="/certificates", tags=["certificates"])

TRUSTED_ROOT_CNS = {"AI PKI Root CA", "AI PKI Secondary Root CA"}


def _cert_type_from_info(info: CertificateInfo) -> str:
    if info.is_ca:
        if info.subject_cn == info.issuer_cn:
            return "root"
        return "intermediate"
    return "leaf"


async def _get_all_cert_infos(db: AsyncSession) -> list[CertificateInfo]:
    result = await db.execute(select(Certificate))
    rows = result.scalars().all()
    infos = []
    for row in rows:
        infos.append(CertificateInfo(
            filename=row.filename,
            subject=row.subject,
            subject_cn=row.subject_cn,
            issuer=row.issuer,
            issuer_cn=row.issuer_cn,
            serial_number=row.serial_number,
            version=row.version,
            valid_from=row.valid_from,
            valid_until=row.valid_until,
            is_expired=row.is_expired,
            days_remaining=row.days_remaining,
            public_key_algorithm=row.public_key_algorithm,
            public_key_size=row.public_key_size,
            signature_algorithm=row.signature_algorithm,
            signature_algorithm_oid="",
            is_ca=row.is_ca,
            path_length=row.path_length,
            key_usage=json.loads(row.key_usage or "[]"),
            extended_key_usage=json.loads(row.extended_key_usage or "[]"),
            subject_alternative_names=json.loads(row.subject_alternative_names or "[]"),
            authority_key_identifier=row.authority_key_identifier,
            subject_key_identifier=row.subject_key_identifier,
            fingerprint_sha256=row.fingerprint_sha256,
            fingerprint_sha1=row.fingerprint_sha1,
            pem_data=row.pem_data,
            certificate_type=row.certificate_type,
        ))
    return infos


async def _store_cert(db: AsyncSession, info: CertificateInfo, filename: str = "") -> Certificate:
    # Check duplicate by fingerprint
    existing = await db.execute(
        select(Certificate).where(Certificate.fingerprint_sha256 == info.fingerprint_sha256)
    )
    row = existing.scalar_one_or_none()
    if row:
        return row

    cert_type = _cert_type_from_info(info)
    row = Certificate(
        filename=filename or info.filename,
        subject=info.subject,
        subject_cn=info.subject_cn,
        issuer=info.issuer,
        issuer_cn=info.issuer_cn,
        serial_number=info.serial_number,
        version=info.version,
        valid_from=info.valid_from,
        valid_until=info.valid_until,
        days_remaining=info.days_remaining,
        is_expired=info.is_expired,
        public_key_algorithm=info.public_key_algorithm,
        public_key_size=info.public_key_size,
        signature_algorithm=info.signature_algorithm,
        is_ca=info.is_ca,
        path_length=info.path_length,
        key_usage=json.dumps(info.key_usage),
        extended_key_usage=json.dumps(info.extended_key_usage),
        subject_alternative_names=json.dumps(info.subject_alternative_names),
        authority_key_identifier=info.authority_key_identifier,
        subject_key_identifier=info.subject_key_identifier,
        fingerprint_sha256=info.fingerprint_sha256,
        fingerprint_sha1=info.fingerprint_sha1,
        certificate_type=cert_type,
        pem_data=info.pem_data,
    )
    db.add(row)
    await db.flush()
    return row


async def _run_analysis(db: AsyncSession, cert_row: Certificate, all_infos: list[CertificateInfo]):
    # Build chain
    cert_info = next((c for c in all_infos if c.fingerprint_sha256 == cert_row.fingerprint_sha256), None)
    if not cert_info:
        return

    chain_result = build_chain(cert_info, all_infos)
    analysis = analyze(cert_info, chain_result, TRUSTED_ROOT_CNS)

    # Delete old findings
    old = await db.execute(select(Finding).where(Finding.certificate_id == cert_row.id))
    for f in old.scalars().all():
        await db.delete(f)

    # Save new findings
    for f in analysis.findings:
        db.add(Finding(
            certificate_id=cert_row.id,
            severity=f.severity,
            finding_type=f.finding_type,
            description=f.description,
            recommendation=f.recommendation,
        ))

    # Save chain
    old_chains = await db.execute(
        select(TrustChain).where(TrustChain.leaf_certificate_id == cert_row.id)
    )
    for c in old_chains.scalars().all():
        await db.delete(c)

    status = "valid" if chain_result.is_valid else (
        "incomplete" if not chain_result.is_complete else "invalid"
    )
    root_id = None
    if chain_result.root_cn:
        r = await db.execute(
            select(Certificate).where(Certificate.subject_cn == chain_result.root_cn)
        )
        root_row = r.scalar_one_or_none()
        root_id = root_row.id if root_row else None

    db.add(TrustChain(
        leaf_certificate_id=cert_row.id,
        root_certificate_id=root_id,
        chain_json=json.dumps([link.model_dump() for link in chain_result.chain]),
        status=status,
        issues_json=json.dumps(chain_result.issues),
    ))


@router.post("/upload", summary="Upload one or more PEM certificates")
async def upload_certificates(
    files: list[UploadFile] = File(...),
    db: AsyncSession = Depends(get_db),
):
    results = []
    for file in files:
        data = await file.read()
        try:
            info = parse_certificate(data, filename=file.filename or "")
            cert_row = await _store_cert(db, info, filename=file.filename or "")
            results.append({"filename": file.filename, "subject_cn": info.subject_cn, "id": cert_row.id})
        except Exception as e:
            results.append({"filename": file.filename, "error": str(e)})

    await db.commit()

    # Re-run analysis for all certs after new imports
    all_infos = await _get_all_cert_infos(db)
    all_certs_q = await db.execute(select(Certificate))
    all_certs = all_certs_q.scalars().all()
    for cert_row in all_certs:
        await _run_analysis(db, cert_row, all_infos)
    await db.commit()

    return {"imported": len(results), "details": results}


@router.get("", response_model=list[dict], summary="List all certificates")
async def list_certificates(
    cert_type: Optional[str] = Query(None, description="Filter: root|intermediate|leaf"),
    db: AsyncSession = Depends(get_db),
):
    q = select(Certificate)
    if cert_type:
        q = q.where(Certificate.certificate_type == cert_type)
    result = await db.execute(q.order_by(Certificate.days_remaining))
    certs = result.scalars().all()
    out = []
    for c in certs:
        findings_q = await db.execute(
            select(Finding).where(Finding.certificate_id == c.id)
        )
        findings = findings_q.scalars().all()
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        overall_risk = "TRUSTED"
        if findings:
            top = min(findings, key=lambda f: severity_order.get(f.severity, 5))
            overall_risk = top.severity

        out.append({
            "id": c.id,
            "filename": c.filename,
            "subject_cn": c.subject_cn,
            "issuer_cn": c.issuer_cn,
            "certificate_type": c.certificate_type,
            "valid_from": c.valid_from.isoformat(),
            "valid_until": c.valid_until.isoformat(),
            "days_remaining": c.days_remaining,
            "is_expired": c.is_expired,
            "public_key_algorithm": c.public_key_algorithm,
            "public_key_size": c.public_key_size,
            "signature_algorithm": c.signature_algorithm,
            "is_ca": c.is_ca,
            "overall_risk": overall_risk,
            "fingerprint_sha256": c.fingerprint_sha256,
        })
    return out


@router.get("/{cert_id}", summary="Get certificate details")
async def get_certificate(cert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Certificate).where(Certificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {
        "id": cert.id,
        "filename": cert.filename,
        "subject": cert.subject,
        "subject_cn": cert.subject_cn,
        "issuer": cert.issuer,
        "issuer_cn": cert.issuer_cn,
        "serial_number": cert.serial_number,
        "version": cert.version,
        "valid_from": cert.valid_from.isoformat(),
        "valid_until": cert.valid_until.isoformat(),
        "days_remaining": cert.days_remaining,
        "is_expired": cert.is_expired,
        "public_key_algorithm": cert.public_key_algorithm,
        "public_key_size": cert.public_key_size,
        "signature_algorithm": cert.signature_algorithm,
        "is_ca": cert.is_ca,
        "path_length": cert.path_length,
        "key_usage": json.loads(cert.key_usage or "[]"),
        "extended_key_usage": json.loads(cert.extended_key_usage or "[]"),
        "subject_alternative_names": json.loads(cert.subject_alternative_names or "[]"),
        "authority_key_identifier": cert.authority_key_identifier,
        "subject_key_identifier": cert.subject_key_identifier,
        "fingerprint_sha256": cert.fingerprint_sha256,
        "fingerprint_sha1": cert.fingerprint_sha1,
        "certificate_type": cert.certificate_type,
    }


@router.get("/{cert_id}/chain", summary="Get trust chain for a certificate")
async def get_chain(cert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(TrustChain).where(TrustChain.leaf_certificate_id == cert_id))
    chain_row = result.scalar_one_or_none()
    if not chain_row:
        raise HTTPException(status_code=404, detail="Chain not found — run analysis first")
    return {
        "status": chain_row.status,
        "chain": json.loads(chain_row.chain_json),
        "issues": json.loads(chain_row.issues_json),
        "validated_at": chain_row.validated_at.isoformat(),
    }


@router.get("/{cert_id}/analysis", summary="Get security analysis for a certificate")
async def get_analysis(cert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Certificate).where(Certificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    findings_q = await db.execute(select(Finding).where(Finding.certificate_id == cert_id))
    findings = findings_q.scalars().all()

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    overall_risk = "TRUSTED"
    if findings:
        top = min(findings, key=lambda f: severity_order.get(f.severity, 5))
        overall_risk = top.severity

    chain_q = await db.execute(select(TrustChain).where(TrustChain.leaf_certificate_id == cert_id))
    chain_row = chain_q.scalar_one_or_none()

    return {
        "certificate_cn": cert.subject_cn,
        "overall_risk": overall_risk,
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "finding_type": f.finding_type,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in sorted(findings, key=lambda f: severity_order.get(f.severity, 5))
        ],
        "chain": {
            "status": chain_row.status if chain_row else "unknown",
            "issues": json.loads(chain_row.issues_json) if chain_row else [],
        } if chain_row else None,
    }


@router.delete("/{cert_id}", summary="Delete a certificate")
async def delete_certificate(cert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Certificate).where(Certificate.id == cert_id))
    cert = result.scalar_one_or_none()
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    await db.delete(cert)
    await db.commit()
    return {"deleted": cert_id}
