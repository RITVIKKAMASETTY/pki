"""
Dashboard, AI analysis, services, and graph APIs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from ..database.models import Certificate, Finding, TrustChain, AIServiceRecord, get_db
from ..services.certificate_parser import parse_certificate
from ..services.chain_builder import build_chain
from ..services.security_analyzer import analyze
from ..services.ai_analyzer import generate_ai_analysis, ai_chat
from ..models.schemas import (
    AnalysisResult, TrustChainResult, ChainLink, SecurityFinding,
    ChatRequest, ChatResponse, AIAnalysisResponse, CertificateInfo
)

dashboard_router = APIRouter(prefix="/dashboard", tags=["dashboard"])
ai_router       = APIRouter(prefix="/ai", tags=["ai"])
services_router = APIRouter(prefix="/services", tags=["services"])
graph_router    = APIRouter(prefix="/graph", tags=["graph"])
fault_router    = APIRouter(prefix="/fault", tags=["fault"])


# ─── Dashboard ────────────────────────────────────────────────────────────────

@dashboard_router.get("", summary="Dashboard statistics")
async def get_dashboard(db: AsyncSession = Depends(get_db)):
    now = datetime.utcnow()  # naive, consistent with SQLite storage

    certs_q = await db.execute(select(Certificate))
    certs = certs_q.scalars().all()
    total = len(certs)

    findings_q = await db.execute(select(Finding))
    all_findings = findings_q.scalars().all()

    # Map cert_id -> worst severity
    cert_risk: dict[int, str] = {}
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for f in all_findings:
        cur = cert_risk.get(f.certificate_id, "TRUSTED")
        if sev_order.get(f.severity, 5) < sev_order.get(cur, 99):
            cert_risk[f.certificate_id] = f.severity

    trusted  = sum(1 for c in certs if cert_risk.get(c.id, "TRUSTED") == "TRUSTED")
    critical = sum(1 for c in certs if cert_risk.get(c.id) in ("CRITICAL",))
    high     = sum(1 for c in certs if cert_risk.get(c.id) in ("HIGH",))
    warning  = sum(1 for c in certs if cert_risk.get(c.id) in ("MEDIUM", "LOW", "INFO"))
    expired  = sum(1 for c in certs if c.is_expired)
    expiring = sum(1 for c in certs if not c.is_expired and 0 < c.days_remaining <= 30)

    # By CA
    ca_map: dict[str, int] = {}
    for c in certs:
        ca_map[c.issuer_cn] = ca_map.get(c.issuer_cn, 0) + 1
    by_ca = [{"ca": k, "count": v} for k, v in sorted(ca_map.items(), key=lambda x: -x[1])]

    # By status
    by_status = [
        {"status": "Trusted",  "count": trusted},
        {"status": "Critical", "count": critical},
        {"status": "High",     "count": high},
        {"status": "Warning",  "count": warning},
        {"status": "Expired",  "count": expired},
    ]

    # Expiry timeline (next 12 months, by month)
    timeline_map: dict[str, int] = {}
    for c in certs:
        vu = c.valid_until.replace(tzinfo=None) if c.valid_until.tzinfo else c.valid_until
        if not c.is_expired and vu > now:
            key = c.valid_until.strftime("%b %Y")
            timeline_map[key] = timeline_map.get(key, 0) + 1
    expiry_timeline = [{"month": k, "count": v} for k, v in sorted(
        timeline_map.items(), key=lambda x: datetime.strptime(x[0], "%b %Y")
    )[:12]]

    # Risk distribution
    risk_dist_map: dict[str, int] = {}
    for cid in [c.id for c in certs]:
        r = cert_risk.get(cid, "TRUSTED")
        risk_dist_map[r] = risk_dist_map.get(r, 0) + 1
    risk_dist = [{"risk": k, "count": v} for k, v in risk_dist_map.items()]

    return {
        "total": total,
        "trusted": trusted,
        "warning": warning + high,
        "critical": critical,
        "expired": expired,
        "expiring_soon": expiring,
        "by_ca": by_ca,
        "by_status": by_status,
        "expiry_timeline": expiry_timeline,
        "risk_distribution": risk_dist,
    }


# ─── Graph ───────────────────────────────────────────────────────────────────

@graph_router.get("", summary="Trust graph nodes and edges for React Flow")
async def get_graph(db: AsyncSession = Depends(get_db)):
    certs_q = await db.execute(select(Certificate))
    certs = certs_q.scalars().all()

    findings_q = await db.execute(select(Finding))
    all_findings = findings_q.scalars().all()
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    cert_risk: dict[int, str] = {}
    for f in all_findings:
        cur = cert_risk.get(f.certificate_id, "TRUSTED")
        if sev_order.get(f.severity, 5) < sev_order.get(cur, 99):
            cert_risk[f.certificate_id] = f.severity

    # Position certs in layers
    roots = [c for c in certs if c.certificate_type == "root"]
    ints  = [c for c in certs if c.certificate_type == "intermediate"]
    leaves = [c for c in certs if c.certificate_type == "leaf"]

    nodes = []

    def node_color(cid):
        r = cert_risk.get(cid, "TRUSTED")
        return {
            "TRUSTED": "#22c55e",
            "INFO":    "#fde047",
            "LOW":     "#84cc16",
            "MEDIUM":  "#f59e0b",
            "HIGH":    "#f97316",
            "CRITICAL":"#ef4444",
        }.get(r, "#6b7280")

    # Roots — row 0
    for i, c in enumerate(roots):
        nodes.append({
            "id": str(c.id),
            "type": "certNode",
            "data": {
                "label": c.subject_cn,
                "certType": c.certificate_type,
                "risk": cert_risk.get(c.id, "TRUSTED"),
                "expired": c.is_expired,
                "daysRemaining": c.days_remaining,
                "color": node_color(c.id),
                "certId": c.id,
            },
            "position": {"x": 300 + i * 400, "y": 50},
        })

    # Intermediates — row 1
    for i, c in enumerate(ints):
        nodes.append({
            "id": str(c.id),
            "type": "certNode",
            "data": {
                "label": c.subject_cn,
                "certType": c.certificate_type,
                "risk": cert_risk.get(c.id, "TRUSTED"),
                "expired": c.is_expired,
                "daysRemaining": c.days_remaining,
                "color": node_color(c.id),
                "certId": c.id,
            },
            "position": {"x": 100 + i * 300, "y": 250},
        })

    # Leaves — row 2
    for i, c in enumerate(leaves):
        nodes.append({
            "id": str(c.id),
            "type": "certNode",
            "data": {
                "label": c.subject_cn,
                "certType": c.certificate_type,
                "risk": cert_risk.get(c.id, "TRUSTED"),
                "expired": c.is_expired,
                "daysRemaining": c.days_remaining,
                "color": node_color(c.id),
                "certId": c.id,
            },
            "position": {"x": 50 + i * 210, "y": 480},
        })

    # Build edges using issuer/subject matching
    cn_to_id = {c.subject_cn: str(c.id) for c in certs}
    edges = []
    seen_edges: set[tuple[str, str]] = set()
    for c in certs:
        if c.subject_cn == c.issuer_cn:
            continue  # self-signed, no edge needed
        parent_id = cn_to_id.get(c.issuer_cn)
        if parent_id and (parent_id, str(c.id)) not in seen_edges:
            seen_edges.add((parent_id, str(c.id)))
            edges.append({
                "id": f"e{parent_id}-{c.id}",
                "source": parent_id,
                "target": str(c.id),
                "animated": cert_risk.get(c.id, "TRUSTED") in ("CRITICAL", "HIGH"),
                "style": {"stroke": node_color(c.id), "strokeWidth": 2},
            })

    return {"nodes": nodes, "edges": edges}


# ─── AI Analysis ─────────────────────────────────────────────────────────────

@ai_router.post("/analyze/{certificate_id}", summary="AI analysis of a certificate")
async def ai_analyze(certificate_id: int, db: AsyncSession = Depends(get_db)):
    cert_q = await db.execute(select(Certificate).where(Certificate.id == certificate_id))
    cert = cert_q.scalar_one_or_none()
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    findings_q = await db.execute(select(Finding).where(Finding.certificate_id == certificate_id))
    findings_rows = findings_q.scalars().all()
    chain_q = await db.execute(select(TrustChain).where(TrustChain.leaf_certificate_id == certificate_id))
    chain_row = chain_q.scalar_one_or_none()

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    overall = "TRUSTED"
    if findings_rows:
        top = min(findings_rows, key=lambda f: sev_order.get(f.severity, 5))
        overall = top.severity

    chain_result = None
    if chain_row:
        links = [ChainLink(**l) for l in json.loads(chain_row.chain_json)]
        chain_result = TrustChainResult(
            leaf_cn=cert.subject_cn,
            chain=links,
            root_cn=None,
            is_complete=chain_row.status != "incomplete",
            is_valid=chain_row.status == "valid",
            issues=json.loads(chain_row.issues_json),
        )

    findings = [
        SecurityFinding(
            finding_type=f.finding_type,
            severity=f.severity,
            description=f.description,
            recommendation=f.recommendation,
        )
        for f in findings_rows
    ]

    analysis = AnalysisResult(
        certificate_cn=cert.subject_cn,
        overall_risk=overall,
        findings=findings,
        chain_result=chain_result,
    )

    response = await generate_ai_analysis(analysis)
    return response.model_dump()


@ai_router.post("/chat", summary="AI PKI assistant chat")
async def chat(request: ChatRequest, db: AsyncSession = Depends(get_db)):
    # Build context from all certs + findings
    context = None
    if request.certificate_context:
        context = request.certificate_context
    else:
        # Provide a summary of the PKI state
        certs_q = await db.execute(select(Certificate))
        certs = certs_q.scalars().all()
        findings_q = await db.execute(select(Finding))
        findings = findings_q.scalars().all()
        context = {
            "total_certificates": len(certs),
            "expired": sum(1 for c in certs if c.is_expired),
            "expiring_soon": sum(1 for c in certs if not c.is_expired and 0 < c.days_remaining <= 30),
            "critical_findings": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high_findings": sum(1 for f in findings if f.severity == "HIGH"),
            "certificates": [
                {"cn": c.subject_cn, "type": c.certificate_type,
                 "days_remaining": c.days_remaining, "expired": c.is_expired}
                for c in certs[:20]
            ]
        }

    result = await ai_chat(request.messages, context)
    return result.model_dump()


# ─── AI Services ─────────────────────────────────────────────────────────────

@services_router.get("", summary="List AI services")
async def list_services(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AIServiceRecord))
    services = result.scalars().all()
    out = []
    for s in services:
        cert_info = None
        if s.certificate_id:
            cert_q = await db.execute(select(Certificate).where(Certificate.id == s.certificate_id))
            cert = cert_q.scalar_one_or_none()
            if cert:
                cert_info = {
                    "id": cert.id,
                    "subject_cn": cert.subject_cn,
                    "days_remaining": cert.days_remaining,
                    "is_expired": cert.is_expired,
                }
        out.append({
            "id": s.id,
            "service_name": s.service_name,
            "domain": s.domain,
            "status": s.status,
            "certificate": cert_info,
        })
    return out


# ─── Fault Injection ─────────────────────────────────────────────────────────

@fault_router.get("/scenarios", summary="List available fault scenarios")
async def fault_scenarios():
    return [
        {"type": "expire",            "label": "Expire Certificate",    "severity": "CRITICAL"},
        {"type": "weak_key",          "label": "Weak Key (512-bit)",     "severity": "HIGH"},
        {"type": "break_chain",       "label": "Break Trust Chain",      "severity": "CRITICAL"},
        {"type": "san_mismatch",      "label": "SAN Hostname Mismatch",  "severity": "HIGH"},
        {"type": "unknown_root",      "label": "Unknown Root CA",        "severity": "CRITICAL"},
    ]
