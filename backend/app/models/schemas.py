"""
Pydantic models / schemas for the PKI Trust Chain Analyzer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


# ─── Certificate ─────────────────────────────────────────────────────────────

class CertificateInfo(BaseModel):
    filename: str = ""
    subject: str
    subject_cn: str
    issuer: str
    issuer_cn: str
    serial_number: str
    version: int
    valid_from: datetime
    valid_until: datetime
    is_expired: bool
    days_remaining: int
    public_key_algorithm: str
    public_key_size: int
    signature_algorithm: str
    signature_algorithm_oid: str
    is_ca: bool
    path_length: Optional[int]
    key_usage: list[str]
    extended_key_usage: list[str]
    subject_alternative_names: list[str]
    authority_key_identifier: Optional[str]
    subject_key_identifier: Optional[str]
    fingerprint_sha256: str
    fingerprint_sha1: str
    pem_data: str


class CertificateDB(BaseModel):
    id: int
    filename: str
    subject_cn: str
    issuer_cn: str
    serial_number: str
    fingerprint_sha256: str
    valid_from: datetime
    valid_until: datetime
    is_ca: bool
    certificate_type: str   # root | intermediate | leaf
    days_remaining: int
    is_expired: bool

    model_config = {"from_attributes": True}


# ─── Trust Chain ─────────────────────────────────────────────────────────────

class ChainLink(BaseModel):
    subject_cn: str
    issuer_cn: str
    certificate_type: str
    is_valid: bool


class TrustChainResult(BaseModel):
    leaf_cn: str
    chain: list[ChainLink]
    root_cn: Optional[str]
    is_complete: bool
    is_valid: bool
    issues: list[str]


# ─── Security Finding ────────────────────────────────────────────────────────

class SecurityFinding(BaseModel):
    finding_type: str
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str
    recommendation: str


class AnalysisResult(BaseModel):
    certificate_cn: str
    overall_risk: str
    findings: list[SecurityFinding]
    chain_result: Optional[TrustChainResult]


# ─── AI Analysis ─────────────────────────────────────────────────────────────

class AIAnalysisRequest(BaseModel):
    certificate_id: int
    question: Optional[str] = None


class AIAnalysisResponse(BaseModel):
    certificate_cn: str
    summary: str
    security_risks: str
    risk_impact: str
    remediation: str
    full_text: str


class ChatMessage(BaseModel):
    role: str   # user | assistant
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    certificate_context: Optional[dict[str, Any]] = None


class ChatResponse(BaseModel):
    reply: str


# ─── Dashboard ───────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total: int
    trusted: int
    warning: int
    critical: int
    expired: int
    expiring_soon: int
    by_ca: list[dict]
    by_status: list[dict]
    expiry_timeline: list[dict]
    risk_distribution: list[dict]


# ─── AI Service ──────────────────────────────────────────────────────────────

class AIService(BaseModel):
    id: int
    service_name: str
    domain: str
    certificate_id: Optional[int]
    status: str

    model_config = {"from_attributes": True}


# ─── Fault Injection ─────────────────────────────────────────────────────────

class FaultInjectionRequest(BaseModel):
    certificate_id: int
    fault_type: str   # expire | remove_intermediate | weak_key | break_chain | unknown_root


class FaultInjectionResult(BaseModel):
    original_status: str
    injected_fault: str
    new_status: str
    description: str
