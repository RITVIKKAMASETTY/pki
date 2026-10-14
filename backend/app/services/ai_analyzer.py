"""
AI Analyzer — Powered by Groq API for ultra-fast, high-accuracy PKI security analysis
and conversational assistant.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from ..models.schemas import AnalysisResult, AIAnalysisResponse, ChatMessage, ChatResponse

try:
    from openai import AsyncOpenAI
    _openai_available = True
except ImportError:
    _openai_available = False

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
PRIMARY_MODEL = os.getenv("AI_MODEL", "openai/gpt-oss-120b")
FALLBACK_MODEL = "qwen/qwen3.8-27b"


def _client() -> "AsyncOpenAI":
    return AsyncOpenAI(
        api_key=GROQ_API_KEY,
        base_url=GROQ_BASE_URL,
    )


SYSTEM_PROMPT = """You are an elite PKI (Public Key Infrastructure), TLS security, and cryptographic attack prevention expert specializing in X.509 certificates and AI service architectures.

Your core responsibilities:
1. Explain certificates, trust chains, issuers, and PKI hierarchy in plain language.
2. Summarize security risks: expired chains, weak cryptography, SAN mismatches, broken roots.
3. Explain impacts specifically for AI microservices, inference pipelines, training APIs, and model registries.
4. Provide clear, prioritized remediation steps for DevOps and Security engineers.

You are ALSO an expert in PKI-related attack prevention. When asked about attacks, always provide:
- A clear explanation of HOW the attack works against PKI/TLS
- WHICH certificate weaknesses enable this attack (e.g., expired cert, no cert pinning, weak key)
- CONCRETE prevention steps: specific configs, commands, certificate policies to deploy
- Detection signals: how to know if an attack has occurred or is in progress
- References to relevant standards (RFC 5280, NIST SP 800-57, CAB Forum Baseline Requirements)

Attack domains you cover:
- **Man-in-the-Middle (MitM)**: Certificate spoofing, proxy interception, SSL stripping
- **Certificate Spoofing & Forgery**: Rogue CA attacks, cross-signing abuse, typosquatting certs
- **Downgrade Attacks**: BEAST, POODLE, DROWN, FREAK — forcing weak cipher suites
- **OCSP Stapling attacks / CRL bypass**: Revocation evasion, soft-fail exploitation
- **BGP Hijacking + Certificate Misissuance**: Route hijacking to intercept domain validation
- **Private Key Compromise**: Key exfiltration, inadequate storage, HSM bypass
- **Certificate Pinning Bypass**: Dynamic code injection, pin extraction, APK manipulation
- **Replay Attacks**: Session token replay using stolen/expired certificates
- **Subdomain Takeover via Certificates**: Dangling DNS + cert reuse
- **mTLS Bypass**: Missing client cert validation, incorrect peer verification

Format responses with markdown tables, code blocks, and clear section headers for readability.
Be authoritative, concise, accurate, and practical."""


def _build_analysis_prompt(analysis: AnalysisResult) -> str:
    cert_cn = analysis.certificate_cn
    risk = analysis.overall_risk
    chain = analysis.chain_result

    chain_status = "Unknown"
    chain_issues = []
    root_cn = "Unknown"

    if chain:
        chain_status = "Valid" if chain.is_valid else ("Incomplete" if not chain.is_complete else "Invalid")
        chain_issues = chain.issues
        root_cn = chain.root_cn or "Not found"

    findings_text = ""
    for f in analysis.findings:
        findings_text += f"\n  [{f.severity}] {f.finding_type}: {f.description}"

    prompt = f"""Analyze this PKI certificate and generate a structured security audit report.

CERTIFICATE: {cert_cn}
OVERALL RISK LEVEL: {risk}

TRUST CHAIN:
  Status: {chain_status}
  Root CA: {root_cn}
  Issues: {'; '.join(chain_issues) if chain_issues else 'None'}

SECURITY FINDINGS:{findings_text if findings_text else chr(10) + '  No findings — certificate appears healthy and valid.'}

Please respond in this EXACT section format:
SUMMARY:
[2-3 sentence overview of this certificate, its role, and its current health]

SECURITY_RISKS:
[Detailed breakdown of identified vulnerabilities or certificate status risks]

RISK_IMPACT:
[Concrete impact on AI services (e.g. inference endpoint outages, pipeline auth failures)]

REMEDIATION:
[Step-by-step actionable remediation instructions to restore full trust]"""

    return prompt


async def generate_ai_analysis(analysis: AnalysisResult) -> AIAnalysisResponse:
    prompt = _build_analysis_prompt(analysis)
    cert_cn = analysis.certificate_cn

    if not GROQ_API_KEY or not _openai_available:
        return _fallback_analysis(analysis)

    client = _client()
    for model_name in [PRIMARY_MODEL, FALLBACK_MODEL]:
        try:
            response = await client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=1200,
            )
            full_text = response.choices[0].message.content or ""
            return _parse_structured_response(cert_cn, full_text)
        except Exception as e:
            print(f"Groq model {model_name} failed: {e}")
            continue

    return _fallback_analysis(analysis, error="Groq API models unavailable")


def _parse_structured_response(cert_cn: str, text: str) -> AIAnalysisResponse:
    sections = {"SUMMARY": "", "SECURITY_RISKS": "", "RISK_IMPACT": "", "REMEDIATION": ""}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        found_section = False
        for key in sections:
            if stripped.startswith(f"{key}:"):
                current = key
                rest = stripped[len(key)+1:].strip()
                if rest:
                    sections[key] += rest + "\n"
                found_section = True
                break
        if not found_section and current:
            sections[current] += line + "\n"

    return AIAnalysisResponse(
        certificate_cn=cert_cn,
        summary=sections["SUMMARY"].strip() or f"Audit summary for {cert_cn}",
        security_risks=sections["SECURITY_RISKS"].strip() or "No critical risks detected.",
        risk_impact=sections["RISK_IMPACT"].strip() or "Normal operations expected.",
        remediation=sections["REMEDIATION"].strip() or "Maintain standard certificate monitoring schedule.",
        full_text=text,
    )


def _fallback_analysis(analysis: AnalysisResult, error: str = "") -> AIAnalysisResponse:
    cert_cn = analysis.certificate_cn
    risk = analysis.overall_risk
    findings = analysis.findings

    if not findings:
        summary = f"The certificate for '{cert_cn}' appears healthy with no detected issues."
        risks = "No security risks detected."
        impact = "The AI service using this certificate should operate normally."
        remediation = "Continue monitoring the certificate validity and plan renewal before expiry."
    else:
        top = findings[0]
        summary = (f"The certificate for '{cert_cn}' has a risk level of {risk}. "
                   f"The most critical issue is: {top.finding_type} — {top.description}")
        risks = "\n".join(f"• [{f.severity}] {f.finding_type}: {f.description}" for f in findings)
        impact = (f"If left unaddressed, these issues could cause TLS handshake failures, "
                  f"service outages, or security vulnerabilities in AI services depending on "
                  f"'{cert_cn}'.")
        remediation = "\n".join(f"• {f.recommendation}" for f in findings)

    note = f"\n\n(AI analysis note: {error})" if error else ""
    return AIAnalysisResponse(
        certificate_cn=cert_cn,
        summary=summary + note,
        security_risks=risks,
        risk_impact=impact,
        remediation=remediation,
        full_text=summary + "\n\n" + risks + "\n\n" + impact + "\n\n" + remediation + note,
    )


async def ai_chat(
    messages: list[ChatMessage],
    cert_context: Optional[dict] = None,
) -> ChatResponse:
    """
    Conversational AI assistant for PKI questions powered by Groq.
    """
    context_block = ""
    if cert_context:
        context_block = f"\n\nCurrent PKI Environment & Certificate Context:\n{json.dumps(cert_context, indent=2, default=str)}"

    system = SYSTEM_PROMPT + context_block

    if not GROQ_API_KEY or not _openai_available:
        return ChatResponse(reply=_fallback_chat(messages))

    client = _client()
    oai_messages = [{"role": "system", "content": system}]
    for m in messages:
        oai_messages.append({"role": m.role, "content": m.content})

    for model_name in [PRIMARY_MODEL, FALLBACK_MODEL]:
        try:
            response = await client.chat.completions.create(
                model=model_name,
                messages=oai_messages,
                temperature=0.4,
                max_tokens=900,
            )
            reply = response.choices[0].message.content or ""
            if reply.strip():
                return ChatResponse(reply=reply)
        except Exception as e:
            print(f"Groq chat model {model_name} failed: {e}")
            continue

    return ChatResponse(reply=_fallback_chat(messages))


def _fallback_chat(messages: list[ChatMessage]) -> str:
    last = messages[-1].content.lower() if messages else ""
    if "expir" in last:
        return ("Certificates expire based on their Not After date. "
                "You should renew certificates at least 30 days before expiry. "
                "Check the dashboard 'Expiring Soon' panel for upcoming expirations.")
    if "chain" in last or "trust" in last:
        return ("A trust chain connects a leaf certificate → intermediate CA → root CA. "
                "If any link is missing or has an invalid signature, the chain is broken "
                "and TLS clients will reject the certificate.")
    if "risk" in last or "critical" in last:
        return ("Critical findings include: expired certificates, broken trust chains, "
                "unknown root CAs, and weak cryptographic keys. "
                "These should be remediated immediately.")
    return ("I'm your PKI security assistant. Ask me about certificates, trust chains, "
            "expiry, security risks, or specific AI services.")
