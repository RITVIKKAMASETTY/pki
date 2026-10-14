"""
FastAPI application entry point.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database.models import init_db, AsyncSessionLocal, Certificate, AIServiceRecord
from .api.certificates import router as cert_router, _store_cert, _run_analysis, _get_all_cert_infos
from .api.dashboard import (
    dashboard_router, ai_router, services_router, graph_router, fault_router
)
from .services.certificate_parser import parse_certificate

DATASET_DIR = Path(__file__).parent.parent.parent / "dataset"

AI_SERVICES = [
    {"service_name": "Inference API",    "domain": "inference.ai.company.com"},
    {"service_name": "Model Registry",   "domain": "models.ai.company.com"},
    {"service_name": "Training API",     "domain": "training.ai.company.com"},
    {"service_name": "Vector Database",  "domain": "vector.ai.company.com"},
    {"service_name": "Monitoring",       "domain": "monitoring.ai.company.com"},
    {"service_name": "Data Pipeline",    "domain": "data-pipeline.ai.company.com"},
    {"service_name": "Feature Store",    "domain": "feature-store.ai.company.com"},
    {"service_name": "Orchestrator API", "domain": "orchestrator.ai.company.com"},
    {"service_name": "Legacy API",       "domain": "legacy.ai.company.com"},
]


async def _seed_database():
    """Load all PEM files from the dataset directory into the database."""
    async with AsyncSessionLocal() as db:
        # Gather PEM files
        pem_files = []
        for subdir in ("roots", "intermediates", "leaf"):
            folder = DATASET_DIR / subdir
            if folder.exists():
                for f in sorted(folder.iterdir()):
                    if f.suffix in (".pem", ".crt", ".cer"):
                        pem_files.append((str(f), f"{subdir}/{f.name}"))

        stored_rows = []
        for filepath, label in pem_files:
            try:
                pem_data = Path(filepath).read_bytes()
                info = parse_certificate(pem_data, filename=label)
                # Set certificate_type correctly before storing
                if info.is_ca and info.subject_cn == info.issuer_cn:
                    cert_type = "root"
                elif info.is_ca:
                    cert_type = "intermediate"
                else:
                    cert_type = "leaf"

                from .database.models import Certificate as CertModel
                from sqlalchemy import select
                existing = await db.execute(
                    select(CertModel).where(CertModel.fingerprint_sha256 == info.fingerprint_sha256)
                )
                row = existing.scalar_one_or_none()
                if not row:
                    row = CertModel(
                        filename=label,
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
                stored_rows.append((row, info))
                print(f"  Loaded: {label}")
            except Exception as e:
                print(f"  WARN: {label} — {e}")

        await db.commit()

        # Run analysis for all certs
        all_infos = await _get_all_cert_infos(db)
        from sqlalchemy import select
        from .database.models import Certificate as CertModel
        all_q = await db.execute(select(CertModel))
        all_certs = all_q.scalars().all()
        for cert_row in all_certs:
            await _run_analysis(db, cert_row, all_infos)
        await db.commit()

        # Seed AI services
        from sqlalchemy import select
        from .database.models import AIServiceRecord as SvcModel
        existing_svc = await db.execute(select(SvcModel))
        if not existing_svc.scalars().all():
            for svc in AI_SERVICES:
                # Link to cert by domain CN
                cert_q = await db.execute(
                    select(CertModel).where(CertModel.subject_cn == svc["domain"])
                )
                cert = cert_q.scalar_one_or_none()
                db.add(SvcModel(
                    service_name=svc["service_name"],
                    domain=svc["domain"],
                    certificate_id=cert.id if cert else None,
                    status="active",
                ))
            await db.commit()

        print("Database seeded successfully.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await _seed_database()
    yield


app = FastAPI(
    title="PKI Trust Chain Analyzer",
    description="X.509 certificate analysis platform for AI services",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(cert_router)
app.include_router(dashboard_router)
app.include_router(ai_router)
app.include_router(services_router)
app.include_router(graph_router)
app.include_router(fault_router)


@app.get("/", tags=["root"])
async def root():
    return {"message": "PKI Trust Chain Analyzer API", "version": "1.0.0", "docs": "/docs"}
