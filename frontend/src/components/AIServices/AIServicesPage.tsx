import React, { useEffect, useState } from 'react';
import { api, AIService } from '../../services/api';

interface Props {
  onSelectCert?: (id: number) => void;
}

export function AIServicesPage({ onSelectCert }: Props) {
  const [services, setServices] = useState<AIService[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.services()
      .then(data => {
        setServices(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const getStatusBadge = (svc: AIService) => {
    if (!svc.certificate) {
      return <span className="risk-badge risk-HIGH">No Certificate</span>;
    }
    if (svc.certificate.is_expired) {
      return <span className="risk-badge risk-CRITICAL">Service At Risk (Expired)</span>;
    }
    if (svc.certificate.days_remaining <= 30) {
      return <span className="risk-badge risk-MEDIUM">Expiring Soon ({svc.certificate.days_remaining}d)</span>;
    }
    return <span className="risk-badge risk-TRUSTED">Healthy</span>;
  };

  return (
    <div className="page-content">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)' }}>
            🤖 AI Service Mesh & Certificate Health
          </h2>
          <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            Real-time PKI TLS/mTLS certificate binding for core AI microservices and pipelines.
          </p>
        </div>
      </div>

      {loading ? (
        <div className="card" style={{ textAlign: 'center', padding: 50, color: 'var(--text-muted)' }}>
          <div className="spin" style={{ display: 'inline-block', fontSize: 28, marginBottom: 12 }}>⟳</div>
          <div>Loading AI services…</div>
        </div>
      ) : (
        <div className="grid-3" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 16 }}>
          {services.map(svc => (
            <div
              key={svc.id}
              className="card"
              style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                padding: '20px',
                position: 'relative',
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                  <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)' }}>
                    {svc.service_name}
                  </h3>
                  {getStatusBadge(svc)}
                </div>

                <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--cyan)', marginBottom: 14 }}>
                  {svc.domain}
                </div>

                <div style={{
                  background: 'var(--bg-2)',
                  borderRadius: 'var(--r-sm)',
                  padding: '10px 12px',
                  fontSize: 12,
                  marginBottom: 16,
                  border: '1px solid var(--border)'
                }}>
                  {svc.certificate ? (
                    <>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                        <span style={{ color: 'var(--text-muted)' }}>Bound Certificate:</span>
                        <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 500 }}>
                          {svc.certificate.subject_cn}
                        </span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Validity:</span>
                        <span style={{
                          fontWeight: 700,
                          color: svc.certificate.is_expired ? 'var(--critical)' : svc.certificate.days_remaining <= 30 ? 'var(--warning)' : 'var(--trusted)'
                        }}>
                          {svc.certificate.is_expired ? 'EXPIRED' : `${svc.certificate.days_remaining} days left`}
                        </span>
                      </div>
                    </>
                  ) : (
                    <span style={{ color: 'var(--critical)' }}>No certificate mapped to this service</span>
                  )}
                </div>
              </div>

              {svc.certificate && onSelectCert && (
                <button
                  className="btn btn-ghost btn-sm"
                  style={{ width: '100%', justifyContent: 'center' }}
                  onClick={() => onSelectCert(svc.certificate!.id)}
                >
                  View Certificate Chain & Audit →
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
