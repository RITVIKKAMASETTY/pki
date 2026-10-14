import React, { useEffect, useState } from 'react';
import { api, Certificate, AnalysisResult, Finding } from '../../services/api';

interface FindingWithCert extends Finding {
  certId: number;
  certCN: string;
  certType: string;
}

interface Props {
  onSelectCert?: (id: number) => void;
}

export function RiskPanel({ onSelectCert }: Props) {
  const [findings, setFindings] = useState<FindingWithCert[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [search, setSearch] = useState('');

  useEffect(() => {
    async function loadAllFindings() {
      setLoading(true);
      try {
        const certs = await api.certificates();
        const allFindings: FindingWithCert[] = [];
        
        await Promise.all(
          certs.map(async (cert) => {
            try {
              const analysis: AnalysisResult = await api.analysis(cert.id);
              if (analysis && analysis.findings) {
                analysis.findings.forEach(f => {
                  allFindings.push({
                    ...f,
                    certId: cert.id,
                    certCN: cert.subject_cn,
                    certType: cert.certificate_type,
                  });
                });
              }
            } catch {
              // skip errors for single cert analysis
            }
          })
        );

        // Sort by severity priority: CRITICAL > HIGH > MEDIUM > LOW > INFO
        const severityRank: Record<string, number> = {
          CRITICAL: 5,
          HIGH: 4,
          MEDIUM: 3,
          LOW: 2,
          INFO: 1,
        };
        allFindings.sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0));

        setFindings(allFindings);
      } catch (err) {
        console.error('Failed to load risk findings', err);
      } finally {
        setLoading(false);
      }
    }

    loadAllFindings();
  }, []);

  const counts = {
    ALL: findings.length,
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
    INFO: findings.filter(f => f.severity === 'INFO').length,
  };

  const filtered = findings.filter(f => {
    const matchSev = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
    const matchSearch =
      f.certCN.toLowerCase().includes(search.toLowerCase()) ||
      f.finding_type.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase());
    return matchSev && matchSearch;
  });

  return (
    <div className="page-content">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)' }}>
            🛡 Security & Risk Intelligence
          </h2>
          <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            Deep analysis of cryptographic strength, trust chain posture, expiry exposures, and compliance risks.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <span className="risk-badge risk-CRITICAL">{counts.CRITICAL} Critical</span>
          <span className="risk-badge risk-HIGH">{counts.HIGH} High</span>
          <span className="risk-badge risk-MEDIUM">{counts.MEDIUM} Medium</span>
          <span className="risk-badge risk-LOW">{counts.LOW} Low</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '14px 20px' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map(sev => (
              <button
                key={sev}
                className={`btn btn-sm ${selectedSeverity === sev ? 'btn-primary' : 'btn-ghost'}`}
                onClick={() => setSelectedSeverity(sev)}
                style={{ textTransform: 'capitalize' }}
              >
                {sev} ({counts[sev]})
              </button>
            ))}
          </div>

          <div style={{ marginLeft: 'auto', minWidth: 260 }}>
            <input
              type="text"
              placeholder="Search findings, types, or services..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="chat-input"
              style={{ width: '100%', padding: '6px 12px', fontSize: 12 }}
            />
          </div>
        </div>
      </div>

      {/* Findings List */}
      {loading ? (
        <div className="card" style={{ textAlign: 'center', padding: 50, color: 'var(--text-muted)' }}>
          <div className="spin" style={{ display: 'inline-block', fontSize: 28, marginBottom: 12 }}>⟳</div>
          <div>Auditing certificate security posture & findings…</div>
        </div>
      ) : filtered.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: 50, color: 'var(--text-muted)' }}>
          <div style={{ fontSize: 32, marginBottom: 8 }}>🎉</div>
          <div>No findings match the selected criteria.</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filtered.map((item, idx) => (
            <div
              key={`${item.certId}-${item.finding_type}-${idx}`}
              className={`finding-card finding-${item.severity}`}
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--r-md)',
                padding: '16px 20px',
                transition: 'all 0.15s ease',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span className={`risk-badge risk-${item.severity}`}>
                    {item.severity}
                  </span>
                  <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>
                    {item.finding_type.replace(/_/g, ' ')}
                  </span>
                </div>

                <button
                  className="btn btn-ghost btn-sm"
                  style={{ fontSize: 11, cursor: 'pointer' }}
                  onClick={() => onSelectCert && onSelectCert(item.certId)}
                >
                  Inspect {item.certCN} →
                </button>
              </div>

              <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 10, lineHeight: 1.5 }}>
                {item.description}
              </p>

              <div style={{
                background: 'var(--bg-1)',
                borderLeft: '3px solid var(--accent)',
                padding: '10px 14px',
                borderRadius: 'var(--r-sm)',
                fontSize: 12,
                color: 'var(--text-primary)'
              }}>
                <strong style={{ color: 'var(--accent)' }}>Remediation: </strong>
                {item.recommendation}
              </div>

              <div style={{ marginTop: 10, display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-muted)' }}>
                <span>Subject: <strong style={{ color: 'var(--text-secondary)' }}>{item.certCN}</strong></span>
                <span>Type: <strong style={{ color: 'var(--text-secondary)' }}>{item.certType}</strong></span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
