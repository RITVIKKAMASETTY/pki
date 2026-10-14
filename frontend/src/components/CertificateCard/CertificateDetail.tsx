import React, { useEffect, useState } from 'react';
import { api, type CertificateDetail as CertDetailType, ChainResult, AnalysisResult, AIAnalysis } from '../../services/api';
import { MarkdownView } from '../MarkdownView';

interface Props {
  certId: number;
  onClose?: () => void;
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="detail-row">
      <div className="detail-label">{label}</div>
      <div className="detail-value">{value}</div>
    </div>
  );
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export function CertificateDetail({ certId, onClose }: Props) {
  const [cert, setCert] = useState<CertDetailType | null>(null);
  const [chain, setChain] = useState<ChainResult | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [tab, setTab] = useState<'details' | 'chain' | 'analysis' | 'ai'>('details');

  useEffect(() => {
    setCert(null); setChain(null); setAnalysis(null); setAiAnalysis(null);
    Promise.all([
      api.certificate(certId),
      api.chain(certId).catch(() => null),
      api.analysis(certId),
    ]).then(([c, ch, a]) => {
      setCert(c); setChain(ch as ChainResult | null); setAnalysis(a);
    });
  }, [certId]);

  const handleAIAnalyze = async () => {
    setAiLoading(true);
    try {
      const ai = await api.aiAnalyze(certId);
      setAiAnalysis(ai);
      setTab('ai');
    } finally {
      setAiLoading(false);
    }
  };

  if (!cert) return (
    <div className="card" style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>
      <div className="spin" style={{ display: 'inline-block', fontSize: 24, marginBottom: 8 }}>⟳</div>
      <div>Loading…</div>
    </div>
  );

  const riskClass = analysis?.overall_risk ?? 'TRUSTED';

  return (
    <div className="card fade-in-up" style={{ padding: 0, overflow: 'hidden' }}>
      {/* Header */}
      <div style={{
        padding: '18px 20px',
        background: 'var(--bg-2)',
        borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'flex-start', gap: 14,
      }}>
        <div style={{
          width: 40, height: 40, borderRadius: 'var(--r-md)',
          background: `conic-gradient(from 0deg, var(--accent), var(--accent-2))`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 18, flexShrink: 0,
        }}>
          {cert.is_ca ? '🏛' : '📜'}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {cert.subject_cn}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
            Issued by: {cert.issuer_cn}
          </div>
        </div>
        <span className={`risk-badge risk-${riskClass}`}>{riskClass}</span>
        {onClose && (
          <button className="btn btn-ghost btn-sm" onClick={onClose} style={{ padding: '4px 8px' }}>✕</button>
        )}
      </div>

      {/* Tabs */}
      <div style={{
        display: 'flex', gap: 0, borderBottom: '1px solid var(--border)',
        background: 'var(--bg-1)',
      }}>
        {[
          { key: 'details', label: '📋 Details' },
          { key: 'chain',    label: '🔗 Trust Chain' },
          { key: 'analysis', label: `🛡 Analysis ${analysis?.findings?.length ? `(${analysis.findings.length})` : ''}` },
          { key: 'ai',       label: '🤖 AI Report' },
        ].map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key as typeof tab)}
            style={{
              padding: '10px 16px', border: 'none',
              background: tab === t.key ? '#fef9c3' : 'transparent',
              color: tab === t.key ? '#854d0e' : 'var(--text-muted)',
              fontWeight: tab === t.key ? 700 : 500,
              borderBottom: tab === t.key ? '3px solid #eab308' : '3px solid transparent',
              cursor: 'pointer', fontSize: 12, transition: 'all 0.15s',
            }}
          >
            {t.label}
          </button>
        ))}
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', padding: '0 12px' }}>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleAIAnalyze}
            disabled={aiLoading}
          >
            {aiLoading ? <span className="spin">⟳</span> : '✨'} AI Analyze
          </button>
        </div>
      </div>

      {/* Tab content */}
      <div style={{ padding: 20, maxHeight: 'calc(100vh - 350px)', overflowY: 'auto' }}>

        {tab === 'details' && (
          <>
            <Row label="Subject" value={cert.subject} />
            <Row label="Issuer" value={cert.issuer} />
            <Row label="Serial Number" value={cert.serial_number} />
            <Row label="Version" value={`v${cert.version}`} />
            <Row label="Valid From" value={formatDate(cert.valid_from)} />
            <Row label="Valid Until" value={
              <span style={{ color: cert.is_expired ? 'var(--critical)' : cert.days_remaining <= 30 ? 'var(--warning)' : 'var(--trusted)' }}>
                {formatDate(cert.valid_until)} ({cert.is_expired ? `expired ${Math.abs(cert.days_remaining)}d ago` : `${cert.days_remaining}d left`})
              </span>
            } />
            <Row label="Public Key" value={`${cert.public_key_algorithm} ${cert.public_key_size}-bit`} />
            <Row label="Signature Algo" value={cert.signature_algorithm} />
            <Row label="Is CA" value={cert.is_ca ? `Yes (path_length=${cert.path_length ?? '∞'})` : 'No'} />
            {cert.key_usage.length > 0 && <Row label="Key Usage" value={cert.key_usage.join(', ')} />}
            {cert.extended_key_usage.length > 0 && <Row label="Ext. Key Usage" value={cert.extended_key_usage.join(', ')} />}
            {cert.subject_alternative_names.length > 0 && (
              <Row label="SANs" value={
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {cert.subject_alternative_names.map(s => (
                    <span key={s} style={{ background: 'var(--bg-3)', padding: '2px 6px', borderRadius: 4, fontSize: 11 }}>{s}</span>
                  ))}
                </div>
              } />
            )}
            {cert.subject_key_identifier && <Row label="SKI" value={cert.subject_key_identifier} />}
            {cert.authority_key_identifier && <Row label="AKI" value={cert.authority_key_identifier} />}
            <Row label="SHA-256 Fingerprint" value={cert.fingerprint_sha256} />
            <Row label="SHA-1 Fingerprint" value={cert.fingerprint_sha1} />
          </>
        )}

        {tab === 'chain' && (
          chain ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                <span className={`risk-badge risk-${chain.status === 'valid' ? 'TRUSTED' : 'CRITICAL'}`}>
                  {chain.status.toUpperCase()}
                </span>
                {chain.issues.length > 0 && (
                  <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{chain.issues.length} issue(s)</span>
                )}
              </div>

              <div className="chain-path">
                {chain.chain.map((link, i) => (
                  <React.Fragment key={i}>
                    <div className={`chain-node ${link.is_valid ? 'valid' : 'invalid'}`}>
                      <div style={{
                        width: 28, height: 28, borderRadius: 6,
                        background: link.is_valid ? 'var(--trusted-bg)' : 'var(--critical-bg)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14,
                        border: `1px solid ${link.is_valid ? 'var(--trusted-border)' : 'var(--critical-border)'}`,
                      }}>
                        {link.certificate_type === 'root' ? '🏛' : link.certificate_type === 'intermediate' ? '🔑' : '📜'}
                      </div>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                          {link.subject_cn}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {link.certificate_type} · {link.is_valid ? '✓ Valid' : '✕ Invalid/Expired'}
                        </div>
                      </div>
                    </div>
                    {i < chain.chain.length - 1 && <div className="chain-arrow" />}
                  </React.Fragment>
                ))}
              </div>

              {chain.issues.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--critical)', marginBottom: 8 }}>
                    Chain Issues:
                  </div>
                  {chain.issues.map((issue, i) => (
                    <div key={i} style={{
                      padding: '8px 12px', marginBottom: 6, borderRadius: 'var(--r-sm)',
                      background: 'var(--critical-bg)', border: '1px solid var(--critical-border)',
                      fontSize: 12, color: 'var(--critical)',
                    }}>
                      {issue}
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Chain data not available.</div>
          )
        )}

        {tab === 'analysis' && (
          analysis ? (
            <>
              <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 10 }}>
                <span>Overall Risk:</span>
                <span className={`risk-badge risk-${analysis.overall_risk}`}>{analysis.overall_risk}</span>
              </div>
              {analysis.findings.length === 0 ? (
                <div style={{
                  padding: '20px', borderRadius: 'var(--r-md)',
                  background: 'var(--trusted-bg)', border: '1px solid var(--trusted-border)',
                  color: 'var(--trusted)', fontSize: 13, textAlign: 'center',
                }}>
                  ✓ No security findings — certificate appears healthy.
                </div>
              ) : (
                analysis.findings.map((f, i) => (
                  <div key={i} className={`finding-card finding-${f.severity}`}>
                    <div className="finding-type">
                      <span className={`risk-badge risk-${f.severity}`} style={{ marginRight: 8 }}>{f.severity}</span>
                      {f.finding_type}
                    </div>
                    <div className="finding-desc">{f.description}</div>
                    <div className="finding-rec">💡 {f.recommendation}</div>
                  </div>
                ))
              )}
            </>
          ) : (
            <div style={{ color: 'var(--text-muted)' }}>Analysis loading…</div>
          )
        )}

        {tab === 'ai' && (
          aiAnalysis ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="card" style={{ padding: 18 }}>
                <div className="card-title">📋 Executive Summary</div>
                <MarkdownView content={aiAnalysis.summary} />
              </div>
              <div className="card" style={{ padding: 18 }}>
                <div className="card-title">⚠ Security Risks</div>
                <MarkdownView content={aiAnalysis.security_risks} />
              </div>
              <div className="card" style={{ padding: 18 }}>
                <div className="card-title">💥 AI Service Impact</div>
                <MarkdownView content={aiAnalysis.risk_impact} />
              </div>
              <div className="card" style={{ padding: 18 }}>
                <div className="card-title">🔧 Prioritized Remediation</div>
                <MarkdownView content={aiAnalysis.remediation} />
              </div>
            </div>
          ) : (
            <div style={{
              textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)',
            }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>🤖</div>
              <div style={{ fontSize: 13 }}>Click "AI Analyze" to generate an AI-powered security report for this certificate.</div>
            </div>
          )
        )}
      </div>
    </div>
  );
}
