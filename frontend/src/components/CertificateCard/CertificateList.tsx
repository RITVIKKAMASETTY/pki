import React, { useEffect, useState } from 'react';
import { api, Certificate } from '../../services/api';

interface Props {
  onSelectCert: (id: number) => void;
  selectedId?: number;
}

const TYPE_LABELS: Record<string, string> = {
  root: 'Root CA',
  intermediate: 'Intermediate',
  leaf: 'Leaf',
};

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function DaysIndicator({ days, expired }: { days: number; expired: boolean }) {
  if (expired) return <span style={{ color: 'var(--critical)', fontWeight: 700, fontSize: 12 }}>Expired</span>;
  if (days <= 7)  return <span style={{ color: 'var(--critical)', fontWeight: 700, fontSize: 12 }}>{days}d</span>;
  if (days <= 30) return <span style={{ color: 'var(--warning)', fontWeight: 700, fontSize: 12 }}>{days}d</span>;
  return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{days}d</span>;
}

export function CertificateList({ onSelectCert, selectedId }: Props) {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [uploading, setUploading] = useState(false);

  const load = () => {
    setLoading(true);
    api.certificates().then(c => { setCerts(c); setLoading(false); }).catch(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const filtered = certs.filter(c => {
    const matchType = filter === 'all' || c.certificate_type === filter;
    const matchSearch = c.subject_cn.toLowerCase().includes(search.toLowerCase()) ||
                        c.issuer_cn.toLowerCase().includes(search.toLowerCase());
    return matchType && matchSearch;
  });

  const handleUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setUploading(true);
    await api.uploadCerts(Array.from(files));
    setUploading(false);
    load();
  };

  return (
    <div className="page-content">
      {/* Controls */}
      <div className="card" style={{ padding: '14px 20px' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            className="chat-input"
            style={{ maxWidth: 260, padding: '7px 12px' }}
            placeholder="🔍 Search certificates…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          {(['all', 'root', 'intermediate', 'leaf'] as const).map(t => (
            <button
              key={t} className={`btn ${filter === t ? 'btn-primary btn-sm' : 'btn-ghost btn-sm'}`}
              onClick={() => setFilter(t)}
            >
              {t === 'all' ? 'All' : TYPE_LABELS[t]}
            </button>
          ))}
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <label className="btn btn-ghost btn-sm" style={{ cursor: 'pointer' }}>
              {uploading ? <span className="spin">⟳</span> : '📎'} Upload PEM
              <input type="file" accept=".pem,.crt,.cer" multiple style={{ display: 'none' }}
                onChange={e => handleUpload(e.target.files)} />
            </label>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0 }}>
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading…</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Certificate CN</th>
                  <th>Type</th>
                  <th>Issuer</th>
                  <th>Valid Until</th>
                  <th>Days Left</th>
                  <th>Key</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 && (
                  <tr><td colSpan={7} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                    No certificates found.
                  </td></tr>
                )}
                {filtered.map(c => (
                  <tr
                    key={c.id}
                    onClick={() => onSelectCert(c.id)}
                    style={{
                      borderLeft: selectedId === c.id ? '3px solid var(--accent)' : '3px solid transparent',
                      background: selectedId === c.id ? 'var(--bg-glass)' : undefined,
                    }}
                  >
                    <td><span className="cert-cn">{c.subject_cn}</span></td>
                    <td>
                      <span className={`cert-type type-${c.certificate_type}`}>
                        {TYPE_LABELS[c.certificate_type]}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{c.issuer_cn}</td>
                    <td style={{ fontSize: 12 }}>{formatDate(c.valid_until)}</td>
                    <td><DaysIndicator days={c.days_remaining} expired={c.is_expired} /></td>
                    <td style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      {c.public_key_algorithm} {c.public_key_size}
                    </td>
                    <td>
                      <span className={`risk-badge risk-${c.overall_risk}`}>
                        {c.overall_risk}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
