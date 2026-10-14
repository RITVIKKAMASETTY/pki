import React, { useEffect, useState } from 'react';
import { api, DashboardStats } from '../../services/api';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';

const RISK_COLORS: Record<string, string> = {
  Trusted: 'var(--trusted)',
  Critical: 'var(--critical)',
  High: 'var(--high)',
  Warning: 'var(--warning)',
  Expired: '#6b7280',
};

const CHART_COLORS = ['#facc15', '#ffffff', '#fde047', '#eab308', '#ca8a04', '#e2e8f0'];

interface StatCardProps {
  icon: string;
  number: number;
  label: string;
  color: string;
  sublabel?: string;
}

function StatCard({ icon, number, label, color, sublabel }: StatCardProps) {
  return (
    <div className="stat-card fade-in-up">
      <div className="stat-icon" style={{ color }}>{icon}</div>
      <div className="stat-number" style={{ color }}>{number}</div>
      <div className="stat-label">{label}</div>
      {sublabel && <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{sublabel}</div>}
    </div>
  );
}

interface DashboardProps {
  onSelectCert?: (id: number) => void;
}

export function DashboardPage({ onSelectCert }: DashboardProps = {}) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.dashboard().then(d => { setStats(d); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  if (loading) return (
    <div className="page-content" style={{ alignItems: 'center', justifyContent: 'center', minHeight: 400 }}>
      <div style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
        <div className="spin" style={{ display: 'inline-block', fontSize: 32, marginBottom: 12 }}>⟳</div>
        <div>Loading dashboard…</div>
      </div>
    </div>
  );

  if (!stats) return <div className="page-content"><div className="card">Failed to load dashboard.</div></div>;

  return (
    <div className="page-content">
      {/* Stat Cards */}
      <div className="grid-4 fade-in-up">
        <StatCard icon="📋" number={stats.total} label="Total Certificates" color="var(--accent)" />
        <StatCard icon="✓" number={stats.trusted} label="Trusted" color="var(--trusted)" sublabel="Valid chains" />
        <StatCard
          icon="⚠"
          number={stats.warning + stats.critical}
          label="Issues Found"
          color="var(--warning)"
          sublabel={`${stats.critical} critical, ${stats.warning} other`}
        />
        <StatCard icon="✕" number={stats.expired} label="Expired" color="var(--critical)"
          sublabel={stats.expiring_soon > 0 ? `+${stats.expiring_soon} expiring soon` : undefined} />
      </div>

      {/* Charts row */}
      <div className="grid-2">
        {/* Certificate Status Pie */}
        <div className="card">
          <div className="card-title">Certificate Status</div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={stats.by_status.filter(s => s.count > 0)}
                dataKey="count" nameKey="status"
                cx="50%" cy="50%" outerRadius={80} innerRadius={50}
                paddingAngle={3}
                label={({ status, count }) => `${status} (${count})`}
                labelLine={false}
              >
                {stats.by_status.filter(s => s.count > 0).map((entry) => (
                  <Cell key={entry.status} fill={RISK_COLORS[entry.status] ?? 'var(--bg-4)'} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Risk Distribution */}
        <div className="card">
          <div className="card-title">Risk Distribution</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={stats.risk_distribution} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
              <XAxis dataKey="risk" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {stats.risk_distribution.map((entry) => (
                  <Cell key={entry.risk} fill={RISK_COLORS[entry.risk] ?? CHART_COLORS[0]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid-2">
        {/* By CA */}
        <div className="card">
          <div className="card-title">Certificates by CA</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={stats.by_ca} layout="vertical" margin={{ top: 5, right: 10, left: 60, bottom: 5 }}>
              <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <YAxis dataKey="ca" type="category" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} width={120} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)' }}
              />
              <Bar dataKey="count" fill="var(--accent)" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Expiry Timeline */}
        <div className="card">
          <div className="card-title">Expiry Timeline</div>
          {stats.expiry_timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={stats.expiry_timeline} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <XAxis dataKey="month" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-3)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)' }}
                />
                <Line type="monotone" dataKey="count" stroke="var(--cyan)" strokeWidth={2}
                  dot={{ fill: 'var(--cyan)', r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px 0', fontSize: 13 }}>
              No upcoming expirations in next 12 months
            </div>
          )}
        </div>
      </div>

      {/* Quick findings summary */}
      <div className="card">
        <div className="card-title">Quick Actions</div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          {stats.expiring_soon > 0 && (
            <div style={{
              padding: '10px 16px', borderRadius: 'var(--r-md)',
              background: 'var(--warning-bg)', border: '1px solid var(--warning-border)',
              color: 'var(--warning)', fontSize: 13, fontWeight: 600,
            }}>
              ⚠ {stats.expiring_soon} certificate{stats.expiring_soon > 1 ? 's' : ''} expiring within 30 days
            </div>
          )}
          {stats.expired > 0 && (
            <div style={{
              padding: '10px 16px', borderRadius: 'var(--r-md)',
              background: 'var(--critical-bg)', border: '1px solid var(--critical-border)',
              color: 'var(--critical)', fontSize: 13, fontWeight: 600,
            }}>
              ✕ {stats.expired} expired certificate{stats.expired > 1 ? 's' : ''} — immediate action required
            </div>
          )}
          {stats.critical > 0 && (
            <div style={{
              padding: '10px 16px', borderRadius: 'var(--r-md)',
              background: 'var(--critical-bg)', border: '1px solid var(--critical-border)',
              color: 'var(--critical)', fontSize: 13, fontWeight: 600,
            }}>
              🔴 {stats.critical} critical security finding{stats.critical > 1 ? 's' : ''}
            </div>
          )}
          {stats.trusted === stats.total && (
            <div style={{
              padding: '10px 16px', borderRadius: 'var(--r-md)',
              background: 'var(--trusted-bg)', border: '1px solid var(--trusted-border)',
              color: 'var(--trusted)', fontSize: 13, fontWeight: 600,
            }}>
              ✓ All certificates healthy
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
