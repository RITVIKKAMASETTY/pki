import React, { useState } from 'react';
import { DashboardPage } from './components/Dashboard/DashboardPage';
import { CertificateList } from './components/CertificateCard/CertificateList';
import { CertificateDetail } from './components/CertificateCard/CertificateDetail';
import { TrustGraph } from './components/TrustGraph/TrustGraph';
import { RiskPanel } from './components/RiskPanel/RiskPanel';
import { AIServicesPage } from './components/AIServices/AIServicesPage';
import { AIChat } from './components/AIChat/AIChat';

type Tab = 'dashboard' | 'graph' | 'certificates' | 'risks' | 'services' | 'chat';

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('dashboard');
  const [selectedCertId, setSelectedCertId] = useState<number | null>(null);

  const handleSelectCert = (id: number) => {
    setSelectedCertId(id);
  };

  const handleCloseDetail = () => {
    setSelectedCertId(null);
  };

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">🛡️</div>
          <h1>PKI ChainIQ</h1>
          <p>Trust Chain Analysis for AI Services</p>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">Monitoring</div>
          <button
            className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <span className="nav-icon">📊</span>
            <span>Dashboard</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'graph' ? 'active' : ''}`}
            onClick={() => setActiveTab('graph')}
          >
            <span className="nav-icon">🕸</span>
            <span>Trust Graph</span>
          </button>

          <div className="nav-section-label">PKI Infrastructure</div>
          <button
            className={`nav-item ${activeTab === 'certificates' ? 'active' : ''}`}
            onClick={() => setActiveTab('certificates')}
          >
            <span className="nav-icon">📜</span>
            <span>Certificates</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'risks' ? 'active' : ''}`}
            onClick={() => setActiveTab('risks')}
          >
            <span className="nav-icon">🛡</span>
            <span>Risk Intel</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'services' ? 'active' : ''}`}
            onClick={() => setActiveTab('services')}
          >
            <span className="nav-icon">🤖</span>
            <span>AI Services</span>
          </button>

          <div className="nav-section-label">AI Copilot</div>
          <button
            className={`nav-item ${activeTab === 'chat' ? 'active' : ''}`}
            onClick={() => setActiveTab('chat')}
          >
            <span className="nav-icon">💬</span>
            <span>AI Assistant</span>
          </button>
        </nav>

        {/* Sidebar Footer */}
        <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--trusted)', display: 'inline-block' }} />
            <span>PKI Engine Active</span>
          </div>
          <div style={{ marginTop: 4, fontFamily: 'var(--font-mono)' }}>FastAPI + SQLite</div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content" style={{ display: 'flex', flexDirection: 'column' }}>
        <header className="topbar">
          <h2>
            {activeTab === 'dashboard' && 'Security & PKI Overview'}
            {activeTab === 'graph' && 'Interactive Trust Chain Topology'}
            {activeTab === 'certificates' && 'Certificate Registry & X.509 Parser'}
            {activeTab === 'risks' && 'Security Risk & Vulnerability Analysis'}
            {activeTab === 'services' && 'AI Microservices Mesh Status'}
            {activeTab === 'chat' && 'AI Security Assistant & Chain Auditor'}
          </h2>

          <div className="topbar-actions">
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => {
                if (activeTab === 'certificates') {
                  const input = document.getElementById('cert-upload-input');
                  if (input) input.click();
                } else {
                  setActiveTab('certificates');
                }
              }}
            >
              ➕ Upload Certificate
            </button>
          </div>
        </header>

        <div style={{ flex: 1, position: 'relative', overflow: 'auto' }}>
          {activeTab === 'dashboard' && <DashboardPage onSelectCert={handleSelectCert} />}
          {activeTab === 'graph' && (
            <div style={{ height: 'calc(100vh - 65px)', width: '100%' }}>
              <TrustGraph onSelectCert={handleSelectCert} />
            </div>
          )}
          {activeTab === 'certificates' && (
            <CertificateList onSelectCert={handleSelectCert} selectedId={selectedCertId ?? undefined} />
          )}
          {activeTab === 'risks' && <RiskPanel onSelectCert={handleSelectCert} />}
          {activeTab === 'services' && <AIServicesPage onSelectCert={handleSelectCert} />}
          {activeTab === 'chat' && <AIChat />}
        </div>
      </main>

      {/* Modal / Slide-over for Certificate Details */}
      {selectedCertId !== null && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.4)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            justifyContent: 'flex-end',
            zIndex: 1000,
          }}
          onClick={handleCloseDetail}
        >
          <div
            style={{
              width: '100%',
              maxWidth: 720,
              height: '100%',
              background: '#ffffff',
              borderLeft: '1px solid var(--border)',
              boxShadow: '-10px 0 30px rgba(0,0,0,0.12)',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '16px 24px',
                borderBottom: '1px solid var(--border)',
                background: '#fafafa',
              }}
            >
              <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
                Certificate Inspector & Chain Verification
              </h3>
              <button
                className="btn btn-ghost btn-sm"
                onClick={handleCloseDetail}
                style={{ fontSize: 16, padding: '4px 10px', lineHeight: 1 }}
              >
                ✕
              </button>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
              <CertificateDetail certId={selectedCertId} onClose={handleCloseDetail} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
