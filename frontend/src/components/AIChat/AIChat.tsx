import React, { useEffect, useRef, useState } from 'react';
import { api, ChatMessage } from '../../services/api';
import { MarkdownView } from '../MarkdownView';

type ChatMode = 'general' | 'attacks';

const QUICK_QUESTIONS = [
  'Which certificates are expiring soon?',
  'Show me broken trust chains.',
  'What happens if Root CA is compromised?',
  'Which AI services have critical findings?',
  'Explain the difference between a root and intermediate CA.',
];

interface AttackScenario {
  id: string;
  icon: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  shortDesc: string;
  prompt: string;
}

const ATTACK_SCENARIOS: AttackScenario[] = [
  {
    id: 'mitm',
    icon: '🕵️',
    name: 'Man-in-the-Middle (MitM)',
    severity: 'CRITICAL',
    shortDesc: 'Intercept & forge encrypted TLS sessions',
    prompt: 'Explain how a Man-in-the-Middle (MitM) attack works against TLS/PKI, what certificate weaknesses enable it, and give me concrete prevention steps with configs to protect our AI microservices.',
  },
  {
    id: 'rogue-ca',
    icon: '🏴',
    name: 'Rogue CA / Certificate Forgery',
    severity: 'CRITICAL',
    shortDesc: 'Fake CA issues trusted certificates for any domain',
    prompt: 'Explain how Rogue CA and certificate forgery attacks work, including how attackers create fake certificates that browsers/clients trust, and provide a full prevention guide including CAA DNS records, CT logs, and root store policies.',
  },
  {
    id: 'downgrade',
    icon: '⬇️',
    name: 'TLS Downgrade (BEAST/POODLE/FREAK)',
    severity: 'CRITICAL',
    shortDesc: 'Force weak cipher suites to break encryption',
    prompt: 'Explain TLS downgrade attacks (BEAST, POODLE, DROWN, FREAK) — how they force weak cipher suites on our AI services, which certificate or TLS config weaknesses they exploit, and give me the exact TLS configuration to prevent them including recommended cipher suite lists.',
  },
  {
    id: 'revocation-bypass',
    icon: '🔓',
    name: 'Revocation Bypass (OCSP/CRL)',
    severity: 'HIGH',
    shortDesc: 'Use revoked certificates by bypassing CRL/OCSP',
    prompt: 'Explain how attackers bypass certificate revocation checks (OCSP soft-fail, CRL staleness, OCSP stapling attacks). How does this affect our AI service certificates? Give me specific OpenSSL and server configs to enforce strict revocation checking.',
  },
  {
    id: 'key-compromise',
    icon: '🗝️',
    name: 'Private Key Compromise',
    severity: 'CRITICAL',
    shortDesc: 'Private key theft enables complete impersonation',
    prompt: 'Explain how private key compromise attacks work against PKI infrastructure — how keys are stolen (filesystem access, memory dumps, side channels), what an attacker can do with a stolen key, and give me a complete key protection strategy including HSM usage, file permissions, and key rotation procedures.',
  },
  {
    id: 'pinning-bypass',
    icon: '📌',
    name: 'Certificate Pinning Bypass',
    severity: 'HIGH',
    shortDesc: 'Circumvent pinned certificates in mobile/API clients',
    prompt: 'Explain certificate pinning bypass attacks — how attackers extract or manipulate pinned certificate hashes in mobile apps and API clients connecting to our AI services. Include both static and dynamic bypass techniques and how to implement robust pinning with backup pins.',
  },
  {
    id: 'mtls-bypass',
    icon: '🔄',
    name: 'mTLS / Client Auth Bypass',
    severity: 'CRITICAL',
    shortDesc: 'Skip mutual authentication to access protected AI APIs',
    prompt: 'Explain mTLS (mutual TLS) bypass attacks — how attackers skip or circumvent client certificate validation to gain unauthorized access to protected AI APIs and inference endpoints. Include misconfiguration patterns and how to properly enforce client certificate verification in nginx, envoy, and Python service configs.',
  },
  {
    id: 'subdomain-takeover',
    icon: '🌐',
    name: 'Subdomain Takeover via Certs',
    severity: 'HIGH',
    shortDesc: 'Claim abandoned subdomains and get valid certificates',
    prompt: 'Explain subdomain takeover attacks in the context of AI service certificates — how attackers claim abandoned DNS subdomains and obtain valid certificates for them (e.g., vector.ai.company.com pointing to a deleted cloud resource). Give detection methods and prevention steps including DNS monitoring and CAA records.',
  },
  {
    id: 'bgp-hijack',
    icon: '📡',
    name: 'BGP Hijacking + Cert Misissuance',
    severity: 'CRITICAL',
    shortDesc: 'Route hijacking to pass domain validation and get fake certs',
    prompt: 'Explain BGP hijacking combined with certificate misissuance — how attackers reroute internet traffic to pass domain control validation (DCV) checks and get a CA to issue them fraudulent certificates for our AI service domains. Include RPKI, CAA records, and multi-perspective validation as countermeasures.',
  },
  {
    id: 'replay',
    icon: '♻️',
    name: 'Replay Attacks',
    severity: 'MEDIUM',
    shortDesc: 'Reuse captured TLS sessions or stolen tokens',
    prompt: 'Explain replay attacks in the context of TLS and certificate-based authentication for AI services — how captured handshakes, session tokens, or client certificates can be replayed. What certificate and TLS session settings prevent replay attacks? Include TLS session ticket rotation, nonce requirements, and certificate validity windows.',
  },
];

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'var(--critical)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--warning)',
};

const SEVERITY_BG: Record<string, string> = {
  CRITICAL: 'var(--critical-bg)',
  HIGH: 'var(--high-bg)',
  MEDIUM: 'var(--warning-bg)',
};

export function AIChat() {
  const [mode, setMode] = useState<ChatMode>('general');
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: 'assistant',
      content: '👋 Hello! I\'m your PKI security assistant.\n\nI can help you understand certificates, trust chains, security risks, and how to **prevent attacks** on your AI infrastructure.\n\nSwitch to the **🛡 Attack Prevention** tab to get step-by-step guidance on preventing MitM, downgrade, key compromise, mTLS bypass, and more.',
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedAttack, setSelectedAttack] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const send = async (text?: string) => {
    const content = text ?? input.trim();
    if (!content || loading) return;

    const userMsg: ChatMessage = { role: 'user', content };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput('');
    setLoading(true);

    try {
      const res = await api.chat(newMessages);
      setMessages([...newMessages, { role: 'assistant', content: res.reply }]);
    } catch {
      setMessages([...newMessages, { role: 'assistant', content: '⚠ Failed to reach AI service. Please check your connection.' }]);
    } finally {
      setLoading(false);
    }
  };

  const handleAttackCard = (scenario: AttackScenario) => {
    setSelectedAttack(scenario.id);
    setMode('general');  // switch to chat view to show the response
    send(scenario.prompt);
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  };

  return (
    <div style={{ padding: 24, height: '100%', display: 'flex', flexDirection: 'column', gap: 0, overflow: 'hidden' }}>

      {/* Header */}
      <div style={{ marginBottom: 14 }}>
        <h2 style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 2 }}>
          🤖 PKI AI Security Copilot
        </h2>
        <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          PKI analysis, trust chain verification & attack prevention guidance
        </p>
      </div>

      {/* Mode Tabs */}
      <div style={{
        display: 'flex',
        gap: 0,
        borderBottom: '1px solid var(--border)',
        marginBottom: 14,
      }}>
        <button
          onClick={() => setMode('general')}
          style={{
            padding: '9px 18px',
            border: 'none',
            background: mode === 'general' ? '#fef9c3' : 'transparent',
            color: mode === 'general' ? '#854d0e' : 'var(--text-muted)',
            fontWeight: mode === 'general' ? 700 : 500,
            borderBottom: mode === 'general' ? '3px solid #eab308' : '3px solid transparent',
            cursor: 'pointer',
            fontSize: 13,
            transition: 'all 0.15s',
          }}
        >
          💬 AI Assistant
        </button>
        <button
          onClick={() => setMode('attacks')}
          style={{
            padding: '9px 18px',
            border: 'none',
            background: mode === 'attacks' ? '#fff5f5' : 'transparent',
            color: mode === 'attacks' ? 'var(--critical)' : 'var(--text-muted)',
            fontWeight: mode === 'attacks' ? 700 : 500,
            borderBottom: mode === 'attacks' ? '3px solid var(--critical)' : '3px solid transparent',
            cursor: 'pointer',
            fontSize: 13,
            transition: 'all 0.15s',
          }}
        >
          🛡 Attack Prevention
        </button>
      </div>

      {/* ATTACK PREVENTION PANEL */}
      {mode === 'attacks' ? (
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>

          <div style={{
            background: '#fff5f5',
            border: '1px solid var(--critical-border)',
            borderRadius: 'var(--r-md)',
            padding: '14px 18px',
            display: 'flex',
            gap: 12,
            alignItems: 'flex-start',
          }}>
            <span style={{ fontSize: 20 }}>🔐</span>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--critical)', marginBottom: 3 }}>
                PKI Attack Prevention Guide
              </div>
              <div style={{ fontSize: 12, color: '#334155', lineHeight: 1.6 }}>
                Click any attack below to get a detailed AI-generated prevention guide — how the attack works,
                which certificate vulnerabilities it exploits, and exact config steps to protect your AI services.
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
            {ATTACK_SCENARIOS.map(attack => (
              <button
                key={attack.id}
                onClick={() => handleAttackCard(attack)}
                disabled={loading}
                style={{
                  background: '#ffffff',
                  border: `1px solid ${selectedAttack === attack.id ? SEVERITY_COLOR[attack.severity] : 'var(--border)'}`,
                  borderLeft: `4px solid ${SEVERITY_COLOR[attack.severity]}`,
                  borderRadius: 'var(--r-md)',
                  padding: '14px 16px',
                  textAlign: 'left',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  transition: 'all 0.18s ease',
                  boxShadow: selectedAttack === attack.id
                    ? `0 0 0 2px ${SEVERITY_COLOR[attack.severity]}33`
                    : '0 2px 6px rgba(0,0,0,0.04)',
                  opacity: loading ? 0.7 : 1,
                  display: 'flex',
                  gap: 12,
                  alignItems: 'flex-start',
                }}
                onMouseEnter={e => {
                  if (!loading) (e.currentTarget as HTMLElement).style.borderColor = SEVERITY_COLOR[attack.severity];
                }}
                onMouseLeave={e => {
                  if (selectedAttack !== attack.id) {
                    (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)';
                    (e.currentTarget as HTMLElement).style.borderLeftColor = SEVERITY_COLOR[attack.severity];
                  }
                }}
              >
                <span style={{ fontSize: 24, flexShrink: 0 }}>{attack.icon}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                    <span style={{ fontWeight: 700, fontSize: 13, color: '#0f172a' }}>{attack.name}</span>
                    <span style={{
                      fontSize: 9,
                      fontWeight: 800,
                      padding: '2px 6px',
                      borderRadius: 10,
                      background: SEVERITY_BG[attack.severity],
                      color: SEVERITY_COLOR[attack.severity],
                      border: `1px solid ${SEVERITY_COLOR[attack.severity]}55`,
                      letterSpacing: '0.5px',
                      textTransform: 'uppercase',
                      flexShrink: 0,
                    }}>
                      {attack.severity}
                    </span>
                  </div>
                  <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.4 }}>
                    {attack.shortDesc}
                  </div>
                  <div style={{ marginTop: 8, fontSize: 11, color: SEVERITY_COLOR[attack.severity], fontWeight: 600 }}>
                    {selectedAttack === attack.id && loading ? '⟳ Generating guide…' : '→ Click for prevention guide'}
                  </div>
                </div>
              </button>
            ))}
          </div>

          {/* Quick attack-related questions */}
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.6px', marginBottom: 8 }}>
              Or ask directly:
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {[
                'Are any of our AI services vulnerable to MitM?',
                'Which certs need pinning immediately?',
                'How do I set up mTLS for inference.ai.company.com?',
                'What TLS version should all services use?',
                'How do I detect if a certificate has been misused?',
              ].map(q => (
                <button
                  key={q}
                  className="btn btn-ghost btn-sm"
                  style={{ fontSize: 11 }}
                  onClick={() => { setMode('general'); send(q); }}
                  disabled={loading}
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        </div>
      ) : (
        /* GENERAL CHAT PANEL */
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 }}>

          {/* Quick questions */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', flexShrink: 0 }}>
            {QUICK_QUESTIONS.map(q => (
              <button
                key={q}
                className="btn btn-ghost btn-sm"
                style={{ fontSize: 11, padding: '4px 10px' }}
                onClick={() => send(q)}
                disabled={loading}
              >
                {q}
              </button>
            ))}
          </div>

          <div className="chat-container" style={{ flex: 1, minHeight: 0 }}>
            <div className="chat-header">
              <div style={{
                width: 8, height: 8, borderRadius: '50%',
                background: 'var(--trusted)', boxShadow: '0 0 8px var(--trusted)',
              }} />
              <span style={{ fontSize: 13, fontWeight: 600 }}>PKI Security AI</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                {loading ? 'Thinking…' : 'Ready'}
              </span>
            </div>

            <div className="chat-messages">
              {messages.map((m, i) => (
                <div key={i} className={`chat-msg ${m.role}`}>
                  {m.role === 'assistant' && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, borderBottom: '1px solid #f1f5f9', paddingBottom: 4 }}>
                      <span style={{ fontSize: 13 }}>🤖</span>
                      <span style={{ fontSize: 11, color: '#854d0e', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        PKI AI Copilot
                      </span>
                    </div>
                  )}
                  <MarkdownView content={m.content} isUser={m.role === 'user'} />
                </div>
              ))}
              {loading && (
                <div className="chat-msg assistant">
                  <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                    <div style={{ display: 'flex', gap: 3 }}>
                      {[0, 1, 2].map(i => (
                        <div key={i} style={{
                          width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)',
                          animation: `spin 1s ease-in-out ${i * 0.15}s infinite`,
                          opacity: 0.7,
                        }} />
                      ))}
                    </div>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Analyzing PKI data…</span>
                  </div>
                </div>
              )}
              <div ref={bottomRef} />
            </div>

            <div className="chat-input-row">
              <textarea
                className="chat-input"
                rows={2}
                placeholder="Ask about certificates, trust chains, attacks, expiry, risks…"
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKey}
              />
              <button
                className="btn btn-primary"
                onClick={() => send()}
                disabled={loading || !input.trim()}
                style={{ alignSelf: 'flex-end', padding: '10px 16px' }}
              >
                Send
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
