import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import ReactDOM from 'react-dom/client';

    // Same-origin: empty base means every fetch is relative ("/api/...", "/health"),
    // so the UI talks to whatever origin served it — localhost:5000/8080 in dev, or the
    // Railway/Render URL in prod. Hardcoding a host (e.g. http://localhost:5000) breaks
    // the deployed app because the browser would call the user's own machine.
    const API_BASE = "";

    // Session auth uses an HttpOnly cookie set by /api/auth/login.
    // The cookie is sent automatically by the browser — no JS-readable
    // storage is used and no header needs to be constructed manually.
    const authHeaders = () => ({});

    /* ------------------------------------------------------------------ */
    /* Constants                                                            */
    /* ------------------------------------------------------------------ */

    const SIGNAL_LABELS = {
      impossible_travel:  'Impossible Travel',
      mfa_fatigue:        'MFA Fatigue',
      ip_reputation:      'IP Reputation',
      device_novelty:     'Device Novelty',
      login_hour_anomaly: 'Login Hour Anomaly',
      cluster_context:    'Cluster Context',
      file_reputation:    'File Reputation',
    };

    const SIGNAL_WEIGHTS = {
      impossible_travel: 30, mfa_fatigue: 25, ip_reputation: 20,
      device_novelty: 15, login_hour_anomaly: 10, cluster_context: 15,
      file_reputation: 40,
    };

    const SIGNAL_ORDER = [
      'impossible_travel', 'mfa_fatigue', 'ip_reputation',
      'device_novelty', 'login_hour_anomaly', 'file_reputation', 'cluster_context',
    ];

    function getDisplayVerdict(verdict) {
      return verdict;
    }

    const VERDICT_COLOR = {
      high_risk: 'var(--high)', medium_risk: 'var(--medium)', low_risk: 'var(--low)',
    };
    const VERDICT_LABEL = {
      high_risk: 'HIGH RISK', medium_risk: 'MEDIUM RISK', low_risk: 'LOW RISK',
    };
    const VERDICT_BADGE_CLASS = {
      high_risk: 'badge-high', medium_risk: 'badge-medium', low_risk: 'badge-low',
    };

    const EXAMPLE_KEYS = ['high_risk', 'medium_risk', 'low_risk'];
    const EXAMPLE_DISPLAY = { high_risk: 'HIGH RISK', medium_risk: 'MEDIUM RISK', low_risk: 'LOW RISK' };
    const EXAMPLE_DESCRIPTIONS = {
      high_risk:   'CEO account takeover — Tor exit + MFA fatigue + impossible travel',
      medium_risk: 'Ambiguous — needs human review',
      low_risk:    'Benign VPN travel',
    };
    const EXAMPLE_BADGE_CLASS = { high_risk: 'badge-high', medium_risk: 'badge-medium', low_risk: 'badge-low' };

    const VIEW_LABELS = {
      triage: 'Alert Input', queue: 'Alert Queue', cases: 'Cases',
      signals: 'Signal Breakdown', mitre: 'MITRE / NIST',
      intel: 'Threat Intel',
      safety: 'Safety Gates', weights: 'Signal Weights',
      history: 'Verdict History', feedbackhist: 'Feedback History',
      audit: 'Audit Log',
      settings: 'Settings', agent: 'Agentic Analysis',
    };

    const VIEW_TO_KEY = {
      triage: 'alert-input', queue: 'alert-queue', cases: 'cases',
      signals: 'signal-breakdown', mitre: 'mitre-nist',
      intel: 'threat-intel',
      safety: 'safety-gates', weights: 'signal-weights',
      audit: 'audit-log',
      settings: 'settings', agent: 'agent-view',
    };

    const NAV = [
      { section: 'TRIAGE', items: [
        { key: 'alert-input', label: 'Alert Input', action: 'view:triage', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2' },
        { key: 'alert-queue', label: 'Alert Queue', action: 'view:queue', icon: 'M4 6h16M4 10h16M4 14h16M4 18h16' },
        { key: 'cases', label: 'Cases', action: 'view:cases', icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z' },
      ]},
      { section: 'ANALYZE', items: [
        { key: 'signal-breakdown', label: 'Signal Breakdown', action: 'view:signals', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
        { key: 'mitre-nist', label: 'MITRE / NIST', action: 'view:mitre', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
      ]},
      { section: 'INTEL', items: [
        { key: 'threat-intel', label: 'Threat Intel', action: 'view:intel', icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z' },
      ]},
      { section: 'CONFIGURE', items: [
        { key: 'safety-gates', label: 'Safety Gates', action: 'view:safety', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
        { key: 'signal-weights', label: 'Signal Weights', action: 'view:weights', icon: 'M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4' },
      ]},
      { section: 'AUDIT', items: [
        { key: 'audit-log', label: 'Audit Log', action: 'view:audit', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
      ]},
      { section: 'AGENT', items: [
        { key: 'agent-view', label: 'Agentic Analysis', action: 'view:agent', badge: 'IN PROGRESS', icon: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z' },
      ]},
    ];

    const SIGNAL_META = {
      impossible_travel: {
        description: "Detects authentication from two geographically distant locations within a timeframe physically impossible for human travel. Threshold: >500 km/hr implied velocity.",
        mitre: "T1078.004 — Valid Accounts: Cloud Accounts",
        nist: "DE.CM-1 — Network monitoring",
        example: "Login from New York at 09:00 and Moscow at 09:30 UTC (7,500 km in 30 min).",
      },
      mfa_fatigue: {
        description: "Detects repeated MFA push denials followed by approval — a pattern consistent with MFA bombing where the user eventually approves to stop notifications.",
        mitre: "T1621 — MFA Request Generation",
        nist: "DE.CM-3 — Personnel activity monitoring",
        example: "12 MFA denials over 10 minutes followed by 1 approval.",
      },
      ip_reputation: {
        description: "Cross-references source IPs against AbuseIPDB, VirusTotal, and AlienVault OTX. Flags known C2 infrastructure, Tor exit nodes, and scanners.",
        mitre: "T1071 — Application Layer Protocol",
        nist: "DE.CM-1 — Network monitoring",
        example: "Source IP 198.51.100.23 tagged as C2/Cobalt-Strike infrastructure.",
      },
      device_novelty: {
        description: "Identifies authentication from a device not previously seen in the user's baseline. First-seen devices carry higher risk than recognised endpoints.",
        mitre: "T1078 — Valid Accounts",
        nist: "DE.CM-3 — Personnel activity monitoring",
        example: "User authenticates from device ID 'unknown-mobile-7f3a' — no prior history.",
      },
      login_hour_anomaly: {
        description: "Compares authentication timestamp against the user's historical login hour distribution. Logins outside the 95th percentile window are flagged.",
        mitre: "T1078 — Valid Accounts",
        nist: "DE.CM-7 — Monitoring for unauthorised access",
        example: "User typically logs in 08:00–18:00; authentication at 03:47 UTC is flagged.",
      },
      cluster_context: {
        description: "Correlated-case context — the alert is part of an active case (same source IP or user within the 60-minute correlation window). Points ramp with sibling count (1 → 5, 2 → 8, 3+ → 10), plus +5 when an ascending ATT&CK kill-chain spans the siblings. Additive on top of the 100-point core score — context aggravates, never mitigates; solo alerts are unaffected.",
        mitre: "— (meta-context; sibling alerts carry their own techniques)",
        nist: "DE.AE-3 — Event data are correlated",
        example: "2 related alerts in the last 60 min, kill-chain detected → +13 points.",
      },
      file_reputation: {
        description: "Multi-engine file-hash malware verdict. Prefers the verdict embedded in the source alert (Wazuh's VirusTotal integration) over an ADTE VirusTotal /files lookup. Confirmed malware adds the full weight; a partial detection ratio adds 20; a clean scan registers 0 (negative evidence). Additive on top of the 100-point core score — malware aggravates, never mitigates; non-file alerts are unaffected.",
        mitre: "T1204 — User Execution / T1105 — Ingress Tool Transfer",
        nist: "DE.CM-4 — Malicious code is detected",
        example: "VirusTotal 58/72 engines flag /tmp/malware/eicar.com → +40 points → high risk.",
      },
    };

    const ALL_TACTICS = [
      'Initial Access', 'Credential Access', 'Persistence', 'Privilege Escalation',
      'Lateral Movement', 'Defense Evasion', 'Discovery', 'Command and Control',
      'Execution', 'Exfiltration',
    ];

    const WEIGHTS_DATA = [
      { name: 'impossible_travel', label: 'Impossible Travel', weight: 30, color: '#ef4444', method: 'Geospatial velocity analysis', mitre: 'T1078.004' },
      { name: 'mfa_fatigue', label: 'MFA Fatigue', weight: 25, color: '#f97316', method: 'MFA denial sequence pattern matching', mitre: 'T1621' },
      { name: 'ip_reputation', label: 'IP Reputation', weight: 20, color: '#3b82f6', method: 'Multi-source threat intel aggregation', mitre: 'T1071' },
      { name: 'device_novelty', label: 'Device Novelty', weight: 15, color: '#8b5cf6', method: 'Device baseline comparison', mitre: 'T1078' },
      { name: 'login_hour_anomaly', label: 'Login Hour', weight: 10, color: '#22c55e', method: 'Historical hour distribution analysis', mitre: 'T1078' },
      { name: 'file_reputation', label: 'File Reputation', weight: 40, color: '#eab308', method: 'VirusTotal multi-engine hash verdict (embedded or /files lookup, additive)', mitre: 'T1204', context: true },
      { name: 'cluster_context', label: 'Cluster Context', weight: 15, color: '#14b8a6', method: 'Case-store sibling correlation (60-min window, additive)', mitre: '—', context: true },
    ];

    // Core scoring signals only (sum to 100) — excludes additive context signals.
    const CORE_WEIGHTS_DATA = WEIGHTS_DATA.filter(w => !w.context);

    const GATES = [
      { id: 1, name: 'Kill Switch', env: 'ADTE_KILL_SWITCH', cfgKey: 'kill_switch',
        desc: 'Reserved: would halt all automated actions engine-wide once an execution layer exists.',
        condition: 'ADTE_KILL_SWITCH=true',
        action: 'Reserved — no execution layer today; this gates nothing.',
        activeLabel: (v) => v ? ['TRIGGERED', 'var(--critical)'] : ['SAFE', 'var(--success)'],
      },
      { id: 2, name: 'Dry Run Mode', env: 'ADTE_DRY_RUN', cfgKey: 'dry_run',
        desc: 'Reserved: would log actions without executing writes once an execution layer exists.',
        condition: 'ADTE_DRY_RUN=true (default on)',
        action: 'Reserved — no execution layer today; this gates nothing.',
        activeLabel: (v) => v ? ['ACTIVE', 'var(--medium)'] : ['DISABLED', 'var(--success)'],
      },
      { id: 3, name: 'Execution Enabled', env: 'ADTE_EXECUTION_ENABLED', cfgKey: 'execution_enabled',
        desc: 'Reserved: master execution opt-in for a future execution layer.',
        condition: 'ADTE_EXECUTION_ENABLED=true required',
        action: 'Reserved — no execution layer today; this gates nothing.',
        activeLabel: (v) => v ? ['ENABLED', 'var(--success)'] : ['BLOCKED', 'var(--medium)'],
      },
      { id: 4, name: 'Tenant Allowlist', env: 'ADTE_TENANT_ALLOWLIST', cfgKey: 'tenant_allowlist',
        desc: 'Reserved: would restrict actions to approved tenant IDs.',
        condition: 'Incident tenant must be in allowlist',
        action: 'Reserved — no execution layer today; this gates nothing.',
        activeLabel: (v) => (Array.isArray(v) && v.length > 0) ? ['CONFIGURED', 'var(--success)'] : ['OPEN', 'var(--medium)'],
      },
      { id: 5, name: 'User / Severity', env: 'ADTE_USER_ALLOWLIST', cfgKey: 'user_allowlist',
        desc: 'Reserved: would restrict actions to approved users OR High+ severity incidents.',
        condition: 'User in allowlist OR severity High/Critical',
        action: 'Reserved — no execution layer today; this gates nothing.',
        activeLabel: (v) => (Array.isArray(v) && v.length > 0) ? ['CONFIGURED', 'var(--success)'] : ['OPEN', 'var(--medium)'],
      },
      { id: 6, name: 'Action Allowlist', env: 'ADTE_ACTION_ALLOWLIST', cfgKey: 'action_allowlist',
        desc: 'Reserved: would restrict permitted action types to an explicit set.',
        condition: 'Action type must be in allowlist',
        action: 'Reserved — no execution layer today; this gates nothing.',
        activeLabel: (v) => (Array.isArray(v) && v.length > 0) ? ['CONFIGURED', 'var(--success)'] : ['OPEN', 'var(--medium)'],
      },
    ];

    /* ------------------------------------------------------------------ */
    /* Icons                                                                */
    /* ------------------------------------------------------------------ */

    function NavIcon({ path, size = 18 }) {
      return (
        <svg className="nav-icon" width={size} height={size} viewBox="0 0 24 24" fill="none"
             stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <path d={path} />
        </svg>
      );
    }

    function IconSun({ size = 16 }) {
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
        </svg>
      );
    }

    function IconMoon({ size = 16 }) {
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
        </svg>
      );
    }

    function IconChevron({ size = 16, direction = 'left' }) {
      const rotate = direction === 'right' ? 'rotate(180deg)' : 'rotate(0)';
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
             strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ transform: rotate }}>
          <polyline points="15 18 9 12 15 6"/>
        </svg>
      );
    }

    function IconSend({ size = 18 }) {
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
        </svg>
      );
    }

    function IconSettings({ size = 16 }) {
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/>
        </svg>
      );
    }

    /* ------------------------------------------------------------------ */
    /* Sidebar                                                              */
    /* ------------------------------------------------------------------ */

    function Sidebar({ activeView, onNav, triageCount, serverOnline, collapsed, onToggleCollapse }) {
      const activeKey = VIEW_TO_KEY[activeView] || null;
      return (
        <div className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
          {/* Brand */}
          <div style={{ padding: collapsed ? '14px 0' : '14px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: collapsed ? 'center' : 'flex-start', gap: 12, minHeight: 56, transition: 'padding 0.25s ease' }}>
            {/* Bar-constructed eye mark */}
            <svg width="46" height="24" viewBox="-44 -23 88 46" fill="none" style={{ flexShrink: 0 }}>
              <g fill="#c0392b">
                <rect x="-12" y="-22" width="24" height="5"/>
                <rect x="-23" y="-13" width="14" height="5"/>
                <rect x="9"   y="-13" width="14" height="5"/>
                <rect x="-31" y="-4"  width="19" height="5"/>
                <rect x="12"  y="-4"  width="19" height="5"/>
                <rect x="-6"  y="-4"  width="12" height="5"/>
                <rect x="-23" y="5"   width="14" height="5"/>
                <rect x="9"   y="5"   width="14" height="5"/>
                <rect x="-12" y="14"  width="24" height="5"/>
                <rect x="-42" y="-2"  width="10" height="2" opacity="0.5"/>
                <rect x="32"  y="-2"  width="10" height="2" opacity="0.5"/>
              </g>
            </svg>
            {/* Wordmark — hidden in collapsed mode via sidebar-brand-text class */}
            <div className="sidebar-brand-text" style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, minWidth: 0 }}>
              <span className="mono" style={{ fontSize: 17, fontWeight: 700, letterSpacing: 3, color: 'var(--text-primary)', lineHeight: 1 }}>ADTE</span>
              <span className="mono" style={{ fontSize: 7, letterSpacing: 2, color: '#c0392b', lineHeight: 1 }}>DETECTION ENGINE</span>
            </div>
          </div>

          {/* Nav sections */}
          <div style={{ flex: 1, overflowY: 'auto', paddingTop: 8 }}>
            {NAV.map(group => (
              <div key={group.section} style={{ marginBottom: 4 }}>
                <div className="nav-section-label" style={{
                  fontSize: '0.6rem', fontWeight: 600, letterSpacing: '0.12em',
                  color: 'var(--text-muted)', textTransform: 'uppercase',
                  padding: '10px 16px 4px',
                }}>
                  {group.section}
                </div>
                {group.items.map(item => (
                  <div
                    key={item.key}
                    className={`nav-item ${activeKey === item.key ? 'active' : ''}`}
                    onClick={() => onNav(item.action)}
                    title={collapsed ? item.label : ''}
                  >
                    <NavIcon path={item.icon} />
                    <span className="nav-label" style={{ flex: 1 }}>{item.label}</span>
                    {item.badge && (
                      <span className="nav-label badge badge-medium" style={{ fontSize: '0.45rem', padding: '2px 5px', letterSpacing: '0.08em', flexShrink: 0 }}>
                        {item.badge}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            ))}
          </div>

          {/* Footer */}
          <div style={{
            borderTop: '1px solid var(--border)',
            padding: collapsed ? '10px 8px' : '12px 16px',
            display: 'flex', flexDirection: 'column', alignItems: collapsed ? 'center' : 'stretch',
            gap: collapsed ? 8 : 6,
            transition: 'padding 0.25s ease',
          }}>
            {!collapsed && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
                  <span>SESSION</span>
                  <span style={{ color: 'var(--text-secondary)' }}>TRG/{String(triageCount).padStart(3, '0')}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{
                    width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                    background: serverOnline ? 'var(--success)' : 'var(--critical)',
                  }} />
                  <span className="mono" style={{ fontSize: '0.6rem', color: serverOnline ? 'var(--success)' : 'var(--critical)' }}>
                    {serverOnline ? 'ONLINE' : 'OFFLINE'}
                  </span>
                </div>
              </div>
            )}
            {collapsed && (
              <div title={serverOnline ? 'Server Online' : 'Server Offline'} style={{
                width: 8, height: 8, borderRadius: '50%',
                background: serverOnline ? 'var(--success)' : 'var(--critical)',
              }} />
            )}
            <button
              onClick={onToggleCollapse}
              title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              style={{
                width: collapsed ? 36 : '100%',
                height: 28, padding: 0,
                background: 'transparent', border: '1px solid var(--border)',
                borderRadius: 4, cursor: 'pointer', color: 'var(--text-muted)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                transition: 'width 0.25s ease',
              }}
            >
              <IconChevron size={14} direction={collapsed ? 'right' : 'left'} />
            </button>
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* Shared Components                                                    */
    /* ------------------------------------------------------------------ */

    function Breadcrumb({ view }) {
      return (
        <div style={{ marginBottom: 20, fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="mono" style={{ color: 'var(--accent)', fontWeight: 600 }}>ADTE</span>
          <span style={{ color: 'var(--border-accent)' }}>/</span>
          <span>{VIEW_LABELS[view] || view}</span>
        </div>
      );
    }

    function NoResultBanner({ onGoTriage }) {
      return (
        <div className="panel" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 16px', marginBottom: 20 }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Run a triage first — load an example and click <strong>Run Triage</strong>
          </span>
          <button className="btn btn-primary" onClick={onGoTriage} style={{ flexShrink: 0 }}>
            Go to Alert Input
          </button>
        </div>
      );
    }

    function VerdictBadge({ verdict, riskScore }) {
      const display = getDisplayVerdict(verdict);
      const cls = VERDICT_BADGE_CLASS[display] || 'badge-low';
      return (
        <span className={`badge ${cls}`} style={{ fontSize: '0.7rem', padding: '4px 12px' }}>
          {VERDICT_LABEL[display] || display}
        </span>
      );
    }

    function MitreBadges({ techniques, phase }) {
      const techs = Array.isArray(techniques) ? techniques : [];
      if (!techs.length && !phase) return null;
      const phaseInfo = phase && NIST_800_61_PHASES[phase];
      return (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center', marginTop: 6 }}>
          {techs.map(t => {
            const info = MITRE_TECH_MAP[t];
            const label = info ? `${t} · ${info.name}` : t;
            const title = info ? `Tactic: ${info.tactic} | NIST CSF: ${info.nist} — ${info.nistLabel}` : t;
            return (
              <span key={t} className="badge badge-accent" title={title} style={{ fontSize: '0.65rem' }}>{label}</span>
            );
          })}
          {phase && (
            <span className="badge badge-medium" title={phaseInfo ? phaseInfo.desc : phase} style={{ fontSize: '0.65rem' }}>
              {phaseInfo ? `NIST 800-61 Phase ${phaseInfo.num}: ${phase}` : phase}
            </span>
          )}
        </div>
      );
    }

    function ScoreBar({ riskScore, confidence, verdict, pct }) {
      const color = VERDICT_COLOR[getDisplayVerdict(verdict)] || 'var(--success)';
      return (
        <div style={{ margin: '16px 0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 10 }}>
            <span className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>RISK SCORE</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
              <span className="mono" style={{
                fontSize: '3rem', fontWeight: 700, color, lineHeight: 1,
                animation: 'countUp 0.4s ease-out both',
              }}>{riskScore}</span>
              <span className="mono" style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>/100</span>
              <span className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginLeft: 8 }}>CONF {confidence}%</span>
            </div>
          </div>
          <div className="score-bar-track">
            <div className="score-bar-fill" style={{ width: `${pct}%`, background: color }} />
          </div>
        </div>
      );
    }

    function SignalCard({ name, signal, verdict }) {
      const label = SIGNAL_LABELS[name] || name;
      const maxPts = SIGNAL_WEIGHTS[name] ?? signal.max_possible ?? 10;
      const isSkipped = /skipped|weight redistributed|unavailable/i.test(signal.detail || '');
      const barPct = maxPts > 0 ? Math.min(100, (signal.score / maxPts) * 100) : 0;
      const confPct = Math.round((signal.confidence ?? 0) * 100);
      const barColor = !isSkipped && signal.score > 0
        ? (barPct >= 100 ? 'var(--critical)' : barPct >= 50 ? 'var(--high)' : 'var(--success)')
        : 'var(--border)';
      return (
        <div className="panel" style={{
          borderLeft: isSkipped
            ? '3px dashed var(--border-accent)'
            : `3px solid ${barColor}`,
          background: isSkipped ? 'transparent' : undefined,
        }}>
          <div style={{ padding: '12px 14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 6 }}>
              <span className="mono" style={{ fontSize: '0.7rem', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: isSkipped ? 'var(--text-muted)' : 'var(--text-primary)' }}>
                {isSkipped ? '⊘ ' : ''}{label}
              </span>
              {isSkipped
                ? <span className="badge badge-low" style={{ opacity: 0.7 }}>SKIPPED</span>
                : <span className="mono" style={{ fontSize: '0.75rem', color: signal.score > 0 ? barColor : 'var(--text-muted)', fontWeight: 600 }}>{signal.score}/{maxPts}</span>
              }
            </div>
            {!isSkipped && (
              <div className="score-bar-track" style={{ height: 4, marginBottom: 8 }}>
                <div style={{ width: `${barPct}%`, height: '100%', background: barColor, borderRadius: 2 }} />
              </div>
            )}
            <div style={{ fontSize: '0.75rem', color: isSkipped ? 'var(--text-muted)' : 'var(--text-secondary)', lineHeight: 1.5, display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
              {signal.detail}
            </div>
            {!isSkipped && (
              <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', textAlign: 'right', marginTop: 6 }}>conf {confPct}%</div>
            )}
          </div>
        </div>
      );
    }

    function ActionBanner({ result }) {
      const color = VERDICT_COLOR[getDisplayVerdict(result.verdict)] || 'var(--text-muted)';
      return (
        <div className="panel" style={{ borderLeft: `3px solid ${color}`, marginTop: 12 }}>
          <div style={{ padding: '14px 16px' }}>
            <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 6, letterSpacing: '0.08em' }}>RECOMMENDED ACTION</div>
            <div style={{ color, fontWeight: 600, fontSize: '0.9rem', marginBottom: 8, lineHeight: 1.4 }}>
              {result.recommended_action}
            </div>
            {result.actions?.length > 0 && (
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
                {result.actions.map(a => (
                  <span key={a} className="badge" style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>{a}</span>
                ))}
              </div>
            )}
            {result.safety?.human_review_required && (
              <div className="mono" style={{ color: 'var(--medium)', fontSize: '0.65rem', marginTop: 8 }}>
                ⚠ HUMAN REVIEW REQUIRED — automated actions suppressed
              </div>
            )}
          </div>
        </div>
      );
    }

    function FeedbackPanel({ result }) {
      const [submitted, setSubmitted] = useState(null);
      const [busy, setBusy] = useState(false);
      const [failed, setFailed] = useState(false);
      const [ip, setIp] = useState('');

      const incidentId = (result.evidence && result.evidence.incident_id)
        || (result.report && result.report.incident_id)
        || result.incident_id || 'unknown';

      const submit = (label) => {
        setBusy(true); setFailed(false);
        const body = { incident_id: incidentId, label };
        if (ip.trim()) body.ip = ip.trim();
        fetch(`${API_BASE}/api/feedback`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
          body: JSON.stringify(body),
        })
          .then(r => r.json().then(d => ({ ok: r.ok, d })))
          .then(({ ok, d }) => {
            if (ok) setSubmitted({ label, registryUpdated: d.registry_updated });
            else setFailed(true);
          })
          .catch(() => setFailed(true))
          .finally(() => setBusy(false));
      };

      if (submitted) {
        return (
          <div className="panel" style={{ marginTop: 12 }}>
            <div style={{ padding: '12px 16px' }}>
              <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--success)' }}>
                {submitted.label === 'fp' ? 'FALSE POSITIVE' : 'TRUE POSITIVE'} recorded
                {submitted.registryUpdated && ' — IP promoted to FP registry'}
              </span>
            </div>
          </div>
        );
      }

      return (
        <div className="panel" style={{ marginTop: 12 }}>
          <div className="panel-header">Analyst Feedback</div>
          <div style={{ padding: '12px 16px', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <input
              type="text" value={ip} onChange={e => setIp(e.target.value)}
              placeholder="Source IP (optional)" disabled={busy}
              className="mono"
              style={{ flex: '1 1 140px', minWidth: 120, maxWidth: 200, fontSize: '0.75rem' }}
            />
            <button className="btn btn-danger" onClick={() => submit('fp')} disabled={busy}>FALSE POSITIVE</button>
            <button className="btn" onClick={() => submit('tp')} disabled={busy} style={{ borderColor: 'var(--success)', color: 'var(--success)' }}>TRUE POSITIVE</button>
            {failed && <span className="mono" style={{ fontSize: '0.65rem', color: 'var(--critical)' }}>submission failed</span>}
          </div>
        </div>
      );
    }

    function LoadingSkeleton() {
      return (
        <div>
          <div className="skeleton" style={{ height: 56, marginBottom: 12 }} />
          <div className="skeleton" style={{ height: 50, marginBottom: 12, width: '70%' }} />
          <div className="skeleton" style={{ height: 52, marginBottom: 12 }} />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
            {[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 100 }} />)}
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* Stat Cards                                                           */
    /* ------------------------------------------------------------------ */

    function StatCards({ rows, loading }) {
      const high   = rows ? rows.filter(r => r.verdict === 'high_risk').length   : 0;
      const medium = rows ? rows.filter(r => r.verdict === 'medium_risk').length : 0;
      const low    = rows ? rows.filter(r => r.verdict === 'low_risk').length    : 0;

      const cards = [
        { label: 'High Risk',    sublabel: 'high_risk',    value: high,   color: 'var(--high)' },
        { label: 'Medium Risk',  sublabel: 'medium_risk',  value: medium, color: 'var(--medium)' },
        { label: 'Low Risk',     sublabel: 'low_risk',     value: low,    color: 'var(--success)' },
      ];

      return (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 20 }}>
          {cards.map((card, i) => (
            <div key={card.label} className="stat-card animate-in" style={{ animationDelay: `${i * 0.08}s`, borderLeft: `4px solid ${card.color}` }}>
              <div className="stat-label">{card.label}</div>
              {loading && rows === null
                ? <div className="skeleton" style={{ height: 32, width: '60%', margin: '4px 0' }} />
                : <div className="stat-value" style={{ color: card.color }}>{card.value}</div>
              }
            </div>
          ))}
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* Donut Chart                                                          */
    /* ------------------------------------------------------------------ */

    function VerdictDonut({ rows, loading }) {
      const canvasRef = useRef(null);
      const chartRef = useRef(null);

      const counts = useMemo(() => {
        if (!rows) return { high: 0, medium: 0, low: 0 };
        return {
          high:   rows.filter(r => r.verdict === 'high_risk').length,
          medium: rows.filter(r => r.verdict === 'medium_risk').length,
          low:    rows.filter(r => r.verdict === 'low_risk').length,
        };
      }, [rows]);

      useEffect(() => {
        if (!canvasRef.current) return;
        if (chartRef.current) chartRef.current.destroy();

        const ctx = canvasRef.current.getContext('2d');
        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';

        chartRef.current = new Chart(ctx, {
          type: 'doughnut',
          data: {
            labels: ['High Risk', 'Medium Risk', 'Low Risk'],
            datasets: [{
              data: [counts.high, counts.medium, counts.low],
              backgroundColor: ['#f97316', '#eab308', '#6b7280'],
              borderColor: isDark ? '#111111' : '#ffffff',
              borderWidth: 2,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: true,
            cutout: '65%',
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: isDark ? '#1a1a1a' : '#ffffff',
                titleColor: isDark ? '#f0f0f0' : '#171717',
                bodyColor: isDark ? '#a0a0a0' : '#525252',
                borderColor: isDark ? '#2a2a2a' : '#e5e5e5',
                borderWidth: 1,
              },
            },
          },
        });

        return () => { if (chartRef.current) chartRef.current.destroy(); };
      }, [counts]);

      return (
        <div className="panel animate-in" style={{ animationDelay: '0.2s' }}>
          <div className="panel-header">Verdict Distribution</div>
          <div className="panel-body" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            {loading && rows === null ? (
              <>
                <div className="skeleton" style={{ width: 120, height: 120, borderRadius: '50%', flexShrink: 0 }} />
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {[70, 50, 80, 60].map((w, i) => (
                    <div key={i} className="skeleton" style={{ height: 14, width: `${w}%` }} />
                  ))}
                </div>
              </>
            ) : (
              <>
                <div style={{ width: 120, height: 120 }}>
                  <canvas ref={canvasRef} />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {[
                    { label: 'High Risk',   sublabel: 'high_risk',   color: '#f97316', count: counts.high },
                    { label: 'Medium Risk', sublabel: 'medium_risk', color: '#eab308', count: counts.medium },
                    { label: 'Low Risk',    sublabel: 'low_risk',    color: '#6b7280', count: counts.low },
                  ].map(item => (
                    <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 10, height: 10, borderRadius: 2, background: item.color, flexShrink: 0 }} />
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{item.label}</span>
                      <span className="mono" style={{ fontSize: '0.75rem', fontWeight: 600, color: item.color, marginLeft: 'auto' }}>{item.count}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* Sparkline                                                            */
    /* ------------------------------------------------------------------ */

    function Sparkline({ rows }) {
      const canvasRef = useRef(null);
      const chartRef = useRef(null);

      useEffect(() => {
        if (!canvasRef.current || !rows || rows.length === 0) return;
        if (chartRef.current) chartRef.current.destroy();

        const hourBuckets = {};
        rows.forEach(r => {
          const h = r.timestamp ? r.timestamp.slice(11, 13) : '00';
          hourBuckets[h] = (hourBuckets[h] || 0) + 1;
        });
        const labels = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'));
        const data = labels.map(l => hourBuckets[l] || 0);

        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
        const ctx = canvasRef.current.getContext('2d');

        chartRef.current = new Chart(ctx, {
          type: 'line',
          data: {
            labels,
            datasets: [{
              data,
              borderColor: '#3b82f6',
              backgroundColor: 'rgba(59,130,246,0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.4,
              pointRadius: 0,
              pointHoverRadius: 4,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              x: {
                grid: { color: isDark ? '#1a1a1a' : '#f0f0f0' },
                ticks: { color: isDark ? '#666' : '#a3a3a3', font: { size: 9, family: 'JetBrains Mono' }, maxRotation: 0 },
              },
              y: {
                grid: { color: isDark ? '#1a1a1a' : '#f0f0f0' },
                ticks: { color: isDark ? '#666' : '#a3a3a3', font: { size: 9, family: 'JetBrains Mono' } },
                beginAtZero: true,
              },
            },
            plugins: { legend: { display: false }, tooltip: {
              backgroundColor: isDark ? '#1a1a1a' : '#ffffff',
              titleColor: isDark ? '#f0f0f0' : '#171717',
              bodyColor: isDark ? '#a0a0a0' : '#525252',
              borderColor: isDark ? '#2a2a2a' : '#e5e5e5',
              borderWidth: 1,
            }},
          },
        });

        return () => { if (chartRef.current) chartRef.current.destroy(); };
      }, [rows]);

      return (
        <div className="panel animate-in" style={{ animationDelay: '0.3s' }}>
          <div className="panel-header">Alert Volume (by hour)</div>
          <div className="panel-body" style={{ height: 120 }}>
            <canvas ref={canvasRef} />
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* TriageResult                                                         */
    /* ------------------------------------------------------------------ */

    // Alert-supplied URLs are UNTRUSTED (a hostile alert controls
    // data.virustotal.permalink). React does not sanitize href, so a
    // javascript:/data: URI would be executable on click. Render a link only
    // when it is an https:// URL on VirusTotal's own host.
    function safeVtPermalink(raw) {
      if (typeof raw !== 'string' || !raw) return null;
      try {
        const u = new URL(raw);
        if (u.protocol !== 'https:') return null;
        if (u.hostname !== 'virustotal.com' && !u.hostname.endsWith('.virustotal.com')) return null;
        return u.href;
      } catch {
        return null;  // not an absolute URL → never rendered as a link
      }
    }

    function MalwarePanel({ result }) {
      const files = result.evidence?.files;
      if (!files || files.length === 0) return null;
      const lookups = result.evidence?.file_reputation || {};
      return (
        <div className="panel" style={{ marginTop: 12, borderLeft: '3px solid #eab308' }}>
          <div className="panel-header" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>Malware Evidence</span>
            <span className="badge" style={{ fontSize: '0.55rem', background: '#eab3081f', color: '#eab308', border: '1px solid #eab308' }}>FILE REPUTATION</span>
          </div>
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {files.map((f, i) => {
              const hash = f.sha256 || f.sha1 || f.md5 || '';
              const lookup = hash ? lookups[hash.toLowerCase()] : null;
              const hasEmbedded = f.vt_positives != null && f.vt_total;
              const ratio = hasEmbedded ? f.vt_positives / f.vt_total : null;
              const malicious = ratio != null ? ratio >= 0.5 : (lookup ? lookup.is_malicious : false);
              const ratioColor = malicious ? 'var(--high)' : 'var(--text-secondary)';
              return (
                <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {f.path && (
                    <div className="mono" style={{ fontSize: '0.78rem', fontWeight: 600, wordBreak: 'break-all' }}>{f.path}</div>
                  )}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    {hasEmbedded && (
                      <span className="badge" style={{ fontSize: '0.6rem', background: `${ratioColor}1f`, color: ratioColor, border: `1px solid ${ratioColor}` }}>
                        VirusTotal {f.vt_positives}/{f.vt_total} engines
                      </span>
                    )}
                    {!hasEmbedded && lookup && (
                      <span className="badge" style={{ fontSize: '0.6rem', background: `${ratioColor}1f`, color: ratioColor, border: `1px solid ${ratioColor}` }}>
                        {lookup.is_malicious ? 'MALICIOUS' : 'CLEAN'} · {lookup.source}
                        {lookup.positives != null && lookup.total != null ? ` ${lookup.positives}/${lookup.total}` : ''}
                      </span>
                    )}
                    {f.fim_action && (
                      <span className="badge badge-accent" style={{ fontSize: '0.6rem' }}>
                        FIM: {f.fim_action}{f.fim_action === 'deleted' ? ' (Wazuh active response)' : ''}
                      </span>
                    )}
                  </div>
                  {hash && (
                    <div className="mono" style={{ fontSize: '0.66rem', color: 'var(--text-muted)' }} title={hash}>
                      {hash.slice(0, 16)}… ({hash.length === 64 ? 'sha256' : hash.length === 40 ? 'sha1' : 'md5'})
                    </div>
                  )}
                  {(() => {
                    const href = safeVtPermalink(f.vt_permalink);
                    if (!href) return null;
                    return (
                      <a href={href} target="_blank" rel="noopener noreferrer"
                         style={{ fontSize: '0.68rem', color: 'var(--accent)' }}>
                        VirusTotal report →
                      </a>
                    );
                  })()}
                </div>
              );
            })}
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              ADTE recommends containment — Wazuh's active response is the executor. ADTE never deletes.
            </div>
          </div>
        </div>
      );
    }

    function TriageResult({ result, scoreBarPct, onOpenCase }) {
      const signalSummary = result.report?.signal_summary || {};
      const caseInfo = result.case;
      return (
        <div>
          <div style={{ marginBottom: 12 }}>
            <VerdictBadge verdict={result.verdict} riskScore={result.risk_score} />
          </div>
          <ScoreBar riskScore={result.risk_score} confidence={result.confidence} verdict={result.verdict} pct={scoreBarPct} />
          <MitreBadges techniques={result.mitre_techniques} phase={result.nist_phase} />
          {caseInfo && (
            <div className="panel" style={{ marginTop: 12, borderLeft: `3px solid ${caseInfo.escalated ? 'var(--high)' : 'var(--accent)'}` }}>
              <div className="panel-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                <span className="mono">{caseInfo.case_id}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {caseInfo.escalated && <span className="badge badge-high" style={{ fontSize: '0.55rem' }}>ESCALATED</span>}
                  <VerdictBadge verdict={caseInfo.case_verdict} riskScore={caseInfo.case_score} />
                </div>
              </div>
              <div className="panel-body" style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div>
                  {caseInfo.alert_count} correlated alert{caseInfo.alert_count === 1 ? '' : 's'} in the {caseInfo.window_minutes} min window
                  · case score <span className="mono" style={{ fontWeight: 600 }}>{caseInfo.case_score}</span>
                </div>
                {caseInfo.kill_chain?.detected && <TacticChips tactics={caseInfo.kill_chain.tactics_in_order} />}
                {caseInfo.related_incident_ids?.length > 0 && (
                  <div className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                    Related: {caseInfo.related_incident_ids.join(', ')}
                  </div>
                )}
                {onOpenCase && (
                  <button className="btn" style={{ alignSelf: 'flex-start', fontSize: '0.72rem' }}
                    onClick={() => onOpenCase(caseInfo.case_id)}>
                    View case →
                  </button>
                )}
              </div>
            </div>
          )}
          <MalwarePanel result={result} />
          {result.report?.one_paragraph_summary && (() => {
            const isMock = (result.report.confidence_note || '').includes('template-based');
            return (
              <div className="panel" style={{ marginTop: 12 }}>
                <div className="panel-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span>Summary</span>
                  <span className={`badge ${isMock ? '' : 'badge-accent'}`} style={{ fontSize: '0.55rem' }}>
                    {isMock ? 'DETERMINISTIC' : 'CLAUDE'}
                  </span>
                </div>
                <div className="panel-body" style={{ fontSize: '0.8rem', lineHeight: 1.65, color: 'var(--text-secondary)' }}>
                  {result.report.one_paragraph_summary}
                </div>
                {result.report.confidence_note && (
                  <div style={{ padding: '4px 12px 10px', fontSize: '0.7rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    {result.report.confidence_note}
                  </div>
                )}
              </div>
            );
          })()}
          <div style={{ marginTop: 16 }}>
            <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: 10 }}>SIGNAL BREAKDOWN</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
              {SIGNAL_ORDER.map(name => {
                const s = signalSummary[name];
                return s ? <SignalCard key={name} name={name} signal={s} verdict={result.verdict} /> : null;
              })}
            </div>
          </div>
          {result.report && <MitrePanel report={result.report} />}
          <ActionBanner result={result} />
          <FeedbackPanel result={result} />
          <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: 14, display: 'flex', gap: 14, justifyContent: 'flex-end', flexWrap: 'wrap' }}>
            {result.report?.incident_id && <span>INC: {result.report.incident_id}</span>}
            {result.report?.user && <span>USER: {result.report.user}</span>}
            {result.report?.timestamp && <span>{result.report.timestamp.slice(0,19).replace('T',' ')} UTC</span>}
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* MitrePanel                                                           */
    /* ------------------------------------------------------------------ */

    function MitrePanel({ report }) {
      const tactics = report.mitre_tactics || [];
      const techniques = report.mitre_techniques || [];
      const phases = report.nist_phases || [];
      if (tactics.length === 0 && techniques.length === 0) return null;
      return (
        <div className="panel" style={{ marginTop: 12 }}>
          <div className="panel-header">MITRE ATT&CK / NIST CSF 2.0</div>
          <div className="panel-body">
            {tactics.length > 0 && (
              <div style={{ marginBottom: 10, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {tactics.map(t => <span key={t} className="badge badge-high">{t}</span>)}
              </div>
            )}
            {techniques.length > 0 && (
              <div style={{ marginBottom: 10 }}>
                {techniques.map(t => (
                  <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span className="badge badge-accent">{t.id}</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{t.name}</span>
                  </div>
                ))}
              </div>
            )}
            {phases.length > 0 && (
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {phases.map(p => <span key={p} className="badge badge-medium">{p}</span>)}
              </div>
            )}
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: QueueView                                                      */
    /* ------------------------------------------------------------------ */

    function QueueView({ onLoadIncident, onGoIntel }) {
      const [rows, setRows] = useState(null);
      const [loading, setLoading] = useState(true);
      const [dataSource, setDataSource] = useState(null);
      const [hours, setHours] = useState(24);
      const [limit, setLimit] = useState(50);
      const [minLevel, setMinLevel] = useState(1);
      const [lastFetch, setLastFetch] = useState(null);
      const [authError, setAuthError] = useState(null);
      const [sortCol, setSortCol] = useState('risk_score');
      const [sortDir, setSortDir] = useState('desc');

      const load = useCallback((h, lim, ml) => {
        setLoading(true);
        const params = new URLSearchParams({ hours: h, limit: lim, min_level: ml });
        fetch(`${API_BASE}/api/queue?${params}`, { headers: authHeaders() })
          .then(r => {
            // An auth failure is NOT a Wazuh outage.  A 401/403 body is valid
            // JSON, so without this status check it parsed cleanly, left
            // rows/source undefined, and rendered the amber "WAZUH
            // UNAVAILABLE" banner — telling the operator to configure a SIEM
            // when they simply needed to log in.  Sessions are wiped by every
            // redeploy, so this is the common case, not an edge case.
            if (r.status === 401 || r.status === 403) {
              const err = new Error('auth');
              err.authStatus = r.status;
              throw err;
            }
            return r.json();
          })
          .then(data => {
            setAuthError(null);
            setRows(data.rows || []);
            setDataSource(data.source || null);
            setLastFetch(new Date());
            setLoading(false);
          })
          .catch(e => {
            setAuthError(e && e.authStatus ? e.authStatus : null);
            setRows([]);
            setDataSource(null);
            setLoading(false);
          });
      }, []);

      useEffect(() => {
        load(hours, limit, minLevel);
        const id = setInterval(() => load(hours, limit, minLevel), 60000);
        return () => clearInterval(id);
      }, []);

      const sortedRows = useMemo(() => {
        if (!rows) return [];
        return [...rows].sort((a, b) => {
          let va = a[sortCol], vb = b[sortCol];
          if (typeof va === 'string') va = va.toLowerCase();
          if (typeof vb === 'string') vb = vb.toLowerCase();
          if (va < vb) return sortDir === 'asc' ? -1 : 1;
          if (va > vb) return sortDir === 'asc' ? 1 : -1;
          return 0;
        });
      }, [rows, sortCol, sortDir]);

      const handleSort = (col) => {
        if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
        else { setSortCol(col); setSortDir('desc'); }
      };

      const handleRefresh = () => load(hours, limit, minLevel);

      const colTemplate = '80px 130px 1fr 110px 70px 110px 80px';
      const headers = [
        { key: 'timestamp', label: 'Time' },
        { key: 'incident_id', label: 'Incident ID' },
        { key: 'user', label: 'User' },
        { key: 'source_ip', label: 'Source IP' },
        { key: 'risk_score', label: 'Risk' },
        { key: 'verdict', label: 'Verdict' },
        { key: 'status', label: 'Status' },
      ];

      // IIFE used here because the banner has three possible outcomes
      // (null / wazuh banner / mock banner) — cleaner than nested ternaries.
      const sourceBanner = (() => {
        if (loading && rows === null) return null;
        // Auth first: a logged-out session must never be reported as a SIEM
        // outage.  Sessions are cleared by every redeploy (ephemeral disk).
        if (authError) {
          return (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 16px', borderRadius: 6, marginBottom: 16,
              background: 'rgba(59,130,246,0.08)',
              border: '1px solid var(--accent)',
            }}>
              <span style={{ fontSize: '0.9rem', flexShrink: 0 }}>🔒</span>
              <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--accent)', fontWeight: 600 }}>
                {authError === 403 ? 'INSUFFICIENT ROLE' : 'AUTHENTICATION REQUIRED'}
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                {authError === 403
                  ? '— Your API key lacks the analyst role needed to read the queue.'
                  : '— Open Settings and log in with an ADTE API key to load the queue. Sessions are cleared on every redeploy.'}
              </span>
            </div>
          );
        }
        if (dataSource === 'wazuh') {
          return (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 16px', borderRadius: 6, marginBottom: 16,
              background: 'var(--success-dim)',
              border: '1px solid var(--success)',
            }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--success)', flexShrink: 0 }} />
              <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--success)', fontWeight: 600 }}>
                WAZUH LIVE
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                — {rows ? rows.length : 0} alert{rows && rows.length !== 1 ? 's' : ''} retrieved (last {hours}h)
              </span>
            </div>
          );
        }
        return (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '10px 16px', borderRadius: 6, marginBottom: 16,
            background: 'rgba(234,179,8,0.08)',
            border: '1px solid var(--medium)',
          }}>
            <span style={{ fontSize: '0.9rem', flexShrink: 0 }}>⚠</span>
            <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--medium)', fontWeight: 600 }}>
              WAZUH UNAVAILABLE
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              — Showing {rows ? rows.length : 3} example incident{(!rows || rows.length !== 1) ? 's' : ''} (mock fallback). Configure <code style={{ fontSize: '0.7rem' }}>ADTE_WAZUH_HOST</code> to connect a live instance.
            </span>
          </div>
        );
      })();

      return (
        <div style={{ padding: 24 }}>
          <Breadcrumb view="queue" />
          {sourceBanner}
          <StatCards rows={rows} loading={loading} />

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
            <VerdictDonut rows={rows} loading={loading} />
            <Sparkline rows={rows} />
          </div>

          {/* Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <label className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>HOURS</label>
              <input type="number" min="1" max="168" value={hours}
                onChange={e => setHours(Math.max(1, Math.min(168, parseInt(e.target.value) || 24)))}
                style={{ width: 56, fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <label className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>LIMIT</label>
              <input type="number" min="1" max="500" value={limit}
                onChange={e => setLimit(Math.max(1, Math.min(500, parseInt(e.target.value) || 50)))}
                style={{ width: 60, fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <label className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>LEVEL</label>
              <input type="number" min="1" max="15" value={minLevel}
                onChange={e => setMinLevel(Math.max(1, Math.min(15, parseInt(e.target.value) || 1)))}
                style={{ width: 50, fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem' }} />
            </div>
            <button className="btn btn-primary" onClick={handleRefresh} disabled={loading}>
              {loading ? 'Loading…' : 'Refresh'}
            </button>
            <span className="mono" style={{ marginLeft: 'auto', fontSize: '0.65rem', color: 'var(--text-muted)' }}>
              {lastFetch ? `Last: ${lastFetch.toLocaleTimeString()}` : ''}
            </span>
          </div>

          {/* Table */}
          {loading && <div>{[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 44, marginBottom: 4 }} />)}</div>}

          {!loading && (!rows || rows.length === 0) && (
            <div style={{ textAlign: 'center', paddingTop: 60, color: 'var(--text-muted)', fontSize: '0.8rem' }}>
              No alerts in queue
            </div>
          )}

          {!loading && rows && rows.length > 0 && (
            <div className="data-table">
              <div className="data-table-header" style={{ gridTemplateColumns: colTemplate }}>
                {headers.map(h => (
                  <span key={h.key} onClick={() => handleSort(h.key)} style={{ cursor: 'pointer' }}>
                    {h.label} {sortCol === h.key ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                  </span>
                ))}
              </div>
              {sortedRows.map(row => {
                const qTechs = Array.isArray(row.mitre_techniques) ? row.mitre_techniques : [];
                return (
                  <div key={row.incident_id}>
                    <div className="data-table-row" style={{ gridTemplateColumns: colTemplate }}
                      onClick={() => onLoadIncident(row)}>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {row.timestamp ? row.timestamp.slice(11,19) : '—'}
                      </span>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{row.incident_id}</span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.user}</span>
                      <span className="mono" style={{ fontSize: '0.75rem', color: row.source_ip ? 'var(--info, #60a5fa)' : 'var(--text-muted)', cursor: row.source_ip ? 'pointer' : 'default', textDecoration: row.source_ip ? 'underline dotted' : 'none' }}
                        onClick={row.source_ip ? e => { e.stopPropagation(); onGoIntel && onGoIntel(row.source_ip); } : undefined}
                        title={row.source_ip ? `Look up ${row.source_ip} in Threat Intel` : undefined}>
                        {row.source_ip || '—'}
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{ width: 32, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${row.risk_score}%`, height: '100%', background: VERDICT_COLOR[getDisplayVerdict(row.verdict, row.risk_score)], borderRadius: 2 }} />
                        </div>
                        <span className="mono" style={{ fontSize: '0.75rem', color: VERDICT_COLOR[getDisplayVerdict(row.verdict, row.risk_score)], fontWeight: 600 }}>{row.risk_score}</span>
                      </div>
                      <VerdictBadge verdict={row.verdict} riskScore={row.risk_score} />
                      <span className="badge badge-low">OPEN</span>
                    </div>
                    {(qTechs.length > 0 || row.nist_phase) && (
                      <div style={{ padding: '0 16px 8px' }}>
                        <MitreBadges techniques={qTechs} phase={row.nist_phase} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
          <div className="mono" style={{ marginTop: 10, fontSize: '0.6rem', color: 'var(--text-muted)', textAlign: 'right' }}>
            Auto-refreshes every 60s · Click row to triage · Click IP to enrich · Click headers to sort
          </div>
        </div>
      );
    }

    // Summary table for /api/triage/batch responses. Reuses the QueueView
    // data-table idiom; clicking a success row focuses that entry as the
    // single `result` so TriageResult and every downstream view (Signals,
    // MITRE, Intel, Audit) work on it unchanged.
    function BatchResultsTable({ results, meta, selectedIndex, onSelect, onOpenCase }) {
      const colTemplate = '32px 1.2fr 1fr 90px 110px 76px';
      const caseSummaries = meta.cases || [];
      return (
        <div style={{ marginBottom: 24 }}>
          <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: 8 }}>
            BATCH — {meta.count} alerts · <span style={{ color: 'var(--success)' }}>{meta.succeeded} triaged</span>
            {meta.failed > 0 && <> · <span style={{ color: 'var(--medium)' }}>{meta.failed} failed</span></>}
          </div>
          {caseSummaries.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 10 }}>
              {caseSummaries.map(c => (
                <div key={c.case_id} className="panel" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', cursor: onOpenCase ? 'pointer' : 'default', borderLeft: `3px solid ${c.escalated ? 'var(--high)' : 'var(--accent)'}` }}
                  onClick={onOpenCase ? () => onOpenCase(c.case_id) : undefined}
                  title={onOpenCase ? `Open ${c.case_id} in the Cases view` : c.case_id}>
                  <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>{c.case_id}</span>
                  <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{c.alert_count} alert{c.alert_count === 1 ? '' : 's'}</span>
                  <VerdictBadge verdict={c.case_verdict} riskScore={c.case_score} />
                  {c.escalated && <span className="badge badge-high" style={{ fontSize: '0.5rem' }}>ESCALATED</span>}
                  {c.kill_chain?.detected && <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--high)' }} title={c.kill_chain.tactics_in_order.join(' → ')}>⛓</span>}
                </div>
              ))}
            </div>
          )}
          <div className="data-table">
            <div className="data-table-header" style={{ gridTemplateColumns: colTemplate }}>
              <span>#</span><span>INCIDENT</span><span>USER</span><span>RISK</span><span>VERDICT</span><span>CASE</span>
            </div>
            {results.map(r => {
              if (!r.ok) {
                return (
                  <div key={r.index} className="data-table-row" style={{ gridTemplateColumns: '32px 1fr', cursor: 'default' }}>
                    <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{r.index + 1}</span>
                    <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--medium)' }}>⚠ {r.error}</span>
                  </div>
                );
              }
              const techs = Array.isArray(r.mitre_techniques) ? r.mitre_techniques : [];
              const focused = selectedIndex === r.index;
              return (
                <div key={r.index}>
                  <div className="data-table-row" style={{ gridTemplateColumns: colTemplate, background: focused ? 'var(--accent-dim)' : undefined }}
                    onClick={() => onSelect(r)} title="Show full triage result">
                    <span className="mono" style={{ fontSize: '0.75rem', color: focused ? 'var(--accent)' : 'var(--text-muted)' }}>{r.index + 1}</span>
                    <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.report?.incident_id || '—'}</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.report?.user || '—'}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{ width: 32, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                        <div style={{ width: `${r.risk_score}%`, height: '100%', background: VERDICT_COLOR[getDisplayVerdict(r.verdict, r.risk_score)], borderRadius: 2 }} />
                      </div>
                      <span className="mono" style={{ fontSize: '0.75rem', color: VERDICT_COLOR[getDisplayVerdict(r.verdict, r.risk_score)], fontWeight: 600 }}>{r.risk_score}</span>
                    </div>
                    <VerdictBadge verdict={r.verdict} riskScore={r.risk_score} />
                    <span className="mono" style={{ fontSize: '0.68rem', color: r.case ? (r.case.escalated ? 'var(--high)' : 'var(--accent)') : 'var(--text-muted)' }}
                      title={r.case ? r.case.case_id : 'Not correlated'}>
                      {r.case ? r.case.case_id.slice(-6) : '—'}
                    </span>
                  </div>
                  {techs.length > 0 && (
                    <div style={{ padding: '0 16px 8px' }}>
                      <MitreBadges techniques={techs} phase={r.nist_phase} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div className="mono" style={{ marginTop: 8, fontSize: '0.6rem', color: 'var(--text-muted)', textAlign: 'right' }}>
            Click a row for the full result · Signals / MITRE views follow the focused alert
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: CasesView — correlated alert clusters                          */
    /* ------------------------------------------------------------------ */

    // Ordered kill-chain tactic chips with arrows between stages.
    function TacticChips({ tactics }) {
      if (!tactics || tactics.length === 0) return null;
      return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <span className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>KILL CHAIN</span>
          {tactics.map((t, i) => (
            <React.Fragment key={`${t}-${i}`}>
              {i > 0 && <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>→</span>}
              <span className="badge badge-high" style={{ fontSize: '0.55rem' }}>{t}</span>
            </React.Fragment>
          ))}
        </div>
      );
    }

    const CASE_STATUS_FILTERS = ['all', 'open', 'closed'];

    function CasesView({ focusCaseId, onGoIntel }) {
      const [rows, setRows] = useState(null);
      const [statusFilter, setStatusFilter] = useState('all');
      const [expandedId, setExpandedId] = useState(focusCaseId || null);
      const [detail, setDetail] = useState(null);
      const [detailError, setDetailError] = useState(null);
      const [error, setError] = useState(null);

      // Stale flags: two quick filter clicks (or expand/collapse) put two
      // requests in flight; without the cleanup guard the LAST response to
      // resolve would win regardless of the currently selected filter/case.
      useEffect(() => {
        let stale = false;
        setError(null);
        fetch(`${API_BASE}/api/cases?status=${statusFilter}&limit=100`, { headers: authHeaders() })
          .then(r => r.json().then(d => ({ ok: r.ok, status: r.status, d })))
          .then(({ ok, status, d }) => {
            if (stale) return;
            if (ok) setRows(d.cases || []);
            else if (status === 401) setError('Authentication required — open Settings (gear icon) and log in.');
            else setError(d?.error || 'Failed to load cases');
          })
          .catch(() => { if (!stale) setError('Could not reach the cases API'); });
        return () => { stale = true; };
      }, [statusFilter]);

      useEffect(() => {
        if (!expandedId) { setDetail(null); setDetailError(null); return; }
        let stale = false;
        setDetail(null);
        setDetailError(null);
        fetch(`${API_BASE}/api/cases/${expandedId}`, { headers: authHeaders() })
          .then(r => r.json().then(d => ({ ok: r.ok, status: r.status, d })))
          .then(({ ok, status, d }) => {
            if (stale) return;
            if (ok) setDetail(d);
            else setDetailError(d?.error || `Failed to load case (HTTP ${status})`);
          })
          .catch(() => { if (!stale) setDetailError('Could not reach the cases API'); });
        return () => { stale = true; };
      }, [expandedId]);

      const colTemplate = '1.3fr 60px 1.4fr 90px 110px 56px 120px';
      return (
        <div style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>
              CORRELATED CASES — alerts sharing a source IP or user inside the rolling window
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              {CASE_STATUS_FILTERS.map(s => (
                <button key={s} className="btn" onClick={() => setStatusFilter(s)}
                  style={{ fontSize: '0.65rem', padding: '4px 10px',
                    borderColor: statusFilter === s ? 'var(--accent)' : undefined,
                    background: statusFilter === s ? 'var(--accent-dim)' : undefined }}>
                  {s.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          {error && (
            <div className="panel" style={{ borderLeft: '3px solid var(--medium)', marginBottom: 12 }}>
              <div className="panel-body mono" style={{ fontSize: '0.75rem', color: 'var(--medium)' }}>⚠ {error}</div>
            </div>
          )}
          {!error && rows && rows.length === 0 && (
            <div style={{ paddingTop: 60, textAlign: 'center' }}>
              <div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.7rem', letterSpacing: '0.15em' }}>NO CASES YET</div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 8, opacity: 0.6 }}>
                Run triage on related alerts — same source IP or user within the window — and they will group here.
              </div>
            </div>
          )}
          {!error && rows && rows.length > 0 && (
            <div className="data-table">
              <div className="data-table-header" style={{ gridTemplateColumns: colTemplate }}>
                <span>CASE</span><span>ALERTS</span><span>ENTITIES</span><span>RISK</span><span>VERDICT</span><span>CHAIN</span><span>LAST ACTIVITY</span>
              </div>
              {rows.map(c => {
                const expanded = expandedId === c.case_id;
                const entities = [...(c.users || []), ...(c.ips || [])];
                return (
                  <div key={c.case_id}>
                    <div className="data-table-row" style={{ gridTemplateColumns: colTemplate, background: expanded ? 'var(--accent-dim)' : undefined }}
                      onClick={() => setExpandedId(expanded ? null : c.case_id)} title={expanded ? 'Collapse' : 'Expand case detail'}>
                      <span className="mono" style={{ fontSize: '0.72rem', color: expanded ? 'var(--accent)' : 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {c.case_id}{c.escalated && <span style={{ color: 'var(--high)', marginLeft: 6 }} title="Escalated by correlation">▲</span>}
                      </span>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{c.alert_count}</span>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                        title={entities.join(', ')}>
                        {entities[0] || '—'}{entities.length > 1 && <span style={{ color: 'var(--text-muted)' }}> +{entities.length - 1}</span>}
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{ width: 32, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${c.case_score}%`, height: '100%', background: VERDICT_COLOR[c.case_verdict], borderRadius: 2 }} />
                        </div>
                        <span className="mono" style={{ fontSize: '0.75rem', color: VERDICT_COLOR[c.case_verdict], fontWeight: 600 }}>{c.case_score}</span>
                      </div>
                      <VerdictBadge verdict={c.case_verdict} riskScore={c.case_score} />
                      <span className="mono" style={{ fontSize: '0.75rem', color: c.kill_chain?.detected ? 'var(--high)' : 'var(--text-muted)' }}
                        title={c.kill_chain?.detected ? c.kill_chain.tactics_in_order.join(' → ') : 'No kill-chain progression'}>
                        {c.kill_chain?.detected ? '⛓ ✓' : '—'}
                      </span>
                      <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                        {(c.last_activity || '').slice(0, 19).replace('T', ' ')}
                        {c.status === 'open' && <span className="badge badge-low" style={{ marginLeft: 6, fontSize: '0.5rem' }}>OPEN</span>}
                      </span>
                    </div>
                    {expanded && !detail && (
                      <div className="mono" style={{ padding: '8px 16px', borderBottom: '1px solid var(--border)', fontSize: '0.7rem', color: detailError ? 'var(--medium)' : 'var(--text-muted)' }}>
                        {detailError ? `⚠ ${detailError}` : 'Loading case detail…'}
                      </div>
                    )}
                    {expanded && detail && detail.case_id === c.case_id && (
                      <div style={{ padding: '10px 16px 14px', borderBottom: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 10 }}>
                        {detail.kill_chain?.detected && <TacticChips tactics={detail.kill_chain.tactics_in_order} />}
                        <div>
                          <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: 6 }}>ESCALATION RATIONALE</div>
                          {(detail.escalation_rationale || []).map((r, i) => (
                            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: '0.75rem', color: 'var(--text-secondary)', padding: '2px 0' }}>
                              <span>{r.detail}</span>
                              <span className="mono" style={{ color: r.points >= 0 ? 'var(--accent)' : 'var(--text-muted)', fontWeight: 600, flexShrink: 0 }}>
                                {r.points >= 0 ? `+${r.points}` : r.points}
                              </span>
                            </div>
                          ))}
                        </div>
                        <div>
                          <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: 6 }}>
                            MEMBER ALERTS ({(detail.members || []).length})
                          </div>
                          {(detail.members || []).map((m, i) => (
                            <div key={i} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.4fr 90px 110px', gap: 8, alignItems: 'center', fontSize: '0.72rem', color: 'var(--text-secondary)', padding: '3px 0' }}>
                              <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.incident_id}</span>
                              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.user || '—'}</span>
                              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={m.rule_name || ''}>
                                {(m.ips || []).map((ip, k) => (
                                  <span key={ip} className="mono" style={{ color: 'var(--info, #60a5fa)', cursor: 'pointer', textDecoration: 'underline dotted', marginRight: 6 }}
                                    onClick={e => { e.stopPropagation(); onGoIntel && onGoIntel(ip); }} title={`Look up ${ip} in Threat Intel`}>
                                    {ip}
                                  </span>
                                ))}
                                {m.rule_name || ''}
                              </span>
                              <span className="mono" style={{ color: VERDICT_COLOR[m.verdict], fontWeight: 600 }}>{Math.round(m.risk_score)}</span>
                              <VerdictBadge verdict={m.verdict} riskScore={m.risk_score} />
                            </div>
                          ))}
                          <div className="mono" style={{ marginTop: 6, fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                            Members are stored summaries — re-run an incident through Alert Input for the full signal breakdown.
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
          <div className="mono" style={{ marginTop: 10, fontSize: '0.6rem', color: 'var(--text-muted)', textAlign: 'right' }}>
            Cases group triaged alerts by shared source IP / user · Click a row to expand · Click an IP to enrich
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: SignalsView                                                    */
    /* ------------------------------------------------------------------ */

    function SignalsView({ result, onGoTriage }) {
      const summary = result?.report?.signal_summary || {};
      const rationale = result?.rationale || [];

      return (
        <div style={{ padding: 24, maxWidth: 900 }}>
          <Breadcrumb view="signals" />
          <div style={{ marginBottom: 20 }}>
            <h2 className="heading" style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: 4 }}>Signal Breakdown</h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              {result ? 'Live scores from last triage run.' : 'No triage run yet — showing signal reference data.'}
            </p>
          </div>
          {!result && <NoResultBanner onGoTriage={onGoTriage} />}

          {SIGNAL_ORDER.map((name, idx) => {
            const meta = SIGNAL_META[name] || {};
            const s = summary[name];
            const rat = rationale.find(r => r.signal === name);
            const maxPts = SIGNAL_WEIGHTS[name] || 10;
            const score = s?.score ?? 0;
            const barPct = s ? Math.min(100, (score / maxPts) * 100) : 0;
            const confPct = s ? Math.round((s.confidence ?? 0) * 100) : null;
            const barColor = barPct >= 100 ? 'var(--critical)' : barPct >= 50 ? 'var(--high)' : barPct > 0 ? 'var(--success)' : 'var(--border)';
            const isSkipped = s && /skipped|weight redistributed/i.test(s.detail || '');
            const sigColor = WEIGHTS_DATA.find(w => w.name === name)?.color || '#666';

            return (
              <div key={name} className="panel animate-in" style={{ marginBottom: 12, borderLeft: `3px solid ${sigColor}`, animationDelay: `${idx * 0.06}s` }}>
                <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span className="mono" style={{ fontSize: '0.8rem', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                    {SIGNAL_LABELS[name]}
                  </span>
                  <span className="badge" style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                    {maxPts} pts max
                  </span>
                </div>
                <div style={{ padding: '14px 16px' }}>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>{meta.description}</p>

                  {result && s && (
                    <div style={{ marginBottom: 12 }}>
                      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 8 }}>
                        <span className="mono" style={{ fontSize: '1.8rem', fontWeight: 700, color: isSkipped ? 'var(--text-muted)' : barColor, lineHeight: 1 }}>
                          {isSkipped ? '—' : score}
                        </span>
                        <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>/ {maxPts} pts</span>
                        {confPct !== null && !isSkipped && (
                          <span className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginLeft: 8 }}>conf {confPct}%</span>
                        )}
                        {isSkipped && <span className="badge badge-low">SKIPPED</span>}
                      </div>
                      {!isSkipped && (
                        <div className="score-bar-track" style={{ height: 5, marginBottom: 10 }}>
                          <div style={{ width: `${barPct}%`, height: '100%', background: barColor, borderRadius: 3, transition: 'width 0.6s ease' }} />
                        </div>
                      )}
                      {(s?.detail || rat?.detail) && (
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.6, background: 'var(--bg-elevated)', padding: '10px 12px', borderLeft: `2px solid ${barColor}`, borderRadius: '0 4px 4px 0' }}>
                          {s?.detail || rat?.detail}
                        </div>
                      )}
                    </div>
                  )}

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginTop: 10 }}>
                    {[
                      { label: 'MITRE', value: meta.mitre },
                      { label: 'NIST', value: meta.nist },
                      { label: 'Example', value: meta.example },
                    ].map(({ label, value }) => (
                      <div key={label} style={{ background: 'var(--bg-elevated)', padding: '8px 10px', borderRadius: 4 }}>
                        <div className="mono" style={{ fontSize: '0.6rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: 4 }}>{label}</div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: MitreView                                                      */
    /* ------------------------------------------------------------------ */

    const NIST_800_61_PHASES = {
      'Detection & Analysis': {
        num: 2,
        desc: 'Identify, analyze, and prioritize events. Determine whether the event constitutes an incident, assess scope and impact, and assign initial severity.',
      },
      'Containment': {
        num: 3,
        fullName: 'Containment, Eradication & Recovery',
        desc: 'Limit damage and prevent further exploitation. Disable accounts, revoke sessions, isolate affected systems. Then eradicate the threat root cause and restore systems to normal operation.',
      },
      'Preparation': {
        num: 1,
        desc: 'Establish incident response capability before incidents occur: define policies, assemble tools, conduct training, and set up communication channels.',
      },
      'Post-Incident Activity': {
        num: 4,
        desc: 'Review the incident handling process, document lessons learned, update detection rules, and improve defenses to prevent recurrence.',
      },
    };

    function MitreView({ result, onGoTriage, highlight, focusTechs, focusNistPhases }) {
      const tactics = result?.report?.mitre_tactics || [];
      const techniques = result?.report?.mitre_techniques || [];
      const nistPhases = result?.report?.nist_phases || [];
      const tacticSet = new Set(tactics);
      const NIST_FUNCTIONS = ['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER'];

      const resultTechIds = new Set(techniques.map(t => t.id));
      // only show reference cards for techs not already shown in the live result panel
      const referenceTechs = (focusTechs || []).filter(t => !resultTechIds.has(t));
      // highlight the tactic for any focused tech
      const focusTacticSet = new Set((focusTechs || []).map(t => MITRE_TECH_MAP[t]?.tactic).filter(Boolean));

      useEffect(() => {
        if (!highlight) return;
        const id = highlight === '__nist__' ? 'mitre-nist-section' : `mitre-tech-${highlight}`;
        const el = document.getElementById(id);
        if (!el) return;
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        el.classList.remove('mitre-highlight-flash');
        // void offsetWidth forces a synchronous reflow so the browser registers
        // the class removal before re-adding it — without this, consecutive
        // navigation to the same element wouldn't re-trigger the CSS animation.
        void el.offsetWidth;
        el.classList.add('mitre-highlight-flash');
        const t = setTimeout(() => el.classList.remove('mitre-highlight-flash'), 1600);
        return () => clearTimeout(t);
      }, [highlight]);

      return (
        <div style={{ padding: 24 }}>
          <Breadcrumb view="mitre" />
          {!result && !focusTechs && !focusNistPhases && <NoResultBanner onGoTriage={onGoTriage} />}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>

            {/* LEFT — MITRE ATT&CK */}
            <div>
              <h3 className="heading" style={{ fontSize: '1rem', fontWeight: 700, marginBottom: 12 }}>MITRE ATT&CK</h3>

              {/* Reference cards for techs not in the live result — one card per technique */}
              {referenceTechs.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  {referenceTechs.length > 1 && (
                    <div className="mono" style={{ fontSize: '0.58rem', color: 'var(--text-muted)', marginBottom: 8, letterSpacing: '0.06em' }}>
                      TECHNIQUE REFERENCES ({referenceTechs.length})
                    </div>
                  )}
                  {referenceTechs.map(t => {
                    const meta = MITRE_TECH_MAP[t] || {};
                    return (
                      <div key={t} id={`mitre-tech-${t}`} className="panel" style={{ borderLeft: '3px solid var(--accent)', marginBottom: 8 }}>
                        {referenceTechs.length === 1 && (
                          <div className="panel-header" style={{ color: 'var(--accent)' }}>TECHNIQUE REFERENCE</div>
                        )}
                        <div className="panel-body">
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                            <span className="badge badge-accent" style={{ fontSize: '0.75rem', padding: '4px 10px' }}>{t}</span>
                            <span style={{ fontSize: '0.85rem', fontWeight: 700 }}>{meta.name || t}</span>
                          </div>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: '0.8rem' }}>
                            <div>
                              <div className="mono" style={{ fontSize: '0.58rem', color: 'var(--text-muted)', marginBottom: 3, letterSpacing: '0.06em' }}>TACTIC</div>
                              <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{meta.tactic || '—'}</div>
                            </div>
                            <div>
                              <div className="mono" style={{ fontSize: '0.58rem', color: 'var(--text-muted)', marginBottom: 3, letterSpacing: '0.06em' }}>NIST CSF DETECT</div>
                              <div>
                                <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{meta.nist || '—'}</span>
                                {meta.nistLabel && <span style={{ color: 'var(--text-muted)', marginLeft: 6, fontSize: '0.75rem' }}>· {meta.nistLabel}</span>}
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {result && tactics.length > 0 && (
                <div style={{ marginBottom: 14, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {tactics.map(t => <span key={t} className="badge badge-high">{t}</span>)}
                </div>
              )}
              {result && techniques.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  {techniques.map(t => (
                    <div key={t.id} id={`mitre-tech-${t.id}`} className="panel" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', marginBottom: 6 }}>
                      <span className="badge badge-accent">{t.id}</span>
                      <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>{t.name}</span>
                    </div>
                  ))}
                </div>
              )}
              <div className="panel">
                <div className="panel-header">Tactic Coverage Matrix</div>
                <div className="panel-body" style={{ padding: 0 }}>
                  {ALL_TACTICS.map((tactic, i) => {
                    const fired = tacticSet.has(tactic) || focusTacticSet.has(tactic);
                    return (
                      <div key={tactic} style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '8px 14px',
                        borderBottom: i < ALL_TACTICS.length - 1 ? '1px solid var(--border)' : 'none',
                        background: fired ? 'var(--critical-dim)' : 'transparent',
                      }}>
                        <div style={{
                          width: 8, height: 8, borderRadius: '50%',
                          background: fired ? 'var(--critical)' : 'transparent',
                          border: `2px solid ${fired ? 'var(--critical)' : 'var(--border-accent)'}`,
                        }} />
                        <span style={{ fontSize: '0.8rem', color: fired ? 'var(--text-primary)' : 'var(--text-muted)', fontWeight: fired ? 600 : 400 }}>{tactic}</span>
                        {fired && <span className="badge badge-critical" style={{ marginLeft: 'auto' }}>DETECTED</span>}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* RIGHT — NIST */}
            <div id="mitre-nist-section">
              <h3 className="heading" style={{ fontSize: '1rem', fontWeight: 700, marginBottom: 12 }}>NIST SP 800-61 Rev. 2</h3>

              {/* Phase reference cards — one per phase, shown when arriving from audit log NIST badge */}
              {focusNistPhases && focusNistPhases.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  {focusNistPhases.length > 1 && (
                    <div className="mono" style={{ fontSize: '0.58rem', color: 'var(--text-muted)', marginBottom: 8, letterSpacing: '0.06em' }}>
                      INCIDENT HANDLING PHASES ({focusNistPhases.length})
                    </div>
                  )}
                  {focusNistPhases.map(phase => {
                    const ph = NIST_800_61_PHASES[phase] || { num: '?', desc: '' };
                    return (
                      <div key={phase} className="panel" style={{ borderLeft: '3px solid var(--medium)', marginBottom: 8 }}>
                        {focusNistPhases.length === 1 && (
                          <div className="panel-header" style={{ color: 'var(--medium)' }}>INCIDENT HANDLING PHASE</div>
                        )}
                        <div className="panel-body">
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                            <span className="badge badge-medium" style={{ fontSize: '0.7rem', padding: '3px 10px' }}>Phase {ph.num}</span>
                            <span style={{ fontSize: '0.9rem', fontWeight: 700 }}>{ph.fullName || phase}</span>
                          </div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.65 }}>{ph.desc}</div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              <div className="panel" style={{ borderLeft: '3px solid var(--accent)', marginBottom: 14 }}>
                <div className="panel-body">
                  <div className="mono" style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--accent)', marginBottom: 2 }}>DETECT Function — NIST CSF 2.0</div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>ADTE's primary coverage area — identifying and analyzing security events in real time.</div>
                </div>
              </div>

              {nistPhases.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 8 }}>FIRED CATEGORIES</div>
                  {nistPhases.map(phase => (
                    <div key={phase} className="panel" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px', marginBottom: 4 }}>
                      <span className="badge badge-accent">{phase}</span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {phase.startsWith('DE.CM-1') ? 'Network monitoring'
                          : phase.startsWith('DE.CM-3') ? 'Personnel activity monitoring'
                          : phase.startsWith('DE.CM-7') ? 'Monitoring for unauthorised access'
                          : phase}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 8 }}>CSF 2.0 FUNCTIONS</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 16 }}>
                {NIST_FUNCTIONS.map(fn => (
                  <span key={fn} className={`badge ${fn === 'DETECT' ? 'badge-accent' : ''}`}
                    style={fn !== 'DETECT' ? { background: 'var(--bg-elevated)', border: '1px solid var(--border)', color: 'var(--text-muted)' } : {}}>
                    {fn}
                  </span>
                ))}
              </div>

              <div className="panel">
                <div className="panel-body" style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                  ADTE covers the <strong style={{ color: 'var(--accent)' }}>DETECT</strong> function.
                  Response actions (<strong>RESPOND</strong>) are not implemented — ADTE recommends only; the safety-gate config is reserved for a future execution layer.
                </div>
              </div>
            </div>

          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: IntelView                                                      */
    /* ------------------------------------------------------------------ */

    const TAGS_VISIBLE_DEFAULT = 5;

    function IntelView({ intelIp, setIntelIp, intelResult, setIntelResult, intelLoading, setIntelLoading, intelError, setIntelError, intelHistory, setIntelHistory, autoLookupTrigger, result }) {
      const IP_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
      const IP_REGEX_G = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
      const [tagsExpanded, setTagsExpanded] = useState(false);

      // Collapse tag list whenever a new result comes in
      useEffect(() => { setTagsExpanded(false); }, [intelResult?.ip]);

      // IP Reputation signal from last triage
      const ipRepSignal = result?.report?.signal_summary?.ip_reputation;
      const repDetail = ipRepSignal?.detail || result?.rationale?.find(r => r.signal === 'ip_reputation')?.detail || '';
      const repIps = [...new Set(repDetail.match(IP_REGEX_G) || [])];
      const repScore = ipRepSignal?.score ?? 0;
      const repMaxPts = SIGNAL_WEIGHTS.ip_reputation;
      const repConf = ipRepSignal?.confidence ?? 0;
      const repIsMalicious = repScore > 0;
      const repColor = repIsMalicious ? 'var(--critical)' : 'var(--success)';

      useEffect(() => {
        if (result && !intelIp) {
          const detail = result?.report?.signal_summary?.ip_reputation?.detail || '';
          const match = detail.match(IP_REGEX);
          if (match) setIntelIp(match[0]);
        }
      }, [result]);

      const handleLookup = useCallback(() => {
        if (!intelIp.trim()) return;
        setIntelLoading(true); setIntelError(null); setIntelResult(null);
        fetch(`${API_BASE}/api/intel?ip=${encodeURIComponent(intelIp.trim())}`, { headers: authHeaders() })
          .then(r => r.json().then(d => ({ ok: r.ok, d })))
          .then(({ ok, d }) => {
            if (!ok) { setIntelError(d.error || 'Lookup failed'); return; }
            setIntelResult(d);
            setIntelHistory(h => [d, ...h.filter(x => x.ip !== d.ip)].slice(0, 5));
          })
          .catch(() => setIntelError('Network error — is the server running?'))
          .finally(() => setIntelLoading(false));
      }, [intelIp]);

      // Auto-lookup when navigated here programmatically (e.g. click IP in queue)
      useEffect(() => {
        if (autoLookupTrigger > 0 && intelIp.trim()) handleLookup();
      }, [autoLookupTrigger]);

      const verdictColor = intelResult
        ? (intelResult.is_malicious ? 'var(--critical)' : 'var(--success)')
        : 'var(--text-muted)';

      return (
        <div style={{ padding: 24, maxWidth: 760 }}>
          <Breadcrumb view="intel" />

          {/* IP Reputation Signal — from last triage */}
          {result && (
            <>
              <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: 8 }}>IP REPUTATION SIGNAL — LAST TRIAGE</div>
              <div className="panel" style={{ marginBottom: repIps.length > 0 ? 10 : 20 }}>
                <div className="panel-body">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
                    <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SIGNAL SCORE</span>
                    <span className="mono" style={{ fontSize: '0.8rem', color: repColor, fontWeight: 600 }}>{repScore}/{repMaxPts} pts · conf {Math.round(repConf * 100)}%</span>
                  </div>
                  <div className="score-bar-track" style={{ height: 5, marginBottom: 10 }}>
                    <div style={{ width: `${Math.min(100, (repScore / repMaxPts) * 100)}%`, height: '100%', background: repColor, borderRadius: 3 }} />
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{repDetail || 'No detail available.'}</div>
                </div>
              </div>
              {repIps.length > 0 && (
                <>
                  <div className="data-table" style={{ marginBottom: 6 }}>
                    <div className="data-table-header" style={{ gridTemplateColumns: '1fr 80px 1fr' }}>
                      <span>IP Address</span><span>Score</span><span>Tags</span>
                    </div>
                    {repIps.map(ip => (
                      <div key={ip} className="data-table-row" style={{ gridTemplateColumns: '1fr 80px 1fr', cursor: 'pointer' }}
                        onClick={() => { setIntelIp(ip); setIntelError(null); setIntelResult(null); }}
                        title={`Populate lookup for ${ip}`}>
                        <span className="mono" style={{ fontSize: '0.8rem', color: repIsMalicious ? 'var(--critical)' : 'var(--text-primary)', textDecoration: 'underline dotted' }}>{ip}</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                          <div style={{ width: 32, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{ width: `${Math.round(repConf * 100)}%`, height: '100%', background: repColor, borderRadius: 2 }} />
                          </div>
                          <span className="mono" style={{ fontSize: '0.7rem', color: repColor }}>{Math.round(repConf * 100)}</span>
                        </div>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {repIsMalicious
                            ? ['c2', 'malicious'].map(t => <span key={t} className="badge badge-critical">{t}</span>)
                            : <span className="badge badge-success">clean</span>
                          }
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 8, textAlign: 'right' }}>
                    Click any IP to populate the lookup below
                  </div>
                </>
              )}
              <div style={{ borderTop: '1px solid var(--border)', margin: '16px 0' }} />
            </>
          )}

          <h2 className="heading" style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 16 }}>IP Threat Intelligence</h2>

          <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
            <input
              type="text" value={intelIp} onChange={e => setIntelIp(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleLookup()}
              placeholder="Enter IPv4 address (e.g. 198.51.100.23)"
              className="mono" style={{ flex: 1, fontSize: '0.85rem' }}
            />
            <button className="btn btn-primary" onClick={handleLookup} disabled={intelLoading || !intelIp.trim()}>
              {intelLoading ? 'Looking up…' : 'Enrich'}
            </button>
          </div>

          {intelError && (
            <div className="panel" style={{ borderLeft: '3px solid var(--medium)', marginBottom: 16 }}>
              <div className="panel-body mono" style={{ fontSize: '0.75rem', color: 'var(--medium)' }}>⚠ {intelError}</div>
            </div>
          )}

          {intelResult && (
            <div className="panel" style={{ marginBottom: 20 }}>
              <div style={{ padding: '16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span className="mono" style={{ fontSize: '1.3rem', fontWeight: 500 }}>{intelResult.ip}</span>
                <span className={`badge ${intelResult.is_malicious ? 'badge-critical' : 'badge-success'}`} style={{ fontSize: '0.75rem', padding: '4px 12px' }}>
                  {intelResult.is_malicious ? 'MALICIOUS' : 'CLEAN'}
                </span>
              </div>
              <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                <div>
                  <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 4 }}>CONFIDENCE</div>
                  <div className="score-bar-track" style={{ height: 4, marginBottom: 4 }}>
                    <div style={{ width: `${(intelResult.confidence * 100).toFixed(0)}%`, height: '100%', background: verdictColor, borderRadius: 2 }} />
                  </div>
                  <span className="mono" style={{ fontSize: '0.8rem', color: verdictColor, fontWeight: 600 }}>{(intelResult.confidence * 100).toFixed(0)}%</span>
                </div>
                <div>
                  <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 4 }}>SOURCE</div>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{intelResult.source}</span>
                </div>
                <div>
                  <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 4 }}>QUERIED</div>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    {intelResult.queried_at ? intelResult.queried_at.slice(0,19).replace('T',' ') : '—'}
                  </span>
                </div>
              </div>
              {intelResult.tags && intelResult.tags.length > 0 && (() => {
                const tags = intelResult.tags;
                const badgeCls = intelResult.is_malicious ? 'badge-critical' : 'badge-low';
                const hasMore = tags.length > TAGS_VISIBLE_DEFAULT;
                const visible = tagsExpanded ? tags : tags.slice(0, TAGS_VISIBLE_DEFAULT);
                return (
                  <div style={{ padding: '0 16px 14px' }}>
                    <div className="mono" style={{ fontSize: '0.58rem', color: 'var(--text-muted)', marginBottom: 6, letterSpacing: '0.06em' }}>
                      TAGS · {tags.length} total
                    </div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                      {visible.map(tag => (
                        <span key={tag} className={`badge ${badgeCls}`}>{tag}</span>
                      ))}
                      {hasMore && !tagsExpanded && (
                        <span style={{ fontSize: '0.68rem', color: 'var(--accent)', cursor: 'pointer', textDecoration: 'underline dotted', whiteSpace: 'nowrap' }}
                          onClick={() => setTagsExpanded(true)}>
                          +{tags.length - TAGS_VISIBLE_DEFAULT} more — see all
                        </span>
                      )}
                      {tagsExpanded && (
                        <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', cursor: 'pointer', textDecoration: 'underline dotted', whiteSpace: 'nowrap' }}
                          onClick={() => setTagsExpanded(false)}>
                          show less
                        </span>
                      )}
                    </div>
                  </div>
                );
              })()}
            </div>
          )}

          {intelHistory.length > 0 && (
            <div className="panel">
              <div className="panel-header">Recent Lookups</div>
              {intelHistory.map((h, i) => (
                <div key={h.ip} onClick={() => { setIntelIp(h.ip); setIntelResult(h); setIntelError(null); }}
                  style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px', borderBottom: i < intelHistory.length - 1 ? '1px solid var(--border)' : 'none', cursor: 'pointer', transition: 'background 0.1s' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                  <span className="mono" style={{ fontSize: '0.8rem', flex: 1, color: h.is_malicious ? 'var(--critical)' : 'var(--text-primary)' }}>{h.ip}</span>
                  <span className={`badge ${h.is_malicious ? 'badge-critical' : 'badge-success'}`}>
                    {h.is_malicious ? 'MALICIOUS' : 'CLEAN'}
                  </span>
                  <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{(h.confidence * 100).toFixed(0)}%</span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>›</span>
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: IpRepView                                                      */
    /* ------------------------------------------------------------------ */

    function IpRepView({ result, onGoTriage, onGoIntel }) {
      if (!result) {
        return (
          <div style={{ padding: 24, maxWidth: 760 }}>
            <Breadcrumb view="iprep" />
            <NoResultBanner onGoTriage={onGoTriage} />
          </div>
        );
      }

      const IP_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
      const ipRepSignal = result?.report?.signal_summary?.ip_reputation;
      const detail = ipRepSignal?.detail || result?.rationale?.find(r => r.signal === 'ip_reputation')?.detail || '';
      const ips = detail.match(IP_REGEX) || [];
      const uniqueIps = [...new Set(ips)];
      const score = ipRepSignal?.score ?? 0;
      const maxPts = SIGNAL_WEIGHTS.ip_reputation;
      const conf = ipRepSignal?.confidence ?? 0;
      const isMalicious = score > 0;
      const repColor = isMalicious ? 'var(--critical)' : 'var(--success)';

      return (
        <div style={{ padding: 24, maxWidth: 760 }}>
          <Breadcrumb view="iprep" />
          <h2 className="heading" style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 16 }}>IP Reputation — Last Triage</h2>

          <div className="panel" style={{ marginBottom: 16 }}>
            <div className="panel-body">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
                <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SIGNAL SCORE</span>
                <span className="mono" style={{ fontSize: '0.8rem', color: repColor, fontWeight: 600 }}>{score}/{maxPts} pts · conf {Math.round(conf * 100)}%</span>
              </div>
              <div className="score-bar-track" style={{ height: 5, marginBottom: 10 }}>
                <div style={{ width: `${Math.min(100, (score / maxPts) * 100)}%`, height: '100%', background: repColor, borderRadius: 3 }} />
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{detail || 'No detail available.'}</div>
            </div>
          </div>

          {uniqueIps.length > 0 && (
            <div className="data-table">
              <div className="data-table-header" style={{ gridTemplateColumns: '1fr 80px 1fr' }}>
                <span>IP Address</span><span>Score</span><span>Tags</span>
              </div>
              {uniqueIps.map(ip => (
                <div key={ip} className="data-table-row" style={{ gridTemplateColumns: '1fr 80px 1fr', cursor: onGoIntel ? 'pointer' : 'default' }}
                  onClick={() => onGoIntel && onGoIntel(ip)}
                  title={onGoIntel ? `Look up ${ip} in Threat Intel` : undefined}>
                  <span className="mono" style={{ fontSize: '0.8rem', color: isMalicious ? 'var(--critical)' : 'var(--text-primary)', textDecoration: onGoIntel ? 'underline dotted' : 'none' }}>{ip}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <div style={{ width: 32, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: `${Math.round(conf * 100)}%`, height: '100%', background: repColor, borderRadius: 2 }} />
                    </div>
                    <span className="mono" style={{ fontSize: '0.7rem', color: repColor }}>{Math.round(conf * 100)}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {isMalicious
                      ? ['c2', 'malicious'].map(t => <span key={t} className="badge badge-critical">{t}</span>)
                      : <span className="badge badge-success">clean</span>
                    }
                  </div>
                </div>
              ))}
            </div>
          )}
          {uniqueIps.length > 0 && onGoIntel && (
            <div className="mono" style={{ marginTop: 8, fontSize: '0.6rem', color: 'var(--text-muted)', textAlign: 'right' }}>
              Click any IP to look it up in Threat Intel
            </div>
          )}
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: SafetyView                                                     */
    /* ------------------------------------------------------------------ */

    function SafetyView() {
      const [cfg, setCfg] = useState(null);
      const [loading, setLoading] = useState(true);

      useEffect(() => {
        fetch(`${API_BASE}/api/config`, { headers: authHeaders() })
          .then(r => r.json())
          .then(d => { setCfg(d); setLoading(false); })
          .catch(() => setLoading(false));
      }, []);

      return (
        <div style={{ padding: 24 }}>
          <Breadcrumb view="safety" />
          <h2 className="heading" style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 4 }}>Safety Gates</h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 20 }}>
            Reserved configuration for a future execution layer — ADTE is triage-only and executes no automated actions today. These gate values are read-only from /api/config.
          </p>

          {loading && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
              {[1,2,3,4,5,6].map(i => <div key={i} className="skeleton" style={{ height: 140 }} />)}
            </div>
          )}

          {!loading && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
              {GATES.map((gate, idx) => {
                const val = cfg?.[gate.cfgKey];
                const [statusLabel, statusColor] = gate.activeLabel(val);
                return (
                  <div key={gate.id} className="panel animate-in" style={{ animationDelay: `${idx * 0.05}s` }}>
                    <div style={{ padding: '14px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '2px 8px', borderRadius: 3 }}>
                            {gate.id}
                          </span>
                          <span style={{ fontSize: '0.85rem', fontWeight: 700 }}>{gate.name}</span>
                        </div>
                        <span className="mono" style={{ fontSize: '0.65rem', fontWeight: 700, color: statusColor, border: `1px solid ${statusColor}`, padding: '2px 8px', borderRadius: 3 }}>
                          {statusLabel}
                        </span>
                      </div>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 8, lineHeight: 1.6 }}>{gate.desc}</p>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', lineHeight: 1.7 }}>
                        <span style={{ color: 'var(--text-secondary)' }}>Condition:</span> {gate.condition}<br/>
                        <span style={{ color: 'var(--text-secondary)' }}>Action:</span> {gate.action}
                      </div>
                      <div className="mono" style={{ marginTop: 8, fontSize: '0.65rem', color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '3px 8px', borderRadius: 3, display: 'inline-block' }}>
                        {gate.env}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: WeightsView                                                    */
    /* ------------------------------------------------------------------ */

    function WeightsView() {
      const donutRef = useRef(null);
      const chartRef = useRef(null);

      useEffect(() => {
        if (!donutRef.current) return;
        if (chartRef.current) chartRef.current.destroy();
        const ctx = donutRef.current.getContext('2d');
        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';

        chartRef.current = new Chart(ctx, {
          type: 'doughnut',
          data: {
            labels: CORE_WEIGHTS_DATA.map(w => w.label),
            datasets: [{
              data: CORE_WEIGHTS_DATA.map(w => w.weight),
              backgroundColor: CORE_WEIGHTS_DATA.map(w => w.color),
              borderColor: isDark ? '#0a0a0a' : '#ffffff',
              borderWidth: 3,
            }],
          },
          options: {
            responsive: true, maintainAspectRatio: true, cutout: '60%',
            plugins: { legend: { display: false } },
          },
        });
        return () => { if (chartRef.current) chartRef.current.destroy(); };
      }, []);

      const WAZUH_SKIPPED = ['impossible_travel', 'mfa_fatigue'];
      const remaining3 = CORE_WEIGHTS_DATA.filter(w => !WAZUH_SKIPPED.includes(w.name));
      const skipped3 = CORE_WEIGHTS_DATA.filter(w => WAZUH_SKIPPED.includes(w.name));
      const total3 = remaining3.reduce((s, w) => s + w.weight, 0);

      return (
        <div style={{ padding: 24, maxWidth: 900 }}>
          <Breadcrumb view="weights" />
          <h2 className="heading" style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 4 }}>Signal Weight Model</h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 20 }}>Core signals sum to 100. When correlated case context exists, a sixth additive signal (Cluster Context) adds up to +15 — final score capped at 100. Solo alerts are unaffected.</p>

          <div style={{ display: 'flex', gap: 30, alignItems: 'flex-start', marginBottom: 24, flexWrap: 'wrap' }}>
            <div style={{ width: 180, height: 180, flexShrink: 0 }}>
              <canvas ref={donutRef} />
            </div>
            <div style={{ flex: 1, minWidth: 220 }}>
              {CORE_WEIGHTS_DATA.map(w => (
                <div key={w.name} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                  <div style={{ width: 12, height: 12, borderRadius: 2, background: w.color, flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '0.8rem', fontWeight: 600, marginBottom: 2 }}>{w.label}</div>
                    <div className="score-bar-track" style={{ height: 4 }}>
                      <div style={{ width: `${w.weight}%`, height: '100%', background: w.color, borderRadius: 2 }} />
                    </div>
                  </div>
                  <span className="mono" style={{ fontSize: '0.85rem', fontWeight: 700, color: w.color, width: 28, textAlign: 'right' }}>{w.weight}</span>
                </div>
              ))}
              {/* Additive signals — sit outside the 100-pt core donut. */}
              {WEIGHTS_DATA.filter(w => w.context).map((cc, i) => (
                <div key={cc.name} style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 6, paddingTop: 10, borderTop: i === 0 ? '1px dashed var(--border)' : 'none' }}>
                  <div style={{ width: 12, height: 12, borderRadius: 2, background: cc.color, flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: '0.8rem', fontWeight: 600, marginBottom: 2, display: 'flex', alignItems: 'center', gap: 6 }}>
                      {cc.label}
                      <span className="badge" style={{ fontSize: '0.5rem', background: `${cc.color}1f`, color: cc.color, border: `1px solid ${cc.color}` }}>ADDITIVE</span>
                    </div>
                    <div className="score-bar-track" style={{ height: 4 }}>
                      {/* Additive weights can exceed 100% of the 100-pt core scale; clamp the bar. */}
                      <div style={{ width: `${Math.min(100, cc.weight)}%`, height: '100%', background: cc.color, borderRadius: 2 }} />
                    </div>
                  </div>
                  <span className="mono" style={{ fontSize: '0.85rem', fontWeight: 700, color: cc.color, width: 28, textAlign: 'right' }}>+{cc.weight}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Detail table */}
          <div className="data-table" style={{ marginBottom: 20 }}>
            <div className="data-table-header" style={{ gridTemplateColumns: '1fr 60px 1fr 80px' }}>
              <span>Signal</span><span>Weight</span><span>Detection Method</span><span>MITRE</span>
            </div>
            {WEIGHTS_DATA.map(w => (
              <div key={w.name} className="data-table-row" style={{ gridTemplateColumns: '1fr 60px 1fr 80px', cursor: 'default' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: w.color }} />
                  <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>{w.label}</span>
                  {w.context && (
                    <span className="badge" style={{ fontSize: '0.55rem', background: `${w.color}1f`, color: w.color, border: `1px solid ${w.color}` }}>ADDITIVE +{w.weight}</span>
                  )}
                </div>
                <span className="mono" style={{ fontSize: '0.8rem', color: w.color, fontWeight: 700 }}>{w.weight}</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{w.method}</span>
                <span className="badge badge-accent">{w.mitre}</span>
              </div>
            ))}
          </div>

          {/* Redistribution */}
          <div className="panel" style={{ marginBottom: 8 }}>
            <div className="panel-header">Weight Redistribution (Wazuh Mode)</div>
            <div className="panel-body">
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                Wazuh alerts carry no geolocation or MFA data. The two skipped signals' combined
                weight ({skipped3.reduce((s,w) => s+w.weight, 0)} pts) is redistributed proportionally
                across the {remaining3.length} evaluable core signals ({total3} pts → scaled to 100).
                Additive signals (File Reputation, Cluster Context) are excluded — they never enter redistribution.
              </p>
              <div className="data-table" style={{ marginTop: 12 }}>
                <div className="data-table-header" style={{ gridTemplateColumns: '1fr 80px 100px 80px' }}>
                  <span>Signal</span><span>Original</span><span>Redistributed</span><span>Change</span>
                </div>
                {skipped3.map(w => (
                  <div key={w.name} className="data-table-row" style={{ gridTemplateColumns: '1fr 80px 100px 80px', cursor: 'default', opacity: 0.5 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 8, height: 8, borderRadius: 2, background: w.color, flexShrink: 0 }} />
                      <span style={{ fontSize: '0.8rem', fontWeight: 600, textDecoration: 'line-through', color: 'var(--text-muted)' }}>{w.label}</span>
                    </div>
                    <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{w.weight}</span>
                    <span className="badge" style={{ fontSize: '0.6rem', alignSelf: 'center' }}>SKIPPED</span>
                    <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>—</span>
                  </div>
                ))}
                {remaining3.map(w => {
                  const redist = Math.round(w.weight * 100 / total3);
                  const diff = redist - w.weight;
                  return (
                    <div key={w.name} className="data-table-row" style={{ gridTemplateColumns: '1fr 80px 100px 80px', cursor: 'default' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ width: 8, height: 8, borderRadius: 2, background: w.color, flexShrink: 0 }} />
                        <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>{w.label}</span>
                      </div>
                      <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{w.weight}</span>
                      <span className="mono" style={{ fontSize: '0.8rem', color: w.color, fontWeight: 700 }}>{redist}</span>
                      <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--success)' }}>+{diff}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* Lookup: ATT&CK technique ID → name, tactic, NIST CSF detect code.
       Kept in sync with examples/mitre_technique_map.yaml. */
    const MITRE_TECH_MAP = {
      'T1078.004': { name: 'Valid Accounts: Cloud Accounts',          tactic: 'Initial Access',       nist: 'DE.CM-1', nistLabel: 'Anomalies & Events' },
      'T1621':     { name: 'Multi-Factor Authentication Request Gen.', tactic: 'Credential Access',   nist: 'DE.CM-1', nistLabel: 'Anomalies & Events' },
      'T1071':     { name: 'Application Layer Protocol',              tactic: 'Command and Control',  nist: 'DE.CM-7', nistLabel: 'System Monitoring' },
      'T1078':     { name: 'Valid Accounts',                          tactic: 'Initial Access',       nist: 'DE.CM-1', nistLabel: 'Anomalies & Events' },
      'T1110':     { name: 'Brute Force',                             tactic: 'Credential Access',    nist: 'DE.CM-1', nistLabel: 'Anomalies & Events' },
      'T1021':     { name: 'Remote Services',                         tactic: 'Lateral Movement',     nist: 'DE.CM-3', nistLabel: 'Malicious Activity Monitoring' },
      'T1548':     { name: 'Abuse Elevation Control Mechanism',       tactic: 'Privilege Escalation', nist: 'DE.CM-1', nistLabel: 'Anomalies & Events' },
      'T1098':     { name: 'Account Manipulation',                    tactic: 'Persistence',          nist: 'DE.CM-3', nistLabel: 'Malicious Activity Monitoring' },
      'T1020':     { name: 'Automated Exfiltration',                  tactic: 'Exfiltration',         nist: 'DE.CM-2', nistLabel: 'Secure Configuration Monitoring' },
      'T1562':     { name: 'Indicator Removal',                       tactic: 'Defense Evasion',      nist: 'DE.CM-7', nistLabel: 'System Monitoring' },
      'T1087':     { name: 'Account Discovery',                       tactic: 'Discovery',            nist: 'DE.CM-1', nistLabel: 'Anomalies & Events' },
      'T1059':     { name: 'Command and Scripting Interpreter',       tactic: 'Execution',            nist: 'DE.CM-6', nistLabel: 'Malicious Activity Monitoring' },
    };

    const NIST_PHASE_LABEL = {
      'Containment':          'NIST SP 800-61 Rev. 2 — Phase 3: Containment, Eradication & Recovery',
      'Detection & Analysis': 'NIST SP 800-61 Rev. 2 — Phase 2: Detection & Analysis',
      'Preparation':          'NIST SP 800-61 Rev. 2 — Phase 1: Preparation',
      'Post-Incident Activity': 'NIST SP 800-61 Rev. 2 — Phase 4: Post-Incident Activity',
    };

    /* VIEW: VerdictHistoryView                                             */
    /* ------------------------------------------------------------------ */

    function VerdictHistoryView({ result, onNav }) {
      const [rows, setRows] = useState(null);
      const [loading, setLoading] = useState(true);
      const [error, setError] = useState(null);
      const [filter, setFilter] = useState('');
      const [dateRange, setDateRange] = useState('all');
      const activeId = result?.incident_id;

      const sinceParam = (range) => {
        if (range === '24h') return new Date(Date.now() - 86400000).toISOString();
        if (range === '7d')  return new Date(Date.now() - 604800000).toISOString();
        return null;
      };

      const load = useCallback((verdict, range) => {
        setLoading(true); setError(null);
        const params = new URLSearchParams({ limit: 100 });
        if (verdict) params.set('verdict', verdict);
        const since = sinceParam(range || 'all');
        if (since) params.set('since', since);
        fetch(`${API_BASE}/api/verdicts?${params}`, { headers: authHeaders() })
          .then(r => r.json().then(d => ({ ok: r.ok, d })))
          .then(({ ok, d }) => { if (ok) setRows(d.verdicts || []); else setError(d.error || 'Failed'); })
          .catch(() => setError('Network error'))
          .finally(() => setLoading(false));
      }, []);

      useEffect(() => { load('', 'all'); }, [load]);

      const handleFilterChange = (e) => { const v = e.target.value; setFilter(v); load(v || null, dateRange); };
      const handleDateRangeChange = (e) => { const v = e.target.value; setDateRange(v); load(filter || null, v); };

      const handleClear = () => {
        if (!window.confirm('Clear all verdict history? This cannot be undone.')) return;
        fetch(`${API_BASE}/api/verdicts`, { method: 'DELETE', headers: authHeaders() })
          .then(r => r.json())
          .then(d => { if (d.status === 'ok') { setRows([]); setFilter(''); setDateRange('all'); } else setError('Clear failed'); })
          .catch(() => setError('Clear failed'));
      };

      const colTemplate = '220px 170px 1fr 160px';

      // Deduplicate by incident_id (rows are newest-first; keep the latest run per ID).
      const _dedupSeen = new Set();
      const dedupedRows = (rows || []).filter(r => { if (_dedupSeen.has(r.incident_id)) return false; _dedupSeen.add(r.incident_id); return true; });

      // Pre-compute aggregates so both summary strip and column headers can share them
      const allTechs = [...new Set(dedupedRows.flatMap(r => { try { return JSON.parse(r.mitre_techniques || '[]'); } catch { return []; } }))];
      const allPhases = [...new Set(dedupedRows.map(r => r.nist_phase).filter(Boolean))];

      return (
        <div style={{ padding: 24 }}>
          <Breadcrumb view="history" />
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <h2 className="heading" style={{ fontSize: '1.1rem', fontWeight: 700 }}>Verdict History</h2>
            <select value={filter} onChange={handleFilterChange} className="mono" style={{ fontSize: '0.75rem', marginLeft: 16 }}>
              <option value="">All verdicts</option>
              <option value="high_risk">High Risk</option>
              <option value="medium_risk">Medium Risk</option>
              <option value="low_risk">Low Risk</option>
            </select>
            <select value={dateRange} onChange={handleDateRangeChange} className="mono" style={{ fontSize: '0.75rem' }}>
              <option value="all">All time</option>
              <option value="24h">Last 24 h</option>
              <option value="7d">Last 7 days</option>
            </select>
            <button className="btn btn-danger" onClick={handleClear} disabled={!rows || rows.length === 0} style={{ marginLeft: 'auto' }}>
              Clear All
            </button>
          </div>

          {loading && <div>{[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 48, marginBottom: 4 }} />)}</div>}
          {error && !loading && (
            <div className="panel" style={{ borderLeft: '3px solid var(--medium)' }}>
              <div className="panel-body mono" style={{ fontSize: '0.75rem', color: 'var(--medium)' }}>⚠ {error}</div>
            </div>
          )}
          {!loading && !error && rows && rows.length === 0 && (
            <div style={{ textAlign: 'center', paddingTop: 60, color: 'var(--text-muted)', fontSize: '0.8rem' }}>No verdicts logged yet.</div>
          )}
          {!loading && !error && rows && rows.length > 0 && (() => {
            const verdictCounts = dedupedRows.reduce((acc, r) => { acc[r.verdict] = (acc[r.verdict] || 0) + 1; return acc; }, {});
            return (
              <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-accent)', borderRadius: 6, marginBottom: 10, display: 'grid', gridTemplateColumns: colTemplate, padding: '12px 16px', gap: 0, alignItems: 'start' }}>
                <div>
                  <div className="mono" style={{ fontSize: '0.55rem', color: 'var(--text-muted)', marginBottom: 7, letterSpacing: '0.07em' }}>INCIDENTS</div>
                  <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)' }}>{dedupedRows.length}</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: 5 }}>{rows.length > dedupedRows.length ? `unique · ${rows.length} total runs` : 'logged'}</span>
                </div>
                <div>
                  <div className="mono badge-clickable" style={{ fontSize: '0.55rem', color: 'var(--accent)', marginBottom: 7, letterSpacing: '0.07em', cursor: 'pointer', textDecoration: 'underline dotted', display: 'inline-block' }}
                    onClick={() => onNav('view:signals')} title="View signal breakdown">
                    VERDICTS ↗
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    {Object.entries(verdictCounts).map(([v, count]) => {
                      const isActive = filter === v;
                      return (
                        <div key={v} style={{ display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer', opacity: isActive ? 1 : 0.85 }}
                          onClick={() => { setFilter(v); load(v); }}
                          title={`Filter table to ${VERDICT_LABEL[v] || v} verdicts${isActive ? ' (active — click to clear)' : ''}`}>
                          <VerdictBadge verdict={v} />
                          <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>×{count}</span>
                          {isActive && <span style={{ fontSize: '0.55rem', color: 'var(--accent)', marginLeft: 2 }}>●</span>}
                        </div>
                      );
                    })}
                    {filter && (
                      <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', cursor: 'pointer', textDecoration: 'underline dotted', marginTop: 2 }}
                        onClick={() => { setFilter(''); load(''); }}>
                        clear filter
                      </span>
                    )}
                  </div>
                </div>
                <div>
                  <div className="mono badge-clickable" style={{ fontSize: '0.55rem', color: 'var(--accent)', marginBottom: 7, letterSpacing: '0.07em', cursor: 'pointer', textDecoration: 'underline dotted', display: 'inline-block' }}
                    onClick={() => onNav('view:mitre', { techs: allTechs })}
                    title="View all techniques in MITRE view">
                    ALL TECHNIQUES ↗
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                    {allTechs.length ? allTechs.map(t => {
                      const meta = MITRE_TECH_MAP[t] || {};
                      return (
                        <span key={t} className="badge badge-accent badge-clickable"
                          onClick={() => onNav('view:mitre', { tech: t })}
                          title={meta.name ? `${t} — ${meta.name}\nTactic: ${meta.tactic}\nNIST CSF: ${meta.nist}\n\nClick to view this technique` : t}
                          style={{ fontSize: '0.65rem' }}>{t}</span>
                      );
                    }) : <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>—</span>}
                  </div>
                </div>
                <div>
                  <div className="mono badge-clickable" style={{ fontSize: '0.55rem', color: 'var(--accent)', marginBottom: 7, letterSpacing: '0.07em', cursor: 'pointer', textDecoration: 'underline dotted', display: 'inline-block' }}
                    onClick={() => onNav('view:mitre', { section: 'nist', nistPhases: allPhases })}
                    title="View all NIST phases in MITRE view">
                    ALL PHASES ↗
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5, alignItems: 'flex-start' }}>
                    {allPhases.length ? allPhases.map(phase => (
                      <span key={phase} className="badge badge-medium badge-clickable"
                        onClick={() => onNav('view:mitre', { section: 'nist', nistPhase: phase })}
                        title={`${NIST_PHASE_LABEL[phase] || phase}\n\nClick to view this phase`}
                        style={{ fontSize: '0.65rem', whiteSpace: 'nowrap' }}>{phase}</span>
                    )) : <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>—</span>}
                  </div>
                </div>
              </div>
            );
          })()}

          {!loading && !error && rows && rows.length > 0 && (
            <div className="data-table">
              <div className="data-table-header" style={{ gridTemplateColumns: colTemplate }}>
                <span style={{ cursor: 'pointer', textDecoration: 'underline dotted' }}
                  onClick={() => onNav('view:signals')} title="Signal Breakdown">
                  Incident · Timestamp
                </span>
                <span style={{ cursor: 'pointer', textDecoration: 'underline dotted' }}
                  onClick={() => onNav('view:signals')} title="Signal Breakdown">
                  Verdict · Risk
                </span>
                <span style={{ cursor: 'pointer', textDecoration: 'underline dotted' }}
                  onClick={() => onNav('view:mitre', { techs: allTechs })} title="View all techniques in MITRE view">
                  MITRE Techniques
                </span>
                <span style={{ cursor: 'pointer', textDecoration: 'underline dotted' }}
                  onClick={() => onNav('view:mitre', { section: 'nist', nistPhases: allPhases })} title="View all NIST phases">
                  NIST Phase
                </span>
              </div>
              {dedupedRows.map(row => {
                let techs = [];
                try { techs = row.mitre_techniques ? JSON.parse(row.mitre_techniques) : []; } catch {}
                const isLoaded = activeId === row.incident_id;
                const signalDest = isLoaded ? 'view:signals' : 'view:triage';
                const signalTip  = isLoaded ? 'View signal breakdown' : 'Load in Alert Input to re-run';
                return (
                  <div key={row.id} className="data-table-row" style={{ gridTemplateColumns: colTemplate, cursor: 'default', alignItems: 'start', paddingTop: 10, paddingBottom: 10 }}>

                    {/* Incident ID + Timestamp — both clickable to signals/triage */}
                    <div style={{ cursor: 'pointer', display: 'flex', flexDirection: 'column', gap: 4 }}
                      onClick={() => onNav(signalDest)} title={signalTip}>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--accent)', textDecoration: 'underline dotted' }}>
                        {row.incident_id}
                        {!isLoaded && <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginLeft: 4 }}>↩</span>}
                      </span>
                      <span className="mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                        {row.logged_at ? row.logged_at.slice(0,19).replace('T',' ') : '—'}
                      </span>
                    </div>

                    {/* Verdict badge + Risk score — both clickable to signals/triage */}
                    <div style={{ cursor: 'pointer', display: 'flex', flexDirection: 'column', gap: 5 }}
                      onClick={() => onNav(signalDest)} title={signalTip}>
                      <VerdictBadge verdict={row.verdict} riskScore={row.risk_score} />
                      <span className="mono" style={{ fontSize: '0.8rem', color: VERDICT_COLOR[row.verdict] || 'var(--text-muted)', fontWeight: 700 }}>
                        {row.risk_score}
                        <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', fontWeight: 400, marginLeft: 2 }}>/ 100</span>
                      </span>
                    </div>

                    {/* MITRE technique badges — each deep-links to its panel in MITRE view */}
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'flex-start' }}>
                      {techs.length
                        ? techs.map(t => {
                            const meta = MITRE_TECH_MAP[t] || {};
                            const tip = meta.name
                              ? `${t} — ${meta.name}\nTactic: ${meta.tactic}\nNIST CSF: ${meta.nist} · ${meta.nistLabel}\n\nClick to jump to this technique in MITRE view`
                              : `Click to open MITRE / NIST view`;
                            return (
                              <div key={t} style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 2 }}>
                                <span className="badge badge-accent badge-clickable"
                                  onClick={() => onNav('view:mitre', { tech: t })} title={tip}
                                  style={{ fontSize: '0.65rem' }}>
                                  {t}
                                </span>
                                {meta.tactic && (
                                  <span style={{ fontSize: '0.52rem', color: 'var(--text-muted)', paddingLeft: 1, letterSpacing: '0.02em' }}>
                                    {meta.tactic}
                                  </span>
                                )}
                              </div>
                            );
                          })
                        : <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>—</span>
                      }
                    </div>

                    {/* NIST phase badge — deep-links to NIST section in MITRE view */}
                    {row.nist_phase ? (
                      <span className="badge badge-medium badge-clickable"
                        onClick={() => onNav('view:mitre', { section: 'nist', nistPhase: row.nist_phase })}
                        title={`${NIST_PHASE_LABEL[row.nist_phase] || 'NIST SP 800-61 Rev. 2 — ' + row.nist_phase}\n\nClick to jump to NIST section in MITRE view`}
                        style={{ fontSize: '0.65rem', whiteSpace: 'nowrap' }}>
                        {row.nist_phase}
                      </span>
                    ) : (
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>—</span>
                    )}

                  </div>
                );
              })}
            </div>
          )}
          {!loading && !error && rows && rows.length > 0 && (
            <div className="mono" style={{ marginTop: 8, fontSize: '0.6rem', color: 'var(--text-muted)', textAlign: 'right' }}>
              Incident / Timestamp → Signal Breakdown &nbsp;·&nbsp; Verdict / Risk → Signal Breakdown &nbsp;·&nbsp; Blue [T-ID] → MITRE view (jumps to technique) &nbsp;·&nbsp; Yellow phase → NIST section &nbsp;·&nbsp; ↩ loads in Alert Input
            </div>
          )}
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: FeedbackHistoryView                                            */
    /* ------------------------------------------------------------------ */

    function FeedbackHistoryView() {
      const [rows, setRows] = useState(null);
      const [loading, setLoading] = useState(true);
      const [error, setError] = useState(null);
      const [labelFilter, setLabelFilter] = useState('all');
      const [searchText, setSearchText] = useState('');

      // Load from server whenever the label filter changes.
      const load = useCallback((label) => {
        setLoading(true); setError(null);
        const params = new URLSearchParams();
        if (label && label !== 'all') params.set('label', label);
        const qs = params.toString();
        fetch(`${API_BASE}/api/feedback${qs ? '?' + qs : ''}`, { headers: authHeaders() })
          .then(r => r.json().then(d => ({ ok: r.ok, d })))
          .then(({ ok, d }) => { if (ok) setRows(d.feedback || []); else setError(d.error || 'Failed'); })
          .catch(() => setError('Network error'))
          .finally(() => setLoading(false));
      }, []);

      useEffect(() => { load('all'); }, [load]);

      const handleLabelChange = (e) => {
        const v = e.target.value;
        setLabelFilter(v);
        setSearchText('');  // clear search when label changes
        load(v);
      };

      const handleClear = () => {
        if (!window.confirm('Clear all feedback history? This cannot be undone.')) return;
        fetch(`${API_BASE}/api/feedback`, { method: 'DELETE', headers: authHeaders() })
          .then(r => r.json())
          .then(d => { if (d.status === 'ok') { setRows([]); setSearchText(''); } else setError('Clear failed'); })
          .catch(() => setError('Clear failed'));
      };

      // Client-side filter: substring match on incident_id and ip (case-insensitive).
      const visibleRows = rows
        ? rows.filter(r =>
            !searchText ||
            r.incident_id.toLowerCase().includes(searchText.toLowerCase()) ||
            (r.ip || '').toLowerCase().includes(searchText.toLowerCase())
          )
        : null;

      const colTemplate = '170px 150px 90px 1fr';
      const inputStyle = { fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 4, color: 'var(--text-primary)', padding: '4px 8px' };

      return (
        <div style={{ padding: 24 }}>
          <Breadcrumb view="feedbackhist" />
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
            <h2 className="heading" style={{ fontSize: '1.1rem', fontWeight: 700 }}>Feedback History</h2>

            {/* Label filter — server-side */}
            <select value={labelFilter} onChange={handleLabelChange} style={{ ...inputStyle, marginLeft: 16 }}>
              <option value="all">All Labels</option>
              <option value="fp">False Positive</option>
              <option value="tp">True Positive</option>
            </select>

            {/* Text search — client-side, partial match on ID or IP */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <input type="text" value={searchText} onChange={e => setSearchText(e.target.value)}
                placeholder="Search ID or IP…" style={{ ...inputStyle, minWidth: 180 }} />
              {searchText && (
                <button onClick={() => setSearchText('')}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.85rem', padding: '2px 4px' }}>✕</button>
              )}
            </div>

            {/* Row count badge */}
            {!loading && rows !== null && (
              <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                {searchText
                  ? `${visibleRows.length} of ${rows.length}`
                  : `${rows.length} row${rows.length !== 1 ? 's' : ''}`}
              </span>
            )}

            <button className="btn btn-danger" onClick={handleClear} disabled={!rows || rows.length === 0} style={{ marginLeft: 'auto' }}>
              Clear All
            </button>
          </div>

          {loading && <div>{[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 40, marginBottom: 4 }} />)}</div>}
          {error && !loading && (
            <div className="panel" style={{ borderLeft: '3px solid var(--medium)' }}>
              <div className="panel-body mono" style={{ fontSize: '0.75rem', color: 'var(--medium)' }}>⚠ {error}</div>
            </div>
          )}
          {!loading && !error && visibleRows && visibleRows.length === 0 && (
            <div style={{ textAlign: 'center', paddingTop: 60, color: 'var(--text-muted)', fontSize: '0.8rem' }}>
              {rows && rows.length > 0 ? 'No rows match your search.' : 'No feedback submitted yet.'}
            </div>
          )}
          {!loading && !error && visibleRows && visibleRows.length > 0 && (
            <div className="data-table">
              <div className="data-table-header" style={{ gridTemplateColumns: colTemplate }}>
                {['Submitted At', 'Incident ID', 'Label', 'IP'].map(h => <span key={h}>{h}</span>)}
              </div>
              {visibleRows.map(row => (
                <div key={row.id} className="data-table-row" style={{ gridTemplateColumns: colTemplate, cursor: 'default' }}>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {row.submitted_at ? row.submitted_at.slice(0,19).replace('T',' ') : '—'}
                  </span>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{row.incident_id}</span>
                  <span className={`badge ${row.label === 'fp' ? 'badge-critical' : 'badge-success'}`}>
                    {row.label === 'fp' ? 'FALSE POS' : 'TRUE POS'}
                  </span>
                  <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{row.ip || '—'}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: AuditView (Verdict History + Feedback History)                */
    /* ------------------------------------------------------------------ */

    function AuditView({ result, onNav }) {
      const [tab, setTab] = useState('verdicts');
      const tabStyle = (key) => ({
        background: 'none', border: 'none', borderBottom: tab === key ? '2px solid var(--accent)' : '2px solid transparent',
        color: tab === key ? 'var(--accent)' : 'var(--text-muted)',
        fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', fontWeight: tab === key ? 600 : 400,
        padding: '8px 16px', cursor: 'pointer', letterSpacing: '0.04em',
      });
      return (
        <div>
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', paddingLeft: 24 }}>
            <button style={tabStyle('verdicts')} onClick={() => setTab('verdicts')}>VERDICTS</button>
            <button style={tabStyle('feedback')} onClick={() => setTab('feedback')}>FEEDBACK</button>
          </div>
          {tab === 'verdicts' && <VerdictHistoryView result={result} onNav={onNav} />}
          {tab === 'feedback' && <FeedbackHistoryView />}
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* VIEW: SettingsView (LLM Config)                                      */
    /* ------------------------------------------------------------------ */

    function SettingsView({ llmAvailable }) {
      const [adteApiKey, setAdteApiKey] = useState('');
      const [keyStatus, setKeyStatus] = useState(null); // null | 'checking' | 'ok' | 'invalid'
      const [keyRole, setKeyRole] = useState('');

      // On mount: probe whether an existing HttpOnly session cookie is valid.
      // JS cannot read the cookie itself — the browser sends it automatically.
      useEffect(() => {
        fetch(`${API_BASE}/api/auth-check`, { credentials: 'include' })
          .then(r => r.json().then(d => ({ ok: r.ok, d })))
          .then(({ ok, d }) => {
            if (ok && d.authenticated && d.role && d.role !== 'open') {
              setKeyStatus('ok');
              setKeyRole(d.role);
            }
          })
          .catch(() => {});
      }, []);

      const handleLogin = () => {
        const trimmed = adteApiKey.trim();
        if (!trimmed) return;
        setKeyStatus('checking');
        // POST key once to exchange for an HttpOnly session cookie.
        // The raw key is never written to sessionStorage or localStorage.
        fetch(`${API_BASE}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ api_key: trimmed }),
        })
          .then(r => r.json().then(d => ({ ok: r.ok, d })))
          .then(({ ok, d }) => {
            if (ok && d.authenticated) {
              setKeyStatus('ok');
              setKeyRole(d.role || '');
              setAdteApiKey(''); // wipe input — key is now server-side only
            } else {
              setKeyStatus('invalid');
              setKeyRole('');
            }
          })
          .catch(() => { setKeyStatus('invalid'); setKeyRole(''); });
      };

      const handleLogout = () => {
        fetch(`${API_BASE}/api/auth/logout`, { method: 'POST', credentials: 'include' })
          .finally(() => { setKeyStatus(null); setKeyRole(''); setAdteApiKey(''); });
      };

      const isLoggedIn = keyStatus === 'ok';
      const keyStatusLabel = keyStatus === 'checking' ? 'VERIFYING…'
        : keyStatus === 'ok' ? `SESSION ACTIVE · ${keyRole.toUpperCase().replace(/_/g, ' ')}`
        : keyStatus === 'invalid' ? 'INVALID KEY'
        : 'OPEN MODE';
      const keyStatusClass = keyStatus === 'ok' ? 'badge-success'
        : keyStatus === 'invalid' ? 'badge-high'
        : '';
      const panelBorder = keyStatus === 'ok' ? '3px solid var(--success)'
        : keyStatus === 'invalid' ? '3px solid var(--high)'
        : '3px solid var(--border)';

      return (
        <div style={{ padding: 24, maxWidth: 600 }}>
          <Breadcrumb view="settings" />
          <h2 className="heading" style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 4 }}>Settings</h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 20 }}>
            All API keys are stored server-side as environment variables. The browser session uses an HttpOnly cookie — the key is never stored in JS-accessible storage.
          </p>

          <div className="panel" style={{ marginBottom: 16, borderLeft: panelBorder }}>
            <div className="panel-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span>ADTE Session</span>
              <span className={`badge ${keyStatusClass}`} style={{ fontSize: '0.55rem' }}>
                {keyStatusLabel}
              </span>
            </div>
            <div className="panel-body">
              {isLoggedIn ? (
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--success)', marginBottom: 10 }}>
                    Authenticated as <strong>{keyRole.replace(/_/g, ' ')}</strong>. Session expires in 8 hours.
                  </div>
                  <button className="btn btn-danger" onClick={handleLogout}>Log Out</button>
                </div>
              ) : (
                <div>
                  <input type="password" value={adteApiKey}
                    onChange={e => { setAdteApiKey(e.target.value); setKeyStatus(null); setKeyRole(''); }}
                    onKeyDown={e => e.key === 'Enter' && handleLogin()}
                    placeholder="Paste your ADTE API key…" className="mono"
                    style={{ width: '100%', fontSize: '0.8rem', marginBottom: 8 }} />
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 10 }}>
                    Key is exchanged for an HttpOnly session cookie — it is never stored in the browser after login.
                  </div>
                  {keyStatus === 'invalid' && (
                    <div style={{ fontSize: '0.7rem', color: 'var(--high)', marginBottom: 8, fontWeight: 600 }}>
                      Key not recognised — check it matches an <code>ADTE_API_KEY_*</code> value in your <code>.env</code>.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {!isLoggedIn && (
              <button className="btn btn-primary" onClick={handleLogin} disabled={!adteApiKey.trim()}>Log In</button>
            )}
          </div>

          <div className="panel" style={{ marginTop: 20, borderLeft: '3px solid var(--medium)' }}>
            <div className="panel-body" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
              <strong style={{ color: 'var(--medium)' }}>Note:</strong> LLM output is display-only and never feeds back into scoring.
              All verdicts are deterministic. RBAC is enforced server-side only when <code>ADTE_API_KEY_*</code> env vars are set.
              Threat intel keys (VirusTotal, OTX, AbuseIPDB) are configured server-side via env vars — see <code>.env.example</code>.
            </div>
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* NL Query Bar                                                         */
    /* ------------------------------------------------------------------ */

    function QueryBar({ onQuery, provider }) {
      const [query, setQuery] = useState('');
      const [response, setResponse] = useState(null);
      const [loading, setLoading] = useState(false);

      const handleSubmit = () => {
        if (!query.trim() || loading) return;
        setLoading(true); setResponse(null);
        fetch(`${API_BASE}/api/triage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...authHeaders() },
          body: JSON.stringify({ query: query.trim() }),
        })
          .then(r => r.json())
          .then(d => setResponse(d.report?.one_paragraph_summary || d.error || 'No summary available'))
          .catch(() => setResponse('Query failed — check server connection'))
          .finally(() => setLoading(false));
      };

      return (
        <div className="query-bar">
          <span className={`badge ${provider === 'anthropic' ? 'badge-accent' : 'badge-success'}`} style={{ flexShrink: 0 }}>
            {provider === 'anthropic' ? 'Claude' : 'GPT'}
          </span>
          <input
            className="query-input" type="text"
            value={query} onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            placeholder="Ask ADTE... (natural language query)"
          />
          <button className="btn btn-primary" onClick={handleSubmit} disabled={loading || !query.trim()}
            style={{ padding: '8px 12px', display: 'flex', alignItems: 'center', gap: 6 }}>
            <IconSend size={14} />
          </button>
          {response && (
            <div style={{ position: 'absolute', bottom: '100%', left: 24, right: 24, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: '8px 8px 0 0', padding: '12px 16px', maxHeight: 200, overflowY: 'auto' }}>
              <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--accent)', marginBottom: 4 }}>SUMMARY</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{response}</div>
              <button onClick={() => setResponse(null)} style={{ position: 'absolute', top: 8, right: 12, background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16 }}>×</button>
            </div>
          )}
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* Agent View — in-progress placeholder                                 */
    /* ------------------------------------------------------------------ */

    function AgentView({ query }) {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 440, padding: '60px 24px', textAlign: 'center' }}>
          <div style={{ width: 64, height: 64, borderRadius: '50%', background: 'var(--bg-elevated)', border: '1px solid var(--border-accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 24 }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
            <span className="mono" style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.06em' }}>AGENTIC ANALYSIS</span>
            <span className="badge badge-medium" style={{ fontSize: '0.55rem', letterSpacing: '0.1em' }}>IN PROGRESS</span>
          </div>

          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', maxWidth: 500, lineHeight: 1.75, marginBottom: 32 }}>
            Natural language querying and autonomous alert investigation are under active development.
            This capability will allow analysts to ask questions about incidents, request deeper analysis,
            and trigger guided response workflows directly from the query bar.
          </p>

          {query && (
            <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 20px', maxWidth: 500, width: '100%', marginBottom: 28, textAlign: 'left' }}>
              <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 6, letterSpacing: '0.08em' }}>YOUR QUERY</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>"{query}"</div>
            </div>
          )}

          <div className="panel" style={{ borderLeft: '3px solid var(--accent)', maxWidth: 500, width: '100%', textAlign: 'left' }}>
            <div className="panel-body" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.7 }}>
              <strong style={{ color: 'var(--text-secondary)' }}>Planned capabilities:</strong> on-demand incident summarisation, cross-alert correlation queries, and guided MITRE technique drill-down with full audit trail.
            </div>
          </div>
        </div>
      );
    }

    /* ------------------------------------------------------------------ */
    /* App                                                                  */
    /* ------------------------------------------------------------------ */

    function App() {
      const [inputText, setInputText] = useState('');
      const [examples, setExamples] = useState(null);
      const [exampleCursor, setExampleCursor] = useState(0);
      const [loadedKey, setLoadedKey] = useState(null);
      const [result, setResult] = useState(null);
      const [batchResults, setBatchResults] = useState(null);   // array of per-alert entries from /api/triage/batch
      const [batchMeta, setBatchMeta] = useState(null);         // { count, succeeded, failed }
      const [loading, setLoading] = useState(false);
      const [error, setError] = useState(null);
      const [triageCount, setTriageCount] = useState(0);
      const [scoreBarPct, setScoreBarPct] = useState(0);
      const [utcTime, setUtcTime] = useState('--:--:-- UTC');
      const [activeView, setActiveView] = useState('queue');
      const [serverOnline, setServerOnline] = useState(true);
      const [lastTriageTime, setLastTriageTime] = useState(null);
      const [intelIp, setIntelIp] = useState('');
      const [intelResult, setIntelResult] = useState(null);
      const [intelHistory, setIntelHistory] = useState([]);
      const [intelLoading, setIntelLoading] = useState(false);
      const [intelError, setIntelError] = useState(null);
      const [intelAutoLookupTrigger, setIntelAutoLookupTrigger] = useState(0);
      const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
      const [theme, setTheme] = useState('dark');
      const [llmAvailable, setLlmAvailable] = useState(false);
      const [queryBarInput, setQueryBarInput] = useState('');
      const [agentQuery, setAgentQuery] = useState('');
      const [mitreHighlight, setMitreHighlight] = useState(null);
      const [mitreFocusTechs, setMitreFocusTechs] = useState(null);
      const [mitreNistPhases2, setMitreNistPhases2] = useState(null);
      const [focusCaseId, setFocusCaseId] = useState(null);   // case pre-expanded when opening the Cases view
      const llmProvider = 'anthropic';

      useEffect(() => {
        fetch(`${API_BASE}/api/examples`, { headers: authHeaders() }).then(r => r.json()).then(setExamples).catch(() => {});
      }, []);

      useEffect(() => {
        const tick = () => setUtcTime(new Date().toISOString().slice(11,19) + ' UTC');
        tick(); const id = setInterval(tick, 1000); return () => clearInterval(id);
      }, []);

      useEffect(() => {
        const check = () => fetch(`${API_BASE}/health`, { headers: authHeaders() }).then(r => setServerOnline(r.ok)).catch(() => setServerOnline(false));
        check(); const id = setInterval(check, 30000); return () => clearInterval(id);
      }, []);

      useEffect(() => {
        fetch(`${API_BASE}/api/config`, { headers: authHeaders() })
          .then(r => r.json())
          .then(d => setLlmAvailable(d.llm_available === true))
          .catch(() => {});
      }, []);

      useEffect(() => {
        if (!result) return;
        // Reset to 0 first so the CSS width transition always plays from zero.
        // The 80 ms delay gives the browser one frame to paint the reset before
        // animating to the target score — without it the bar jumps immediately.
        setScoreBarPct(0);
        const t = setTimeout(() => setScoreBarPct(result.risk_score), 80);
        return () => clearTimeout(t);
      }, [result]);

      const toggleTheme = () => {
        const next = theme === 'dark' ? 'light' : 'dark';
        setTheme(next);
        document.documentElement.setAttribute('data-theme', next);
      };

      const isLive = lastTriageTime && (Date.now() - lastTriageTime) < 60000;

      // handleNav routes to any view and optionally pre-focuses the MITRE panel.
      // Three context shapes:
      //   { tech }       — single technique badge clicked → scroll + flash that card
      //   { techs }      — "All techniques" from summary strip → highlight set
      //   { section: 'nist', nistPhase? / nistPhases? } → scroll to NIST section
      const handleNav = useCallback((action, ctx) => {
        setActiveView(action.replace('view:', ''));
        // Sidebar navigation shows the fresh case list; only openCase()
        // (which bypasses handleNav) pre-expands a specific case.
        setFocusCaseId(null);
        if (ctx?.tech) {
          setMitreHighlight(ctx.tech);
          setMitreFocusTechs([ctx.tech]);
          setMitreNistPhases2(null);
        } else if (ctx?.techs) {
          setMitreHighlight(null);
          setMitreFocusTechs(ctx.techs);
          setMitreNistPhases2(null);
        } else if (ctx?.section === 'nist') {
          setMitreHighlight('__nist__');
          setMitreFocusTechs(null);
          setMitreNistPhases2(ctx.nistPhase ? [ctx.nistPhase] : ctx.nistPhases || null);
        } else {
          setMitreFocusTechs(null);
          setMitreNistPhases2(null);
        }
      }, []);

      const openCase = useCallback((caseId) => {
        setFocusCaseId(caseId);
        setActiveView('cases');
      }, []);

      const navigateToIntel = useCallback((ip) => {
        setIntelIp(ip);
        setIntelResult(null);
        setIntelError(null);
        setActiveView('intel');
        // Increment (not toggle) so navigating to the same IP twice still fires
        // IntelView's useEffect — a boolean flip would no-op on repeated calls.
        setIntelAutoLookupTrigger(t => t + 1);
      }, []);

      const handleLoadExample = useCallback(() => {
        if (!examples) return;
        const key = EXAMPLE_KEYS[exampleCursor % EXAMPLE_KEYS.length];
        setInputText(JSON.stringify(examples[key], null, 2));
        setLoadedKey(key);
        setExampleCursor(c => (c + 1) % EXAMPLE_KEYS.length);
        setResult(null); setError(null); setBatchResults(null); setBatchMeta(null);
      }, [examples, exampleCursor]);

      const handleLoadSpecific = useCallback((key) => {
        if (!examples) return;
        setInputText(JSON.stringify(examples[key], null, 2));
        setLoadedKey(key);
        setResult(null); setError(null); setBatchResults(null); setBatchMeta(null);
      }, [examples]);

      const runTriage = useCallback((parsed) => {
        setLoading(true); setError(null); setResult(null); setBatchResults(null); setBatchMeta(null);
        const useLlm = llmAvailable;
        const url = useLlm ? `${API_BASE}/api/triage?use_llm=true` : `${API_BASE}/api/triage`;
        fetch(url, {
          method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
          credentials: 'include',   // send the HttpOnly adte_session cookie set by /api/auth/login
          body: JSON.stringify(parsed),
        })
          // Parse the body defensively: an auth/RBAC block or a proxy/CSRF
          // rejection may carry a non-JSON body, and a parse throw must never
          // be reported as a generic "network error".
          .then(async r => {
            let d = null;
            try { d = await r.json(); } catch { /* non-JSON body */ }
            return { ok: r.ok, status: r.status, d };
          })
          .then(({ ok, status, d }) => {
            if (ok) { setResult(d); setTriageCount(c => c + 1); setLastTriageTime(Date.now()); return; }
            // Surface the real reason per HTTP status so a role-based-access
            // failure is not mislabelled as a CORS or network problem.
            if (status === 401) {
              setError(`${d?.error || 'Authentication required'} — open Settings (gear icon, top-right) and log in with your API key.`);
            } else if (status === 403) {
              // Includes the CSRF "Cross-origin request rejected" and the
              // demo-mode / insufficient-permissions messages verbatim.
              setError(d?.error || 'Request forbidden by the server.');
            } else {
              setError(d?.error || `Triage failed (HTTP ${status}).`);
            }
          })
          .catch(() => setError('Could not reach the triage API — check your connection, or sign in via Settings if this deployment is secured.'))
          .finally(() => setLoading(false));
      }, [llmAvailable]);

      const runBatchTriage = useCallback((parsed) => {
        setLoading(true); setError(null); setResult(null); setBatchResults(null); setBatchMeta(null);
        fetch(`${API_BASE}/api/triage/batch`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
          credentials: 'include',   // send the HttpOnly adte_session cookie set by /api/auth/login
          body: JSON.stringify(parsed),
        })
          .then(async r => {
            let d = null;
            try { d = await r.json(); } catch { /* non-JSON body */ }
            return { ok: r.ok, status: r.status, d };
          })
          .then(({ ok, status, d }) => {
            if (ok) {
              setBatchResults(d.results || []);
              setBatchMeta({ count: d.count, succeeded: d.succeeded, failed: d.failed, cases: d.cases || [] });
              setTriageCount(c => c + (d.succeeded || 0));
              setLastTriageTime(Date.now());
              return;
            }
            if (status === 401) {
              setError(`${d?.error || 'Authentication required'} — open Settings (gear icon, top-right) and log in with your API key.`);
            } else if (status === 403) {
              setError(d?.error || 'Request forbidden by the server.');
            } else {
              setError(d?.error || `Batch triage failed (HTTP ${status}).`);
            }
          })
          .catch(() => setError('Could not reach the triage API — check your connection, or sign in via Settings if this deployment is secured.'))
          .finally(() => setLoading(false));
      }, []);

      const handleRunTriage = useCallback(() => {
        let parsed;
        try { parsed = JSON.parse(inputText); }
        catch { setError('Invalid JSON — check syntax before submitting'); return; }
        // Batch detection mirrors the backend's _extract_batch_items: a bare
        // array, {"alerts":[...]} (unless it's a raw Sentinel incident, which
        // legitimately carries an `alerts` list), or a full _search response.
        // Single-element wrappers stay on /api/triage, which unwraps them.
        const batchItems = Array.isArray(parsed) ? parsed
          : (parsed && Array.isArray(parsed.alerts) && !(parsed.incident_id && parsed.title)) ? parsed.alerts
          : (parsed && parsed.hits && Array.isArray(parsed.hits.hits)) ? parsed.hits.hits
          : null;
        if (batchItems && batchItems.length > 1) runBatchTriage(parsed);
        else runTriage(parsed);
      }, [inputText, runTriage, runBatchTriage]);

      const handleLoadIncident = useCallback((row) => {
        const json = row.incident_json;
        setInputText(JSON.stringify(json, null, 2));
        setLoadedKey(null);
        setActiveView('triage');
        setTimeout(() => runTriage(json), 80);
      }, [runTriage]);

      const canRun = !loading && inputText.trim().length > 0;

      return (
        <div>
          <Sidebar
            activeView={activeView} onNav={handleNav}
            triageCount={triageCount} serverOnline={serverOnline}
            collapsed={sidebarCollapsed} onToggleCollapse={() => setSidebarCollapsed(c => !c)}
          />

          <div className="content-area" style={{ marginLeft: sidebarCollapsed ? 56 : 240 }}>
            {/* Header */}
            <header className="app-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {VIEW_LABELS[activeView] || activeView}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                {isLive && <span className="mono badge badge-success" style={{ fontSize: '0.6rem' }}>● LIVE</span>}
                <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>TRG/{String(triageCount).padStart(3,'0')}</span>
                <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{utcTime}</span>
                <button onClick={toggleTheme} className="theme-toggle" title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`} />
                <button onClick={() => setActiveView('settings')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}>
                  <IconSettings size={18} />
                </button>
              </div>
            </header>

            {/* Content */}
            <div style={{ flex: 1, overflowY: 'auto', paddingBottom: 64, minHeight: 0 }}>
              {activeView === 'queue' && <QueueView onLoadIncident={handleLoadIncident} onGoIntel={navigateToIntel} />}
              {activeView === 'cases' && <CasesView focusCaseId={focusCaseId} onGoIntel={navigateToIntel} />}
              {activeView === 'signals' && <SignalsView result={result} onGoTriage={() => setActiveView('triage')} />}
              {activeView === 'mitre' && <MitreView result={result} onGoTriage={() => setActiveView('triage')} highlight={mitreHighlight} focusTechs={mitreFocusTechs} focusNistPhases={mitreNistPhases2} />}
              {activeView === 'intel' && (
                <IntelView intelIp={intelIp} setIntelIp={setIntelIp}
                  intelResult={intelResult} setIntelResult={setIntelResult}
                  intelLoading={intelLoading} setIntelLoading={setIntelLoading}
                  intelError={intelError} setIntelError={setIntelError}
                  intelHistory={intelHistory} setIntelHistory={setIntelHistory}
                  autoLookupTrigger={intelAutoLookupTrigger}
                  result={result} />
              )}
              {activeView === 'safety' && <SafetyView />}
              {activeView === 'weights' && <WeightsView />}
              {activeView === 'audit' && <AuditView result={result} onNav={handleNav} />}
              {activeView === 'settings' && <SettingsView llmAvailable={llmAvailable} />}
              {activeView === 'agent' && <AgentView query={agentQuery} />}

              {activeView === 'triage' && (
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 440px) 1fr', height: '100%' }}>
                  {/* Left: Input */}
                  <div style={{ borderRight: '1px solid var(--border)', padding: 24, paddingBottom: 64, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>ALERT INPUT</div>
                    <textarea
                      value={inputText}
                      onChange={e => { setInputText(e.target.value); setError(null); }}
                      placeholder={"// Paste NormalizedIncident JSON here\n// or click Load Example\n{\n  \"incident_id\": \"INC-...\",\n  ...\n}"}
                      style={{ flex: 1, minHeight: 200, width: '100%' }}
                      spellCheck={false}
                    />

                    {/* Scenario tiles — fill space, replace generic Load Example */}
                    <div>
                      <div className="mono" style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 8, letterSpacing: '0.08em' }}>QUICK LOAD</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {EXAMPLE_KEYS.map(key => (
                          <button key={key} className="btn" onClick={() => handleLoadSpecific(key)} disabled={!examples}
                            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', textAlign: 'left',
                              borderColor: loadedKey === key ? 'var(--accent)' : undefined,
                              background: loadedKey === key ? 'var(--accent-dim)' : undefined }}>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{EXAMPLE_DESCRIPTIONS[key]}</span>
                            <span className={`badge ${EXAMPLE_BADGE_CLASS[key]}`} style={{ fontSize: '0.5rem', flexShrink: 0, marginLeft: 8 }}>{EXAMPLE_DISPLAY[key]}</span>
                          </button>
                        ))}
                      </div>
                    </div>

                    <button className="btn btn-primary" onClick={handleRunTriage} disabled={!canRun} style={{ width: '100%' }}>
                      {loading ? 'Processing…' : '▶ Run Triage'}
                    </button>
                    {error && (
                      <div className="panel" style={{ borderLeft: '3px solid var(--medium)' }}>
                        <div className="panel-body mono" style={{ fontSize: '0.75rem', color: 'var(--medium)' }}>⚠ {error}</div>
                      </div>
                    )}
                  </div>

                  {/* Right: Results */}
                  <div style={{ padding: 24, paddingBottom: 64, overflowY: 'auto' }}>
                    <div className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: 12 }}>TRIAGE RESULTS</div>
                    {loading && <LoadingSkeleton />}
                    {!loading && !result && !batchResults && (
                      <div style={{ paddingTop: 80, textAlign: 'center' }}>
                        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--border-accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        <div className="mono" style={{ color: 'var(--text-muted)', marginTop: 16, fontSize: '0.7rem', letterSpacing: '0.15em' }}>
                          AWAITING INPUT
                        </div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 8, opacity: 0.6 }}>
                          Paste alert JSON or load an example
                        </div>
                      </div>
                    )}
                    {!loading && batchResults && (
                      <BatchResultsTable
                        results={batchResults} meta={batchMeta}
                        selectedIndex={result ? result.index : null}
                        onSelect={r => setResult(r)}
                        onOpenCase={openCase}
                      />
                    )}
                    {!loading && result && <TriageResult result={result} scoreBarPct={scoreBarPct} onOpenCase={openCase} />}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Query Bar */}
          <div className="query-bar" style={{ left: sidebarCollapsed ? 56 : 240 }}>
            <span className="badge badge-accent" style={{ flexShrink: 0, fontSize: '0.55rem' }}>Claude</span>
            <span className="badge badge-medium" style={{ flexShrink: 0, fontSize: '0.5rem', letterSpacing: '0.08em' }}>COMING SOON</span>
            <input
              className="query-input" type="text"
              value={queryBarInput}
              onChange={e => setQueryBarInput(e.target.value)}
              placeholder="Ask ADTE... (agentic queries — not yet implemented)"
              onKeyDown={e => {
                if (e.key === 'Enter' && queryBarInput.trim()) {
                  setAgentQuery(queryBarInput.trim());
                  setQueryBarInput('');
                  setActiveView('agent');
                }
              }}
            />
            <button className="btn btn-primary" style={{ padding: '8px 12px' }}
              onClick={() => {
                if (!queryBarInput.trim()) return;
                setAgentQuery(queryBarInput.trim());
                setQueryBarInput('');
                setActiveView('agent');
              }}>
              <IconSend size={14} />
            </button>
          </div>
        </div>
      );
    }

    ReactDOM.createRoot(document.getElementById('root')).render(<App />);
