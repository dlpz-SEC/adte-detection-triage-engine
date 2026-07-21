// ADTE Overview — the landing page a first-time visitor sees before entering the
// console. Pure static content: no fetches, no auth, renders identically for
// anonymous visitors. One-way dependency: app.jsx imports this file; this file
// imports only React. Copy lives in data consts below so future edits are
// content edits, not component surgery.
import React from 'react';

// Point-in-time claims. Source of truth: the portfolio-sync skill's
// references/current-claims.md (regenerated from the repos by collect_stats.py).
// Bump here when the claims file changes.
const STATS = [
  { value: '669', label: 'Passing Tests' },
  { value: '7', label: 'Scoring Signals' },
  { value: '24', label: 'REST Route Handlers' },
  { value: '42', label: 'ATT&CK Map Entries' },
];

const GITHUB_URL = 'https://github.com/dlpz-SEC/adte-detection-triage-engine';

// ---------------------------------------------------------------------------
// Pipeline stages — shared data for both diagram variants. Sublines are kept
// short; the full detail lives in STAGE_DETAILS prose below the diagram.
// ---------------------------------------------------------------------------
const PIPELINE_STAGES = [
  { key: 'ingest',   label: 'INGEST',      sub1: '4 auto-detected shapes',      sub2: 'multi-alert → /api/triage/batch' },
  { key: 'normalize',label: 'NORMALIZE',   sub1: 'OCSF-inspired schema',        sub2: 'input severity rejected' },
  { key: 'peek',     label: 'CASE PEEK',   sub1: 'read-only correlation',       sub2: 'runs before scoring' },
  { key: 'enrich',   label: 'ENRICH',      sub1: 'AbuseIPDB · VirusTotal · OTX', sub2: 'FP registry · user history' },
  { key: 'score',    label: 'SCORE',       sub1: '5 weighted signals Σ 100', sub2: '+15 cluster · +40 file · cap 100' },
  { key: 'verdict',  label: 'VERDICT',     sub1: 'deterministic',               sub2: 'same input, same score', chips: true },
  { key: 'audit',    label: 'AUDIT LOG',   sub1: 'SQLite forensic trail',       sub2: 'written before case ingest' },
  { key: 'case',     label: 'CASE INGEST', sub1: 'fail-open join / create',     sub2: 'IP · user · hash · 60 min' },
  { key: 'respond',  label: 'RESPOND',     sub1: 'per-signal rationale',        sub2: 'recommendations only' },
];

const STAGE_DETAILS = [
  { n: '01', title: 'Ingest', body: 'POST /api/triage auto-detects four input shapes: a canonical NormalizedIncident, a raw Wazuh/OpenSearch alert, a Sentinel-format incident, or a batch wrapper holding exactly one alert. Multi-alert payloads route to POST /api/triage/batch — capped at 25 alerts with a 45 s deadline and per-alert error isolation.' },
  { n: '02', title: 'Normalize', body: 'Every source lands in one OCSF-inspired schema: events[] with per-event type and auth status, a top-level source enum. Input severity is rejected outright — the engine derives it from the computed score, so a source can never pre-inflate its own priority. Malformed input returns 422, never 500.' },
  { n: '03', title: 'Correlation peek', body: 'Before scoring, a read-only peek asks the case store whether sibling alerts already share this alert’s source IP, user, or file hash. The peek excludes the incident’s own ID, so re-triaging an alert can never boost itself.' },
  { n: '04', title: 'Enrich', body: 'Threat intel per unique IP across AbuseIPDB, VirusTotal, and AlienVault OTX, aggregated with provider-failure isolation — with no API keys a deterministic mock feed answers instead. Plus the analyst-fed false-positive registry, per-user behavioral history, and bounded file-hash lookups (at most 5 per alert).' },
  { n: '05', title: 'Score', body: 'Five core weighted signals summing to exactly 100: impossible travel 30, MFA fatigue 25, IP reputation 20, device novelty 15, login-hour anomaly 10. A signal with no evaluable data skips, and its weight redistributes proportionally across the rest — a Wazuh alert with no geo data still scores over the full 0–100 range. Two additive aggravators then apply only when their evidence exists: cluster context up to +15, file reputation up to +40, capped at 100 total. Aggravators can raise a score, never lower one.' },
  { n: '06', title: 'Verdict', body: 'Below 30 is low risk, 30–70 is medium, above 70 is high. Fully deterministic — the same incident always produces the same score, the same per-signal rationale, the same recommendation. There is no black box to argue with.' },
  { n: '07', title: 'Audit, correlate, respond', body: 'The verdict is written to the SQLite audit trail first, then a fail-open case ingest joins or creates a correlated case (shared source IP, user, or file hash inside a 60-minute window; a kill-chain flag fires on 3+ ascending ATT&CK tactics across 2+ members). The response carries the score, verdict, per-signal rationale, MITRE technique details, and recommended actions.' },
  { n: '✦', title: 'LLM narrative — advisory only', body: 'An optional Claude-generated analyst narrative (use_llm) runs after the verdict is final and falls back to a deterministic template. It annotates decisions; it cannot make them — a design invariant, not a configuration.' },
];

// ---------------------------------------------------------------------------
// Console tour — icons are the exact NAV paths from app.jsx (duplicated by
// design: this file must not import from app.jsx).
// ---------------------------------------------------------------------------
const VIEW_CARDS = [
  { action: 'view:triage', label: 'Alert Input', auth: null,
    icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2',
    desc: 'Paste any incident JSON — or Quick Load a bundled scenario — and run triage. Renders the score, verdict, and per-signal breakdown. The workspace is open; running triage requires an analyst login.' },
  { action: 'view:queue', label: 'Alert Queue', auth: 'ANALYST LOGIN',
    icon: 'M4 6h16M4 10h16M4 14h16M4 18h16',
    desc: 'Live auto-refreshing alert table — a Wazuh Indexer when reachable, an 8-alert demo seed otherwise — with verdict distribution and hourly volume charts.' },
  { action: 'view:cases', label: 'Cases', auth: 'ANALYST LOGIN',
    icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z',
    desc: 'Correlated incident cases: alerts grouped by shared IP, user, or file hash, with kill-chain progression across ATT&CK tactics.' },
  { action: 'view:signals', label: 'Signal Breakdown', auth: null,
    icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
    desc: 'Reference for all 7 signals — weight, detection method, MITRE technique, NIST control — overlaid with live scores from your last triage run.' },
  { action: 'view:mitre', label: 'MITRE / NIST', auth: null,
    icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    desc: 'Maps triage results onto the ATT&CK tactic/technique matrix and the NIST 800-61 incident-response phases.' },
  { action: 'view:intel', label: 'Threat Intel', auth: 'ANALYST LOGIN',
    icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z',
    desc: 'IP-reputation lookup across AbuseIPDB, VirusTotal, and OTX with aggregation and lookup history.' },
  { action: 'view:safety', label: 'Safety Gates', auth: 'SENIOR LOGIN',
    icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
    desc: 'Read-only display of the six reserved execution gates — kill switch, dry run, allowlists. ADTE is triage-only today; the gates exist for a future that must be explicitly enabled.' },
  { action: 'view:weights', label: 'Signal Weights', auth: null,
    icon: 'M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4',
    desc: 'Visualizes how the signals compose the score — weight doughnut plus per-signal method cards.' },
  { action: 'view:audit', label: 'Audit Log', auth: 'ANALYST LOGIN',
    icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
    desc: 'Tabbed verdict and analyst-feedback history — the NIST 800-61 non-repudiation trail. Deletes are soft, preserving forensics.' },
  { action: 'view:agent', label: 'Agentic Analysis', auth: null, badge: 'IN PROGRESS',
    icon: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z',
    desc: 'Placeholder for natural-language querying and autonomous investigation. Honestly labeled: in progress, not shipped.' },
];

// ---------------------------------------------------------------------------
// Security posture — every claim here was verified against the code.
// ---------------------------------------------------------------------------
const SECURITY_CONTROLS = [
  { title: 'Role-based access control', body: 'Four roles — readonly < analyst < senior_analyst < admin — with a per-route minimum. API keys are compared in constant time (hmac.compare_digest); unknown roles fail closed.' },
  { title: 'Per-route rate limiting', body: 'flask-limiter on every data route: triage 10/min, batch 5/min, queue 20/min, intel 30/min, destructive deletes 5/min. A custom JSON 429 keeps errors structured.' },
  { title: 'CSRF origin gate', body: 'Every state-changing /api/ request has its Origin checked against the host before RBAC even runs — defense-in-depth on top of SameSite=Strict cookies. ProxyFix trusts exactly one TLS proxy hop, no more.' },
  { title: 'Session design', body: 'Login exchanges the API key for a session token stored SHA-256-hashed at rest — the server keeps only the hash. HttpOnly + SameSite=Strict + Secure cookie, 8-hour server-side TTL, logout revocation, fail-closed on store errors.' },
  { title: 'API keys never reach the browser', body: 'RBAC and threat-intel keys live in server environment variables only. The frontend holds a cookie, never a key; /api/config masks values to first-4/last-4; HTTP client logging is pinned so auth headers cannot leak into logs.' },
  { title: 'Security headers', body: 'Content-Security-Policy with no unsafe-inline scripts, Strict-Transport-Security, X-Frame-Options DENY, X-Content-Type-Options nosniff — on every response.' },
  { title: 'SSRF defense', body: 'The Wazuh indexer URL passes a scheme allowlist, a cloud-metadata host block (169.254.169.254, metadata.google.internal), and a link-local IP check. Disabling TLS verification is refused for any non-localhost host.' },
  { title: 'Strict input validation', body: 'Pydantic models on every boundary; input severity rejected by design; malformed payloads return 422, never a 500 with internals; 1 MB body cap; batch capped at 25 alerts / 45 s; wrapper nesting bounded.' },
  { title: 'Demo-mode lockdown', body: 'With no API keys configured the server refuses every write — all POST/PUT/DELETE return 403. An unkeyed deployment cannot be driven.' },
  { title: 'Parameterized SQL throughout', body: 'Every query in the audit, session, and case stores uses placeholder binding — injection payloads are stored as inert data, verified by a dedicated test file. Deletes are soft (deleted_at), preserving the forensic trail.' },
  { title: 'Audit access log', body: 'One structured line per API request — IP, role, method, path, status. Request bodies are never logged.' },
  { title: 'Supply-chain pinning', body: 'Every dependency carries both bounds (e.g. requests>=2.32.4,<3.0) so a redeploy can never silently pull a breaking or unvetted major release. Security floors raised proactively on CVEs.' },
];

const PATCHED_VULNS = [
  { sev: 'high', tone: 'var(--high)', title: 'Unsafe href sink — alert-supplied VirusTotal permalink',
    found: 'The malware evidence panel rendered the alert’s embedded VirusTotal permalink directly as a link target. Alert fields describe what an adversary did — and the triage endpoint accepts pasted JSON, so that URL is attacker-authored.',
    impact: 'A crafted alert could plant an arbitrary link dressed as a VirusTotal report — a phishing vector. Script execution was already blocked by the CSP, which is exactly why the framing here is phishing, not code execution.',
    fix: 'The permalink is now allowlisted before rendering: https only, virustotal.com or its subdomains only, otherwise no link is rendered at all.' },
  { sev: 'high', tone: 'var(--high)', title: 'Self-inflicted denial of service — intel client blocking the request thread',
    found: 'The VirusTotal client slept out its 15-second rate window on the request thread. Enrichment iterates observables sequentially, so a queue refresh with ~10 unique IPs blocked for ~150 seconds — and gunicorn’s 60-second timeout killed the worker.',
    impact: 'A worker-killing stall an attacker could drive on demand with a single many-hash alert.',
    fix: 'The client now abstains instead of sleeping: inside a closed rate window it returns a neutral error result the aggregator excludes from its average. No intel client may ever block the request thread — that is now a documented invariant with regression tests.' },
  { sev: 'high', tone: 'var(--high)', title: 'TLS verification disabled by default in the Wazuh adapter',
    found: 'The indexer client defaulted to verify_ssl=False and the environment loader never overrode it — certificate validation was silently off.',
    impact: 'Alert ingestion was open to man-in-the-middle interception on any non-local deployment.',
    fix: 'Verification now defaults on, and explicitly disabling it is refused for any non-localhost host. The process-wide urllib3 warning suppression that hid the problem was replaced with a narrowly scoped one.' },
  { sev: 'medium', tone: 'var(--medium)', title: 'CSRF origin gate false-403 behind TLS termination',
    found: 'Behind Railway’s TLS proxy, gunicorn saw http internally while browsers sent an https Origin — the exact-match origin check rejected every legitimate same-origin POST, including login itself.',
    impact: 'The deployed app was unusable — and the failure masked the real auth errors behind it.',
    fix: 'ProxyFix now trusts exactly one proxy hop (x_proto/x_host/x_for), restoring the true external scheme, host, and client IP. Two regression tests pin the behavior: same-origin-behind-proxy passes, foreign origins still 403.' },
  { sev: 'medium', tone: 'var(--medium)', title: 'Prompt injection surface in the LLM narrative path',
    found: 'Alert text flows into the optional Claude narrative prompt, and alert text is attacker-authored — instruction-override and role-impersonation payloads were a real concern (MITRE ATLAS AML.T0051 / T0054).',
    impact: 'A crafted alert could attempt to steer the analyst-facing narrative.',
    fix: 'Two layers: alert data is wrapped in explicit untrusted-data delimiters with the system role in a separate API field, and a sanitizer redacts override phrases, role impersonation, and zero-width characters. A 30-payload adversarial corpus runs in CI. The invariant that matters most: the verdict is computed before any LLM call — injection can distort a narrative, never a decision.' },
  { sev: 'medium', tone: 'var(--medium)', title: 'Session state lost across gunicorn workers',
    found: 'Sessions lived in an in-process dict. With two gunicorn workers, roughly half of authenticated requests landed on the worker that had never seen the session — random “Session expired” failures.',
    impact: 'Unreliable auth in production, and a reliability bug wearing a security symptom.',
    fix: 'Sessions moved to a SQLite store shared by all workers — which is also what brought SHA-256-hashed tokens at rest, server-side TTL, and real logout revocation.' },
  { sev: 'low', tone: 'var(--low)', title: 'Hardening batch from the security audit',
    found: 'A structured self-audit (high/medium/low findings, all tracked to closure) surfaced a set of smaller defects.',
    impact: 'Individually minor; collectively the difference between code that works and code that holds.',
    fix: 'MFA-fatigue event-ordering bug under descending sort; missing HTTP timeouts on outbound calls; CLI error messages leaking schema internals; a ZeroDivision guard when every signal skips; false-positive-registry entries validated with warnings instead of silently dropped; strict CIDR parsing.' },
];

// ---------------------------------------------------------------------------
// Small shared pieces
// ---------------------------------------------------------------------------
function SectionHeading({ eyebrow, title, sub }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div className="mono" style={{ fontSize: '0.65rem', fontWeight: 600, letterSpacing: '0.18em', color: '#c0392b', marginBottom: 6 }}>
        {eyebrow}
      </div>
      <h2 className="heading" style={{ fontSize: '1.7rem', fontWeight: 700, letterSpacing: '0.02em', color: 'var(--text-primary)', margin: 0, textTransform: 'uppercase' }}>
        {title}
      </h2>
      {sub && <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: '8px 0 0', maxWidth: 720, lineHeight: 1.6 }}>{sub}</p>}
    </div>
  );
}

// The sidebar's bar-constructed eye mark, enlarged for the hero.
function LogoMark({ size = 92 }) {
  return (
    <svg width={size} height={size * 0.52} viewBox="-44 -23 88 46" fill="none" aria-hidden="true">
      <g fill="#c0392b">
        <rect x="-12" y="-22" width="24" height="5" />
        <rect x="-23" y="-13" width="14" height="5" />
        <rect x="9" y="-13" width="14" height="5" />
        <rect x="-31" y="-4" width="19" height="5" />
        <rect x="12" y="-4" width="19" height="5" />
        <rect x="-6" y="-4" width="12" height="5" />
        <rect x="-23" y="5" width="14" height="5" />
        <rect x="9" y="5" width="14" height="5" />
        <rect x="-12" y="14" width="24" height="5" />
        <rect x="-42" y="-2" width="10" height="2" opacity="0.5" />
        <rect x="32" y="-2" width="10" height="2" opacity="0.5" />
      </g>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Pipeline diagram — one stage-box renderer, two geometries. Inline SVG is
// document markup, so CSS variables resolve and both themes work untouched.
// ---------------------------------------------------------------------------
function StageBox({ x, y, w, h, stage }) {
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="6" fill="var(--bg-elevated)" stroke="var(--border-accent)" strokeWidth="1" />
      <rect x={x} y={y} width="3" height={h} rx="1.5" fill={stage.key === 'verdict' ? 'var(--medium)' : 'var(--accent)'} />
      <text x={x + 14} y={y + 24} fill="var(--text-primary)" fontSize="12" fontWeight="700" fontFamily="var(--font-mono)" letterSpacing="1.5">
        {stage.label}
      </text>
      {stage.chips ? (
        <g fontFamily="var(--font-mono)" fontSize="8.5" fontWeight="600">
          <rect x={x + 12} y={y + 36} width={(w - 36) / 3} height="18" rx="3" fill="var(--low-dim, rgba(107,114,128,0.15))" />
          <text x={x + 12 + (w - 36) / 6} y={y + 48} fill="var(--low)" textAnchor="middle">{'<30 LOW'}</text>
          <rect x={x + 18 + (w - 36) / 3} y={y + 36} width={(w - 36) / 3} height="18" rx="3" fill="var(--medium-dim, rgba(234,179,8,0.15))" />
          <text x={x + 18 + (w - 36) / 2} y={y + 48} fill="var(--medium)" textAnchor="middle">30-70 MED</text>
          <rect x={x + 24 + 2 * (w - 36) / 3} y={y + 36} width={(w - 36) / 3} height="18" rx="3" fill="var(--high-dim, rgba(249,115,22,0.15))" />
          <text x={x + 24 + 5 * (w - 36) / 6} y={y + 48} fill="var(--high)" textAnchor="middle">{'>70 HIGH'}</text>
          <text x={x + 14} y={y + 70} fill="var(--text-secondary)" fontSize="9" fontFamily="var(--font-mono)">{stage.sub1} · {stage.sub2}</text>
        </g>
      ) : (
        <g fontFamily="var(--font-mono)" fontSize="9" fill="var(--text-secondary)">
          <text x={x + 14} y={y + 44}>{stage.sub1}</text>
          <text x={x + 14} y={y + 60}>{stage.sub2}</text>
        </g>
      )}
    </g>
  );
}

function ArrowDefs({ id }) {
  return (
    <defs>
      <marker id={id} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--accent)" />
      </marker>
    </defs>
  );
}

function PipelineDiagramWide() {
  const BW = 172, BH = 88, GAP = 20, Y1 = 24, Y2 = 252;
  const row1 = PIPELINE_STAGES.slice(0, 5);
  const row2 = PIPELINE_STAGES.slice(5, 9);
  const x1 = i => 12 + i * (BW + GAP);
  // Row 2 is 4 boxes — center it under row 1.
  const row2W = 4 * BW + 3 * GAP;
  const x2 = i => (960 - row2W) / 2 + i * (BW + GAP);
  const corridorY = (Y1 + BH + Y2) / 2; // wrap-around arrow corridor
  return (
    <svg className="pipeline-wide" viewBox="0 0 960 470" width="100%" preserveAspectRatio="xMidYMid meet" role="img"
      aria-label="ADTE triage pipeline: ingest, normalize, case peek, enrich, score, then verdict, audit log, case ingest, respond, with an advisory-only LLM narrative attached after the verdict">
      <ArrowDefs id="ov-arrow-w" />
      {row1.map((s, i) => <StageBox key={s.key} x={x1(i)} y={Y1} w={BW} h={BH} stage={s} />)}
      {row1.slice(0, -1).map((s, i) => (
        <line key={`a1-${i}`} x1={x1(i) + BW} y1={Y1 + BH / 2} x2={x1(i + 1) - 3} y2={Y1 + BH / 2}
          stroke="var(--accent)" strokeWidth="1.5" markerEnd="url(#ov-arrow-w)" />
      ))}
      {/* wrap-around: SCORE down, across, into VERDICT */}
      <path d={`M ${x1(4) + BW / 2} ${Y1 + BH} L ${x1(4) + BW / 2} ${corridorY} L ${x2(0) + BW / 2} ${corridorY} L ${x2(0) + BW / 2} ${Y2 - 4}`}
        fill="none" stroke="var(--accent)" strokeWidth="1.5" markerEnd="url(#ov-arrow-w)" />
      {row2.map((s, i) => <StageBox key={s.key} x={x2(i)} y={Y2} w={BW} h={BH} stage={s} />)}
      {row2.slice(0, -1).map((s, i) => (
        <line key={`a2-${i}`} x1={x2(i) + BW} y1={Y2 + BH / 2} x2={x2(i + 1) - 3} y2={Y2 + BH / 2}
          stroke="var(--accent)" strokeWidth="1.5" markerEnd="url(#ov-arrow-w)" />
      ))}
      {/* LLM advisory box — dashed, hanging off VERDICT */}
      <path d={`M ${x2(0) + BW / 2} ${Y2 + BH} L ${x2(0) + BW / 2} ${Y2 + BH + 26}`}
        fill="none" stroke="var(--medium)" strokeWidth="1.2" strokeDasharray="4 4" />
      <rect x={x2(0) - 20} y={Y2 + BH + 26} width={BW + 130} height="52" rx="6"
        fill="none" stroke="var(--medium)" strokeWidth="1.2" strokeDasharray="4 4" />
      <text x={x2(0) - 6} y={Y2 + BH + 47} fill="var(--medium)" fontSize="10.5" fontWeight="700" fontFamily="var(--font-mono)" letterSpacing="1">
        LLM NARRATIVE — ADVISORY ONLY
      </text>
      <text x={x2(0) - 6} y={Y2 + BH + 64} fill="var(--text-secondary)" fontSize="9" fontFamily="var(--font-mono)">
        runs after the verdict is final · deterministic fallback · never changes a decision
      </text>
    </svg>
  );
}

function PipelineDiagramTall() {
  const BW = 396, BH = 78, GAP = 34, X = 12;
  const y = i => 10 + i * (BH + GAP);
  const n = PIPELINE_STAGES.length;
  const llmY = y(n - 1) + BH + 30;
  return (
    <svg className="pipeline-tall" viewBox={`0 0 420 ${llmY + 96}`} width="100%" preserveAspectRatio="xMidYMid meet" role="img"
      aria-label="ADTE triage pipeline, vertical layout">
      <ArrowDefs id="ov-arrow-t" />
      {PIPELINE_STAGES.map((s, i) => <StageBox key={s.key} x={X} y={y(i)} w={BW} h={BH} stage={s} />)}
      {PIPELINE_STAGES.slice(0, -1).map((s, i) => (
        <line key={`at-${i}`} x1={X + BW / 2} y1={y(i) + BH} x2={X + BW / 2} y2={y(i + 1) - 4}
          stroke="var(--accent)" strokeWidth="1.5" markerEnd="url(#ov-arrow-t)" />
      ))}
      <path d={`M ${X + BW / 2} ${y(n - 1) + BH} L ${X + BW / 2} ${llmY}`}
        fill="none" stroke="var(--medium)" strokeWidth="1.2" strokeDasharray="4 4" />
      <rect x={X} y={llmY} width={BW} height="60" rx="6" fill="none" stroke="var(--medium)" strokeWidth="1.2" strokeDasharray="4 4" />
      <text x={X + 14} y={llmY + 24} fill="var(--medium)" fontSize="11" fontWeight="700" fontFamily="var(--font-mono)" letterSpacing="1">
        LLM NARRATIVE — ADVISORY ONLY
      </text>
      <text x={X + 14} y={llmY + 42} fill="var(--text-secondary)" fontSize="9" fontFamily="var(--font-mono)">
        after the verdict · deterministic fallback · never decides
      </text>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------
function Hero({ onEnterConsole }) {
  return (
    <div className="animate-in" style={{ padding: '48px 0 40px', borderBottom: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 24 }}>
        <LogoMark />
        <div className="mono" style={{ fontSize: '0.65rem', fontWeight: 600, letterSpacing: '0.2em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
          Portfolio project · Detection engineering · Live deployment
        </div>
      </div>
      <h1 className="heading" style={{ fontSize: 'clamp(2rem, 5vw, 3.4rem)', fontWeight: 700, lineHeight: 1.05, letterSpacing: '0.01em', margin: '0 0 18px', color: 'var(--text-primary)', textTransform: 'uppercase' }}>
        Autonomous Detection<br />& Triage Engine
      </h1>
      <p style={{ fontSize: '1rem', lineHeight: 1.7, color: 'var(--text-secondary)', maxWidth: 680, margin: '0 0 16px' }}>
        ADTE is a source-agnostic triage engine for security alerts. It ingests incidents from
        multiple SIEM formats, enriches them with threat intelligence and behavioral context,
        scores them across seven weighted signals, and returns a deterministic verdict with a
        per-signal rationale an analyst can argue with.
      </p>
      <div style={{ borderLeft: '3px solid #c0392b', padding: '10px 16px', maxWidth: 680, marginBottom: 28, background: 'var(--bg-surface)' }}>
        <span className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-primary)', fontWeight: 600 }}>
          ADTE recommends. It never executes.
        </span>
        <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          {' '}Every verdict ends at an explainable recommendation for a human analyst — there is
          no code path that mutates an external system.
        </span>
      </div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <button className="btn btn-primary" onClick={onEnterConsole} style={{ fontSize: '0.85rem', padding: '10px 22px' }}>
          Enter Console →
        </button>
        <a className="btn" href={GITHUB_URL} target="_blank" rel="noopener noreferrer"
          style={{ fontSize: '0.85rem', padding: '10px 22px', textDecoration: 'none', display: 'inline-flex', alignItems: 'center' }}>
          View on GitHub
        </a>
      </div>
    </div>
  );
}

function StatStrip() {
  return (
    <div className="animate-in" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 180px), 1fr))', gap: 12, padding: '28px 0', animationDelay: '0.08s' }}>
      {STATS.map(s => (
        <div key={s.label} className="stat-card">
          <div className="stat-value" style={{ color: 'var(--text-primary)' }}>{s.value}</div>
          <div className="stat-label">{s.label}</div>
        </div>
      ))}
    </div>
  );
}

function IdentityPanels() {
  const panels = [
    { title: 'The problem', body: 'SOC analysts drown in alerts — most are noise, and the ones that matter (credential theft, MFA fatigue, active malware) need fast, structured decisions. Manual triage is slow, inconsistent, and impossible to audit.' },
    { title: 'What ADTE does', body: 'Automates the mechanical first pass: normalize any source into one schema, enrich with intel and history, score deterministically, correlate related alerts into campaign cases, and log every verdict to a forensic audit trail.' },
    { title: 'What it never does', body: 'Act. No account disables, no file deletion, no API calls into your infrastructure. High-risk verdicts arrive as recommendations with the evidence attached — the human, or a downstream SOAR of your choosing, stays in the loop.' },
  ];
  return (
    <div className="animate-in" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 260px), 1fr))', gap: 12, paddingBottom: 40, animationDelay: '0.14s' }}>
      {panels.map(p => (
        <div key={p.title} className="panel">
          <div className="panel-header">{p.title}</div>
          <div className="panel-body" style={{ fontSize: '0.82rem', lineHeight: 1.65, color: 'var(--text-secondary)' }}>{p.body}</div>
        </div>
      ))}
    </div>
  );
}

function ArchitectureSection() {
  return (
    <div style={{ paddingBottom: 44 }}>
      <SectionHeading eyebrow="SYSTEM DESIGN" title="How a verdict is made"
        sub="One request, nine stages, no black box. The diagram is the actual request path of POST /api/triage — not a marketing abstraction." />
      <div className="panel" style={{ padding: '20px 16px', marginBottom: 20 }}>
        <PipelineDiagramWide />
        <PipelineDiagramTall />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 320px), 1fr))', gap: 12 }}>
        {STAGE_DETAILS.map(d => (
          <div key={d.n} style={{ display: 'flex', gap: 14, padding: '14px 16px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6 }}>
            <div className="mono" style={{ fontSize: '0.7rem', fontWeight: 700, color: '#c0392b', flexShrink: 0, paddingTop: 2 }}>{d.n}</div>
            <div>
              <div className="mono" style={{ fontSize: '0.72rem', fontWeight: 600, letterSpacing: '0.08em', color: 'var(--text-primary)', textTransform: 'uppercase', marginBottom: 5 }}>{d.title}</div>
              <div style={{ fontSize: '0.78rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>{d.body}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function BrainHandsSplit() {
  const row = (label, desc) => (
    <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
      <span className="mono" style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent)', flexShrink: 0, minWidth: 74 }}>{label}</span>
      <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{desc}</span>
    </div>
  );
  return (
    <div style={{ paddingBottom: 44 }}>
      <SectionHeading eyebrow="INTEGRATION" title="Brain and hands"
        sub="A separate Wazuh lab runs a full automated malware response. Rather than merge it — and reintroduce the execution path ADTE deliberately removed — the two systems divide the labor." />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))', gap: 12 }}>
        <div className="panel">
          <div className="panel-header">Hands — Wazuh detects and executes</div>
          <div className="panel-body">
            {row('RULE 554', 'File-integrity monitoring catches a file landing in the watched path')}
            {row('RULE 87105', 'The built-in VirusTotal integration scans the hash and embeds the multi-engine verdict in the alert')}
            {row('RULE 553', 'An active-response script deletes the convicted file — Wazuh executes, on its own authority')}
          </div>
        </div>
        <div className="panel">
          <div className="panel-header">Brain — ADTE triages and correlates</div>
          <div className="panel-body">
            {row('INGESTS', 'All three alerts, through the same adapter a live indexer feeds')}
            {row('SCORES', 'The embedded VirusTotal verdict powers the +40 file-reputation signal — zero additional API cost')}
            {row('CORRELATES', 'The same hash on a second host joins the first host’s case: one campaign, not two tickets')}
            {row('RECOMMENDS', 'quarantine_file · preserve_forensic_copy · hash_sweep_fleet · isolate_host — recommendations, every one')}
          </div>
        </div>
      </div>
      <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 12, textAlign: 'center', letterSpacing: '0.06em' }}>
        ADTE never deletes and never calls the Wazuh API.
      </div>
    </div>
  );
}

function ViewCardsGrid({ onNav }) {
  return (
    <div style={{ paddingBottom: 44 }}>
      <SectionHeading eyebrow="CONSOLE TOUR" title="Ten views, one investigation"
        sub="Everything below is live in this deployment — click any card to open the view. Read views work without a login; chips mark the ones whose data needs an API key in secured mode." />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))', gap: 12 }}>
        {VIEW_CARDS.map(v => (
          <div key={v.action} className="panel" onClick={() => onNav(v.action)} role="button" tabIndex={0}
            onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onNav(v.action); } }}
            style={{ cursor: 'pointer' }}>
            <div className="panel-body" style={{ display: 'flex', gap: 14 }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.5"
                strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true">
                <path d={v.icon} />
              </svg>
              <div style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5, flexWrap: 'wrap' }}>
                  <span className="mono" style={{ fontSize: '0.78rem', fontWeight: 700, letterSpacing: '0.06em', color: 'var(--text-primary)', textTransform: 'uppercase' }}>{v.label}</span>
                  {v.badge && <span className="badge badge-medium" style={{ fontSize: '0.55rem' }}>{v.badge}</span>}
                  {v.auth && <span className="mono" style={{ fontSize: '0.55rem', fontWeight: 600, letterSpacing: '0.08em', color: 'var(--text-muted)', border: '1px solid var(--border-accent)', borderRadius: 3, padding: '2px 6px' }}>{v.auth}</span>}
                </div>
                <div style={{ fontSize: '0.76rem', lineHeight: 1.55, color: 'var(--text-secondary)' }}>{v.desc}</div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SecuritySection() {
  return (
    <div style={{ paddingBottom: 44 }}>
      <SectionHeading eyebrow="SECURITY POSTURE" title="Built like a target"
        sub="A triage endpoint accepts attacker-described data by definition — every alert field is treated as hostile input. These controls are in the code, not on a roadmap." />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', gap: 12 }}>
        {SECURITY_CONTROLS.map(c => (
          <div key={c.title} style={{ padding: '14px 16px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6 }}>
            <div className="mono" style={{ fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.08em', color: 'var(--accent)', textTransform: 'uppercase', marginBottom: 6 }}>{c.title}</div>
            <div style={{ fontSize: '0.76rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>{c.body}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function PatchedVulnsList() {
  return (
    <div style={{ paddingBottom: 44 }}>
      <SectionHeading eyebrow="FOUND & FIXED" title="Vulnerabilities patched"
        sub="Found in self-audits — including adversarial review passes — and fixed with regression tests. Named here because a security tool that hides its own findings has no business scoring anyone else's." />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {PATCHED_VULNS.map((v, i) => (
          <div key={v.title} className="panel" style={{ borderLeft: `3px solid ${v.tone}` }}>
            <div className="panel-body">
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
                <span className="mono" style={{ fontSize: '0.68rem', fontWeight: 700, color: v.tone }}>{String(i + 1).padStart(2, '0')}</span>
                <span className="mono" style={{ fontSize: '0.8rem', fontWeight: 700, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>{v.title}</span>
                <span className="mono" style={{ fontSize: '0.55rem', fontWeight: 700, letterSpacing: '0.1em', color: v.tone, border: `1px solid ${v.tone}`, borderRadius: 3, padding: '2px 7px', textTransform: 'uppercase' }}>{v.sev}</span>
              </div>
              {[['FOUND', v.found], ['IMPACT', v.impact], ['FIX', v.fix]].map(([label, text]) => (
                <div key={label} style={{ display: 'flex', gap: 12, padding: '5px 0', alignItems: 'baseline' }}>
                  <span className="mono" style={{ fontSize: '0.62rem', fontWeight: 700, letterSpacing: '0.1em', color: 'var(--text-muted)', flexShrink: 0, minWidth: 52 }}>{label}</span>
                  <span style={{ fontSize: '0.78rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>{text}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function OverviewFooter() {
  return (
    <div style={{ borderTop: '1px solid var(--border)', padding: '24px 0 8px', display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'center', justifyContent: 'space-between' }}>
      <div className="mono" style={{ fontSize: '0.68rem', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>
        PYTHON 3.11 · FLASK · PYDANTIC · REACT 18 · ESBUILD · SQLITE · RAILWAY
      </div>
      <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
        <a className="mono" href={GITHUB_URL} target="_blank" rel="noopener noreferrer"
          style={{ fontSize: '0.72rem', fontWeight: 600, letterSpacing: '0.08em', color: 'var(--accent)', textDecoration: 'none' }}>
          GITHUB →
        </a>
      </div>
      <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', width: '100%' }}>
        Demo note: with no threat-intel API keys configured, enrichment answers from a deterministic
        mock feed — scores are reproducible, and the example scenarios are golden-pinned in the test suite.
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export default function OverviewPage({ onEnterConsole, onNav }) {
  return (
    <div style={{ maxWidth: 1080, margin: '0 auto', padding: '0 32px 48px' }}>
      <Hero onEnterConsole={onEnterConsole} />
      <StatStrip />
      <IdentityPanels />
      <ArchitectureSection />
      <BrainHandsSplit />
      <ViewCardsGrid onNav={onNav} />
      <SecuritySection />
      <PatchedVulnsList />
      <OverviewFooter />
    </div>
  );
}
