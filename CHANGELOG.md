# Changelog — ADTE (Autonomous Detection & Triage Engine)

Notable development, newest first. Dates are commit dates; hashes are on `main`.
Reconstructed from git history and cross-checked against `Handoff.md`.

---

## 2026-08-19 → 08-20 — Recruiter-facing UI polish (phases 1–5)

Deliberate design pass over the live demo so it reads as engineered, not scaffolded.

- **Design-token foundation** + a 4th Quick Load scenario. (`9b602c7`)
- **Polish phases 2–5** — shared primitives (InlineLink / EmptyState / Banner /
  RiskCell / ViewIntro + `useTheme()`/`cssVar()`); **theme persistence**
  (`adte_theme` localStorage + OS-preference fallback, pre-render bootstrap);
  **stale-chart-theme bug fixed** (theme in chart effect deps, colors via
  `cssVar`); 3-section nav restructure (**CONSOLE / ANALYSIS / SYSTEM**); Audit
  view rebuilt (verdict pill-filters replace the `<select>`); mobile drawer JSX;
  full motion audit (staggers removed, MITRE flash 1.6 s → 350 ms). Dead code
  removed (`IpRepView`, `QueryBar`, `llmProvider`, stray "GPT" string).
  **+593 / −612** across `frontend/src/app.jsx` + `overview.jsx`. (`397e8bb`)
- Bundle **300.3 → 296.3 kb**; **confirmed live on Railway** (WEIGHT MODEL /
  "Nine views" / `adte_theme` markers in served bundle; `/health` 200; unauth
  `POST /api/triage` → 401).
- **Test suite: 766 green** — unchanged by this pass (neither commit touches a
  test file; the 766 floor was set the day before, in `484cca7`).
- Phase 6 remaining items are human-only (visual once-over dark+light, phone
  drawer, keyboard-tab pass).

## 2026-08-17 → 08-18 — Live Microsoft Sentinel integration (milestone A1)

ADTE now ingests **real** Microsoft Sentinel incidents, not just Sentinel-format
JSON. This closes the "mock → real enterprise SIEM" gap end-to-end.

- **Live Sentinel adapter** — `adte/adapters/sentinel.py` (**635 LOC**) pulling
  incidents via the **Log Analytics Query API**; wired into the CLI
  (`--source sentinel`) and the server. Ships with a **630-line adapter test
  suite** and a Sentinel incidents fixture. (`d87350d`)
- **Live wire contract locked** — sanitized real-capture fixture
  (`tests/fixtures/sentinel_live_capture.json`) + pin tests so the adapter is
  held to the shape the real API actually returns. (`312cc5e`)
- **OAuth token scope fixed** to `api.loganalytics.io` (a mocked-HTTP suite had
  masked a wrong hardcoded audience — caught only by smoking live). (`666e755`)
- **Verified end-to-end against a real Azure Sentinel workspace** — pulled real
  incident #1 through the live adapter (SENTINEL LIVE banner, verdict **39
  MEDIUM**). Integration is code-complete and live-proven.
- **Security:** raised gunicorn floor to **23.0** (CVE-2024-6827). (`9af29ce`)
- **Docs:** full accuracy-audit sweep for the milestone. (`484cca7`)
- **Nine durable operational lessons** from the live-Azure session — Connected ≠
  data; the client-secret Value-shown-once gotcha;
  smoke-live-before-claiming-an-adapter-works. (`0513346`) The "Cloud Shell
  `az rest` beats driving the portal" lesson landed with the docs sweep.
  (`484cca7`)

## 2026-07-21 — Live-demo hardening (context)

- Dedicated **recruiter passkey**, isolated from the analyst key, shown inline in
  the triage auth prompt. (`ae903e3`, `c122852`, `7abc700`)
- First-visit **Overview landing page**; `#overview` fragment forces it.
  (`c0c2e85`, `a7f2df8`)
- README leads with the **live Railway deployment** + documents the public /
  passkey access split. (`8e477f0`, `74da21b`)
- Visitor-facing "mock" renamed to "synthetic"; CORS hardening against
  placeholder/malformed origins. (`fb78915`, `495d315`)

---

## State as of 2026-08-20

- **766 tests green**; Railway healthy — `/health` 200 and the served `bundle.js`
  byte-identical (303,434 B) to the local build. Last code-bearing commit is
  `397e8bb`; everything after it is docs.
- **Live Sentinel adapter code-complete and live-proven** against a real Azure
  Sentinel workspace; remaining Sentinel items are account-side configuration,
  not code.
- Open engine work: **Workstream B** — engine signal fixes F1(b) / F2.
