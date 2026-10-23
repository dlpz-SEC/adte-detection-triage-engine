# Postmortem: Railway environment-variable exposure (2026-10-21)

**Status: In Development.** Rotation and hunt are in progress, so placeholders marked `[TODO: …]`
are still open. Every time, address and count in this document either came from a named source or
is a placeholder; none is estimated.

| Field | Value |
|---|---|
| Service | ADTE (Flask API + React SPA), Railway service `adte-detection-triage-engine` |
| Trigger | Third-party disclosure by the hosting platform |
| Exposed set | 21 Railway service variables (19 names confirmed, 2 unconfirmed; Appendix A) |
| Credentials in the exposed set | 9 confirmed (5 ADTE API keys, 1 Wazuh Indexer login pair, 3 provider keys), plus `ADTE_ABUSEIPDB_KEY` unconfirmed |
| Customer data | None. ADTE is a single-operator portfolio deployment. |
| Severity | [TODO: final severity once the hunt closes] |

## Summary

On 2026-10-21 Railway disclosed that an unauthorized third party may have accessed customer
environment variables, and for some customers obtained their decrypted contents
[TODO: link to Railway's notice]. ADTE's production service keeps every credential it uses in
Railway variables. That includes the HTTP Basic login for the Wazuh Indexer, the SIEM data store
that ADTE triages from.

The response treats every Railway variable as read by the third party:

1. inventory what each variable unlocks;
2. rotate every credential at its provider and confirm the old value fails;
3. hunt the Wazuh Indexer and each provider's usage for use of the old values;
4. add a detection for the specific misuse that matters most, an indexer login from an
   unapproved address;
5. remove the design choices that widened the exposure.

[TODO: whether Railway confirmed this project was among those affected.]

## Timeline (UTC)

| When | Event | Source |
|---|---|---|
| [TODO: Railway's detection time] | Railway detects unauthorized access | Railway notice |
| 2026-10-21 [TODO: time] | Railway notifies customers | Railway notice / email |
| [TODO: time] | David reads the notice; response starts | David |
| [TODO: exposure window start] to [TODO: exposure window end] | Period the variables may have been read | Railway notice |
| 2026-10-23 | Inventory of variables ADTE reads, and of the 21 set on Railway, completed | this document, Appendix A |
| [TODO: rotation start] | First credential rotated | checklist below |
| [TODO: rotation finish] | Last credential rotated and old value verified failing | checklist below |
| [TODO: time] | Session-key binding deployed to production | `/version` commit |
| [TODO: hunt complete] | Hunt closed | Hunt section |

## Impact and blast radius

The full table is Appendix A. In order of what an attacker could do with the values:

1. **Wazuh Indexer login: `ADTE_WAZUH_USER`, `ADTE_WAZUH_PASS`, `ADTE_WAZUH_HOST`.** These give
   read access to every alert in `wazuh-alerts-*`, which is the full detection record of the lab.
   The lab runbook records ADTE's indexer user as the indexer `admin` account
   [TODO: confirm on the VM with `GET _plugins/_security/api/account`]. If that holds, the same
   values also allow deleting or rewriting alerts, changing security configuration, creating
   users, and turning off the audit log that a hunt depends on. ADTE itself only ever sends
   `POST wazuh-alerts-*/_search`. The host value also hands over the indexer's address. Whether
   that address is reachable from outside the VM's NAT decides whether this is a usable
   credential or only a known one: [TODO: is 9200 reachable from outside the VM? yes/no, and
   how verified].
2. **`ADTE_API_KEY_ADMIN`.** Full control of ADTE, including the three admin-only deletes
   (verdict audit log, feedback, cases). That is the who/what/when/why trail that NIST SP 800-61
   expects to survive an incident.
3. **`ANTHROPIC_API_KEY`.** Model usage billed to David's account, up to whatever limit the
   account has [TODO: Anthropic spend limit at the time of exposure].
4. **`ADTE_API_KEY_SENIOR`.** Adds false-positive registry promotion, which suppresses future
   detections for an IP, and `GET /api/config`. That route returns the first 4 and last 4
   characters of every configured key, the admin key included.
5. **Provider keys `ADTE_VT_API_KEY`, `ADTE_OTX_KEY` (and `ADTE_ABUSEIPDB_KEY` if set).** Free-tier
   quota drain under David's identity, and, where the provider allows it, submissions (AbuseIPDB
   reports, OTX pulses) attributed to his account.
6. **`ADTE_API_KEY_ANALYST`, `_READONLY`, `_RECRUITER`.** Triage runs, which spend threat-intel
   quota, and reads of the audit data. The recruiter key is published on purpose, so its exposure
   adds nothing.

**Shared across environments:** the local `.env` reuses at least one Railway value
[TODO: which variables]. Those values are rotated in both places.

**Not in the exposed set:** `ADTE_SENTINEL_*`, `ADTE_SLACK_WEBHOOK`, `ADTE_LINEAR_*` and
`ADTE_TRELLO_*` are read by ADTE code, but none is set on Railway. Slack, Linear and Trello are
used only by `scripts/` run from a workstation.

## Response

ADTE holds no credential it could rotate on its own, and none was rotated from this repository.
Every rotation is done by hand in the provider's console, in the order below. The procedure and
the one-line "old value fails" check for each row are in the
[rotation runbook](../runbooks/secret-rotation.md).

| # | Credential | Rotate at | Side effect | Old value fails when | rotated_at | verified_at |
|---|---|---|---|---|---|---|
| 1 | `ADTE_WAZUH_PASS` | Wazuh VM (`wazuh-passwords-tool.sh`) + Railway | Other clients on the same indexer user break until updated (Dashboard, Filebeat if `admin`) | `/_plugins/_security/authinfo` answers 401 | [TODO] | [TODO] |
| 2 | `ADTE_API_KEY_ADMIN` | Railway Variables | Redeploy; old browser sessions live up to 8 h on a Volume unless key binding is deployed | `/api/auth-check` with old key answers 401 | [TODO] | [TODO] |
| 3 | `ANTHROPIC_API_KEY` | Anthropic Console | LLM narrative falls back during the swap | `/v1/models` answers 401 | [TODO] | [TODO] |
| 4 | `ADTE_API_KEY_SENIOR` | Railway Variables | as #2 | as #2 | [TODO] | [TODO] |
| 5 | `ADTE_VT_API_KEY` | VirusTotal profile | VT lookups abstain during the swap | `/api/v3/ip_addresses/8.8.8.8` answers 401 | [TODO] | [TODO] |
| 6 | `ADTE_API_KEY_ANALYST` | Railway Variables | as #2 | as #2 | [TODO] | [TODO] |
| 7 | `ADTE_OTX_KEY` | OTX settings | OTX continues anonymously | `/api/v1/user/me` answers non-200 | [TODO] | [TODO] |
| 8 | `ADTE_ABUSEIPDB_KEY` (if set) | AbuseIPDB account | AbuseIPDB lookups abstain during the swap | `/api/v2/check` answers 401 | [TODO] | [TODO] |
| 9 | `ADTE_API_KEY_READONLY` | Railway Variables | as #2 | as #2 | [TODO] | [TODO] |
| 10 | `ADTE_API_KEY_RECRUITER` | Railway + `frontend/src/app.jsx` literal | Code change and push; public by design | as #2 | [TODO: rotated or deliberately not] | [TODO] |
| 11 | Local `.env` duplicates | `.env` | none | n/a | [TODO] | n/a |

Batching the five Railway variables (#2, #4, #6, #9 and `ADTE_WAZUH_PASS`) into one edit costs a
single redeploy instead of five.

Code shipped as part of the response (branch `docs/incident-2026-10-21-railway`):

- **Sessions bound to their key.** Each browser session now stores a PBKDF2 fingerprint of the key
  that minted it, and is refused once that key is no longer the configured key for its role.
  Before this change a session stored only a role, so rotating a key left the sessions it had
  opened alive for up to the 8 h TTL whenever the database survived the redeploy. Rows written
  before the change are refused (one re-login). Tests: `tests/test_session_key_binding.py`.
- **IP enrichment for the hunt.** `scripts/enrich_unknown_ips.py` runs addresses through ADTE's
  existing threat-intel wrappers. It is a dry run by default and calls no provider.

## Hunt method and findings

**Outcome:** [TODO: hunt outcome.] If nothing is found, this line reads: "No evidence of
credential misuse", followed by the checks from the list below that were actually run, each with
its time range.

| # | Check | Window | Anomaly that would count | Result |
|---|---|---|---|---|
| 1 | Indexer security audit log: successful REST logins by source address (Q1) | from 2026-10-20T00:00:00Z | any address outside the allowlist | [TODO] |
| 2 | Indexer security audit log: failed logins (Q2) | same | repeated failures from one address, especially after rotation | [TODO] |
| 3 | Indexer audit log coverage (Step 0) | n/a | audit logging off, or `AUTHENTICATED` disabled: checks 1 and 2 then prove nothing | [TODO: on/off; AUTHENTICATED logged?] |
| 4 | Indexer reachability from outside the VM | n/a | 9200 forwarded or exposed | [TODO] |
| 5 | Indexer node log `/var/log/wazuh-indexer/` | same | auth errors from unknown addresses | [TODO] |
| 6 | Anthropic Console: usage and cost by day and by key | from 2026-10-20 | requests or spend on days ADTE had no traffic; models ADTE never calls | [TODO] |
| 7 | VirusTotal API usage graph | same | lookups above ADTE's own volume (quota capped at 450/day in ADTE) | [TODO] |
| 8 | OTX account: API activity, pulses, subscriptions | same | pulses or subscriptions David did not create | [TODO] |
| 9 | AbuseIPDB: API usage and reports submitted (if the key was set) | same | any report submitted; checks above 900/day | [TODO] |
| 10 | Railway: project activity / audit log, deployments, variable edits | from 2026-10-20 | deploys or variable changes David did not make | [TODO] |
| 11 | ADTE audit log: verdict/feedback/case deletions, logins | from 2026-10-20 | admin deletes or logins David did not make (ephemeral if no Volume) | [TODO] |

Queries for checks 1 to 5: [hunt/indexer-auth-queries.md](hunt/indexer-auth-queries.md). Any
unknown address goes through `scripts/enrich_unknown_ips.py`, dry run first.

Slack and Linear audit logs are not part of this hunt: neither credential was on Railway.

Unknown addresses found: [TODO: none / list with enrichment result].

## Detection added

`detections/sigma/wazuh_indexer_auth_unexpected_source.yml`, "Wazuh - Indexer Authentication
From Unexpected Source":

- matches a successful REST login (`audit_category: AUTHENTICATED`) to the indexer from an address
  outside a CIDR allowlist;
- tagged `attack.t1078` (Valid Accounts) and `attack.t1552` (Unsecured Credentials);
- `status: experimental`.

`tests/test_sigma_indexer_auth.py` checks it against one positive and four negative events:
an allowlisted source, loopback, a failed login, and transport-layer traffic. The test's matcher
raises on any Sigma construct it does not implement, so it cannot pass by ignoring part of the
rule.

Limits:

- The rule's allowlist ships with a non-routable RFC 5737 placeholder: [TODO: real admin CIDRs,
  kept outside the public repo].
- The rule depends on the indexer's audit log recording `AUTHENTICATED`, which the OpenSearch
  defaults leave out (Follow-up F5).
- It is not yet deployed to any SIEM: [TODO: deployment target and date].

## Root cause and architectural lessons

**Root cause (of the exposure):** a third-party platform's compromise
[TODO: Railway's stated cause]. ADTE's code and configuration were not the entry point.

**Contributing factors (why the exposure reached this far), all within this project's control:**

1. **A triage tool held a SIEM credential with more privilege than triage needs.** ADTE only
   searches one index pattern. Storing an indexer login (recorded as `admin`) on a hosting
   platform meant a platform compromise reached into the monitoring layer: the system that would
   detect misuse of the credential is the system the credential controls. A read-only role scoped
   to `wazuh-alerts-*` would have limited the worst case to reading alerts.
2. **The credential was on a platform that, by design, could not use it.** The indexer sits on a
   NAT'd lab VM, and the hosted app is documented to fall back to a seeded queue
   (`source: "demo"`) when the indexer is unreachable [TODO: confirm the `source` field of
   production `/api/queue` during the exposure window]. If that holds, the variables bought no
   function on Railway and added exposure.
3. **One value in more than one place.** Values shared between Railway and the local `.env` mean
   one exposure forces rotation in both.
4. **Rotation did not end sessions.** Sessions were not tied to the key that created them (fixed
   on this branch).
5. **No usable login trail at the indexer** [TODO: confirm via Step 0]. If the audit log was off,
   or `AUTHENTICATED` was not recorded, the hunt can bound the risk only by reachability, not by
   evidence.

**Supply-chain lesson:** a PaaS is a dependency with the same standing as a pinned package. Its
compromise is in scope for threat modeling, and every secret placed there should be the least
privileged one that does the job on that platform. A secret that does nothing on the platform
should not be there.

## Follow-ups

| ID | Action | Effort | Status |
|---|---|---|---|
| F1 | Rotate every credential in the Response table and record rotated_at / verified_at | about 1 h (manual) | Open |
| F2 | Remove `ADTE_WAZUH_*` from Railway (hosted queue already serves demo data) | about 10 min | Open |
| F3 | Least-privilege indexer role for ADTE: `read` and `search` on `wazuh-alerts-4.x-*` only, its own user, never `admin` | about 1 h on the VM | Open |
| F4 | If live Wazuh data on the hosted app is ever wanted: Tailscale or Cloudflare Tunnel from the VM, plus the F3 role. Do not allowlist Railway egress, which is shared across Railway customers. | about half a day | Proposed |
| F5 | Enable the indexer security audit log with `AUTHENTICATED` recorded, then deploy the Sigma rule with real CIDRs | about 1 h | Open |
| F6 | Separate keys per environment (local, Railway); note each key's home in a private inventory | about 30 min | Open |
| F7 | Provider caps: Anthropic monthly spend limit; VT/AbuseIPDB ADTE quotas are already set below the free tiers (450 / 900 per day) | about 15 min | Open |
| F8 | Session-key binding | done on branch | In Review (not deployed) |
| F9 | Rotation runbook | done on branch | In Review |
| F10 | `/api/config` shows 8 characters of every key to `senior_analyst`; reduce it to presence only or the last 4 | about 1 h incl. tests | Proposed |
| F11 | Startup check that refuses placeholder secrets (`changeme-*`, `your-*`) on a hosted deploy | about 1 h incl. tests | Proposed |
| F12 | Delete `AZURE_TENANT_ID` from Railway (read nowhere) and confirm `ADTE_CORS_ORIGINS` is meant to be set | about 5 min | Open |
| F13 | Confirm the two Railway variables not visible in the inventory screenshot | about 5 min | Open |

## Appendix A: secret inventory

Source: every `os.environ` / `os.getenv` / `env_key` read in `adte/` and `scripts/`, the Railway
service variable list (19 of 21 names visible, 2026-10-23), `.env.example`, `Dockerfile`,
`.railway/railway.ts`, `frontend/package.json`. The frontend build reads no secret:
`process.env.NODE_ENV` only. The recruiter passkey literal in `frontend/src/app.jsx` is public by
design.

### On Railway (exposed set)

| Variable | Authenticates to | What an attacker could do | Privilege | Severity | Old value revoked when |
|---|---|---|---|---|---|
| `ADTE_WAZUH_PASS` (+ `_USER`) | Wazuh Indexer REST, HTTP Basic | Read all alerts; if `admin`, delete or alter alerts, change security config, disable audit | **admin per lab runbook** [TODO: verify]; ADTE needs read | High | old pass gets 401 on `/_plugins/_security/authinfo` |
| `ADTE_WAZUH_HOST` | none (address) | Learn where the indexer lives | n/a | Med (recon) | n/a; re-check exposure (F2, F4) |
| `ADTE_WAZUH_VERIFY_SSL` | none (config) | Learn whether TLS is verified | n/a | Low | n/a |
| `ADTE_API_KEY_ADMIN` | ADTE API (`X-ADTE-Key`, login) | Everything, including deleting the audit log, feedback and cases | admin | High | `/api/auth-check` with old key gets 401 |
| `ADTE_API_KEY_SENIOR` | ADTE API | Promote IPs into the FP registry (suppress detections); read 8 chars of every key via `/api/config` | write | Med | same |
| `ADTE_API_KEY_ANALYST` | ADTE API | Run triage (spends TI quota), write feedback labels, read cases | write (limited) | Med | same |
| `ADTE_API_KEY_READONLY` | ADTE API | Read verdicts, feedback, intel, queue | read | Low | same |
| `ADTE_API_KEY_RECRUITER` | ADTE API (analyst alias) | Same as analyst; already public | write (limited) | Low (no new exposure) | same, after F1 #10 |
| `ANTHROPIC_API_KEY` | Anthropic API | Spend on David's account, any model | account API key | High | `/v1/models` gets 401 |
| `ADTE_VT_API_KEY` | VirusTotal API v3 | Use the daily quota under David's account | read (lookups) | Med | `/api/v3/...` gets 401 |
| `ADTE_OTX_KEY` | AlienVault OTX | Use quota; act as David's OTX account [TODO: can this key create pulses?] | read, possibly write | Med | `/api/v1/user/me` non-200 |
| `ADTE_ABUSEIPDB_KEY` | AbuseIPDB API v2 | Use quota; submit reports as David's account | read + report | Med | `/api/v2/check` gets 401 |
| `ADTE_CORS_ORIGINS` | none (config) | Learn trusted cross-origins | n/a | Low | n/a |
| `ADTE_DRY_RUN`, `ADTE_EXECUTION_ENABLED`, `ADTE_KILL_SWITCH` | none (reserved gates; gate nothing today) | nothing | n/a | Low | n/a |
| `ADTE_TI_QUOTA_ABUSEIPDB`, `ADTE_TI_QUOTA_VIRUSTOTAL` | none (config) | Learn quota ceilings | n/a | Low | n/a |
| `AZURE_TENANT_ID` | none (identifier; read by no code) | Learn the tenant ID if set | n/a | Low | n/a; delete (F12) |
| `ADTE_AUDIT_DB` | none (path) | nothing | n/a | Low | n/a |
| Railway system vars (`RAILWAY_*`) | none (identifiers) | Learn project/service IDs | n/a | Low | n/a |

`ADTE_ABUSEIPDB_KEY` and `ADTE_AUDIT_DB` are the likeliest two hidden names, but neither is
confirmed: [TODO: the 2 Railway variable names not visible in the inventory screenshot].

### Read by ADTE but not on Railway

| Variable | Read by | Note |
|---|---|---|
| `ADTE_SENTINEL_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_WORKSPACE_ID` | `adte/adapters/sentinel.py` | Not set on Railway |
| `ADTE_SLACK_WEBHOOK` | `scripts/alert_router.py` | Workstation-only |
| `ADTE_LINEAR_API_KEY`, `ADTE_LINEAR_TEAM_ID` | `scripts/ticket_client.py` | Workstation-only |
| `ADTE_TRELLO_API_KEY`, `ADTE_TRELLO_TOKEN`, `ADTE_TRELLO_LIST_ID` | `scripts/ticket_client.py` | Workstation-only |
| `ADTE_TI_QUOTA_OTX` | `adte/intel/aggregator.py` | Config |
| `ADTE_TENANT_ALLOWLIST`, `ADTE_USER_ALLOWLIST`, `ADTE_ACTION_ALLOWLIST` | `adte/server.py` (`/api/config`) | Config, reserved |
| `ADTE_FP_REGISTRY`, `LOG_LEVEL` | `adte/server.py` | Config |
| `RAILWAY_GIT_COMMIT_SHA` | `adte/version.py` | Set by Railway at build |

### Flags

- **Over-privileged:** the indexer login, recorded as `admin`, where ADTE needs search on one
  index pattern (F3).
- **Unused where stored:** `ADTE_WAZUH_*` on Railway (F2); `AZURE_TENANT_ID` (F12).
- **Shared across environments:** at least one value is the same locally and on Railway
  [TODO: which] (F6).
- **Cross-tier leak inside ADTE:** `senior_analyst` can read 8 characters of the admin key (F10).
