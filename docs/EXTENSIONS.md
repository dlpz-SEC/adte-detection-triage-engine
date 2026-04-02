# Extensions Guide

This document explains how to extend ADTE with real API integrations, new signal types, and additional enrichment sources.

## Connecting to the Real Sentinel REST API

The current `SentinelAdapter` in `adte/adapters/sentinel.py` uses mock responses. To connect to the real Sentinel API:

### Prerequisites

1. **Azure App Registration** with the following API permissions:
   - `Microsoft Sentinel Contributor` role on the Sentinel workspace
   - Or granular permissions: `Microsoft.SecurityInsights/incidents/read`, `Microsoft.SecurityInsights/incidents/write`, `Microsoft.SecurityInsights/incidents/comments/write`

2. **Environment variables:**
   ```bash
   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-app-client-id
   AZURE_CLIENT_SECRET=your-app-client-secret
   SENTINEL_SUBSCRIPTION_ID=your-subscription-id
   SENTINEL_RESOURCE_GROUP=your-resource-group
   SENTINEL_WORKSPACE_NAME=your-workspace-name
   ```

### Implementation

Replace the mock execution blocks in `SentinelAdapter` with real API calls:

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights

class SentinelAdapter:
    def __init__(self, tenant_id: str, safety_config: SafetyConfig) -> None:
        self._tenant_id = tenant_id
        self._safety = safety_config
        self._credential = DefaultAzureCredential()
        self._client = SecurityInsights(
            credential=self._credential,
            subscription_id=os.environ["SENTINEL_SUBSCRIPTION_ID"],
        )
        self._rg = os.environ["SENTINEL_RESOURCE_GROUP"]
        self._ws = os.environ["SENTINEL_WORKSPACE_NAME"]

    def post_incident_comment(self, incident_id, comment, **kwargs):
        # ... safety gate check (keep as-is) ...

        # Replace mock with real API call:
        result = self._client.incident_comments.create_or_update(
            resource_group_name=self._rg,
            workspace_name=self._ws,
            incident_id=incident_id,
            incident_comment_id=str(uuid.uuid4()),
            incident_comment={"properties": {"message": comment}},
        )
        return {"status": "executed", "action": "POST_COMMENT", ...}
```

### Incident Ingestion

To poll for new incidents instead of reading from JSON files:

```python
def poll_incidents(client, rg, ws, since_minutes=15):
    """Poll Sentinel for recent incidents."""
    filter_str = (
        f"properties/createdTimeUtc ge "
        f"{(datetime.utcnow() - timedelta(minutes=since_minutes)).isoformat()}Z"
    )
    incidents = client.incidents.list(
        resource_group_name=rg,
        workspace_name=ws,
        filter=filter_str,
        orderby="properties/createdTimeUtc desc",
    )
    return [SentinelIncident(**inc.as_dict()) for inc in incidents]
```

## Connecting to Microsoft Graph API (Entra ID)

The current `EntraIDAdapter` in `adte/adapters/entra_id.py` uses mock responses. To connect to the real Graph API:

### Prerequisites

1. **Azure App Registration** with the following API permissions (Application type):
   - `User.ReadWrite.All` — for password reset and account disable
   - `User.RevokeSessions.All` — for token revocation
   - Admin consent granted for all permissions

2. **Environment variables:**
   ```bash
   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-app-client-id
   AZURE_CLIENT_SECRET=your-app-client-secret
   ```

### Implementation

Replace mock execution blocks with Graph SDK calls:

```python
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient

class EntraIDAdapter:
    def __init__(self, tenant_id: str, safety_config: SafetyConfig) -> None:
        self._tenant_id = tenant_id
        self._safety = safety_config
        self._credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
        )
        self._graph = GraphServiceClient(self._credential)

    async def revoke_refresh_tokens(self, user_upn, severity):
        # ... safety gate check (keep as-is) ...

        # Replace mock with real Graph call:
        result = await self._graph.users.by_user_id(user_upn) \
            .revoke_sign_in_sessions.post()
        return {"status": "executed", "action": "REVOKE_SESSIONS", ...}

    async def disable_user(self, user_upn, severity):
        # ... safety gate check (keep as-is) ...

        from msgraph.generated.models.user import User
        user_update = User(account_enabled=False)
        await self._graph.users.by_user_id(user_upn).patch(user_update)
        return {"status": "executed", "action": "DISABLE_ACCOUNT", ...}
```

### Dependencies

Add to `pyproject.toml`:
```toml
dependencies = [
    # ... existing ...
    "msgraph-sdk>=1.0",
    "azure-identity>=1.15",
]
```

## Adding New Signal Types

To add a new signal class to the scoring model:

### Step 1: Define the weight in `decision_policy.py`

```python
WEIGHT_NEW_SIGNAL: int = X  # Points for this signal

SIGNAL_WEIGHTS: dict[str, int] = {
    "impossible_travel": 30,
    "mfa_fatigue": 25,
    "ip_reputation": 20,
    "device_novelty": 15,
    "login_hour_anomaly": 10,
    "new_signal": X,  # Add here
}
```

**Important:** All weights must sum to 100. Redistribute existing weights to accommodate the new signal.

### Step 2: Add the signal method to `engine.py`

```python
def _compute_new_signal(self) -> SignalResult:
    """Evaluate the new signal.

    Returns:
        (score, rationale, confidence) tuple.
    """
    weight = SIGNAL_WEIGHTS["new_signal"]

    # Your detection logic here...
    if condition_detected:
        return (float(weight), "Description of what was detected", 0.85)

    return (0.0, "No anomaly detected", 0.8)
```

### Step 3: Register in `score()`

```python
def score(self) -> "TriageEngine":
    self._signals["impossible_travel"] = self._compute_impossible_travel()
    self._signals["mfa_fatigue"] = self._compute_mfa_fatigue()
    self._signals["ip_reputation"] = self._compute_ip_reputation()
    self._signals["device_novelty"] = self._compute_device_novelty()
    self._signals["login_hour_anomaly"] = self._compute_login_hour_anomaly()
    self._signals["new_signal"] = self._compute_new_signal()  # Add here
    # ... rest of score() unchanged
```

### Step 4: Add tests

Add tests in `tests/test_engine.py` to verify the new signal fires correctly for each example incident.

### Step 5: Update example incident rationale count

In `test_engine.py`, update the rationale structure assertion:
```python
assert len(rationale) == 6  # was 5, now 6
```

### Signal Ideas for Future Implementation

| Signal | Weight (suggested) | Data Source |
|--------|-------------------|-------------|
| **Brute force velocity** | 10-15 | Failed sign-in count in sliding window |
| **OAuth app consent** | 10-15 | Risky app consent grants via Graph API |
| **Mailbox rule creation** | 10-15 | Suspicious inbox rules (forwarding) |
| **Privileged role activation** | 15-20 | PIM role activations correlated with other signals |
| **Cross-tenant anomaly** | 10-15 | Sign-ins from unusual guest tenants |

## Adding New Enrichment Sources

### Adding a New Threat Intelligence Feed

Create a new module or extend `adte/intel/threat_intel.py`:

```python
# adte/intel/virustotal.py

import os
import httpx

_VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
_VT_BASE = "https://www.virustotal.com/api/v3"

def check_virustotal(ip: str) -> ThreatIntelResult:
    """Query VirusTotal for IP reputation."""
    if not _VT_API_KEY:
        return ThreatIntelResult(
            is_malicious=False, confidence=0.0,
            source="virustotal-disabled", tags=[],
        )

    resp = httpx.get(
        f"{_VT_BASE}/ip_addresses/{ip}",
        headers={"x-apikey": _VT_API_KEY},
        timeout=10.0,
    )
    data = resp.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious_count = stats.get("malicious", 0)
    total = sum(stats.values())

    return ThreatIntelResult(
        is_malicious=malicious_count > 3,
        confidence=malicious_count / total if total else 0.0,
        source="virustotal",
        tags=["vt-malicious"] if malicious_count > 3 else [],
    )
```

### Integrating into the Enrichment Pipeline

Update `engine.py` `enrich()` to call additional sources:

```python
def enrich(self) -> "TriageEngine":
    for ip in unique_ips:
        self._threat_intel_results[ip] = check_threat_intel(ip)

        # Add additional TI sources:
        vt_result = check_virustotal(ip)
        if vt_result.is_malicious:
            self._threat_intel_results[ip] = vt_result  # Override with higher-confidence source

        _, ptype = self._fp_registry.is_known_benign_any(ip)
        self._fp_matches[ip] = ptype
    return self
```

### Adding FP Registry Patterns

Edit `examples/fp_registry.yaml` to add new known-benign patterns:

```yaml
- name: "office_365_infrastructure"
  pattern_type: "cloud_service"
  description: "Microsoft 365 frontend IPs"
  cidrs:
    - "13.107.6.0/24"
    - "13.107.18.0/24"
    - "13.107.128.0/22"
    - "23.103.160.0/20"
```

### Adding User Behavioral Baselines

To replace mock user profiles with real data, implement a query against your identity provider or SIEM:

```python
# adte/store/user_history.py

async def get_user_profile_from_graph(upn: str) -> UserProfile:
    """Build a user profile from Graph API and Sentinel sign-in logs."""
    # 1. Query recent sign-in logs for location/device/hour patterns
    # 2. Query registered devices
    # 3. Build baseline from last 30 days of activity
    ...
```

The `UserProfile` model in `adte/models.py` already supports all necessary fields:
- `known_devices: list[DeviceInfo]` — from Entra ID registered devices
- `baseline_login_hours: LoginHourRange` — from sign-in log time analysis
- `last_seen_location: GeoLocation | None` — from most recent sign-in
- `last_seen_at: datetime | None` — timestamp of last activity
- `risk_level: str` — from Entra ID Identity Protection

## Adding New Action Types

### Step 1: Create the adapter method

Add a new method to the appropriate adapter (`SentinelAdapter` or `EntraIDAdapter`):

```python
def quarantine_mailbox(self, user_upn: str, severity: str) -> dict:
    action_type = "QUARANTINE_MAILBOX"
    # ... standard safety gate check pattern ...
```

### Step 2: Register the action type

Add the action type to `ADTE_ACTION_ALLOWLIST` in your environment:

```bash
ADTE_ACTION_ALLOWLIST=CLOSE_INCIDENT,POST_COMMENT,QUARANTINE_MAILBOX
```

### Step 3: Wire into the decision engine

Update `engine.py` `decide()` to include the new action in the recommended actions list:

```python
if self._verdict == "high_risk":
    self._actions = [
        "disable_account",
        "revoke_sessions",
        "quarantine_mailbox",  # Add here
        "notify_soc_tier2",
        "create_ticket_p1",
    ]
```
