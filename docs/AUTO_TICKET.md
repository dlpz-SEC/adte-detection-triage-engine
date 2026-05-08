# Auto-Ticket Pipeline

`scripts/ticket_client.py` creates Linear issues or Trello cards automatically
when the alert router detects a triage verdict that requires follow-up.

- `high_risk` verdicts: ticket created after the Slack/stdout notification, using
  the full triage result (includes confidence, recommended action, and rationale).
- `medium_risk` verdicts: ticket created directly from the queue row (no second
  triage fetch needed).

---

## How It Works

`create_ticket(verdict)` is the single entry point.  It tries providers in order:

1. **Linear** — if `ADTE_LINEAR_API_KEY` is set, attempts to create a Linear issue.
   Returns the issue URL on success.
2. **Trello** — if `ADTE_LINEAR_API_KEY` is not set (or Linear fails), attempts to
   create a Trello card.  Returns the card URL on success.
3. **Neither configured** — returns `None` silently.  No errors, no warnings.
   The alert router continues normally.

Ticket creation failure never affects Slack routing or the next poll cycle.

---

## Prerequisites

- ADTE server running (`python -m adte.server`)
- `scripts/alert_router.py` running (tickets are created from the router loop)
- `requests` installed (already in `pyproject.toml`)
- At least one provider configured via environment variables (optional — the
  script works without any tickets configured)

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ADTE_LINEAR_API_KEY` | No | Linear personal API key |
| `ADTE_LINEAR_TEAM_ID` | No (with Linear key) | Linear team ID to create issues in |
| `ADTE_TRELLO_API_KEY` | No | Trello Power-Up API key |
| `ADTE_TRELLO_TOKEN` | No (with Trello key) | Trello user OAuth token |
| `ADTE_TRELLO_LIST_ID` | No (with Trello key) | Trello list ID to add cards to |

Both `ADTE_LINEAR_API_KEY` and `ADTE_LINEAR_TEAM_ID` must be set for Linear to
activate.  All three Trello variables must be set for Trello to activate.

---

## Linear Setup

1. Go to [linear.app/settings/api](https://linear.app/settings/api) and create a
   **Personal API Key**.
2. Copy the key — it starts with `lin_api_`.
3. Find your **Team ID**: open your team in Linear, go to **Settings → General**,
   copy the Team ID (a UUID).
4. Export both before running:

```bash
export ADTE_LINEAR_API_KEY="lin_api_xxxxxxxxxxxxx"
export ADTE_LINEAR_TEAM_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
python scripts/alert_router.py
```

---

## Trello Setup

1. Go to [trello.com/app-key](https://trello.com/app-key) and copy your
   **API Key**.
2. On the same page, click **Generate a Token** and authorise the app.  Copy the
   token.
3. Find your **List ID**: open the target Trello board, append `.json` to the URL,
   and search for the list name.  Copy its `id` field.
4. Export all three:

```bash
export ADTE_TRELLO_API_KEY="your_api_key"
export ADTE_TRELLO_TOKEN="your_token"
export ADTE_TRELLO_LIST_ID="your_list_id"
python scripts/alert_router.py
```

---

## Ticket Format

**Title:**
```
[HIGH_RISK] INC-20240115-001 — alice@example.com
```

**Body:**
```
Verdict: HIGH_RISK
Risk Score: 87/100
Confidence: 82%
Recommended Action: Immediately disable account, revoke sessions, escalate to Tier-2
Top Signal: impossible_travel — Impossible travel detected — London -> New York: 5570 km in 420 min = 796 km/h
Timestamp: 2026-04-29T14:23:11.432Z
```

For `medium_risk` tickets the body uses the queue row fields; `Confidence` and
`Recommended Action` will show `N/A` if the full triage result was not fetched.

---

## Fallback Behaviour

When neither `ADTE_LINEAR_API_KEY` nor `ADTE_TRELLO_API_KEY` is set, `create_ticket`
returns `None` and the alert router logs:

```
WARNING Ticket creation skipped or failed for INC-20240115-001
```

This is the expected behaviour on unconfigured installs.  Set at least one
provider to activate ticket creation.
