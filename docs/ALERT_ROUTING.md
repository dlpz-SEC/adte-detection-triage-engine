# Alert Routing

`scripts/alert_router.py` is a standalone polling script that watches the ADTE
triage queue and acts on new `high_risk` and `medium_risk` verdicts:

- **`high_risk`** — sends a structured plain-text notification to a Slack incoming
  webhook (or stdout fallback) and opens a ticket via the auto-ticket pipeline.
- **`medium_risk`** — opens a ticket only; no Slack notification.

When no webhook is configured, `high_risk` alerts are printed to stdout, making
the script useful in any environment.  Ticket creation is optional — if neither
`ADTE_LINEAR_API_KEY` nor `ADTE_TRELLO_API_KEY` is set, that step is silently
skipped.  See [AUTO_TICKET.md](AUTO_TICKET.md) for ticket provider setup.

---

## How It Works

1. Every N seconds (default 60) the script calls `GET /api/queue` on the ADTE
   server with a 1-hour look-back window.
2. Each unseen row with `verdict == "high_risk"` is enriched with a follow-up
   `POST /api/triage` call to retrieve `confidence`, `recommended_action`, and
   the full signal rationale (absent from queue rows).
3. The formatted alert is posted to the Slack webhook (or printed to stdout).
4. A ticket is created via `scripts/ticket_client.py` (Linear or Trello).
5. Each unseen row with `verdict == "medium_risk"` triggers ticket creation
   directly from the queue row — no second triage fetch.
6. Seen incident IDs are tracked in memory — duplicates are suppressed for the
   lifetime of the process.  Restarting the script resets the deduplication set.

---

## Prerequisites

- The ADTE server must be running (`python -m adte.server` or via the CLI).
- `requests` must be installed — it is already listed in `pyproject.toml` so a
  standard `pip install -e .` covers it.

---

## Usage

```bash
python scripts/alert_router.py [--url URL] [--interval N]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | `http://localhost:5000` | ADTE server base URL |
| `--interval` | `60` | Poll interval in seconds |

```bash
# Default — poll localhost every 60 seconds
python scripts/alert_router.py

# Remote server, 30-second interval
python scripts/alert_router.py --url http://adte.internal:5000 --interval 30
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ADTE_SLACK_WEBHOOK` | No | Slack incoming webhook URL.  When unset, `high_risk` alerts go to stdout. |
| `ADTE_LINEAR_API_KEY` | No | Linear personal API key for ticket creation. |
| `ADTE_LINEAR_TEAM_ID` | No | Linear team ID (required when using Linear). |
| `ADTE_TRELLO_API_KEY` | No | Trello Power-Up API key for ticket creation. |
| `ADTE_TRELLO_TOKEN` | No | Trello user OAuth token (required when using Trello). |
| `ADTE_TRELLO_LIST_ID` | No | Trello list ID to add cards to (required when using Trello). |

For ticket provider setup see [AUTO_TICKET.md](AUTO_TICKET.md).

---

## Slack Setup

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and click **Create New App** → **From scratch**.
2. Name the app (e.g. `ADTE Alerts`) and choose your workspace.
3. In the left sidebar, go to **Incoming Webhooks** and toggle **Activate Incoming Webhooks** on.
4. Click **Add New Webhook to Workspace**, select a channel, and click **Allow**.
5. Copy the generated webhook URL (it starts with `https://hooks.slack.com/services/...`).
6. Export it before running the script:

```bash
export ADTE_SLACK_WEBHOOK="https://hooks.slack.com/services/T.../B.../..."
python scripts/alert_router.py
```

---

## Example Alert

```
HIGH RISK ALERT
Incident:         INC-20240115-001
User:             alice@example.com
Source IP:        198.51.100.14
Risk Score:       87/100
Confidence:       82%
Top Signal:       impossible_travel
Recommended:      Immediately disable account, revoke sessions, escalate to Tier-2
```

---

## Stdout Fallback

When `ADTE_SLACK_WEBHOOK` is not set the script prints the same message format to
stdout and logs a note in the startup banner:

```
ADTE Alert Router
  ADTE URL:      http://localhost:5000
  Poll interval: 60s
  Slack:         stdout fallback (ADTE_SLACK_WEBHOOK not set)
```

This makes the script suitable for piping into other tools or for local testing
without any Slack configuration.
