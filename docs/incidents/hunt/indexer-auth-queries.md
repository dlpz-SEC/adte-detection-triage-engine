# Hunt: Wazuh Indexer logins since 2026-10-20

Part of the [2026-10-21 Railway env-var exposure](../2026-10-21-railway-env-var-exposure.md)
response. Goal: find every login to the Wazuh Indexer (OpenSearch, port 9200) from a source
address outside the approved set, starting `2026-10-20T00:00:00Z`.

Run everything on the Wazuh VM. Each `curl -u <user>` with no password prompts for one, so the
password never lands in shell history. `--cacert` uses the Wazuh default certificate path; adjust
it if the install differs. Use an admin-capable indexer account to read `security-auditlog-*`.

## Step 0: is there anything to search?

The OpenSearch security plugin writes these logs only when audit logging is on. Its defaults also
leave successful REST logins (`AUTHENTICATED`) out of the log, in `disabled_rest_categories`. If
either holds, an empty result below means **not logged**, not **did not happen**, and the
fallbacks at the bottom are the hunt.

```bash
curl -s --cacert /etc/wazuh-indexer/certs/root-ca.pem -u <user> "https://localhost:9200/_cat/indices/security-auditlog-*?v&s=index"
```

```bash
curl -s --cacert /etc/wazuh-indexer/certs/root-ca.pem -u <user> "https://localhost:9200/_plugins/_security/api/audit?pretty"
```

Record:

- [TODO: audit logging enabled before 2026-10-20? yes/no]
- [TODO: AUTHENTICATED in disabled_rest_categories? yes/no]
- [TODO: oldest security-auditlog index date]

```bash
curl -s --cacert /etc/wazuh-indexer/certs/root-ca.pem -u <user> "https://localhost:9200/security-auditlog-*/_mapping/field/audit_request_remote_address?pretty"
```

If the field is mapped `ip`, query Q3's `must_not` can use CIDR ranges. If it is `text` with a
`.keyword` sub-field (dynamic mapping), Q3 must list exact addresses on `.keyword`.

## Q1: distinct sources of successful REST logins

Aggregation first: every address and user that logged in, with counts and first/last seen. Compare
the address list against the allowlist by eye. This query works whatever the field mapping is.

```bash
curl -s --cacert /etc/wazuh-indexer/certs/root-ca.pem -u <user> -H "Content-Type: application/json" "https://localhost:9200/security-auditlog-*/_search?pretty" -d @q1_auth_sources.json
```

`q1_auth_sources.json`:

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term":  { "audit_category": "AUTHENTICATED" } },
        { "term":  { "audit_request_layer": "REST" } },
        { "range": { "@timestamp": { "gte": "2026-10-20T00:00:00Z" } } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "audit_request_remote_address", "size": 500 },
      "aggs": {
        "users":      { "terms": { "field": "audit_request_effective_user", "size": 20 } },
        "first_seen": { "min": { "field": "@timestamp" } },
        "last_seen":  { "max": { "field": "@timestamp" } }
      }
    }
  }
}
```

With dynamic mapping, use `audit_category.keyword`, `audit_request_layer.keyword`,
`audit_request_remote_address.keyword` and `audit_request_effective_user.keyword` instead.

## Q2: failed logins from anywhere

Someone holding the old password after rotation shows up here, not in Q1. Use the same body as
Q1 with `"audit_category": "FAILED_LOGIN"`. Save it as `q2_failed_sources.json`.

## Q3: raw events from outside the allowlist

```json
{
  "size": 200,
  "sort": [{ "@timestamp": { "order": "asc" } }],
  "_source": ["@timestamp", "audit_category", "audit_request_remote_address",
              "audit_request_effective_user", "audit_rest_request_method", "audit_rest_request_path"],
  "query": {
    "bool": {
      "filter": [
        { "terms": { "audit_category": ["AUTHENTICATED", "FAILED_LOGIN"] } },
        { "term":  { "audit_request_layer": "REST" } },
        { "range": { "@timestamp": { "gte": "2026-10-20T00:00:00Z" } } }
      ],
      "must_not": [
        { "term": { "audit_request_remote_address": "127.0.0.1" } },
        { "term": { "audit_request_remote_address": "[TODO: allowlisted address 1]" } },
        { "term": { "audit_request_remote_address": "[TODO: allowlisted address 2]" } }
      ]
    }
  }
}
```

Keep the filled-in allowlist out of the repository: edit a copy outside it. If the field is mapped
`ip`, a `must_not` entry can be a CIDR, like
`{ "term": { "audit_request_remote_address": "192.168.0.0/16" } }`.

## Q4: what an unknown source did after logging in

For each address Q1 or Q3 turns up that nobody recognises:

```json
{
  "size": 200,
  "sort": [{ "@timestamp": { "order": "asc" } }],
  "query": {
    "bool": {
      "filter": [
        { "term":  { "audit_request_remote_address": "[TODO: unknown address]" } },
        { "range": { "@timestamp": { "gte": "2026-10-20T00:00:00Z" } } }
      ]
    }
  }
}
```

Look for writes or deletes on `wazuh-alerts-*`, any request to `_plugins/_security`, and any
`.opendistro_security` access. Then enrich the addresses (dry run first, so no provider is
called):

```bash
.venv/Scripts/python.exe scripts/enrich_unknown_ips.py --file unknown_ips.txt
```

## Fallbacks when the audit log has nothing

| Source | Where | What to look for |
|---|---|---|
| Indexer node log | `/var/log/wazuh-indexer/wazuh-cluster.log` (default name) | authentication failures and their remote addresses, from 2026-10-20 |
| Reachability | VMware NAT port-forwarding table; VM `ss -ltnp \| grep 9200`; host firewall | Can anything outside the VM reach 9200 at all? If not, the leaked password could not be used from outside, which bounds the risk. It still gets rotated. |
| ADTE's own reads | ADTE's indexer user only calls `POST wazuh-alerts-*/_search` | Any other method or path by that user is not ADTE |
| Wazuh alerts | `wazuh-alerts-*`, `rule.groups: authentication_success` on the VM | logins to the VM itself near the window |
