# Runbook: rotate ADTE's secrets

Written after the [2026-10-21 Railway env-var exposure](../incidents/2026-10-21-railway-env-var-exposure.md).
Use it whenever a hosting platform, a laptop, or a CI system that held ADTE's variables may have
been read. Status: Complete (procedure). It has not yet been timed end to end.

## Rules

- Rotate in each provider's own console. ADTE has no rotation code and should not get any: the
  app never needs write access to its own credentials.
- Never paste a key into a chat, a ticket, a commit, or a command line. The verification commands
  read the **old** value from an environment variable you set for the check and clear straight
  after. In Windows PowerShell 5.1 this reads it without echoing it or writing it to history:

```powershell
$s = Read-Host "old value" -AsSecureString; $env:OLD_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)); Remove-Variable s
```
- A rotation is done only when the **old** value fails. A new value working proves nothing about
  the old one.
- Keys differ per environment. A local `.env` never reuses a Railway value.

## Order (highest blast radius first)

| # | Variable(s) | Rotate where | Side effects |
|---|---|---|---|
| 1 | `ADTE_WAZUH_PASS` (and review `ADTE_WAZUH_USER`) | Wazuh VM: `bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u <user> -p <new>` (or Dashboard > Security > Internal users), then Railway Variables | Every client using that indexer user breaks until updated. If the user is `admin`, that includes the Dashboard login and Filebeat's keystore (`filebeat keystore`; restart filebeat), so check the Wazuh docs for the installed version before running the tool. A Railway variable change redeploys ADTE. |
| 2 | `ADTE_API_KEY_ADMIN`, `_SENIOR`, `_ANALYST`, `_READONLY` | Railway > service > Variables; generate with `python -c "import secrets; print(secrets.token_hex(24))"` | Redeploy (about 1 to 2 min). Header (CLI) callers with the old key get 401 at once. Browser sessions: from the session-key-binding change on, a session minted by a rotated key gets 401 on its next request. Before that change is deployed, old sessions survive up to 8 h if `ADTE_AUDIT_DB` is on a Volume, and are wiped by the redeploy if it is not. |
| 3 | `ANTHROPIC_API_KEY` | console.anthropic.com > API keys: create new, set on Railway, then **delete** old | Narrative summaries fall back to deterministic text if the key is missing during the swap. |
| 4 | `ADTE_VT_API_KEY` | virustotal.com > profile > API key (reset) | VT lookups abstain until the new key is set. The new key starts a fresh daily quota at the provider; ADTE's in-process quota resets on redeploy. |
| 5 | `ADTE_OTX_KEY` | otx.alienvault.com > settings > API key (regenerate) | OTX also works anonymously, so lookups continue at the anonymous rate. |
| 6 | `ADTE_ABUSEIPDB_KEY` (if set) | abuseipdb.com > account > API (create new, delete old) | AbuseIPDB lookups abstain until set. |
| 7 | `ADTE_API_KEY_RECRUITER` (optional) | Railway Variables, **and** the literal `RECRUITER_PASSKEY` in `frontend/src/app.jsx`, the README and Settings panel copy | A code change plus a push, which deploys. The key is public by design, so rotating it removes nothing an attacker lacked. |
| 8 | Local `.env` copies | `.env` in the repo root | Replace any value that matched Railway's with a local-only key. |

## Verify the old value fails

Each command prints only an HTTP status. Run them in Windows PowerShell 5.1 with `curl.exe`.

**ADTE API key** (any tier). Expect `401`:

```powershell
curl.exe -s -o NUL -w "%{http_code}" -H "X-ADTE-Key: $env:OLD_KEY" https://autonomousdetection.up.railway.app/api/auth-check
```

**Wazuh Indexer.** Run it on the VM; it prompts for the password, so type the **old** one. Expect `401`:

```bash
curl -s -o /dev/null -w "%{http_code}\n" --cacert /etc/wazuh-indexer/certs/root-ca.pem -u <user> https://localhost:9200/_plugins/_security/authinfo
```

**Anthropic.** Expect `401`:

```powershell
curl.exe -s -o NUL -w "%{http_code}" -H "x-api-key: $env:OLD_KEY" -H "anthropic-version: 2023-06-01" https://api.anthropic.com/v1/models
```

**VirusTotal.** Expect `401`:

```powershell
curl.exe -s -o NUL -w "%{http_code}" -H "x-apikey: $env:OLD_KEY" https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8
```

**OTX.** Expect a non-200 (OTX answers a bad key with 403 on this endpoint at the time of
writing):

```powershell
curl.exe -s -o NUL -w "%{http_code}" -H "X-OTX-API-KEY: $env:OLD_KEY" https://otx.alienvault.com/api/v1/user/me
```

**AbuseIPDB.** Expect `401`:

```powershell
curl.exe -s -o NUL -w "%{http_code}" -G -H "Key: $env:OLD_KEY" -H "Accept: application/json" --data-urlencode "ipAddress=8.8.8.8" https://api.abuseipdb.com/api/v2/check
```

Then clear the variable:

```powershell
Remove-Item Env:OLD_KEY
```

## After rotation

1. Run each check above with the **new** value, expecting 200, so the service is not left broken.
2. ADTE's deploy log shows `ADTE startup — N/3 threat intel sources configured`, with N equal to
   the number of TI keys set.
3. Record `rotated_at` / `verified_at` (UTC, from `date -u`) in the incident's checklist.
