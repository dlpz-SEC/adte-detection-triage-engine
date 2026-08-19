# Security Policy

## Supported Versions

ADTE is a portfolio and research project. There are no versioned releases. Security fixes are applied to the main branch as discovered.

## Reporting a Vulnerability

This repository has GitHub Private Vulnerability Reporting enabled. To report a security issue, use the "Report a vulnerability" button under the Security tab.

I'll respond within 7 days. There is no bug bounty program.

## Known non-issues (out of scope)

- **The recruiter demo passkey** published in the README and `frontend/src/app.jsx`
  is intentional — a rate-limited, analyst-role demo credential for the hosted
  demo, revocable at any time by rotating the `ADTE_API_KEY_RECRUITER`
  environment variable. Please do not report it as a leaked secret.
