# Security Policy

## Supported Versions

We release security updates for the current stable release. Older versions are not officially supported.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities in public issues.**

If you believe you have found a security issue in Graph Hunter:

1. **Report privately** by email to [idi@base4security.com](mailto:idi@base4security.com). Include a clear description, steps to reproduce, and impact if possible.
2. Allow a reasonable time (e.g. 90 days) for a fix before any public disclosure, unless the issue is already public.
3. We will acknowledge receipt and work with you to understand and address the finding.

We appreciate responsible disclosure and will credit reporters (with their permission) in release notes or advisories.

## Security Notes

- **Desktop app:** All processing is local; no telemetry. The optional HTTP API (127.0.0.1) is protected by a token printed at startup; keep it private.
- **Gateway:** The gateway service has no built-in authentication. Run it only in a trusted environment (e.g. localhost or a protected network). Do not expose it to the internet without adding authentication and HTTPS.
- **SIEM credentials:** Sent from the UI to the gateway in request bodies. Use HTTPS when the gateway is remote.
