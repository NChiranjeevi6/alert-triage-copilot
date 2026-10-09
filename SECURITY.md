# Security & Responsible Use

**Alert Triage Copilot is a defensive tool.** It only reads alert exports and queries
reputation services (VirusTotal, AbuseIPDB). It contains no offensive capability.

## Design choices
- **Internal IPs are never sent to third parties** (RFC 1918, loopback, link-local are filtered out).
- **API keys come from environment variables** only; `.env` is git-ignored.
- **Untrusted SIEM text is HTML-escaped** in the report (covered by a test with an XSS payload).
- **Lookup failures never crash a run**; they are shown as `lookup failed` in the report.
- **Demo data is synthetic**: RFC 5737 documentation IPs, reserved `.example` domains, and the harmless EICAR test hash.

## Before using on real data
- Check your organisation's policy on sending indicators to third-party services.
- Note VirusTotal's terms: the free API is for non-commercial use.

## Reporting a vulnerability
Open a private security advisory on GitHub or email the maintainer. Please do not file public issues for vulnerabilities.
