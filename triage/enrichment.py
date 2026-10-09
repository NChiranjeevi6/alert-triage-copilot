"""Threat-intel enrichment: offline MockProvider (demo/tests) and LiveProvider (VirusTotal + AbuseIPDB)."""
from __future__ import annotations

import time

from .models import IOC, Enrichment

try:
    import requests
except ImportError:  # live mode only
    requests = None

# Synthetic intel for the bundled sample data (RFC 5737 IPs, reserved .example domains).
MOCK_INTEL = {
    "203.0.113.45": dict(abuse=97, reports=412, mal=14, total=90, country="RU", owner="Example Bulletproof Hosting"),
    "198.51.100.23": dict(abuse=58, reports=31, mal=3, total=90, country="NL", owner="Example VPS Provider"),
    "192.0.2.77": dict(abuse=0, reports=0, mal=0, total=90, country="DE", owner="Example Telecom"),
    "login-micros0ft-secure.example": dict(mal=18, total=90, owner="newly registered, lookalike"),
    "cdn.updates-check.example": dict(mal=6, total=90, owner="registered 3 days ago"),
    "github.com": dict(mal=0, total=90, owner="GitHub, Inc."),
    # EICAR test file (harmless, universally detected) and the empty-file SHA-256
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": dict(mal=66, total=72, owner="EICAR test file"),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": dict(mal=0, total=72, owner="empty file"),
}


class MockProvider:
    name = "mock"

    def lookup(self, ioc: IOC) -> list[Enrichment]:
        d = MOCK_INTEL.get(ioc.value)
        if d is None:
            return [Enrichment(ioc, "mock", total=90, owner="no data (treated as clean)")]
        return [Enrichment(ioc, "mock", malicious=d.get("mal", 0), total=d.get("total", 0),
                           abuse_score=d.get("abuse", 0), reports=d.get("reports", 0),
                           country=d.get("country", ""), owner=d.get("owner", ""))]


class LiveProvider:
    name = "live"
    VT = "https://www.virustotal.com/api/v3"
    ABUSE = "https://api.abuseipdb.com/api/v2/check"
    VT_PATH = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}

    def __init__(self, vt_key: str | None, abuse_key: str | None, vt_delay: float = 15.0, timeout: int = 10):
        if requests is None:
            raise RuntimeError("live mode needs 'requests' (pip install -r requirements.txt)")
        self.vt_key, self.abuse_key = vt_key, abuse_key
        self.vt_delay, self.timeout = vt_delay, timeout
        self._last_vt = 0.0
        self._session = requests.Session()

    def lookup(self, ioc: IOC) -> list[Enrichment]:
        out = []
        if ioc.type == "ip" and self.abuse_key:
            out.append(self._abuse(ioc))
        if self.vt_key:
            out.append(self._vt(ioc))
        if not out:
            out.append(Enrichment(ioc, "none", error="no API keys configured"))
        return out

    def _abuse(self, ioc: IOC) -> Enrichment:
        try:
            r = self._session.get(self.ABUSE, timeout=self.timeout,
                                  headers={"Key": self.abuse_key, "Accept": "application/json"},
                                  params={"ipAddress": ioc.value, "maxAgeInDays": 90})
            r.raise_for_status()
            d = r.json()["data"]
            return Enrichment(ioc, "abuseipdb", abuse_score=int(d.get("abuseConfidenceScore", 0)),
                              reports=int(d.get("totalReports", 0)), country=d.get("countryCode") or "",
                              owner=d.get("isp") or "")
        except Exception as e:  # network/HTTP/JSON - never crash a triage run
            return Enrichment(ioc, "abuseipdb", error=str(e)[:120])

    def _vt(self, ioc: IOC) -> Enrichment:
        wait = self.vt_delay - (time.time() - self._last_vt)
        if wait > 0:
            time.sleep(wait)  # free tier: 4 requests/minute
        try:
            r = self._session.get(f"{self.VT}/{self.VT_PATH[ioc.type]}/{ioc.value}", timeout=self.timeout,
                                  headers={"x-apikey": self.vt_key})
            self._last_vt = time.time()
            if r.status_code == 404:
                return Enrichment(ioc, "virustotal", owner="not found in VirusTotal")
            r.raise_for_status()
            a = r.json()["data"]["attributes"]
            s = a.get("last_analysis_stats", {})
            return Enrichment(ioc, "virustotal", malicious=int(s.get("malicious", 0)) + int(s.get("suspicious", 0)),
                              total=sum(int(v) for v in s.values()), country=a.get("country") or "",
                              owner=a.get("as_owner") or a.get("meaningful_name") or "")
        except Exception as e:
            self._last_vt = time.time()
            return Enrichment(ioc, "virustotal", error=str(e)[:120])


def enrich_all(alerts, provider) -> dict[IOC, list[Enrichment]]:
    """Look each unique IOC up once, however many alerts share it."""
    cache: dict[IOC, list[Enrichment]] = {}
    for alert in alerts:
        for ioc in alert.iocs:
            key = IOC(ioc.type, ioc.value)
            if key not in cache:
                cache[key] = provider.lookup(ioc)
    return cache
