from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IOC:
    type: str   # "ip" | "domain" | "hash"
    value: str
    role: str = ""  # e.g. src_ip, dest_ip, domain, file_hash


@dataclass
class Enrichment:
    ioc: IOC
    source: str                 # "virustotal" | "abuseipdb" | "mock"
    malicious: int = 0          # engines flagging the IOC (VirusTotal)
    total: int = 0              # engines that analysed it
    abuse_score: int = 0        # 0-100 confidence of abuse (AbuseIPDB)
    reports: int = 0
    country: str = ""
    owner: str = ""
    error: str = ""


@dataclass
class Alert:
    id: str
    rule_name: str
    severity: str               # low | medium | high | critical
    timestamp: str = ""
    host: str = ""
    user: str = ""
    description: str = ""
    mitre: list[str] = field(default_factory=list)
    asset_criticality: str = "medium"   # low | medium | high | critical
    event_count: int = 1
    iocs: list[IOC] = field(default_factory=list)
    internal_ips: list[str] = field(default_factory=list)


@dataclass
class ScoreItem:
    label: str
    points: int
    reason: str


@dataclass
class TriageResult:
    alert: Alert
    enrichments: list[Enrichment]
    score: int
    verdict: str                # CRITICAL | HIGH | MEDIUM | LOW
    priority: str               # P1..P4
    sla: str
    breakdown: list[ScoreItem]
    actions: list[str]
    summary: str
