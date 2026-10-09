"""Normalise alerts from different SIEM exports into one schema and extract IOCs."""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .models import Alert, IOC

INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]

ALIASES = {
    "id": ("id", "alert_id", "_id"),
    "rule_name": ("rule_name", "rule", "alert_name", "name", "signature"),
    "severity": ("severity", "priority", "level"),
    "timestamp": ("timestamp", "time", "@timestamp", "_time"),
    "host": ("host", "hostname", "host.name", "computer"),
    "user": ("user", "username", "user.name", "account"),
    "description": ("description", "message", "summary"),
    "mitre": ("mitre", "mitre_techniques", "technique", "techniques"),
    "asset_criticality": ("asset_criticality", "criticality", "asset_value"),
    "event_count": ("event_count", "count", "events"),
    "src_ip": ("src_ip", "source_ip", "source.ip", "src"),
    "dest_ip": ("dest_ip", "dst_ip", "destination_ip", "destination.ip", "dest", "dst"),
    "domain": ("domain", "dns_query", "url", "query"),
    "file_hash": ("file_hash", "hash", "sha256", "sha1", "md5"),
}

FILE_EXTS = {"exe", "dll", "ps1", "bat", "cmd", "txt", "log", "json", "py", "js", "sh",
             "zip", "vbs", "msi", "tmp", "dat", "ini", "cfg", "xml", "doc", "docx", "xls"}
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
SEVERITIES = {"info": "low", "informational": "low", "low": "low", "medium": "medium",
              "moderate": "medium", "high": "high", "critical": "critical", "severe": "critical"}


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # malformed -> never send to a third party
    return any(addr in n for n in INTERNAL_NETS if n.version == addr.version)


def _pick(raw: dict, key: str, default=""):
    for alias in ALIASES[key]:
        if alias in raw and raw[alias] not in (None, ""):
            return raw[alias]
    return default


def _severity(value) -> str:
    if isinstance(value, (int, float)) or str(value).isdigit():
        n = float(value)
        return "critical" if n >= 9 else "high" if n >= 7 else "medium" if n >= 4 else "low"
    return SEVERITIES.get(str(value).strip().lower(), "medium")


def _criticality(value) -> str:
    v = str(value).strip().lower()
    return {"crown_jewel": "critical", "crown jewel": "critical"}.get(v, v if v in
            ("low", "medium", "high", "critical") else "medium")


def _bare_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    return value.split("/")[0]


def extract_iocs(raw: dict, description: str) -> tuple[list[IOC], list[str]]:
    iocs: dict[tuple[str, str], IOC] = {}
    internal: list[str] = []

    def add(kind: str, value: str, role: str):
        value = value.strip().lower() if kind != "ip" else value.strip()
        if not value:
            return
        if kind == "ip" and is_internal(value):
            if value not in internal:
                internal.append(value)
            return
        iocs.setdefault((kind, value), IOC(kind, value, role))

    for role in ("src_ip", "dest_ip"):
        v = str(_pick(raw, role))
        if v:
            add("ip", v, role)
    dom = _bare_domain(str(_pick(raw, "domain")))
    if dom:
        add("domain", dom, "domain")
    h = str(_pick(raw, "file_hash"))
    if h:
        add("hash", h, "file_hash")

    # opportunistic extraction from free text
    for ip in IPV4_RE.findall(description):
        try:
            ipaddress.ip_address(ip)
            add("ip", ip, "description")
        except ValueError:
            pass
    for d in DOMAIN_RE.findall(description):
        if d.rsplit(".", 1)[-1].lower() not in FILE_EXTS and not IPV4_RE.fullmatch(d):
            add("domain", d, "description")
    for hv in HASH_RE.findall(description):
        add("hash", hv, "description")
    return list(iocs.values()), internal


def normalise(raw: dict, index: int = 0) -> Alert:
    raw = {str(k).lower(): v for k, v in raw.items()}
    description = str(_pick(raw, "description"))
    mitre = _pick(raw, "mitre", [])
    if isinstance(mitre, str):
        mitre = [m.strip().upper() for m in re.split(r"[,;| ]+", mitre) if m.strip()]
    try:
        count = max(1, int(_pick(raw, "event_count", 1)))
    except (TypeError, ValueError):
        count = 1
    iocs, internal = extract_iocs(raw, description)
    return Alert(
        id=str(_pick(raw, "id", f"ALERT-{index + 1:04d}")),
        rule_name=str(_pick(raw, "rule_name", "Unnamed rule")),
        severity=_severity(_pick(raw, "severity", "medium")),
        timestamp=str(_pick(raw, "timestamp")),
        host=str(_pick(raw, "host")),
        user=str(_pick(raw, "user")),
        description=description,
        mitre=[str(m).upper() for m in mitre],
        asset_criticality=_criticality(_pick(raw, "asset_criticality", "medium")),
        event_count=count,
        iocs=iocs,
        internal_ips=internal,
    )


def load_alerts(path: str | Path) -> list[Alert]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".csv":
        rows = list(csv.DictReader(text.splitlines()))
    elif p.suffix == ".jsonl":
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        data = json.loads(text)
        rows = data.get("alerts", []) if isinstance(data, dict) else data
    return [normalise(r, i) for i, r in enumerate(rows)]
