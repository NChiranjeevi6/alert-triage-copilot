"""Transparent, explainable severity scoring: every point has a reason an analyst can read."""
from __future__ import annotations

from .models import Alert, Enrichment, ScoreItem, TriageResult

SEVERITY_BASE = {"low": 10, "medium": 25, "high": 40, "critical": 55}
ASSET_POINTS = {"low": 0, "medium": 3, "high": 7, "critical": 12}
# Techniques that signal impact, credential theft, execution, C2 or exfiltration.
HIGH_IMPACT = {"T1486", "T1003", "T1059", "T1071", "T1566", "T1078", "T1041", "T1105", "T1021", "T1110"}
VERDICTS = [(80, "CRITICAL", "P1", "15 min"), (60, "HIGH", "P2", "1 hour"),
            (35, "MEDIUM", "P3", "4 hours"), (0, "LOW", "P4", "24 hours")]


def _label(score: int):
    for floor, verdict, prio, sla in VERDICTS:
        if score >= floor:
            return verdict, prio, sla


def compute_score(alert: Alert, enrichments: list[Enrichment]) -> tuple[int, list[ScoreItem]]:
    items = [ScoreItem("Rule severity", SEVERITY_BASE[alert.severity], f"SIEM rated this alert {alert.severity}")]

    ip_hits = [e for e in enrichments if e.ioc.type == "ip" and e.abuse_score > 0]
    if ip_hits:
        worst = max(ip_hits, key=lambda e: e.abuse_score)
        items.append(ScoreItem("IP reputation", round(worst.abuse_score * 0.25),
                               f"{worst.ioc.value} abuse confidence {worst.abuse_score}% ({worst.reports} reports)"))

    flagged = [e for e in enrichments if e.malicious > 0]
    if flagged:
        worst = max(flagged, key=lambda e: e.malicious)
        pts = round(min(worst.malicious / 10, 1) * 30)
        items.append(ScoreItem("Malicious detections", pts,
                               f"{worst.ioc.value} flagged by {worst.malicious}/{worst.total} engines"))

    if ASSET_POINTS[alert.asset_criticality]:
        items.append(ScoreItem("Asset criticality", ASSET_POINTS[alert.asset_criticality],
                               f"{alert.host or 'asset'} is {alert.asset_criticality} value"))

    hit = sorted(set(alert.mitre) & HIGH_IMPACT)
    if hit:
        items.append(ScoreItem("ATT&CK technique", 5, f"high-impact technique(s): {', '.join(hit)}"))

    if alert.event_count >= 50:
        items.append(ScoreItem("Event volume", 5, f"{alert.event_count} events"))
    elif alert.event_count >= 10:
        items.append(ScoreItem("Event volume", 3, f"{alert.event_count} events"))

    clean = [e for e in enrichments if not e.error]
    if clean and not ip_hits and not flagged and alert.severity in ("low", "medium"):
        items.append(ScoreItem("All IOCs clean", -10, "no reputation hits on any enriched indicator"))

    score = max(0, min(100, sum(i.points for i in items)))
    return score, items


def recommend(alert: Alert, enrichments: list[Enrichment], verdict: str) -> list[str]:
    acts: list[str] = []
    bad_ips = {e.ioc.value for e in enrichments if e.ioc.type == "ip" and (e.abuse_score >= 50 or e.malicious >= 5)}
    bad_dom = {e.ioc.value for e in enrichments if e.ioc.type == "domain" and e.malicious >= 3}
    bad_hash = {e.ioc.value for e in enrichments if e.ioc.type == "hash" and e.malicious >= 5}
    for ip in sorted(bad_ips):
        acts.append(f"Block {ip} at the perimeter and hunt for other internal hosts that contacted it")
    for d in sorted(bad_dom):
        acts.append(f"Sinkhole/block {d} in DNS and proxy; search proxy logs for other users who visited it")
    for h in sorted(bad_hash):
        acts.append(f"Isolate {alert.host or 'the host'} via EDR; collect the file and hunt hash {h[:16]}... fleet-wide")
    if bad_dom and alert.user:
        acts.append(f"Check whether {alert.user} entered credentials; force a password reset if so")
    if "T1110" in alert.mitre:
        acts.append("Review auth logs for a successful login after the failures; enforce MFA / lockout")
    if verdict == "CRITICAL":
        acts.insert(0, "Escalate to L2/IR lead now and open an incident ticket")
    elif verdict == "LOW" and not acts:
        acts.append("Document the reasoning and close as benign / tune the rule if it recurs")
    elif not acts:
        acts.append("Validate manually with host and user context before closing")
    return acts


def triage(alert: Alert, enrichments: list[Enrichment]) -> TriageResult:
    score, items = compute_score(alert, enrichments)
    verdict, priority, sla = _label(score)
    summary = (f"{priority} {verdict} ({score}/100): '{alert.rule_name}'"
               + (f" on {alert.host}" if alert.host else "")
               + (f" by {alert.user}" if alert.user else "")
               + f". Top factor: {max(items, key=lambda i: i.points).reason}.")
    return TriageResult(alert, enrichments, score, verdict, priority, sla, items,
                        recommend(alert, enrichments, verdict), summary)
