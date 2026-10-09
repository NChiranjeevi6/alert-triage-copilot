import json

from triage.enrichment import MockProvider, enrich_all
from triage.models import IOC
from triage.parsers import is_internal, load_alerts, normalise
from triage.report import to_html, to_json, to_markdown
from triage.scoring import triage

META = {"mode": "mock", "manual_min": 10, "saved_min": 10, "generated": "test"}


def run_all():
    alerts = load_alerts("data/sample_alerts.json")
    intel = enrich_all(alerts, MockProvider())
    return {r.alert.id: r for r in (triage(a, [e for i in a.iocs for e in intel[IOC(i.type, i.value)]]) for a in alerts)}


def test_internal_ips_never_become_iocs():
    a = normalise({"id": "x", "src_ip": "10.1.2.3", "dest_ip": "203.0.113.9"})
    assert [i.value for i in a.iocs] == ["203.0.113.9"]
    assert a.internal_ips == ["10.1.2.3"]
    assert is_internal("192.168.1.1") and not is_internal("8.8.8.8") and is_internal("garbage")


def test_field_aliases_and_severity_normalisation():
    a = normalise({"alert_id": "7", "signature": "R", "level": 8, "hostname": "h", "techniques": "t1059, t1071"})
    assert (a.id, a.rule_name, a.severity, a.host) == ("7", "R", "high", "h")
    assert a.mitre == ["T1059", "T1071"]


def test_free_text_ioc_extraction_ignores_filenames():
    a = normalise({"id": "1", "description": "powershell.exe talked to 203.0.113.9 and evil.example"})
    values = {i.value for i in a.iocs}
    assert "203.0.113.9" in values and "evil.example" in values and "powershell.exe" not in values


def test_known_bad_alerts_escalate():
    r = run_all()
    assert r["A-1001"].verdict == "CRITICAL" and r["A-1001"].priority == "P1"
    assert r["A-1002"].verdict == "CRITICAL"
    assert r["A-1003"].verdict == "HIGH"


def test_benign_alerts_stay_low():
    r = run_all()
    assert r["A-1007"].verdict == "LOW" and r["A-1007"].score <= 15
    assert r["A-1008"].verdict == "LOW"


def test_scores_bounded_and_explainable():
    for res in run_all().values():
        assert 0 <= res.score <= 100
        assert res.breakdown and res.actions and res.summary
        raw = sum(i.points for i in res.breakdown)
        assert res.score == max(0, min(100, raw))


def test_html_report_escapes_untrusted_siem_text():
    html = to_html(list(run_all().values()), META)
    assert "<script>alert(" not in html
    assert "&lt;script&gt;alert(" in html


def test_markdown_and_json_reports_roundtrip():
    results = list(run_all().values())
    assert "A-1001" in to_markdown(results, META)
    assert len(json.loads(to_json(results, META))["results"]) == len(results)
