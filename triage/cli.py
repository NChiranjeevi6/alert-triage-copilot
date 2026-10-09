from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .enrichment import LiveProvider, MockProvider, enrich_all
from .parsers import load_alerts
from .report import to_html, to_json, to_markdown, to_terminal
from .scoring import triage


def run(args) -> int:
    alerts = load_alerts(args.input)
    if not alerts:
        print("no alerts found in input", file=sys.stderr)
        return 1
    if args.mode == "live":
        vt, ab = os.getenv("VT_API_KEY"), os.getenv("ABUSEIPDB_API_KEY")
        if not (vt or ab):
            print("live mode needs VT_API_KEY and/or ABUSEIPDB_API_KEY (see .env.example)", file=sys.stderr)
            return 2
        provider = LiveProvider(vt, ab, vt_delay=args.vt_delay)
    else:
        provider = MockProvider()

    intel = enrich_all(alerts, provider)
    results = [triage(a, [e for ioc in a.iocs for e in intel[type(ioc)(ioc.type, ioc.value)]]) for a in alerts]
    results.sort(key=lambda r: (-r.score, r.alert.id))
    results = [r for r in results if r.score >= args.min_score]

    meta = {"mode": args.mode, "version": __version__, "manual_min": args.manual_minutes,
            "saved_min": len(results) * args.manual_minutes,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "triage_report.html").write_text(to_html(results, meta), encoding="utf-8")
    (out / "triage_report.md").write_text(to_markdown(results, meta), encoding="utf-8")
    (out / "triage_report.json").write_text(to_json(results, meta), encoding="utf-8")
    print(to_terminal(results, meta))
    print(f"\nreports written to {out}/ (open triage_report.html)")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="triage", description="Alert Triage Copilot")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="enrich, score and summarise SIEM alerts")
    a.add_argument("-i", "--input", default="data/sample_alerts.json", help=".json / .jsonl / .csv alert export")
    a.add_argument("-m", "--mode", choices=["mock", "live"], default="mock",
                   help="mock = offline synthetic intel (default); live = VirusTotal + AbuseIPDB")
    a.add_argument("-o", "--out", default="reports")
    a.add_argument("--min-score", type=int, default=0, help="hide alerts below this score")
    a.add_argument("--vt-delay", type=float, default=15.0, help="seconds between VirusTotal calls (free tier = 15)")
    a.add_argument("--manual-minutes", type=int, default=10, help="assumed manual minutes per alert (for time-saved stat)")
    a.set_defaults(func=run)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
