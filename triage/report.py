"""Report writers: terminal, Markdown, JSON and a self-contained HTML dashboard."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from html import escape

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
ANSI = {"CRITICAL": "\033[95m", "HIGH": "\033[93m", "MEDIUM": "\033[96m", "LOW": "\033[92m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


def counts(results) -> Counter:
    return Counter(r.verdict for r in results)


def to_terminal(results, meta) -> str:
    c = counts(results)
    lines = [f"{BOLD}ALERT TRIAGE COPILOT{RESET} {DIM}// {meta['mode']} intel // {len(results)} alerts{RESET}", ""]
    lines.append("  ".join(f"{ANSI[v]}{v} {c[v]}{RESET}" for v in ORDER))
    lines.append("")
    for r in results:
        bar = "█" * (r.score // 5) + "░" * (20 - r.score // 5)
        lines.append(f"{ANSI[r.verdict]}{r.priority} {r.verdict:<8}{RESET} {bar} {r.score:>3}  "
                     f"{r.alert.id}  {r.alert.rule_name}")
    lines.append("")
    lines.append(f"{DIM}est. analyst time saved: {meta['saved_min']} min "
                 f"(assumes {meta['manual_min']} min manual enrichment per alert){RESET}")
    return "\n".join(lines)


def to_json(results, meta) -> str:
    return json.dumps({"meta": meta, "results": [asdict(r) for r in results]}, indent=2)


def to_markdown(results, meta) -> str:
    c = counts(results)
    out = [f"# Alert Triage Report", "",
           f"- **Generated:** {meta['generated']}", f"- **Intel mode:** {meta['mode']}",
           f"- **Alerts:** {len(results)}  |  " + "  |  ".join(f"{v}: {c[v]}" for v in ORDER), "",
           "## Triage queue", "", "| Pri | Verdict | Score | Alert | Rule | Host | SLA |", "|---|---|---|---|---|---|---|"]
    for r in results:
        out.append(f"| {r.priority} | {r.verdict} | {r.score} | {r.alert.id} | {r.alert.rule_name} | "
                   f"{r.alert.host or '-'} | {r.sla} |")
    for r in results:
        out += ["", f"## {r.alert.id} - {r.alert.rule_name}", "", f"> {r.summary}", "",
                "**Score breakdown**", ""]
        out += [f"- `{i.points:+d}` {i.label}: {i.reason}" for i in r.breakdown]
        if r.enrichments:
            out += ["", "**Indicators**", "", "| Type | Value | Source | Verdict data |", "|---|---|---|---|"]
            for e in r.enrichments:
                out.append(f"| {e.ioc.type} | `{e.ioc.value}` | {e.source} | {_intel_text(e)} |")
        out += ["", "**Recommended actions**", ""] + [f"- [ ] {a}" for a in r.actions]
    return "\n".join(out) + "\n"


def _intel_text(e) -> str:
    if e.error:
        return f"lookup failed: {e.error}"
    bits = []
    if e.source != "abuseipdb" and e.total:
        bits.append(f"{e.malicious}/{e.total} engines")
    if e.source in ("abuseipdb", "mock") and e.abuse_score:
        bits.append(f"abuse {e.abuse_score}% ({e.reports} reports)")
    if e.country:
        bits.append(e.country)
    if e.owner:
        bits.append(e.owner)
    return ", ".join(bits) or "no hits"


CSS = """
:root{--bg:#070a10;--panel:#0d121c;--line:#1c2740;--text:#cfe3ff;--dim:#6b7fa3;--cyan:#19e3ff;
--CRITICAL:#ff2d7a;--HIGH:#ff9f1c;--MEDIUM:#ffd23f;--LOW:#3ddc84}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "JetBrains Mono","Fira Code",
"SFMono-Regular",Consolas,"Liberation Mono",monospace;padding:0 0 64px}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px}
header{border-bottom:1px solid var(--line);padding:36px 0 28px;background:
linear-gradient(180deg,#0b1424 0,var(--bg) 100%)}
pre.banner{margin:0 0 14px;color:var(--cyan);font-size:11px;line-height:1.15;overflow-x:auto}
h1{margin:0;font-size:26px;letter-spacing:.02em}
.sub{color:var(--dim);margin-top:6px}
.prompt{color:var(--cyan)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:26px 0 8px}
.stat{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);padding:12px 14px}
.stat b{display:block;font-size:30px;color:var(--c);line-height:1.1}
.stat span{color:var(--dim);font-size:12px}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:22px 0 14px}
button{background:var(--panel);color:var(--text);border:1px solid var(--line);padding:6px 12px;
font:inherit;cursor:pointer}
button[aria-pressed=true]{border-color:var(--cyan);color:var(--cyan)}
:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
details{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);margin-bottom:10px}
summary{cursor:pointer;list-style:none;padding:12px 14px;display:grid;
grid-template-columns:auto 1fr auto;gap:6px 14px;align-items:center}
summary::-webkit-details-marker{display:none}
.tag{color:#07090f;background:var(--c);padding:1px 8px;font-weight:700}
.title{font-weight:600}.meta{color:var(--dim);font-size:12px;grid-column:2/4}
.bar{color:var(--c);letter-spacing:-1px;white-space:nowrap}.bar i{color:var(--line);font-style:normal}
.body{padding:4px 16px 18px;border-top:1px solid var(--line)}
.body h3{margin:18px 0 8px;font-size:13px;color:var(--cyan);font-weight:600}
.body p{margin:6px 0}.summary-line{border-left:2px solid var(--c);padding-left:10px;color:var(--text)}
table{width:100%;border-collapse:collapse;font-size:12.5px;display:block;overflow-x:auto}
th,td{text-align:left;padding:5px 10px 5px 0;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:500}
.pts{color:var(--HIGH)}.pts.neg{color:var(--LOW)}
.chips span{display:inline-block;border:1px solid var(--line);padding:0 8px;margin:0 6px 6px 0;color:var(--cyan)}
ul{margin:0;padding-left:20px}li{margin:3px 0}
footer{color:var(--dim);font-size:12px;margin-top:34px;border-top:1px solid var(--line);padding-top:14px}
@media(max-width:640px){summary{grid-template-columns:1fr}.meta{grid-column:1}}
"""

BANNER = r"""
  ___  __    ____ ____ ______   ______ ____  _____    _____  ____
 / _ |/ /   / __// __//_  __/  /_  __// __ \/  _/ |  / / _ |/ __/
/ __ / /__ / _/ / /_   / /      / /  / /_/ // /  / /_/ / __ / _/
/_/ |_/____//___/\__/  /_/      /_/   \_/\_\/___/ \____/_/ |_/___/
"""


def _card(r) -> str:
    a = r.alert
    bar = "█" * (r.score // 5) + f"<i>{'░' * (20 - r.score // 5)}</i>"
    rows = "".join(
        f"<tr><td>{escape(e.ioc.type)}</td><td>{escape(e.ioc.value)}</td><td>{escape(e.source)}</td>"
        f"<td>{escape(_intel_text(e))}</td></tr>" for e in r.enrichments) or \
        "<tr><td colspan=4>No external indicators (internal-only alert)</td></tr>"
    points = "".join(
        f"<tr><td class='pts{' neg' if i.points < 0 else ''}'>{i.points:+d}</td><td>{escape(i.label)}</td>"
        f"<td>{escape(i.reason)}</td></tr>" for i in r.breakdown)
    chips = "".join(f"<span>{escape(m)}</span>" for m in a.mitre) or "<span>none mapped</span>"
    acts = "".join(f"<li>{escape(x)}</li>" for x in r.actions)
    meta = " | ".join(escape(x) for x in (a.id, a.host, a.user, a.timestamp, f"SLA {r.sla}") if x)
    return f"""<details style="--c:var(--{r.verdict})" data-v="{r.verdict}">
<summary><span class="tag">{r.priority} {r.verdict}</span><span class="title">{escape(a.rule_name)}</span>
<span class="bar" aria-label="score {r.score} of 100">{bar} {r.score}</span><span class="meta">{meta}</span></summary>
<div class="body"><p class="summary-line">{escape(r.summary)}</p>
<h3>$ description</h3><p>{escape(a.description) or '-'}</p>
<h3>$ indicators</h3><table><tr><th>type</th><th>value</th><th>source</th><th>intel</th></tr>{rows}</table>
<h3>$ score --explain</h3><table><tr><th>pts</th><th>factor</th><th>reason</th></tr>{points}</table>
<h3>$ mitre</h3><div class="chips">{chips}</div>
<h3>$ next-actions</h3><ul>{acts}</ul></div></details>"""


def to_html(results, meta) -> str:
    c = counts(results)
    stats = "".join(f'<div class="stat" style="--c:var(--{v})"><b>{c[v]}</b><span>{v.lower()}</span></div>'
                    for v in ORDER)
    stats += (f'<div class="stat" style="--c:var(--cyan)"><b>{meta["saved_min"]}</b>'
              f'<span>est. analyst minutes saved</span></div>')
    filters = '<button aria-pressed="true" data-f="ALL">all</button>' + "".join(
        f'<button aria-pressed="false" data-f="{v}">{v.lower()}</button>' for v in ORDER)
    cards = "\n".join(_card(r) for r in results)
    js = ("document.querySelectorAll('button[data-f]').forEach(b=>b.onclick=()=>{"
          "document.querySelectorAll('button[data-f]').forEach(x=>x.setAttribute('aria-pressed',x===b));"
          "document.querySelectorAll('details[data-v]').forEach(d=>d.hidden=b.dataset.f!=='ALL'&&d.dataset.v!==b.dataset.f)})")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Alert Triage Copilot - Report</title>
<style>{CSS}</style></head><body>
<header><div class="wrap"><pre class="banner" aria-hidden="true">{escape(BANNER)}</pre>
<h1>Alert Triage Copilot</h1>
<div class="sub"><span class="prompt">$</span> triage analyze | {len(results)} alerts | {escape(meta['mode'])} intel |
{escape(meta['generated'])}</div></div></header>
<main class="wrap"><div class="stats">{stats}</div>
<div class="filters">{filters}</div>
{cards}
<footer>Scores are explainable: open any alert and run <code>score --explain</code> to see every point.
Demo data is synthetic. Est. time saved assumes {meta['manual_min']} min of manual enrichment per alert.</footer>
</main><script>{js}</script></body></html>"""
