import csv
import html
import io
import json
from datetime import timezone

from .models import utc
from .rules import SEVERITY_ORDER

COLS = ["rule_id", "severity", "status", "service", "resource", "title", "detail", "remediation", "compliance", "source"]


def _csv_safe(v) -> str:
    """Neutralise spreadsheet formula injection in exported cells."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def scan_dict(scan) -> dict:
    return {"id": scan.id, "provider": scan.provider, "source": scan.source, "account": scan.account,
            "region": scan.region, "score": scan.score, "started_at": utc(scan.started_at).isoformat(),
            "summary": scan.summary}


def finding_dict(f) -> dict:
    return {c: getattr(f, c) for c in COLS} | {"id": f.id}


def _sorted(findings):
    return sorted(findings, key=lambda f: (f.status != "FAIL", SEVERITY_ORDER.index(f.severity)
                                           if f.severity in SEVERITY_ORDER else 9, f.rule_id))


def to_json(scan, findings) -> str:
    return json.dumps({"scan": scan_dict(scan), "findings": [finding_dict(f) for f in _sorted(findings)]}, indent=2)


def to_csv(scan, findings) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(COLS)
    for f in _sorted(findings):
        w.writerow([_csv_safe(getattr(f, c)) for c in COLS])
    return buf.getvalue()


def to_html(scan, findings) -> str:
    e = html.escape
    s = scan.summary or {}
    sev = s.get("by_severity", {})
    rows = "".join(
        f"<tr class='{e(f.severity)}'><td>{e(f.severity)}</td><td>{e(f.rule_id)}</td><td>{e(f.resource)}</td>"
        f"<td>{e(f.title)}<br><small>{e(f.detail)}</small></td><td>{e(f.remediation)}</td></tr>"
        for f in _sorted(findings) if f.status == "FAIL")
    chips = " ".join(f"<b class='{k}'>{v} {k}</b>" for k, v in sev.items())
    ts = utc(scan.started_at).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>Posture report #{scan.id}</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#16202B}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ccd;padding:.5rem;text-align:left;vertical-align:top}}
.critical b,b.critical{{color:#b3261e}}b.high{{color:#c25e00}}b.medium{{color:#8a6d00}}b.low{{color:#2b6a94}}
tr.critical td:first-child{{color:#b3261e;font-weight:700}}tr.high td:first-child{{color:#c25e00;font-weight:700}}</style>
<h1>Cloud posture report</h1>
<p>Scan #{scan.id} &middot; {e(scan.provider)} ({e(scan.source)}) &middot; account {e(scan.account or 'n/a')} &middot; {ts}</p>
<h2>Score: {scan.score}/100</h2>
<p>{s.get('failed', 0)} failed of {s.get('total', 0)} checks. {chips}</p>
<table><tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Finding</th><th>Fix</th></tr>{rows}</table></html>"""
