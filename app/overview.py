"""Aggregates the latest scan of every account into the dashboard view model."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Finding, Scan, utc
from .reporting import finding_dict
from .rules import SEVERITY_ORDER
from .scanner import compute_score

FRAMEWORKS = {"CIS": "CIS AWS Foundations", "PCI": "PCI DSS v4.0"}
MAX_QUEUE = 2000


def _refs(compliance):
    return [r.strip() for r in (compliance or "").split(";") if r.strip()]


def _fw(ref):
    return ref.split(" ", 1)[0]


def _sev(s):
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 9


def _status(score):
    return "healthy" if score >= 75 else "attention" if score >= 40 else "high_risk"


def _load(db, scans):
    ids = [s.id for s in scans]
    out = {i: [] for i in ids}
    if ids:
        for f in db.scalars(select(Finding).where(Finding.scan_id.in_(ids))):
            out[f.scan_id].append(finding_dict(f))
    return out


def _fails(findings):
    return {(f["rule_id"], f["resource"]) for f in findings if f["status"] == "FAIL"}


def build_overview(db: Session) -> dict:
    scans = db.scalars(select(Scan).order_by(Scan.id.desc()).limit(500)).all()
    if not scans:
        return {"empty": True}

    groups: dict[str, list[Scan]] = {}
    for s in scans:
        groups.setdefault(s.account or "unknown", []).append(s)
    latest = {a: lst[0] for a, lst in groups.items()}
    prev = {}
    for a, lst in groups.items():  # previous scan of the same kind (native vs prowler)
        p = next((x for x in lst[1:] if x.source == lst[0].source), None)
        if p:
            prev[a] = p
    fmap = _load(db, list(latest.values()) + list(prev.values()))

    cur, cur_by = [], {}
    for a, s in latest.items():
        rows = fmap[s.id]
        for f in rows:
            f["account"], f["scan_id"], f["started_at"] = a, s.id, utc(s.started_at).isoformat()
        cur_by[a] = rows
        cur += rows

    score = compute_score(cur)
    prev_all = [f for a in latest for f in (fmap[prev[a].id] if a in prev else cur_by[a])]
    prev_score = compute_score(prev_all) if prev else None

    failed_n = sum(f["status"] == "FAIL" for f in cur)
    summary = {"total": len(cur), "passed": len(cur) - failed_n, "failed": failed_n,
               "not_evaluated": sum(len((s.summary or {}).get("collector_errors", [])) for s in latest.values())}

    standards = []
    for code, name in FRAMEWORKS.items():
        sub = [f for f in cur if any(_fw(r) == code for r in _refs(f["compliance"]))]
        if sub:
            standards.append({"code": code, "name": name, "score": compute_score(sub), "total": len(sub),
                              "failed": sum(f["status"] == "FAIL" for f in sub)})

    controls: dict = {}
    for f in cur:
        if f["status"] != "FAIL":
            continue
        for ref in _refs(f["compliance"]):
            e = controls.setdefault((ref, f["rule_id"]), {
                "standard": _fw(ref), "control": ref, "rule_id": f["rule_id"], "title": f["title"],
                "severity": f["severity"], "resources": 0})
            e["resources"] += 1
    failed_controls = sorted(controls.values(), key=lambda e: (_sev(e["severity"]), e["control"]))

    failed = [f for f in cur if f["status"] == "FAIL"]
    failed.sort(key=lambda f: f["started_at"], reverse=True)
    failed.sort(key=lambda f: _sev(f["severity"]))
    counts = {k: sum(f["severity"] == k for f in failed) for k in SEVERITY_ORDER} | {"all": len(failed)}

    insights = None
    if prev:
        new = resolved = improved = 0
        for a, p in prev.items():
            now, was = _fails(cur_by[a]), _fails(fmap[p.id])
            new += len(now - was)
            resolved += len(was - now)
            improved += len({r for r, _ in was} - {r for r, _ in now})
        insights = {"new": new, "resolved": resolved, "controls_improved": improved}

    accounts = sorted((
        {"account": a, "region": s.region, "provider": s.provider, "source": s.source, "score": s.score,
         "scan_id": s.id, "started_at": utc(s.started_at).isoformat(), "status": _status(s.score),
         "failed": (s.summary or {}).get("failed", 0), "total": (s.summary or {}).get("total", 0)}
        for a, s in latest.items()), key=lambda x: -x["score"])
    worst = min(accounts, key=lambda x: x["score"])

    return {"empty": False, "score": score, "previous_score": prev_score,
            "delta": None if prev_score is None else round(score - prev_score, 1),
            "summary": summary, "standards": standards, "failed_controls": failed_controls,
            "queue": {"counts": counts, "items": failed[:MAX_QUEUE]}, "accounts": accounts,
            "insights": insights, "top_risk": {"account": worst["account"], "score": worst["score"]},
            "updated_at": max(a["started_at"] for a in accounts),
            "has_demo": any(a["provider"] == "mock" for a in accounts)}
