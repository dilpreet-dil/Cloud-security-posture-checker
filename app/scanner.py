from collections import Counter

from sqlalchemy.orm import Session

from .collectors import get_collector
from .models import Finding, Scan
from .rules import REGISTRY, SEVERITY_ORDER, SEVERITY_WEIGHT


def evaluate(inventory: dict) -> list[dict]:
    findings = []
    for r in REGISTRY:
        for resource, passed, detail in r.check(inventory):
            findings.append(dict(
                rule_id=r.id, title=r.title, severity=r.severity, service=r.service,
                resource=str(resource), status="PASS" if passed else "FAIL", detail=detail,
                remediation=r.remediation, compliance=r.compliance, source="native"))
    return findings


def compute_score(findings: list[dict]) -> float:
    """Severity-weighted pass rate, 0-100. Criticals count 10x a low."""
    total = sum(SEVERITY_WEIGHT.get(f["severity"], 1) for f in findings)
    if not total:
        return 100.0
    passed = sum(SEVERITY_WEIGHT.get(f["severity"], 1) for f in findings if f["status"] == "PASS")
    return round(100 * passed / total, 1)


def summarize(findings: list[dict]) -> dict:
    failed = [f for f in findings if f["status"] == "FAIL"]
    sev = Counter(f["severity"] for f in failed)
    return {
        "total": len(findings), "passed": len(findings) - len(failed), "failed": len(failed),
        "by_severity": {s: sev.get(s, 0) for s in SEVERITY_ORDER},
        "by_service": dict(Counter(f["service"] for f in failed)),
    }


def save_scan(db: Session, *, provider, source, account, region, findings, extra=None) -> Scan:
    scan = Scan(provider=provider, source=source, account=account, region=region or "",
                score=compute_score(findings), summary={**summarize(findings), **(extra or {})})
    scan.findings = [Finding(**f) for f in findings]
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def run_scan(db: Session, provider: str, region: str | None = None, profile: str | None = None) -> Scan:
    collect = get_collector(provider)
    inv = collect(region, profile) if provider == "mock" else collect(region)
    findings = evaluate(inv)
    errors = inv.get("errors", [])
    return save_scan(db, provider=provider, source="native", account=inv.get("account_id", ""),
                     region=inv.get("region") or region, findings=findings, extra={"collector_errors": errors})
