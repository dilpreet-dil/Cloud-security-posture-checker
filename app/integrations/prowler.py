"""Import Prowler output (v3 JSON and v4/v5 OCSF JSON) into the same finding schema,
so results from external tools sit next to native checks.
Generate input with:  prowler aws -M json-ocsf   (or json)"""
import json
import shutil
import subprocess  # nosec B404 - fixed argv, no shell
import tempfile
from pathlib import Path

SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
       "informational": "low", "info": "low"}


def _get(d, *path, default=""):
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p)
    return default if d is None else d


def normalize(records: list[dict]) -> tuple[list[dict], str]:
    out, account = [], ""
    for r in records:
        if not isinstance(r, dict):
            continue
        if "status_code" in r or "finding_info" in r:  # OCSF
            status = str(r.get("status_code", "")).upper()
            res = (r.get("resources") or [{}])[0]
            item = dict(
                rule_id=str(_get(r, "metadata", "event_code") or _get(r, "finding_info", "uid"))[:64],
                title=str(_get(r, "finding_info", "title"))[:300],
                severity=SEV.get(str(r.get("severity", "")).lower(), "low"),
                service=str(res.get("group", {}).get("name", "") or _get(r, "metadata", "product", "name") or "unknown")[:40],
                resource=str(res.get("name") or res.get("uid") or "")[:300],
                detail=str(r.get("status_detail") or r.get("message") or ""),
                remediation=str(_get(r, "remediation", "desc")))
            account = account or str(_get(r, "cloud", "account", "uid"))
        else:  # Prowler v3
            status = str(r.get("Status", "")).upper()
            item = dict(
                rule_id=str(r.get("CheckID", ""))[:64], title=str(r.get("CheckTitle", ""))[:300],
                severity=SEV.get(str(r.get("Severity", "")).lower(), "low"),
                service=str(r.get("ServiceName", "unknown"))[:40],
                resource=str(r.get("ResourceId", ""))[:300], detail=str(r.get("StatusExtended", "")),
                remediation=str(_get(r, "Remediation", "Recommendation", "Text")))
            account = account or str(r.get("AccountId", ""))
        if status not in ("PASS", "FAIL"):
            continue  # skip MANUAL / MUTED
        item.update(status=status, source="prowler", compliance="")
        out.append(item)
    return out, account


def run_prowler(provider="aws", timeout=3600) -> list[dict]:
    """Optional: invoke a locally installed Prowler CLI and return its parsed findings."""
    exe = shutil.which("prowler")
    if not exe:
        raise RuntimeError("prowler CLI not found on PATH (pip install prowler)")
    with tempfile.TemporaryDirectory() as d:
        subprocess.run([exe, provider, "-M", "json-ocsf", "-o", d, "-F", "scan", "--no-banner"],
                       check=False, timeout=timeout)  # nosec B603 - fixed argv, no shell
        files = sorted(Path(d).glob("scan*.ocsf.json"))
        if not files:
            raise RuntimeError("Prowler produced no OCSF output")
        return json.loads(files[0].read_text())
