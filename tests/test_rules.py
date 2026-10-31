from app.rules import REGISTRY
from app.scanner import compute_score, evaluate, summarize
from tests.conftest import good_inventory


def failed_ids(inv):
    return {f["rule_id"] for f in evaluate(inv) if f["status"] == "FAIL"}


def test_compliant_inventory_scores_100():
    findings = evaluate(good_inventory())
    assert failed_ids(good_inventory()) == set()
    assert compute_score(findings) == 100.0


def test_every_rule_has_unique_id_and_valid_severity():
    ids = [r.id for r in REGISTRY]
    assert len(ids) == len(set(ids))
    assert {r.severity for r in REGISTRY} <= {"critical", "high", "medium", "low"}


def test_open_ssh_rdp_and_all_ports():
    inv = good_inventory()
    inv["security_groups"] = [
        {"id": "a", "ingress": [{"cidr": "0.0.0.0/0", "protocol": "tcp", "from": 20, "to": 30}]},
        {"id": "b", "ingress": [{"cidr": "::/0", "protocol": "tcp", "from": 3389, "to": 3389}]},
        {"id": "c", "ingress": [{"cidr": "0.0.0.0/0", "protocol": "-1"}]},
    ]
    findings = {(f["rule_id"], f["resource"]) for f in evaluate(inv) if f["status"] == "FAIL"}
    assert ("EC2-001", "a") in findings and ("EC2-001", "c") in findings
    assert ("EC2-002", "b") in findings and ("EC2-003", "c") in findings
    assert ("EC2-003", "a") not in findings


def test_iam_rules():
    inv = good_inventory()
    inv["root"] = {"mfa": False, "access_keys": 2}
    inv["iam_users"] = [{"name": "x", "console": True, "mfa": False,
                         "keys": [{"id": "old", "age_days": 120, "active": True}]}]
    inv["password_policy"] = {"min_length": 8}
    assert {"IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005"} <= failed_ids(inv)


def test_critical_failures_hurt_more_than_low():
    crit = good_inventory(); crit["rds_instances"][0]["public"] = True
    low = good_inventory(); low["s3_buckets"][0]["versioning"] = False
    assert compute_score(evaluate(crit)) < compute_score(evaluate(low)) < 100


def test_missing_sections_are_skipped_not_failed():
    assert evaluate({}) == []


def test_summary_counts():
    inv = good_inventory(); inv["ebs_volumes"][0]["encrypted"] = False
    s = summarize(evaluate(inv))
    assert s["failed"] == 1 and s["by_severity"]["medium"] == 1 and s["by_service"] == {"ebs": 1}
