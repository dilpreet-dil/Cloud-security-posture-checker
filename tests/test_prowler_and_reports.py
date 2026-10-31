from app.integrations.prowler import normalize
from app.reporting import _csv_safe

V3 = [{"Status": "FAIL", "Severity": "high", "CheckID": "s3_bucket_public_access", "CheckTitle": "Public bucket",
       "ServiceName": "s3", "ResourceId": "b1", "StatusExtended": "bucket is public", "AccountId": "111",
       "Remediation": {"Recommendation": {"Text": "Block it"}}},
      {"Status": "MANUAL", "Severity": "low", "CheckID": "x"}]
OCSF = [{"status_code": "PASS", "severity": "Critical", "status_detail": "ok", "message": "m",
         "finding_info": {"title": "Root MFA", "uid": "u1"}, "metadata": {"event_code": "iam_root_mfa_enabled"},
         "resources": [{"name": "root", "group": {"name": "iam"}}], "cloud": {"account": {"uid": "222"}},
         "remediation": {"desc": "Enable MFA"}}]


def test_normalize_v3():
    f, acct = normalize(V3)
    assert acct == "111" and len(f) == 1  # MANUAL skipped
    assert f[0]["severity"] == "high" and f[0]["remediation"] == "Block it" and f[0]["source"] == "prowler"


def test_normalize_ocsf():
    f, acct = normalize(OCSF)
    assert acct == "222" and f[0]["rule_id"] == "iam_root_mfa_enabled" and f[0]["service"] == "iam"
    assert f[0]["status"] == "PASS" and f[0]["severity"] == "critical"


def test_import_endpoint(client):
    r = client.post("/api/integrations/prowler/import", json={"findings": V3 + OCSF})
    assert r.status_code == 201
    body = r.json()
    assert body["source"] == "prowler" and body["summary"]["total"] == 2 and body["score"] == 66.7
    assert client.post("/api/integrations/prowler/import", json={"findings": [{"foo": 1}]}).status_code == 422


def test_csv_formula_injection_neutralised():
    assert _csv_safe("=cmd|' /C calc'!A0").startswith("'=")
    assert _csv_safe("normal") == "normal"
