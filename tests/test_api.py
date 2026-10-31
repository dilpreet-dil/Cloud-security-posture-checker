from app import config


def scan(client):
    r = client.post("/api/scans", json={"provider": "mock"})
    assert r.status_code == 201
    return r.json()


def test_health_and_frontend(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert "text/html" in client.get("/").headers["content-type"]


def test_scan_lifecycle(client):
    s = scan(client)
    assert 0 <= s["score"] <= 100 and s["summary"]["total"] > 20
    assert client.get("/api/scans").json()[0]["id"] == s["id"]
    assert client.get(f"/api/scans/{s['id']}").json()["id"] == s["id"]
    assert client.get("/api/scans/9999").status_code == 404
    assert len(client.get("/api/trend").json()) == 1
    assert client.delete(f"/api/scans/{s['id']}").status_code == 204
    assert client.get(f"/api/scans/{s['id']}").status_code == 404


def test_findings_filters(client):
    s = scan(client)
    fails = client.get(f"/api/scans/{s['id']}/findings", params={"status": "FAIL"}).json()
    assert fails and all(f["status"] == "FAIL" for f in fails)
    crit = client.get(f"/api/scans/{s['id']}/findings", params={"severity": "critical"}).json()
    assert all(f["severity"] == "critical" for f in crit)


def test_reports(client):
    s = scan(client)
    for fmt, marker in (("json", '"findings"'), ("csv", "rule_id,severity"), ("html", "<table>")):
        r = client.get(f"/api/scans/{s['id']}/report", params={"format": fmt})
        assert r.status_code == 200 and marker in r.text
    assert client.get(f"/api/scans/{s['id']}/report", params={"format": "exe"}).status_code == 422


def test_invalid_input_rejected(client):
    assert client.post("/api/scans", json={"provider": "gcp"}).status_code == 422
    assert client.post("/api/scans", json={"provider": "aws", "region": "x; rm -rf /"}).status_code == 422


def test_aws_without_credentials_is_a_clean_400(client, monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    r = client.post("/api/scans", json={"provider": "aws"})
    assert r.status_code == 400 and "authenticate" in r.json()["detail"]


def test_api_key_enforced(client, monkeypatch):
    monkeypatch.setattr(config, "API_KEY", "s3cret")
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/scans", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/scans", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/healthz").status_code == 200  # health stays open for probes


def test_timestamps_are_utc_aware(client):
    s = scan(client)
    assert s["started_at"].endswith("Z") or s["started_at"].endswith("+00:00")
