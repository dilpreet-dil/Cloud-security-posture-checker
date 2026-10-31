from app.collectors.mock import DEMO_ACCOUNTS


def run_round(client):
    for name in DEMO_ACCOUNTS:
        assert client.post("/api/scans", json={"provider": "mock", "profile": name}).status_code == 201


def test_empty_overview(client):
    assert client.get("/api/overview").json() == {"empty": True}


def test_overview_after_one_round_has_no_comparison(client):
    run_round(client)
    o = client.get("/api/overview").json()
    assert not o["empty"] and len(o["accounts"]) == 5 and o["insights"] is None and o["delta"] is None
    assert 0 <= o["score"] <= 100 and o["summary"]["total"] == o["summary"]["passed"] + o["summary"]["failed"]
    assert {s["code"] for s in o["standards"]} == {"CIS", "PCI"}
    assert o["queue"]["counts"]["all"] == len(o["queue"]["items"]) == o["summary"]["failed"]
    assert o["top_risk"]["score"] == min(a["score"] for a in o["accounts"])
    assert {a["region"] for a in o["accounts"]} == {r for r, _ in DEMO_ACCOUNTS.values()}


def test_overview_second_round_adds_insights(client):
    run_round(client)
    run_round(client)
    o = client.get("/api/overview").json()
    assert len(o["accounts"]) == 5  # latest per account, not per scan
    assert set(o["insights"]) == {"new", "resolved", "controls_improved"} and o["delta"] is not None


def test_failed_controls_and_queue_ordering(client):
    run_round(client)
    o = client.get("/api/overview").json()
    order = ["critical", "high", "medium", "low"]
    sev = [f["severity"] for f in o["queue"]["items"]]
    assert sev == sorted(sev, key=order.index)
    assert all(c["standard"] in ("CIS", "PCI") for c in o["failed_controls"])


def test_bad_profile_rejected(client):
    assert client.post("/api/scans", json={"provider": "mock", "profile": "x; drop"}).status_code == 422
