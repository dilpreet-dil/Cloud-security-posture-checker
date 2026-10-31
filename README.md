# Cloud Security Posture Checker

A working CSPM: collect cloud configuration, evaluate it against CIS-aligned rules, score it, store results, and report on them. Includes a web dashboard, REST API, database, Prowler integration, tests, and CI.

```
Browser (frontend/index.html)
   │  fetch /api/*  (X-API-Key if configured)
FastAPI (app/main.py) ── reporting.py (JSON · CSV · HTML)
   │
   ├─ collectors/   mock (demo, no credentials) · aws (boto3, read-only)
   ├─ rules.py      18 rules → (resource, pass/fail, detail)
   ├─ scanner.py    evaluate → severity-weighted score → persist
   └─ integrations/prowler.py   import Prowler v3 JSON / OCSF JSON
   │
SQLAlchemy ── SQLite (default) or PostgreSQL
```

## Run it

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload          # http://127.0.0.1:8000  (API docs at /docs)
```
Click **Run demo scan**. No cloud account needed: it scans five fictional accounts (the first run also records a baseline scan so the comparison and insights panels have something to compare).

## The dashboard ("Security Hub")
One screen, all driven by `GET /api/overview`, which rolls up the **latest scan of every account**:

| Panel | Shows |
|---|---|
| Overall security score | Severity-weighted score across all accounts, change since the previous scan, segmented gauge |
| Standards & frameworks / breakdown | Score per framework (CIS AWS Foundations, PCI DSS v4.0). Toggle a standard to include or hide it in the breakdown |
| Security summary | Total / passed / failed checks, and checks that could not be evaluated (missing permissions) |
| Failed controls | Unique failed control references; click one to see the affected resources |
| Findings queue | Failed findings by severity tab; click for details and fixes |
| Account rollup | Healthy / needs attention / high risk counts, a region map, score per account |
| Insights | New and resolved findings and improved controls versus each account's previous scan; top-risk account |

Header buttons: scan AWS, critical-findings bell, tools (Prowler import, clear API key). The left rail opens standards, all findings, and accounts (per-account HTML/CSV/JSON reports).

**About the framework mapping:** each check is tagged with an approximate CIS and PCI DSS v4.0 reference (see `compliance` in `rules.py`). It is a prioritisation aid, not a compliance attestation; verify against the official documents before using it for audits.

Docker + PostgreSQL:
```bash
echo "POSTGRES_PASSWORD=change-me" > .env
echo "CSPM_API_KEY=$(openssl rand -hex 24)" >> .env
docker compose up --build
```

## Scanning a real AWS account
Use **read-only** credentials (env vars, profile, or an IAM role). The AWS-managed `SecurityAudit` policy is sufficient. Minimal actions: `sts:GetCallerIdentity`, `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `s3:GetEncryptionConfiguration`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`, `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`, `iam:GetAccountSummary`, `iam:ListUsers`, `iam:GetLoginProfile`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:GetAccountPasswordPolicy`, `rds:DescribeDBInstances`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`.

Missing permissions are recorded in the scan's `summary.collector_errors` rather than silently reported as failures. Only scan accounts you are authorised to assess.

## Prowler integration
```bash
prowler aws -M json-ocsf -o out/       # run Prowler yourself
```
Then use **Import Prowler results** in the UI, or `POST /api/integrations/prowler/import` with `{"findings": [...]}`. `integrations/prowler.run_prowler()` can also invoke a locally installed CLI. Imported scans are stored with `source = "prowler"` and use the same score and report pipeline. The same adapter pattern fits ScoutSuite, Steampipe, or Trivy.

## API
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/overview` | dashboard roll-up (latest scan per account, standards, queue, insights) |
| POST | `/api/scans` | `{"provider":"mock"\|"aws","region":"us-east-1"}` run a scan (`profile` names a demo account for `mock`) |
| GET | `/api/scans`, `/api/scans/{id}` | history / one scan |
| GET | `/api/scans/{id}/findings?status=&severity=&service=` | filtered findings |
| GET | `/api/scans/{id}/report?format=json\|csv\|html` | download report |
| GET | `/api/trend` | score over the last 30 scans |
| POST | `/api/integrations/prowler/import` | ingest Prowler results |
| DELETE | `/api/scans/{id}` | delete a scan |
| GET | `/healthz` | liveness (unauthenticated) |

## Scoring
`score = 100 × Σ weight(passed checks) / Σ weight(all checks)` with weights critical 10, high 5, medium 3, low 1.

## Add a rule
```python
@rule("S3-005", "Bucket has no wildcard policy", "high", "s3", "Remove Principal:* statements.", "CIS 2.1.5")
def s3_policy(inv):
    return [_r(b["name"], not b.get("wildcard_policy"), "Policy allows Principal *") for b in inv["s3_buckets"]]
```
Collect the new field in `collectors/aws.py` and `mock.py`, then add a test in `tests/test_rules.py`.

## Add a cloud provider
Write `collectors/<name>.py` with `collect(region) -> dict` producing the same inventory shape, register it in `collectors/__init__.py` and the `provider` Literal in `schemas.py`, and write rules (or reuse the shared ones).

## Tests & CI
```bash
pip install -r requirements-dev.txt
pytest -q          # rules, API, auth, reports, Prowler parsing, AWS collector against moto
bandit -r app      # static security scan
```
`.github/workflows/ci.yml` runs both on every push.

## Hardening before real use
- Set `CSPM_API_KEY` (or put the app behind your SSO proxy) and serve over HTTPS; the compose file binds to localhost only.
- Scans run synchronously in the request. For large accounts, move `run_scan` to a worker (Celery/RQ) and poll status.
- Add Alembic migrations once the schema stabilises (the app currently uses `create_all`).
- Multi-account: store assumed-role ARNs per account and call `sts:AssumeRole` in the AWS collector.
- Scheduled scans: cron or a scheduler hitting `POST /api/scans`; alert on score drops using `/api/trend`.
