"""Deterministic-ish demo inventory so the whole stack works without cloud credentials.
Each known misconfiguration is independently 'fixed' with some probability so repeated
scans produce a changing posture trend."""
import random  # nosec B311 - demo data only, not security-sensitive


DEMO_ACCOUNTS = {  # name -> (home region, relative risk: higher = more misconfigurations)
    "Prod-Account": ("us-east-1", 0.35), "Security-Account": ("eu-west-1", 0.5),
    "Dev-Account": ("ap-southeast-1", 0.9), "Shared-Services": ("eu-central-1", 1.1),
    "Legacy-Account": ("sa-east-1", 1.5),
}


def collect(region=None, profile=None, rng=None):
    rng = rng or random.Random()  # nosec B311 - demo data only
    home, risk = DEMO_ACCOUNTS.get(profile, (region, 1.0))
    bad = lambda p=0.65: rng.random() < min(0.97, p * risk)  # noqa: E731  # nosec B311
    world = {"cidr": "0.0.0.0/0", "protocol": "tcp"}
    inv = {
        "account_id": profile or "123456789012",
        "region": home,
        "s3_buckets": [
            {"name": "acme-public-assets", "public_access_block": not bad(0.7), "encryption": True,
             "versioning": not bad(0.5), "logging": not bad(0.8)},
            {"name": "acme-customer-exports", "public_access_block": not bad(0.4),
             "encryption": not bad(0.5), "versioning": True, "logging": not bad(0.6)},
            {"name": "acme-app-logs", "public_access_block": True, "encryption": True,
             "versioning": False, "logging": True},
        ],
        "security_groups": [
            {"id": "sg-0a1b2c-bastion", "ingress": [dict(world, **{"from": 22, "to": 22})] if bad(0.7)
             else [{"cidr": "10.0.0.0/8", "protocol": "tcp", "from": 22, "to": 22}]},
            {"id": "sg-0d4e5f-winapp", "ingress": [dict(world, **{"from": 3389, "to": 3389})] if bad(0.5)
             else []},
            {"id": "sg-0f6a7b-legacy", "ingress": [dict(world, protocol="-1")] if bad(0.4) else []},
            {"id": "sg-0c8d9e-web", "ingress": [dict(world, **{"from": 443, "to": 443})]},
        ],
        "ebs_volumes": [{"id": "vol-01", "encrypted": not bad(0.5)}, {"id": "vol-02", "encrypted": True}],
        "root": {"mfa": not bad(0.5), "access_keys": 1 if bad(0.3) else 0},
        "iam_users": [
            {"name": "alice", "console": True, "mfa": True,
             "keys": [{"id": "AKIA...A1", "age_days": 30, "active": True}]},
            {"name": "bob", "console": True, "mfa": not bad(0.7),
             "keys": [{"id": "AKIA...B2", "age_days": 200 if bad(0.7) else 40, "active": True}]},
            {"name": "ci-deployer", "console": False, "mfa": False,
             "keys": [{"id": "AKIA...C3", "age_days": 400 if bad(0.6) else 20, "active": True}]},
        ],
        "password_policy": {"min_length": 8 if bad(0.6) else 14},
        "rds_instances": [
            {"id": "orders-db", "public": bad(0.5), "encrypted": not bad(0.4), "backup_retention": 1 if bad(0.5) else 7},
            {"id": "analytics-db", "public": False, "encrypted": True, "backup_retention": 14},
        ],
        "cloudtrails": [{"name": "main-trail", "multi_region": not bad(0.4),
                         "logging": True, "log_validation": not bad(0.5)}],
    }
    return inv
