import os
import sys
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite://"  # in-memory, set before the app is imported
os.environ.pop("CSPM_API_KEY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def client():
    Base.metadata.drop_all(engine)
    with TestClient(app) as c:  # lifespan creates tables
        yield c


def good_inventory():
    return {
        "account_id": "1",
        "s3_buckets": [{"name": "b", "public_access_block": True, "encryption": True, "versioning": True, "logging": True}],
        "security_groups": [{"id": "sg-1", "ingress": [{"cidr": "10.0.0.0/8", "protocol": "tcp", "from": 22, "to": 22}]}],
        "ebs_volumes": [{"id": "v", "encrypted": True}],
        "root": {"mfa": True, "access_keys": 0},
        "iam_users": [{"name": "u", "console": True, "mfa": True, "keys": [{"id": "k", "age_days": 5, "active": True}]}],
        "password_policy": {"min_length": 16},
        "rds_instances": [{"id": "d", "public": False, "encrypted": True, "backup_retention": 14}],
        "cloudtrails": [{"name": "t", "multi_region": True, "logging": True, "log_validation": True}],
    }
