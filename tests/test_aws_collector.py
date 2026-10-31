import pytest

moto = pytest.importorskip("moto")
import boto3  # noqa: E402

from app.collectors.aws import collect  # noqa: E402
from app.scanner import evaluate  # noqa: E402


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
                 "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)


def test_collects_and_flags_misconfigurations():
    with moto.mock_aws():
        boto3.client("s3").create_bucket(Bucket="leaky-bucket")
        ec2 = boto3.client("ec2")
        sg = ec2.create_security_group(GroupName="open", Description="open")
        ec2.authorize_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        boto3.client("iam").create_user(UserName="nomfa")
        inv = collect("us-east-1")
        failed = {(f["rule_id"], f["resource"]) for f in evaluate(inv) if f["status"] == "FAIL"}
    assert inv["account_id"] and any(b["name"] == "leaky-bucket" for b in inv["s3_buckets"])
    assert ("S3-001", "leaky-bucket") in failed
    assert ("EC2-001", sg["GroupId"]) in failed
