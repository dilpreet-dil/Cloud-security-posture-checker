"""Read-only AWS collector. Needs boto3 credentials (env, profile or role) with the
SecurityAudit managed policy or the minimal actions listed in the README.
S3 and IAM are global; `region` applies to EC2/EBS/RDS/CloudTrail."""
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import CollectorError

_ABSENT = {
    "NoSuchPublicAccessBlockConfiguration",
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchEntity",
}


def _call(inv, label, fn, default=None):
    """Run an API call. Missing-config errors are expected; anything else (AccessDenied,
    throttling) is recorded in inv['errors'] so gaps in coverage are visible."""
    try:
        return fn()
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code not in _ABSENT:
            inv.setdefault("errors", []).append(f"{label}: {code}")
        return default


def collect(region=None):
    region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    session = boto3.session.Session(region_name=region)
    inv: dict = {"region": region}
    try:
        inv["account_id"] = session.client("sts").get_caller_identity()["Account"]
    except (BotoCoreError, ClientError) as e:
        raise CollectorError(f"Could not authenticate to AWS: {e}") from e

    s3, ec2 = session.client("s3"), session.client("ec2")
    iam, rds, ct = session.client("iam"), session.client("rds"), session.client("cloudtrail")

    # S3
    inv["s3_buckets"] = []
    for b in (_call(inv, "s3:ListBuckets", s3.list_buckets, {}) or {}).get("Buckets", []):
        n = b["Name"]
        pab = _call(inv, f"s3:PAB {n}", lambda: s3.get_public_access_block(Bucket=n)["PublicAccessBlockConfiguration"], {})
        enc = _call(inv, f"s3:Enc {n}", lambda: s3.get_bucket_encryption(Bucket=n), None)
        ver = _call(inv, f"s3:Ver {n}", lambda: s3.get_bucket_versioning(Bucket=n), {})
        log = _call(inv, f"s3:Log {n}", lambda: s3.get_bucket_logging(Bucket=n), {})
        inv["s3_buckets"].append({
            "name": n,
            "public_access_block": bool(pab) and len(pab) == 4 and all(pab.values()),
            "encryption": enc is not None,
            "versioning": (ver or {}).get("Status") == "Enabled",
            "logging": "LoggingEnabled" in (log or {}),
        })

    # EC2 security groups / EBS
    inv["security_groups"], inv["ebs_volumes"] = [], []
    try:
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                ingress = []
                for p in sg.get("IpPermissions", []):
                    proto = p.get("IpProtocol")
                    lo, hi = (0, 65535) if proto == "-1" else (p.get("FromPort", 0), p.get("ToPort", 65535))
                    cidrs = [r["CidrIp"] for r in p.get("IpRanges", [])] + \
                            [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])]
                    ingress += [{"cidr": c, "protocol": proto, "from": lo, "to": hi} for c in cidrs]
                inv["security_groups"].append({"id": sg["GroupId"], "ingress": ingress})
        for page in ec2.get_paginator("describe_volumes").paginate():
            inv["ebs_volumes"] += [{"id": v["VolumeId"], "encrypted": v["Encrypted"]} for v in page["Volumes"]]
    except ClientError as e:
        inv.setdefault("errors", []).append(f"ec2: {e.response['Error']['Code']}")

    # IAM
    summary = _call(inv, "iam:GetAccountSummary", lambda: iam.get_account_summary()["SummaryMap"])
    if summary:
        inv["root"] = {"mfa": bool(summary.get("AccountMFAEnabled")),
                       "access_keys": summary.get("AccountAccessKeysPresent", 0)}
    pol = _call(inv, "iam:PasswordPolicy", lambda: iam.get_account_password_policy()["PasswordPolicy"], {})
    inv["password_policy"] = {"min_length": (pol or {}).get("MinimumPasswordLength", 0)}
    inv["iam_users"] = []
    now = datetime.now(timezone.utc)
    try:
        for page in iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                n = u["UserName"]
                console = _call(inv, f"iam:LoginProfile {n}", lambda: iam.get_login_profile(UserName=n), None) is not None
                mfa = (_call(inv, f"iam:MFA {n}", lambda: iam.list_mfa_devices(UserName=n), {}) or {}).get("MFADevices", [])
                keys = (_call(inv, f"iam:Keys {n}", lambda: iam.list_access_keys(UserName=n), {}) or {}).get("AccessKeyMetadata", [])
                inv["iam_users"].append({
                    "name": n, "console": console, "mfa": bool(mfa),
                    "keys": [{"id": k["AccessKeyId"], "active": k["Status"] == "Active",
                              "age_days": (now - k["CreateDate"]).days} for k in keys],
                })
    except ClientError as e:
        inv.setdefault("errors", []).append(f"iam:ListUsers: {e.response['Error']['Code']}")

    # RDS
    inv["rds_instances"] = []
    try:
        for page in rds.get_paginator("describe_db_instances").paginate():
            inv["rds_instances"] += [{
                "id": d["DBInstanceIdentifier"], "public": d.get("PubliclyAccessible", False),
                "encrypted": d.get("StorageEncrypted", False),
                "backup_retention": d.get("BackupRetentionPeriod", 0)} for d in page["DBInstances"]]
    except ClientError as e:
        inv.setdefault("errors", []).append(f"rds: {e.response['Error']['Code']}")

    # CloudTrail
    trails = _call(inv, "cloudtrail:DescribeTrails", ct.describe_trails, None)
    if trails is not None:
        inv["cloudtrails"] = []
        for t in trails.get("trailList", []):
            st = _call(inv, f"cloudtrail:Status {t['Name']}", lambda: ct.get_trail_status(Name=t["TrailARN"]), {})
            inv["cloudtrails"].append({
                "name": t["Name"], "multi_region": t.get("IsMultiRegionTrail", False),
                "log_validation": t.get("LogFileValidationEnabled", False),
                "logging": (st or {}).get("IsLogging", False)})
    return inv
