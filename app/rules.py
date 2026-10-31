"""Rule engine: each rule inspects the normalized inventory and returns
(resource, passed, detail) tuples. Add a rule by decorating a function."""
from dataclasses import dataclass
from typing import Callable

SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 3, "low": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
WORLD = {"0.0.0.0/0", "::/0"}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    service: str
    remediation: str
    compliance: str
    check: Callable[[dict], list]


REGISTRY: list[Rule] = []


def rule(id, title, severity, service, remediation, compliance=""):
    def deco(fn):
        REGISTRY.append(Rule(id, title, severity, service, remediation, compliance, fn))
        return fn

    return deco


def _r(resource, ok, fail_msg, ok_msg="Compliant"):
    return (resource, bool(ok), ok_msg if ok else fail_msg)


def _world_open(sg, port=None):
    for p in sg.get("ingress", []):
        if p.get("cidr") not in WORLD:
            continue
        lo, hi = p.get("from", 0), p.get("to", 65535)
        if p.get("protocol") == "-1":
            lo, hi = 0, 65535
        if port is None:
            if lo <= 0 and hi >= 65535:
                return True
        elif lo <= port <= hi:
            return True
    return False


# ---- S3 ----
@rule("S3-001", "S3 bucket blocks public access", "critical", "s3",
      "Enable all four S3 Block Public Access settings on the bucket.", "CIS 2.1.4; PCI 7.2.1")
def s3_public(inv):
    return [_r(b["name"], b.get("public_access_block"), "Block Public Access is not fully enabled")
            for b in inv.get("s3_buckets", [])]


@rule("S3-002", "S3 bucket has default encryption", "medium", "s3",
      "Enable default SSE-S3 or SSE-KMS encryption on the bucket.", "CIS 2.1.1; PCI 3.5.1")
def s3_enc(inv):
    return [_r(b["name"], b.get("encryption"), "Default encryption is disabled")
            for b in inv.get("s3_buckets", [])]


@rule("S3-003", "S3 bucket versioning enabled", "low", "s3",
      "Enable bucket versioning to protect against accidental deletion.", "CIS 2.1.3")
def s3_ver(inv):
    return [_r(b["name"], b.get("versioning"), "Versioning is disabled")
            for b in inv.get("s3_buckets", [])]


@rule("S3-004", "S3 server access logging enabled", "low", "s3",
      "Enable server access logging to a dedicated log bucket.", "CIS 2.1.2; PCI 10.2.1")
def s3_log(inv):
    return [_r(b["name"], b.get("logging"), "Access logging is disabled")
            for b in inv.get("s3_buckets", [])]


# ---- EC2 / network ----
@rule("EC2-001", "No security group exposes SSH (22) to the internet", "critical", "ec2",
      "Restrict port 22 to a bastion, VPN CIDR, or use SSM Session Manager.", "CIS 5.2; PCI 1.3.1")
def sg_ssh(inv):
    return [_r(s["id"], not _world_open(s, 22), "Port 22 open to 0.0.0.0/0")
            for s in inv.get("security_groups", [])]


@rule("EC2-002", "No security group exposes RDP (3389) to the internet", "critical", "ec2",
      "Restrict port 3389 to trusted CIDRs or use a gateway.", "CIS 5.2; PCI 1.3.1")
def sg_rdp(inv):
    return [_r(s["id"], not _world_open(s, 3389), "Port 3389 open to 0.0.0.0/0")
            for s in inv.get("security_groups", [])]


@rule("EC2-003", "No security group allows all ports from the internet", "high", "ec2",
      "Replace allow-all ingress with specific ports and source ranges.", "CIS 5.4; PCI 1.3.1")
def sg_all(inv):
    return [_r(s["id"], not _world_open(s), "All ports open to 0.0.0.0/0")
            for s in inv.get("security_groups", [])]


@rule("EBS-001", "EBS volume is encrypted", "medium", "ebs",
      "Enable EBS encryption by default and migrate unencrypted volumes via snapshot copy.", "CIS 2.2.1; PCI 3.5.1")
def ebs_enc(inv):
    return [_r(v["id"], v.get("encrypted"), "Volume is not encrypted")
            for v in inv.get("ebs_volumes", [])]


# ---- IAM ----
@rule("IAM-001", "Root account has MFA enabled", "critical", "iam",
      "Enable a hardware or virtual MFA device on the root user.", "CIS 1.5; PCI 8.4.2")
def root_mfa(inv):
    root = inv.get("root")
    return [] if root is None else [_r("root", root.get("mfa"), "Root MFA is not enabled")]


@rule("IAM-002", "Root account has no access keys", "critical", "iam",
      "Delete root access keys and use IAM roles instead.", "CIS 1.4")
def root_keys(inv):
    root = inv.get("root")
    return [] if root is None else [
        _r("root", root.get("access_keys", 0) == 0, "Root access keys exist")]


@rule("IAM-003", "Console users have MFA", "high", "iam",
      "Require MFA for all IAM users with console passwords.", "CIS 1.10; PCI 8.4.2")
def user_mfa(inv):
    return [_r(u["name"], (not u.get("console")) or u.get("mfa"), "Console user without MFA")
            for u in inv.get("iam_users", [])]


@rule("IAM-004", "Access keys rotated within 90 days", "medium", "iam",
      "Rotate or deactivate access keys older than 90 days.", "CIS 1.14; PCI 8.3.9")
def key_age(inv):
    out = []
    for u in inv.get("iam_users", []):
        old = [k["id"] for k in u.get("keys", []) if k.get("active") and k.get("age_days", 0) > 90]
        out.append(_r(u["name"], not old, f"Active key(s) older than 90 days: {', '.join(old)}"))
    return out


@rule("IAM-005", "Password policy requires 14+ characters", "medium", "iam",
      "Set the account password policy minimum length to at least 14.", "CIS 1.8; PCI 8.3.6")
def pw_policy(inv):
    pol = inv.get("password_policy")
    if pol is None:
        return []
    n = pol.get("min_length", 0)
    return [_r("account-password-policy", n >= 14, f"Minimum length is {n}")]


# ---- RDS ----
@rule("RDS-001", "RDS instance is not publicly accessible", "critical", "rds",
      "Disable public accessibility and place the instance in private subnets.", "CIS 2.3.3; PCI 1.3.1")
def rds_public(inv):
    return [_r(d["id"], not d.get("public"), "Instance is publicly accessible")
            for d in inv.get("rds_instances", [])]


@rule("RDS-002", "RDS storage is encrypted", "high", "rds",
      "Restore from an encrypted snapshot copy; encryption cannot be toggled in place.", "CIS 2.3.1; PCI 3.5.1")
def rds_enc(inv):
    return [_r(d["id"], d.get("encrypted"), "Storage is not encrypted")
            for d in inv.get("rds_instances", [])]


@rule("RDS-003", "RDS backup retention is 7+ days", "low", "rds",
      "Set backup retention to at least 7 days.", "")
def rds_backup(inv):
    return [_r(d["id"], d.get("backup_retention", 0) >= 7,
               f"Retention is {d.get('backup_retention', 0)} day(s)")
            for d in inv.get("rds_instances", [])]


# ---- CloudTrail ----
@rule("CT-001", "A multi-region CloudTrail is logging", "high", "cloudtrail",
      "Create a multi-region trail and start logging.", "CIS 3.1; PCI 10.2.1")
def ct_enabled(inv):
    if "cloudtrails" not in inv:
        return []
    ok = any(t.get("logging") and t.get("multi_region") for t in inv["cloudtrails"])
    return [_r("account", ok, "No active multi-region trail")]


@rule("CT-002", "CloudTrail log file validation enabled", "medium", "cloudtrail",
      "Enable log file integrity validation on the trail.", "CIS 3.2; PCI 10.3.4")
def ct_validation(inv):
    return [_r(t["name"], t.get("log_validation"), "Log file validation is disabled")
            for t in inv.get("cloudtrails", [])]
