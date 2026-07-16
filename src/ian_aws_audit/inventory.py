from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable, Iterator

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger(__name__)

_BOTO_CONFIG = Config(retries={"max_attempts": 3, "mode": "standard"})


def scan(
    session: boto3.Session,
    regions: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
) -> tuple[str | None, list[dict]]:
    """Scan the account referenced by `session`. Returns (account_id, resources)."""
    account_id = _account_id(session)
    regions = regions or _regions(session)
    progress = progress or (lambda _msg: None)

    resources: list[dict] = []

    progress("scanning IAM (global)…")
    resources.extend(_scan_iam_users(session, account_id))

    progress("scanning S3 (global)…")
    resources.extend(_scan_s3_buckets(session, account_id))

    for region in regions:
        progress(f"scanning {region}…")
        resources.extend(_scan_ec2(session, region, account_id))
        resources.extend(_scan_security_groups(session, region, account_id))
        resources.extend(_scan_rds(session, region, account_id))
        resources.extend(_scan_lambda(session, region, account_id))

    return account_id, resources


def _account_id(session: boto3.Session) -> str | None:
    try:
        return session.client("sts", config=_BOTO_CONFIG).get_caller_identity()["Account"]
    except (BotoCoreError, ClientError) as e:
        log.warning("sts get_caller_identity failed: %s", e)
        return None


def _regions(session: boto3.Session) -> list[str]:
    try:
        ec2 = session.client("ec2", region_name="us-east-1", config=_BOTO_CONFIG)
        return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
    except (BotoCoreError, ClientError) as e:
        log.warning("describe_regions failed, falling back to us-east-1: %s", e)
        return ["us-east-1"]


def _scan_ec2(session: boto3.Session, region: str, account_id: str | None) -> Iterator[dict]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    try:
        pages = ec2.get_paginator("describe_instances").paginate()
    except (BotoCoreError, ClientError) as e:
        log.warning("[%s] ec2 describe_instances failed: %s", region, e)
        return

    for page in pages:
        for reservation in page["Reservations"]:
            for i in reservation["Instances"]:
                state = i["State"]["Name"]
                name = _tag(i.get("Tags"), "Name") or i["InstanceId"]
                yield {
                    "resource_type": "ec2_instance",
                    "resource_id": i["InstanceId"],
                    "resource_name": name,
                    "region": region,
                    "health_status": "healthy" if state == "running" else "warning",
                    "metrics": {
                        "aws_account_id": account_id,
                        "state": state,
                        "instance_type": i.get("InstanceType"),
                        "public_ip": i.get("PublicIpAddress"),
                        "private_ip": i.get("PrivateIpAddress"),
                        "vpc_id": i.get("VpcId"),
                        "launch_time": _iso(i.get("LaunchTime")),
                        "tags": _tags_dict(i.get("Tags")),
                    },
                }


def _scan_security_groups(session: boto3.Session, region: str, account_id: str | None) -> Iterator[dict]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    try:
        pages = ec2.get_paginator("describe_security_groups").paginate()
    except (BotoCoreError, ClientError) as e:
        log.warning("[%s] describe_security_groups failed: %s", region, e)
        return

    for page in pages:
        for sg in page["SecurityGroups"]:
            open_rules = _open_ingress(sg.get("IpPermissions", []))
            yield {
                "resource_type": "security_group",
                "resource_id": sg["GroupId"],
                "resource_name": sg.get("GroupName"),
                "region": region,
                "health_status": "critical" if open_rules else "healthy",
                "metrics": {
                    "aws_account_id": account_id,
                    "vpc_id": sg.get("VpcId"),
                    "open_to_world": open_rules,
                    "description": sg.get("Description"),
                },
            }


def _open_ingress(rules: list[dict]) -> list[dict]:
    out = []
    for r in rules:
        cidrs = [c["CidrIp"] for c in r.get("IpRanges", []) if c.get("CidrIp") == "0.0.0.0/0"]
        if not cidrs:
            continue
        out.append({
            "protocol": r.get("IpProtocol"),
            "from_port": r.get("FromPort"),
            "to_port": r.get("ToPort"),
        })
    return out


def _scan_rds(session: boto3.Session, region: str, account_id: str | None) -> Iterator[dict]:
    rds = session.client("rds", region_name=region, config=_BOTO_CONFIG)
    try:
        pages = rds.get_paginator("describe_db_instances").paginate()
    except (BotoCoreError, ClientError) as e:
        log.warning("[%s] describe_db_instances failed: %s", region, e)
        return

    for page in pages:
        for db in page["DBInstances"]:
            public = bool(db.get("PubliclyAccessible"))
            yield {
                "resource_type": "rds_instance",
                "resource_id": db["DBInstanceIdentifier"],
                "resource_name": db.get("DBName") or db["DBInstanceIdentifier"],
                "region": region,
                "health_status": "critical" if public else "healthy",
                "metrics": {
                    "aws_account_id": account_id,
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "instance_class": db.get("DBInstanceClass"),
                    "publicly_accessible": public,
                    "multi_az": db.get("MultiAZ"),
                    "allocated_storage_gb": db.get("AllocatedStorage"),
                    "backup_retention_days": db.get("BackupRetentionPeriod"),
                    "encryption": db.get("StorageEncrypted"),
                    "state": db.get("DBInstanceStatus"),
                },
            }


def _scan_lambda(session: boto3.Session, region: str, account_id: str | None) -> Iterator[dict]:
    client = session.client("lambda", region_name=region, config=_BOTO_CONFIG)
    try:
        pages = client.get_paginator("list_functions").paginate()
    except (BotoCoreError, ClientError) as e:
        log.warning("[%s] list_functions failed: %s", region, e)
        return

    for page in pages:
        for fn in page["Functions"]:
            yield {
                "resource_type": "lambda_function",
                "resource_id": fn["FunctionName"],
                "resource_name": fn["FunctionName"],
                "region": region,
                "health_status": "healthy",
                "metrics": {
                    "aws_account_id": account_id,
                    "runtime": fn.get("Runtime"),
                    "memory_size": fn.get("MemorySize"),
                    "timeout": fn.get("Timeout"),
                    "last_modified": fn.get("LastModified"),
                    "code_size": fn.get("CodeSize"),
                },
            }


def _scan_s3_buckets(session: boto3.Session, account_id: str | None) -> Iterator[dict]:
    s3 = session.client("s3", config=_BOTO_CONFIG)
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (BotoCoreError, ClientError) as e:
        log.warning("s3 list_buckets failed: %s", e)
        return

    for b in buckets:
        name = b["Name"]
        region = _bucket_region(s3, name)
        pab = _public_access_block(s3, name)
        versioning = _bucket_versioning(s3, name)
        encryption = _bucket_encryption(s3, name)

        health = "critical" if _pab_open(pab) else "healthy"
        yield {
            "resource_type": "s3_bucket",
            "resource_id": name,
            "resource_name": name,
            "region": region,
            "health_status": health,
            "metrics": {
                "aws_account_id": account_id,
                "public_access_block": pab,
                "versioning": versioning,
                "encryption": encryption,
                "created": _iso(b.get("CreationDate")),
            },
        }


def _bucket_region(s3, name: str) -> str | None:
    try:
        loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
        return loc or "us-east-1"
    except ClientError:
        return None


def _public_access_block(s3, name: str) -> dict | None:
    try:
        return s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
    except ClientError:
        return None  # not configured = potentially public


def _pab_open(pab: dict | None) -> bool:
    if not pab:
        return True
    return not all(pab.get(k, False) for k in (
        "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets",
    ))


def _bucket_versioning(s3, name: str) -> str | None:
    try:
        return s3.get_bucket_versioning(Bucket=name).get("Status")
    except ClientError:
        return None


def _bucket_encryption(s3, name: str) -> str | None:
    try:
        rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
        return rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] if rules else None
    except ClientError:
        return None


def _scan_iam_users(session: boto3.Session, account_id: str | None) -> Iterator[dict]:
    iam = session.client("iam", config=_BOTO_CONFIG)
    try:
        pages = iam.get_paginator("list_users").paginate()
    except (BotoCoreError, ClientError) as e:
        log.warning("iam list_users failed: %s", e)
        return

    for page in pages:
        for u in page["Users"]:
            name = u["UserName"]
            mfa = _has_mfa(iam, name)
            keys = _access_keys(iam, name)
            attached = _attached_policies(iam, name)
            admin = any(p == "arn:aws:iam::aws:policy/AdministratorAccess" for p in attached)

            health = "critical" if admin and not mfa else ("warning" if not mfa else "healthy")
            yield {
                "resource_type": "iam_user",
                "resource_id": name,
                "resource_name": name,
                "region": "global",
                "health_status": health,
                "metrics": {
                    "aws_account_id": account_id,
                    "mfa_enabled": mfa,
                    "admin": admin,
                    "access_keys": keys,
                    "attached_policies": attached,
                    "created": _iso(u.get("CreateDate")),
                    "password_last_used": _iso(u.get("PasswordLastUsed")),
                },
            }


def _has_mfa(iam, user: str) -> bool:
    try:
        return bool(iam.list_mfa_devices(UserName=user).get("MFADevices"))
    except ClientError:
        return False


def _access_keys(iam, user: str) -> list[dict]:
    try:
        keys = iam.list_access_keys(UserName=user).get("AccessKeyMetadata", [])
    except ClientError:
        return []
    return [{"id": k["AccessKeyId"], "status": k.get("Status"), "created": _iso(k.get("CreateDate"))} for k in keys]


def _attached_policies(iam, user: str) -> list[str]:
    try:
        pages = iam.get_paginator("list_attached_user_policies").paginate(UserName=user)
    except (BotoCoreError, ClientError):
        return []
    out: list[str] = []
    for page in pages:
        out.extend(p["PolicyArn"] for p in page.get("AttachedPolicies", []))
    return out


def _tag(tags: list[dict] | None, key: str) -> str | None:
    for t in tags or []:
        if t.get("Key") == key:
            return t.get("Value")
    return None


def _tags_dict(tags: list[dict] | None) -> dict:
    return {t["Key"]: t.get("Value") for t in tags or [] if t.get("Key")}


def _iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
