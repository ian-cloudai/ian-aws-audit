from __future__ import annotations

import hashlib
import re
from typing import Iterable

COLLAPSE_THRESHOLD = 8

_HEALTH_CLASS = {
    "critical": "critical", "unhealthy": "critical",
    "degraded": "warning", "warning": "warning",
    "healthy": "healthy", "active": "healthy", "available": "healthy",
}

_TYPE_LABELS = {
    "ec2_instance": "EC2",
    "rds_instance": "RDS",
    "lambda_function": "Lambda",
    "s3_bucket": "S3",
    "ecs_service": "ECS",
    "ecs_cluster": "ECS",
}


def build(resources: Iterable[dict]) -> str:
    resources = list(resources)
    if not resources:
        return _empty()

    lines = [
        "graph TB",
        "  classDef critical fill:#fef2f2,stroke:#dc2626,color:#991b1b;",
        "  classDef warning fill:#fffbeb,stroke:#d97706,color:#92400e;",
        "  classDef healthy fill:#f0fdf4,stroke:#16a34a,color:#166534;",
        "  classDef unknown fill:#f9fafb,stroke:#6b7280,color:#374151;",
    ]

    by_account = _group_by(resources, lambda r: (r.get("metrics") or {}).get("aws_account_id"))
    for account_id, account_resources in by_account.items():
        account_node = _node_id("acct", str(account_id))
        lines.append(f'  subgraph {account_node}["AWS {account_id or "account"}"]')

        by_region = _group_by(account_resources, lambda r: r.get("region"))
        for region, region_resources in by_region.items():
            region_node = _node_id("region", f"{account_id}-{region}")
            lines.append(f'    subgraph {region_node}["{region or "global"}"]')

            by_type = _group_by(region_resources, lambda r: r.get("resource_type"))
            for rtype, type_resources in by_type.items():
                _emit_type_block(lines, account_id, region, rtype, type_resources)

            lines.append("    end")
        lines.append("  end")

    return "\n".join(lines)


def _empty() -> str:
    return (
        "graph TB\n"
        '  empty["No AWS resources discovered yet"]\n'
        "  classDef faded fill:#f9fafb,stroke:#d1d5db,color:#6b7280;\n"
        "  class empty faded;"
    )


def _emit_type_block(lines: list[str], account_id, region, rtype, type_resources: list[dict]) -> None:
    type_node = _node_id("type", f"{account_id}-{region}-{rtype}")
    label = f"{_type_label(rtype)} ({len(type_resources)})"

    if len(type_resources) > COLLAPSE_THRESHOLD:
        worst = _worst_health(type_resources)
        lines.append(f'      {type_node}["{label}"]:::{_health_class(worst)}')
        return

    lines.append(f'      subgraph {type_node}["{label}"]')
    for r in type_resources:
        rid = r.get("resource_id", "")
        name = _sanitize(r.get("resource_name") or rid)
        res_node = _node_id("res", f"{account_id}-{region}-{rtype}-{rid}")
        lines.append(f'        {res_node}["{name}"]:::{_health_class(r.get("health_status"))}')
    lines.append("      end")


def _type_label(rtype: str) -> str:
    if rtype in _TYPE_LABELS:
        return _TYPE_LABELS[rtype]
    return (rtype or "").replace("_", " ").title()


def _health_class(status) -> str:
    return _HEALTH_CLASS.get(str(status or "").lower(), "unknown")


def _worst_health(resources: list[dict]) -> str:
    statuses = [str(r.get("health_status") or "").lower() for r in resources]
    if any(s in ("critical", "unhealthy") for s in statuses):
        return "critical"
    if any(s in ("degraded", "warning") for s in statuses):
        return "warning"
    if any(s in ("healthy", "active", "available") for s in statuses):
        return "healthy"
    return "unknown"


def _group_by(items, key):
    out: dict = {}
    for item in items:
        out.setdefault(key(item), []).append(item)
    return out


def _node_id(prefix: str, key: str) -> str:
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}_{digest}"


def _sanitize(text: str) -> str:
    return re.sub(r'["\[\]()]', "", str(text))[:48]
