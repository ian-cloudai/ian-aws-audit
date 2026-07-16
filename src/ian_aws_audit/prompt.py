from __future__ import annotations

import json
from typing import Iterable

MAX_RESOURCES_PER_TYPE = 60

SYSTEM_PROMPT = """You are an AWS infrastructure auditor. You analyze a list of resources and
identify problems in four categories: security, cost, reliability, and
operations. You respond with ONLY valid JSON (no prose, no code fences)
matching this exact schema:

{
  "summary": "2-4 sentence overview of the account's overall posture",
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "category": "security|cost|reliability|operations",
      "title": "short headline (<80 chars)",
      "description": "what's wrong and why it matters (2-4 sentences)",
      "recommendation": "specific action the user should take",
      "resources_affected": ["resource_id_or_name", "..."]
    }
  ]
}

Rules:
- Be specific: cite actual resource IDs, not generic advice.
- Critical = active risk (public RDS, world-readable S3, root keys, exposed secrets).
- High = likely problem (overprovisioned instance, missing backups, no MFA).
- Medium = best-practice gap (no tags, single-AZ prod, oversized log retention).
- Low / info = minor or informational.
- No more than 20 findings. Prioritize the biggest issues.
- If the account is genuinely clean, return 0-2 informational findings explaining what's good."""


_RELEVANT_METRIC_KEYS = {
    "state", "instance_type", "publicly_accessible", "engine", "engine_version",
    "multi_az", "allocated_storage_gb", "runtime", "memory_size", "timeout",
    "encryption", "versioning", "public_access_block", "tags",
}


def build(account_id: str | None, resources: Iterable[dict]) -> tuple[str, str]:
    resources = list(resources)
    lines: list[str] = [
        f"AWS Account: {account_id or 'unknown'}",
        f"Resources discovered: {len(resources)}",
        "",
        "RESOURCE INVENTORY:",
    ]

    by_type: dict[str, list[dict]] = {}
    for r in resources:
        by_type.setdefault(r.get("resource_type", "unknown"), []).append(r)

    for rtype, records in by_type.items():
        capped = records[:MAX_RESOURCES_PER_TYPE]
        note = f" — showing first {len(capped)}" if len(capped) < len(records) else ""
        lines.append("")
        lines.append(f"## {rtype} ({len(records)}{note})")
        for r in capped:
            lines.append(f"- {json.dumps(_format(r), sort_keys=True)}")

    lines.append("")
    lines.append("Return your findings as JSON now.")
    return SYSTEM_PROMPT, "\n".join(lines)


def _format(resource: dict) -> dict:
    metrics = resource.get("metrics") or {}
    base = {
        k: v for k, v in {
            "id": resource.get("resource_id"),
            "name": resource.get("resource_name"),
            "region": resource.get("region"),
            "health": resource.get("health_status"),
        }.items() if v not in (None, "")
    }
    for k in _RELEVANT_METRIC_KEYS:
        if k in metrics and metrics[k] not in (None, ""):
            base[k] = metrics[k]
    return base
