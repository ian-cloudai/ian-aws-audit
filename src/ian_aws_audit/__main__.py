from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3

from . import __version__, anthropic_client, inventory, mermaid, prompt, renderer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ian-aws-audit",
        description="BYOK AWS account audit. Scans your account, asks Claude to review it, "
                    "writes a markdown report.",
    )
    parser.add_argument("--version", action="version", version=f"ian-aws-audit {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="Run an audit and write a markdown report.")
    run.add_argument("--profile", help="AWS profile to use (default: env/default chain).")
    run.add_argument("--region", action="append", help="Region to scan (repeatable). Default: all.")
    run.add_argument("--out", default=None, help="Output file (default: audit-YYYY-MM-DD.md).")
    run.add_argument("--model", default=None, help="Anthropic model (default: claude-sonnet-4-6).")
    run.add_argument("--verbose", "-v", action="store_true", help="Verbose logging.")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    return _run(args)


def _run(args) -> int:
    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    _log(f"scanning AWS account (profile={args.profile or 'default'})…")
    account_id, resources = inventory.scan(session, regions=args.region, progress=_log)
    _log(f"discovered {len(resources)} resources across {len({r['region'] for r in resources})} regions")

    if not resources:
        _log("nothing to audit. Check your AWS credentials.", err=True)
        return 2

    system, user = prompt.build(account_id, resources)
    _log(f"asking Claude ({args.model or anthropic_client.DEFAULT_MODEL}) to review…")
    try:
        client = anthropic_client.Client(model=args.model or anthropic_client.DEFAULT_MODEL)
        raw = client.messages(prompt=user, system=system, max_tokens=6000)
    except anthropic_client.AuditModelError as e:
        _log(f"Anthropic error: {e}", err=True)
        return 3

    report = _parse_report(raw)
    findings = report.get("findings", [])
    severity_counts = _tally(findings)

    md = renderer.render(
        aws_account_id=account_id,
        resource_count=len(resources),
        severity_counts=severity_counts,
        summary=report.get("summary", ""),
        findings=findings,
        mermaid_map=mermaid.build(resources),
        completed_at=datetime.now(timezone.utc),
    )

    out_path = Path(args.out or f"audit-{datetime.now().strftime('%Y-%m-%d')}.md")
    out_path.write_text(md, encoding="utf-8")

    total = len(findings)
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    _log(f"done. {total} findings ({critical} critical, {high} high) → {out_path}")
    _log("schedule this + get alerted on new critical findings → https://iancloud.ai/audit")
    return 0


def _parse_report(raw: str) -> dict:
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        if text.endswith("```"):
            text = text[: -3]
        text = text.strip()
    start = text.find("{")
    if start < 0:
        return _unstructured_fallback(raw)
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        return _unstructured_fallback(raw)


def _unstructured_fallback(raw: str) -> dict:
    return {
        "summary": "The model response could not be parsed as structured JSON. Raw output preserved below.",
        "findings": [{
            "severity": "info",
            "category": "operations",
            "title": "Model returned unstructured response",
            "description": raw[:2000],
            "recommendation": "Re-run the audit. If this persists, try a different --model.",
            "resources_affected": [],
        }],
    }


def _tally(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _log(msg: str, err: bool = False) -> None:
    prefix = "error:" if err else "•"
    print(f"{prefix} {msg}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    sys.exit(main())
