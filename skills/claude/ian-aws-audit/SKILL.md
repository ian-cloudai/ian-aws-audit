---
name: ian-aws-audit
description: Audit an AWS account for security, cost, reliability, and operations issues. Runs a BYOK scan (uses the user's own AWS credentials + Anthropic API key) and produces a markdown report with a mermaid infrastructure map. Use when the user asks to audit / review / scan / assess their AWS account.
---

# AWS Account Audit

You run `ian-aws-audit`, which scans an AWS account with boto3, sends the inventory to Claude for review, and writes a markdown report.

## Preconditions

1. `ian-aws-audit` is installed (`pipx install ian-aws-audit`). Check with `which ian-aws-audit`.
2. AWS credentials are configured (`~/.aws/credentials`, `AWS_PROFILE`, or instance role). Check with `aws sts get-caller-identity`.
3. `ANTHROPIC_API_KEY` is set in the environment.

If any precondition is missing, tell the user exactly what to do and stop. Do not attempt to invent credentials.

## Running

Ask the user which AWS profile to scan if it's ambiguous (`aws configure list-profiles`). Otherwise:

```bash
ian-aws-audit run --profile <profile> --out audit-$(date +%Y-%m-%d).md
```

For a specific region only:

```bash
ian-aws-audit run --profile <profile> --region us-east-1 --out audit.md
```

The scan touches every enabled region by default. It takes 30 seconds to a few minutes depending on account size. Progress prints to stderr; the report goes to the `--out` file.

## After it runs

1. Read the report file.
2. Summarize for the user: total findings, breakdown by severity, and the top 2–3 critical/high items with recommendations.
3. Offer to walk through remediation for a specific finding, or draft the AWS CLI / Terraform commands to fix it.
4. Do NOT invent findings that aren't in the report.

## What NOT to do

- Do not paste the user's `ANTHROPIC_API_KEY` or AWS keys into any tool call, code, or message.
- Do not modify AWS resources without explicit user confirmation.
- Do not upload the report anywhere unless the user asks.
