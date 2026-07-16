# ian-aws-audit

One command. Scans your AWS account. Writes a markdown audit report with a mermaid infrastructure map. Security, cost, reliability, and operations findings — reviewed by Claude, cited to real resource IDs.

BYOK: your AWS credentials, your Anthropic API key. Nothing leaves your machine except the resource inventory going to Anthropic.

Free and OSS forever. Continuous scanning, drift alerts, and multi-account rollup live on the hosted product at **[iancloud.ai/audit](https://iancloud.ai/audit)**.

## Install

```bash
pipx install ian-aws-audit
export ANTHROPIC_API_KEY=sk-ant-...
```

## Run

```bash
ian-aws-audit run --profile prod --out audit.md
```

Scans every enabled region by default. Takes 30 seconds to a few minutes depending on account size. Progress prints to stderr; the report goes to `audit.md`.

Scan a single region:

```bash
ian-aws-audit run --profile prod --region us-east-1 --out audit.md
```

## Sample output

```
• scanning AWS account (profile=prod)…
• scanning IAM (global)…
• scanning S3 (global)…
• scanning us-east-1…
• scanning eu-west-1…
• discovered 84 resources across 2 regions
• asking Claude (claude-sonnet-4-6) to review…
• done. 12 findings (2 critical, 4 high) → audit.md
```

The report contains a summary, a mermaid diagram of the account, and each finding with severity, category, description, recommendation, and the specific resource IDs affected.

## Use inside Claude Code

Copy the skill into your Claude Code skills directory:

```bash
cp -r skills/claude/ian-aws-audit ~/.claude/skills/
```

Then in Claude Code:

> `audit my prod AWS account`

Claude will run the CLI, read the report, summarize the findings, and offer remediation.

## Use inside Cursor

Copy the rule into your project:

```bash
mkdir -p .cursor/rules
cp skills/cursor/ian-aws-audit.mdc .cursor/rules/
```

Then ask Cursor's agent:

> `run an AWS audit on the staging profile`

## What it scans

- EC2 instances (state, type, public IPs, tags)
- Security groups (ingress open to `0.0.0.0/0`)
- RDS instances (public accessibility, multi-AZ, backup retention, encryption)
- S3 buckets (public access block, versioning, encryption)
- Lambda functions (runtime, memory, timeout)
- IAM users (MFA, access key age, attached policies — flags Admin-without-MFA)

More resource types coming. PRs welcome.

## Continuous scanning (hosted)

The CLI is a one-shot local audit. If you want:

- Scheduled scans (daily / weekly) without wiring cron yourself
- Slack or email alerts the moment a new critical or high finding appears
- Multi-account rollup across prod, staging, dev, sandbox
- Historical posture — see how findings change week over week
- Assign findings to owners, track remediation

...that lives on the hosted product at **[iancloud.ai/audit](https://iancloud.ai/audit)**. Uses the same scanner as this CLI; you bring your own Anthropic key.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — required — | Your Anthropic API key |
| `ANTHROPIC_AUDIT_MODEL` | `claude-sonnet-4-6` | Model override |
| `AWS_PROFILE` | default | Standard boto3 profile |

AWS auth uses the standard boto3 credential chain: `--profile`, `AWS_PROFILE`, env vars, or instance/task role.

## What it costs you

- **AWS calls:** free — all `Describe*`/`List*`/`Get*`, no rate impact.
- **Anthropic:** one `messages` call per audit. For an 80-resource account, roughly $0.02–$0.10 with Sonnet 4.6.

## Development

```bash
git clone https://github.com/ian-cloudai/ian-aws-audit
cd ian-aws-audit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT.
