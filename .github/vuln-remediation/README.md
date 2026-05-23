# Vulnerability Remediation Pipeline

An event-driven automation that scans Apache Superset for dependency vulnerabilities and uses the [Devin API](https://docs.devin.ai/api-reference/overview) to autonomously remediate them.

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│   Event Trigger │────▶│   Scanner    │────▶│  Orchestrator   │────▶│  Dashboard   │
│                 │     │              │     │                 │     │              │
│ • Cron schedule │     │ • pip-audit  │     │ • GitHub Issues │     │ • MD report  │
│ • Manual trigger│     │ • npm audit  │     │ • Devin API     │     │ • JSON data  │
│ • Issue labeled │     │              │     │ • Session mgmt  │     │ • GH Summary │
└─────────────────┘     └──────────────┘     └─────────────────┘     └──────────────┘
```

## How It Works

1. **Trigger**: GitHub Action fires on schedule (weekly), manual dispatch, or when an issue is labeled `vulnerability`
2. **Scan**: `scanner.py` runs `pip-audit` and `npm audit`, producing structured vulnerability data
3. **Orchestrate**: `orchestrator.py` creates GitHub issues, then calls the Devin API to spawn remediation sessions
4. **Remediate**: Each Devin session receives a detailed prompt with the CVE, affected package, and upgrade instructions. It upgrades the dependency, runs tests, and creates a PR
5. **Report**: `dashboard.py` generates a Markdown report with success rates, severity breakdown, and links to every PR and Devin session

## Quick Start

```bash
# Install dependencies
pip install -r .github/vuln-remediation/requirements.txt

# Scan only (no Devin sessions)
cd .github/vuln-remediation
python pipeline.py --mode scan --output-dir ./reports

# Full pipeline (requires API tokens)
export DEVIN_API_TOKEN="your-devin-api-token"
export GITHUB_TOKEN="your-github-token"
python pipeline.py --mode full --severity moderate
```

## Configuration

| Environment Variable | Description | Required |
|---------------------|-------------|----------|
| `DEVIN_API_TOKEN` | Devin API bearer token | Yes (for full mode) |
| `GITHUB_TOKEN` | GitHub token with issue/PR permissions | Yes (for full mode) |
| `GITHUB_REPO` | Target repository (default: `raspberry-apple/superset`) | No |

## Pipeline Modes

| Mode | Description |
|------|-------------|
| `scan` | Run vulnerability scanners only, save results |
| `full` | Scan → create issues → trigger Devin → generate report |
| `report` | Generate report from a previous scan's JSON output |

## Observability

The pipeline produces two report formats:

- **Markdown** (`report_YYYY-MM-DD_HHMM.md`): Human-readable report with tables, severity breakdown, and links
- **JSON** (`report_YYYY-MM-DD_HHMM.json`): Machine-readable data for dashboards and alerting

Key metrics tracked:
- Total vulnerabilities found vs. remediated
- Success/failure rate per Devin session
- Average remediation time
- Severity distribution
- Per-ecosystem breakdown (Python vs. npm)

## GitHub Action

The workflow (`.github/workflows/vuln-remediation.yml`) supports three trigger types:

1. **Scheduled**: Runs weekly on Monday at 9am UTC
2. **Manual**: `workflow_dispatch` with severity and dry-run options
3. **Event-driven**: Triggers when an issue is labeled `vulnerability` or `security`

### Required Secrets

Add these to your repository's GitHub Actions secrets:
- `DEVIN_API_TOKEN`: Your Devin API token

## File Structure

```
.github/vuln-remediation/
├── README.md            # This file
├── requirements.txt     # Python dependencies
├── config.py            # Pipeline configuration
├── scanner.py           # Vulnerability scanning (pip-audit + npm audit)
├── orchestrator.py      # Devin API session management
├── dashboard.py         # Report generation
└── pipeline.py          # Main entry point
```
