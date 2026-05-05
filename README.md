# greycortex-investigation

Claude Code skill for automated security assessments of [GreyCortex Mendel](https://www.greycortex.com/) NDR deployments. Discovers sensors via the CEM, spawns one OT Security Network Analyst agent per sensor in parallel, and consolidates global and per-sensor findings into a timestamped markdown report.

## What it does

One invocation produces a `mendel-assessment-YYYYMMDD-HHMMSS.md` file covering:

- **Open incidents** — ranked by risk, flagging unresolved critical/high
- **Top detection events** — CEM-aggregated, filtered by severity threshold
- **OT security findings** — OT-protocol-specific events (Modbus, DNP3, EtherNet/IP, etc.)
- **Threat intelligence hits** — internal hosts communicating with reputation-flagged IPs (section omitted if no hits)
- **Per-sensor analysis** — one parallel agent per sensor investigates notable events, enriches unknown hosts with MAC OUI lookups, and adds subnet context
- **Recommendations** — specific, prioritized actions based on actual findings

## Prerequisites

1. **[greycortex-mcp](https://github.com/laroy-sh/greycortex-mcp)** configured and connected as an MCP server named `greycortex-mendel`
2. **Jina AI MCP server** (`mcp__jina-ai`) connected — used for MAC OUI enrichment of unknown hosts
3. A GreyCortex Mendel service account with at minimum **Viewer** role

## Installation

```bash
claude skill install https://github.com/laroy-sh/greycortex-investigation
```

Or manually:

```bash
mkdir -p ~/.claude/skills/GreyCortex-investigation
cp skill.md ~/.claude/skills/GreyCortex-investigation/SKILL.md
```

## Invocation

In Claude Code:

```
/GreyCortex-investigation
```

Or naturally:

> "Run a security assessment" / "What's the security posture in Mendel?" / "Any threats in the last 7 days?"

The skill prompts for:
1. CEM target IP (defaults to `MENDEL_HOST`)
2. Sensor scope (all or specific sensors)
3. Minimum severity threshold (High ≥7, Critical ≥9, Medium ≥5, All)
4. Time window (24h, 7 days, 30 days, or custom)

## Output

A file named `mendel-assessment-YYYYMMDD-HHMMSS.md` in the current working directory. Only the filename and top finding are printed to chat — the full report is in the file.

## Known constraints

- **Never call `list_event_categories("MITRE")`** — returns all 398 categories, ignores pagination, causes OOM.
- **No flow data** — flows are stored on individual sensors, not the CEM; not accessible via this skill.
- **Read-only** — the skill never creates, modifies, or deletes any Mendel resources.
- Audit log tools (`list_ext_api_logs`, `list_web_api_logs`) and IDS variables (`list_ids_variables`) return 403 for Viewer accounts and are not used; a read-permission request has been filed upstream with GreyCortex.

## Companion MCP server

[greycortex-mcp](https://github.com/laroy-sh/greycortex-mcp) — the Python MCP server that exposes Mendel ExtAPI v2.4.5 as MCP tools.
