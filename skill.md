---
name: GreyCortex-investigation
description: >
  Run a security assessment against a GreyCortex Mendel deployment using the
  Mendel MCP server. Discovers sensors via the CEM, spawns one OT Security
  Network Analyst agent per sensor in parallel to process sensor-scoped CEM
  data, and consolidates global and per-sensor findings into a timestamped
  markdown file covering open incidents, detection events, OT findings, threat
  intel, network topology, and audit observations. Read-only — does not create
  or modify Mendel data. Use when the user asks for a security assessment,
  security posture report, or threat investigation summary from
  Mendel/GreyCortex, or types /GreyCortex-investigation.
user-invocable: true
---

# Mendel Security Assessment

Parallel security posture report from GreyCortex Mendel. The orchestrator
gathers global CEM data and spawns one OT Security Network Analyst agent per
discovered sensor. All agents run in parallel. Output is written to a
timestamped MD file in the current working directory.

## Prerequisites

The GreyCortex Mendel MCP server must be configured and connected. It requires
`MENDEL_HOST`, `MENDEL_USERNAME`, and `MENDEL_PASSWORD` in the server's
environment (set in `.env` at the project root or passed directly).

## MAC Address Enrichment

Whenever an **unknown host** appears identified by MAC address only (no
hostname, no confirmed asset record), look up the OUI (first 3 octets) to
identify the manufacturer **before** reporting it as "unknown identity."

**Procedure:**

1. Extract the first 3 octets, e.g. `00:00:0c` from `00:00:0c:12:34:56`.
2. Call:
   ```
   mcp__jina-ai__search_web(query='MAC OUI "00:00:0c" manufacturer')
   ```
3. Parse the vendor name from authoritative results (IEEE OUI registry,
   maclookup.app, standards-oui.ieee.org). Use the first clear match.
4. Append the result inline: `00:00:0c:12:34:56 [Cisco Systems, Inc — OUI enriched]`.
   If the search is inconclusive, write `[OUI unknown — OUI enriched]` — never leave blank.

**Efficiency:** one search per unique OUI prefix; multiple MACs sharing the
same prefix need only one lookup.

**Caution:** A recognized vendor OUI does not prove the device is genuine —
if the device appeared unexpectedly (off-hours, policy-forbidden subnet),
note that MAC spoofing is possible alongside the vendor identification.

## Unknown Host Profiling

After OUI enrichment, immediately pull the host's Mendel profile and recent
detection events. Do this for every host that triggered the MAC enrichment path.

**Step 1 — Host profile:**

```
list_hosts(filter='macAddress EQ "XX:XX:XX:XX:XX:XX"', limit=5)
```

From the result, extract: host ID, all IPs seen, first/last seen timestamps,
hostname (if resolved), OS fingerprint, and any associated services.
If no result is returned, note "Host not yet in Mendel inventory" and
proceed to Step 2 using the MAC directly.

**Step 2 — Detection events for that host:**

Using the assessment window (ts_since/ts_till), filter by MAC address directly
(works even if the host has no IP or is not yet in the host inventory):

```
list_detection_events(
    interval=interval,
    ts_since=ts_since,
    ts_till=ts_till,
    filter='hostMac EQ "XX:XX:XX:XX:XX:XX"',
    filter_order_by="SEVERITY desc",
    limit=50,
)
```

Valid directional variants: `srcHostMac EQ "..."` or `dstHostMac EQ "..."`.
`hostMac` matches either direction and is preferred for unknown-host triage.

If you have an IP from Step 1, you may also cross-filter:
```
filter='hostMac EQ "XX:XX:XX:XX:XX:XX" OR srcHostAddr EQ "X.X.X.X" OR dstHostAddr EQ "X.X.X.X"'
```

**Output — add an "Unknown Host Profile" subsection** to the report section
where the host appeared (incident, detection event, or topology), with:

- MAC + OUI enrichment line
- IPs seen / first seen / last seen
- Hostname or "not resolved"
- OS fingerprint or "not detected"
- Top 5 detection events by severity (signature, severity, timestamp)
- If no events: "No detection events for this host in the assessment window."

---

## When to use

Trigger when the user asks for any of:
- "run a security assessment" / "mendel assessment" / "security posture"
- "what's going on in Mendel?" / "any threats?" / "OT security status"
- `/GreyCortex-investigation` (direct invocation)
- A time-scoped variant: "assess the last 7 days" / "check yesterday"

Do not trigger for individual lookups ("show me incident 42"), configuration
questions, or when the user is already mid-investigation.

---

## Step 0 — Initialization

Run both sub-steps sequentially before doing anything else.

### Step 0a — CEM IP

**If the user already specified a CEM IP in their invocation**, use it directly — skip this dialog.

**Otherwise**, read the `MENDEL_HOST` environment variable. Present it as the default option so the user can confirm or override:

```
AskUserQuestion(questions=[{
  "question": "Which GreyCortex CEM are you assessing?",
  "header": "CEM target",
  "multiSelect": false,
  "options": [
    {
      "label": "{MENDEL_HOST}",
      "description": "Current value of MENDEL_HOST (default)."
    }
  ]
}])
```

If `MENDEL_HOST` is not set, omit the option and rely solely on the auto-added "Other" field for the user to type the IP.

Parse the result → `cem_ip`. If the user typed a custom IP via the "Other" field, use that value verbatim.

### Step 0b — Sensor enumeration and selection

Immediately after capturing `cem_ip`, call:

```
list_subnets(limit=50)
```

Extract unique, non-null sensor names:

```
all_sensors = sorted({entry["sensor"] for entry in results if entry.get("sensor")})
```

**If no sensors found:** Set `selected_sensors = []`. Skip the selection dialog. Note "No sensors discovered — aggregate CEM assessment only."

**If sensors found:** Present a multi-select dialog, substituting the actual sensor names and populating the "All sensors" description with the full list:

```
AskUserQuestion(questions=[{
  "question": "Which sensors should the assessment include?",
  "header": "Sensor scope",
  "multiSelect": true,
  "options": [
    {
      "label": "All sensors (default)",
      "description": "Include every discovered sensor: [name1, name2, ...]."
    },
    {
      "label": "name1",
      "description": "Sensor name1."
    },
    {
      "label": "name2",
      "description": "Sensor name2."
    }
  ]
}])
```

- If "All sensors" is among the selections, or the user types via "Other", or nothing is explicitly chosen: `selected_sensors = all_sensors`
- Otherwise: `selected_sensors = [the explicitly chosen sensor names]`

### Step 0c — Severity filter

Present a single-select dialog to set the minimum severity threshold for all detection event queries:

```
AskUserQuestion(questions=[{
  "question": "What minimum severity level should the assessment include?",
  "header": "Severity filter",
  "multiSelect": false,
  "options": [
    {
      "label": "High and above (≥7)",
      "description": "Severity 7–10 (High + Critical). Standard triage level (default)."
    },
    {
      "label": "Critical only (≥9)",
      "description": "Severity 9–10 only. Tightest focus, lowest noise."
    },
    {
      "label": "Medium and above (≥5)",
      "description": "Severity 5–10. Broader sweep including Medium events."
    },
    {
      "label": "All events",
      "description": "Severity 1–10. Full visibility including Info and Low events."
    }
  ]
}])
```

Parse the selection → `severity_threshold`:

| Selection             | severity_threshold |
|-----------------------|--------------------|
| High and above (≥7)   | 7 (default)        |
| Critical only (≥9)    | 9                  |
| Medium and above (≥5) | 5                  |
| All events            | 1                  |

If the user selects "Other" or provides no clear answer, default to `severity_threshold = 7`.

Announce before proceeding:
> CEM: {cem_ip} | Sensors: {N} — [{name1}, {name2}, ...] | Severity: ≥{severity_threshold}

---

## Step 1 — Resolve the time window

**If the user already specified a window** in their invocation (e.g. "assess the last 7 days", "check yesterday"), parse it directly — skip the picker.

**Otherwise, ask the user** using `AskUserQuestion` before doing anything else:

```
AskUserQuestion(questions=[{
  "question": "Which time window should the assessment cover?",
  "header": "Time window",
  "multiSelect": false,
  "options": [
    {
      "label": "Last 24 hours",
      "description": "Standard daily review window (default)."
    },
    {
      "label": "Last week",
      "description": "Past 7 days — weekly threat sweep, broader context."
    },
    {
      "label": "Last month",
      "description": "Past 30 days — longer trend analysis."
    },
    {
      "label": "Custom",
      "description": "Specify a date range or duration (e.g. 'last 3 days', '2024-01-10 to 2024-01-17')."
    }
  ]
}])
```

The UI automatically adds an **Other** option — if the user selects it they can type a custom range (e.g. "last 30 days", "2024-01-10 to 2024-01-17"). Parse their free-text answer to derive `ts_since` and `ts_till`.

**Window → timestamp mapping** (all times UTC, `ts_till` = now):

| Selection     | ts_since                                            | ts_till |
|---------------|-----------------------------------------------------|---------|
| Last 24 hours | now − 24 h                                          | now     |
| Last week     | now − 7 days                                        | now     |
| Last month    | now − 30 days                                       | now     |
| Custom        | Parse the user's input; ask to clarify if ambiguous | varies  |

**Interval selection:**

| Window length | interval     |
|---------------|--------------|
| ≤ 2 hours     | ONE_MIN      |
| ≤ 1 day       | FIVE_MINS    |
| ≤ 7 days      | THIRTY_MINS  |
| ≤ 30 days     | FOUR_HOURS   |
| > 30 days     | ONE_DAY      |

Compute:
- `ts_since`: start of window in ISO 8601 UTC, e.g. `2024-01-15T08:00:00Z`
- `ts_till`: end of window in ISO 8601 UTC
- `interval`: from the table above

---

## Step 2 — Sensor scope (resolved in Step 0b)

Sensors were already enumerated and the user's selection was captured in Step 0b. Use `selected_sensors` for all subsequent steps. Do **not** re-call `list_subnets`.

**If `selected_sensors` is empty** (no sensors were discovered): Proceed with Steps 3a–3g (global data only). Skip Step 3e entirely. Note in the report header: "Sensors assessed: None discovered — aggregate CEM assessment only." Omit the Per-Sensor Analysis section.

---

## Step 3 — Gather global data and spawn per-sensor agents (all in parallel)

**Run everything in this step simultaneously.** Do not wait for any sub-step
before starting the others. Emit all MCP tool calls (3a–3g) and all Task agent
invocations (3h) in a single parallel batch.

### 3a. Open incidents

```
list_incidents(filter_order_by="RISK desc", limit=50)
```

Note count by status (`reported`, `to_analyze`, `resolved`) and risk level
(`critical`, `high`, `medium`, `low`, `lowest`). Flag unresolved critical/high.

### 3b. Top detection events (CEM aggregate, all sensors)

```
list_detection_events(
    interval=interval,
    ts_since=ts_since,
    ts_till=ts_till,
    filter=f"severity GTE {severity_threshold}",
    filter_order_by="SEVERITY desc",
    limit=50,
)
```

Severity is an integer 1–10. Events with severity ≥ 7 are high-priority
(7–8 = High, 9–10 = Critical per Mendel's official risk categories).
This returns CEM-aggregated events — no sensor filter is applied here.

### 3c. OT-specific events (CEM aggregate, all sensors)

```
list_detection_events(
    interval=interval,
    ts_since=ts_since,
    ts_till=ts_till,
    event_type="OT",
    filter=f"severity GTE {severity_threshold}",
    filter_order_by="SEVERITY desc",
    limit=50,
)
```

`event_type="OT"` auto-prepends `eventType EQ "OT"` to the filter string.

### 3d. Threat intelligence — hits in observed traffic

Query detection events where a host matched a threat feed during the window:

```
list_detection_events(
    interval=interval,
    ts_since=ts_since,
    ts_till=ts_till,
    filter=f"(srcHostReputation GT 0 OR dstHostReputation GT 0) AND severity GTE {severity_threshold}",
    filter_order_by="SEVERITY desc",
    limit=50,
)
```

For each hit, note: internal host IP, direction (src = egress, dst = ingress),
the external reputation-flagged IP, severity, and event signature.
If zero results are returned, record "No threat intelligence hits in traffic."
Do NOT call list_threat_reputations — listing the raw feed database has no
operational value unless it matches observed traffic.

### 3e. Per-sensor agents (one per sensor, all in parallel)

For each sensor in `selected_sensors` (resolved in Step 0b), spawn one agent using the Agent
tool. Emit all N invocations simultaneously — do not wait between sensors.

**Task invocation shape (repeat for each sensor, substituting SENSOR,
TS_SINCE, and TS_TILL):**

```
Agent(
    subagent_type="general-purpose",
    description="OT Security Network Analyst — sensor SENSOR | TS_SINCE to TS_TILL | severity ≥SEVERITY_THRESHOLD",
    prompt="""
You are an OT Security Network Analyst specializing in ICS/SCADA and
operational technology network security (Modbus, DNP3, EtherNet/IP,
PROFINET, OPC-UA).

Your task: investigate sensor SENSOR using GreyCortex Mendel CEM data for
the window TS_SINCE to TS_TILL. This is an investigation, not a monitoring
report — only surface findings that warrant attention. Do not dump
configuration data or report empty sections.

All MCP tools are read-only. Do NOT create, update, or delete anything.
NEVER call list_event_categories("MITRE") — this endpoint ignores pagination,
returns all 398 MITRE categories, and causes an OOM crash.

---

## Step A — Pull and triage events

Use `list_detection_events` scoped to this sensor — it queries pre-aggregated
interval buckets and reliably handles historical windows:

  list_detection_events(
      interval="INTERVAL",
      ts_since="TS_SINCE",
      ts_till="TS_TILL",
      filter='sensorName EQ "SENSOR"',
      filter_order_by="SEVERITY desc",
      limit=50,
  )

Do NOT use list_new_events for historical assessment windows — it is a
polling cursor endpoint and times out when started from a high-traffic
point in history.

**Triage — an event is notable if any of the following apply:**
- Severity ≥ SEVERITY_THRESHOLD
- Class is reconnaissance, policy-violation, lateral-movement, or anomaly
- Signature suggests unexpected OT protocol activity, unauthorized access,
  or scanning behavior

**If no notable events exist after triage: skip Steps B and C and go
directly to Your Output (no-activity variant).**

## Step B — Investigate context for notable events only

For each notable event, look up the subnet(s) named in that event to get
their annotation. Query only the specific subnets referenced — do NOT list
all subnets:

  list_subnets(sensor_name="SENSOR", address="<srcSubnetAddr>", limit=5)
  list_subnets(sensor_name="SENSOR", address="<dstSubnetAddr>", limit=5)

Use the returned name and policy fields to add context to the finding
(e.g. "Production Line 3" vs. "Vendor Z"). Skip this call if the event
has no subnet address field.

## Step C — OUI enrichment for unknown hosts in notable events only

For every host in a notable event identified only by MAC address (no
confirmed hostname or IP-backed asset record), look up the vendor:

  mcp__jina-ai__search_web(query='MAC OUI "XX:XX:XX" manufacturer')

One lookup per unique OUI prefix. Append inline:
  00:00:0c:12:34:56 [Cisco Systems, Inc — OUI enriched]
If inconclusive: [OUI unknown — OUI enriched]. Never omit.
If the device appeared unexpectedly, note MAC spoofing is possible.

---

## Your output

Return ONLY the block below. Do not add prose outside it. Do not write to a file.

**If no notable events after triage:**

---
### Sensor: SENSOR — No notable activity
No events met the investigation threshold (severity ≥ SEVERITY_THRESHOLD or suspicious class) in the assessment window TS_SINCE — TS_TILL.
---

**If notable events exist:**

---
### Sensor: SENSOR

**Assessment window:** TS_SINCE — TS_TILL

#### Notable Events

| Severity | Signature | Src → Dst | Subnet Context | Timestamp |
|---------|-----------|-----------|----------------|-----------|
| ...     | ...       | ...       | src: [name] → dst: [name] | ... |

{List all notable events. Group repeated same-signature events into a single
row with a count rather than duplicating rows. Include OUI-enriched MAC
inline in Src/Dst when applicable.}

#### Findings

- {2–4 bullets: what is happening, why it matters in OT/ICS context, what
  should be investigated next. Name specific hosts, subnets, signatures.
  Do not write generic security advice.}
---
"""
)
```

**If a sensor agent errors or returns malformed output:** Do not retry. In the
Per-Sensor Analysis section, insert:

```
### Sensor Report: SENSOR
_Agent error: <error message>. Sensor data unavailable for this assessment._
```

---

## Step 4 — Consolidate and write the report

Wait until all parallel work from Step 3 is complete — both the global MCP
calls (3a–3g) and all per-sensor agent Tasks (3h) — before writing anything.

**Output file:** Write the report to a file named
`mendel-assessment-YYYYMMDD-HHMMSS.md` in the current working directory,
where `YYYYMMDD-HHMMSS` is the UTC timestamp at report generation time
(e.g. `mendel-assessment-20260505-143022.md`). Use the Write tool to create
the file. After writing, tell the user the filename. Do not print the full
report body in chat — only the filename and a one-line summary of the top
finding. If a section has nothing to report, write "None in the assessment
window." in that section of the file.

---

```
# Mendel Security Assessment

**CEM:** {cem_ip}
**Window:** {ts_since} — {ts_till}
**Generated:** {current UTC timestamp}
**Sensors assessed:** {N sensors: name1, name2, ...}
  OR if none discovered: None discovered — aggregate CEM assessment only.

## Executive Summary

{2–4 sentences: overall posture, most significant global finding, most
significant per-sensor finding (if any), trend if visible.
Example: "The environment has N open incidents, M high/critical and
unresolved. Sensor collector-1 detected 3 high-severity OT events including
[signature]. Sensor collector-2 has been reporting a SPAN disruption for the
entire window, making its findings unreliable."}

## Critical Findings

{Bulleted list of items needing immediate attention. Draw from BOTH global
data (incidents, CEM events) and per-sensor Sensor-Level Findings. Lead with
the highest-risk item. Prefix sensor-specific items with [SENSOR: name].
If none: "No critical findings in the assessment window."}

## Open Incidents

{Omit this section entirely if there are no incidents.}

**Total:** N  |  Critical: N  |  High: N  |  Unresolved: N

| ID | Caption | Risk | Status | Assignee |
|----|---------|------|--------|---------|
| ... | ... | ... | ... | ... |

{List up to 10 highest-risk. If > 10, note "N more not shown."}

## Top Detection Events

{Omit this section entirely if no events meet the severity threshold.
Only list events with severity ≥ SEVERITY_THRESHOLD. Group repeated
signatures — one row per unique signature with a count column.}

**High-severity (≥7):** N  |  **Critical (≥9):** N

| Severity | Signature | Type | Src → Dst | First Seen | Count |
|---------|-----------|------|-----------|------------|-------|
| ... | ... | ... | ... | ... | ... |

## OT Security Findings

{Omit this section entirely if no OT events were detected. When present,
summarize by signature and affected host — do not list every individual
event row.}

## Threat Intelligence

{Only include this section if Step 3d returned at least one event with a
reputation-flagged host. If zero hits, omit the section entirely — do not
mention feed health, entry counts, or feed names.}

{When hits exist, report per-hit:}

| Direction | Internal Host | External IP (Flagged) | Severity | Signature | Timestamp |
|-----------|--------------|----------------------|---------|-----------|-----------|
| Egress (src) / Ingress (dst) | ... | ... | ... | ... | ... |

{Summarize: which internal hosts are communicating with known-bad IPs,
whether it is outbound (potential C2/exfiltration) or inbound (targeted
attack/scanning), and the associated signatures. Group by internal host.}

## Per-Sensor Analysis

{Only include subsections for sensors that returned notable events.
Paste each such sensor agent's markdown block verbatim.

Sensors that returned "No notable activity" are not given their own
subsection — list them in a single line at the top of this section:
"No notable activity: sensor-a, sensor-b."

If no sensors were discovered, omit this section entirely.}

## Recommendations

1. {Highest-priority global action — be specific, e.g. "Investigate incident
   #N (critical, unresolved for >24h) — assign and triage immediately."}
2. {Next global action.}
3. {Sensor-specific action where warranted, e.g. "[SENSOR: collector-1]
   Review 3 high-severity OT events ([signature]) — inspect affected hosts
   on subnet 10.20.1.0/24."}
{Add or drop items based on data. Do not pad with generic advice.}
```

---

## Constraints and pitfalls

- **NEVER call `list_event_categories("MITRE")`** — this endpoint returns all
  398 MITRE categories and ignores pagination, causing an OOM crash. This
  applies to the orchestrator AND is included verbatim in every per-sensor
  agent prompt.
- Severity in Mendel is an **integer 1–10**, not a label. Official buckets
  (Mendel 4.6.0 docs): Info=1, Low=2–4, Medium=5–6, High=7–8, Critical=9–10.
  Use ≥ 7 as "high-severity" and ≥ 9 as "critical" for report categorization.
- All orchestrator time-based tools (`list_detection_events`) require
  `interval` and time bounds — never omit these.
- **Do NOT use `list_new_events` for historical assessment windows.** It is a
  polling cursor endpoint — starting it from a point in history with high
  event volume causes a server-side table scan that exceeds the 10-second
  read timeout, even when zero events are ultimately returned. Use
  `list_detection_events` with `filter='sensorName EQ "SENSOR"'` instead.
- Keep `limit` at 50 or below for all report-oriented calls.
- **No flow tools.** `list_network_flows`, `run_analysis_view`, and related
  endpoints are not available — flows are stored on individual sensors, not
  on the CEM.
- **Per-sensor agents are context-isolated.** Each agent sees only its own
  prompt — it does not inherit incidents, global events, or other agents'
  results. Cross-sensor correlation is the orchestrator's responsibility
  during consolidation (Step 4).
- Do not create, update, or delete any Mendel resources. This skill is
  strictly read-only.
