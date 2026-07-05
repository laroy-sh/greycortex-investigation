---
name: GreyCortex-investigation
description: >
  Run a security assessment against a GreyCortex Mendel deployment using the
  Mendel MCP server. Discovers sensors via the CEM, spawns one OT Security
  Network Analyst agent per sensor in parallel to process sensor-scoped CEM
  data, and consolidates global and per-sensor findings into a timestamped
  markdown file covering open incidents, detection events, OT findings, and
  threat intel. Read-only — does not create or modify Mendel data. Use when
  the user asks for a security assessment, security posture report, or threat
  investigation summary from Mendel/GreyCortex, or types
  /GreyCortex-investigation.
---

# Mendel Security Assessment

Parallel security posture report from GreyCortex Mendel. The orchestrator
gathers global CEM data and spawns one OT Security Network Analyst agent per
discovered sensor. All agents run in parallel. Output is written to a
timestamped MD file in the current working directory.

## When to use

Trigger when the user asks for any of:
- "run a security assessment" / "mendel assessment" / "security posture"
- "what's going on in Mendel?" / "any threats?" / "OT security status"
- `/GreyCortex-investigation` (direct invocation)
- A time-scoped variant: "assess the last 7 days" / "check yesterday"

Do not trigger for individual lookups ("show me incident 42"), configuration
questions, or when the user is already mid-investigation.

## Prerequisites

- **GreyCortex Mendel MCP server** configured and connected. It requires
  `MENDEL_HOST`, `MENDEL_USERNAME`, and `MENDEL_PASSWORD` in the server's
  environment, set in `.env` at the project root — never commit credentials.
- **Jina AI MCP server** (`mcp__jina-ai`) connected — used for MAC OUI
  enrichment of unknown hosts.

The MCP server always connects to its configured `MENDEL_HOST`. If the user
asks to assess a different CEM, tell them to repoint the MCP server's
environment — this skill cannot switch targets.

---

## Step 0 — Initialization

Run sub-steps 0a and 0b sequentially before doing anything else.

### Step 0a — Sensor enumeration

Call `list_subnets` and paginate until exhausted (the ≤50 limit in
Constraints applies to report-oriented queries, not enumeration):

```
list_subnets(limit=50)            # then offset=50, 100, ... while full pages return
```

Extract unique, non-null sensor names across all pages:

```
all_sensors = sorted({entry["sensor"] for entry in results if entry.get("sensor")})
```

**If no sensors found:** Set `selected_sensors = []`. Omit the sensor
question from the Step 0b dialog. Note "No sensors discovered — aggregate
CEM assessment only."

### Step 0b — Assessment parameters (single dialog)

Ask everything in **one** `AskUserQuestion` call (the tool supports up to 4
questions per call). Include up to three questions: sensor scope, severity,
time window. **If the user already specified a parameter in their
invocation** (e.g. "assess the last 7 days" fixes the time window), parse it
directly and omit that question from the dialog. If no questions remain,
skip the dialog entirely.

```
AskUserQuestion(questions=[
  {
    # Omit this question if no sensors were discovered.
    # If more than 3 sensors exist, present only the "All sensors" option
    # (max 4 options per question) — specific sensors can be typed via the
    # auto-added "Other" field, comma-separated.
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
  },
  {
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
  },
  {
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
      }
    ]
  }
])
```

The UI automatically adds an **Other** option to every question — free-text
answers (e.g. "last 3 days", "2024-01-10 to 2024-01-17") arrive through it.

**Parse the answers:**

- **Sensor scope:** If "All sensors" is among the selections or nothing is
  explicitly chosen: `selected_sensors = all_sensors`. If the user typed via
  "Other": match each comma-separated token against `all_sensors` (exact
  first, then case-insensitive substring); `selected_sensors` = the matched
  names. If nothing matches, fall back to `all_sensors` and say so in the
  announce line.

- **Severity:**

  | Selection             | severity_threshold |
  |-----------------------|--------------------|
  | High and above (≥7)   | 7 (default)        |
  | Critical only (≥9)    | 9                  |
  | Medium and above (≥5) | 5                  |
  | All events            | 1                  |

  If the answer is unclear, default to `severity_threshold = 7`.

- **Time window** (all times UTC, `ts_till` = now):

  | Selection       | ts_since                                            | ts_till |
  |-----------------|-----------------------------------------------------|---------|
  | Last 24 hours   | now − 24 h                                          | now     |
  | Last week       | now − 7 days                                        | now     |
  | Last month      | now − 30 days                                       | now     |
  | Other free text | Parse the user's input; ask to clarify if ambiguous | varies  |

  Compute `ts_since` / `ts_till` as ISO 8601 UTC (e.g.
  `2024-01-15T08:00:00Z`) and pick `interval`:

  | Window length | interval     |
  |---------------|--------------|
  | ≤ 2 hours     | ONE_MIN      |
  | ≤ 1 day       | FIVE_MINS    |
  | ≤ 7 days      | THIRTY_MINS  |
  | ≤ 30 days     | FOUR_HOURS   |
  | > 30 days     | ONE_DAY      |

**CEM target for the report header:** read only the host line via
`grep '^MENDEL_HOST=' .env` (never `cat` the whole file — it contains
`MENDEL_PASSWORD`). If unavailable, use "as configured for the MCP server".
Store as `cem_host`.

Announce before proceeding:
> CEM: {cem_host} | Sensors: {N} — [{name1}, {name2}, ...] | Severity: ≥{severity_threshold} | Window: {ts_since} — {ts_till}

---

## Step 1 — Gather global data and spawn per-sensor agents (all in parallel)

**Run everything in this step simultaneously.** Do not wait for any sub-step
before starting the others. Emit all MCP tool calls (1a–1d) and all Agent
invocations (1e) in a single parallel batch.

**If `selected_sensors` is empty** (no sensors were discovered): run only
Steps 1a–1d (global data) and skip Step 1e entirely. Note in the report
header: "Sensors assessed: None discovered — aggregate CEM assessment only."
Omit the Per-Sensor Analysis section.

**Sensor scoping for 1b–1d:** if `selected_sensors` is a strict subset of
`all_sensors`, append an OR-chained sensor clause to each filter so
deselected sensors don't leak into the global sections:

```
... AND (sensorName EQ "name1" OR sensorName EQ "name2")
```

### 1a. Open incidents

```
list_incidents(filter_order_by="RISK desc", limit=50)
```

Open incidents are point-in-time state, listed regardless of the assessment
window. Note count by status (`reported`, `to_analyze`, `resolved`) and risk
level (`critical`, `high`, `medium`, `low`, `lowest`). Flag unresolved
critical/high.

### 1b. Top detection events (CEM aggregate)

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

### 1c. OT-specific events (CEM aggregate)

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

### 1d. Threat intelligence — hits in observed traffic

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

### 1e. Per-sensor agents (one per sensor, all in parallel)

For each sensor in `selected_sensors`, spawn one agent using the Agent tool.
Emit all N invocations simultaneously — do not wait between sensors.

**Task invocation shape (repeat for each sensor, substituting SENSOR,
TS_SINCE, TS_TILL, INTERVAL, and SEVERITY_THRESHOLD):**

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

## Step D — Unknown Host Profiling

**Trigger condition:** Every host whose triggering event has class
`policy-violation`, `reconnaissance`, or `anomaly` AND that host was
identified by MAC address in the event (i.e., `dstHostMacs` or `srcHostMacs`
is populated). This trigger is independent of Step C — do NOT gate Step D
on whether Step C ran.

**Prioritization (if >10 candidate hosts):**
1. First, select one representative host per unique destination subnet
   (subnet diversity — ensures hosts from different zones are represented
   even when their cnt is lower than same-zone peers).
2. Fill remaining slots up to a total of 10 by highest `cnt` descending.
3. Note all skipped hosts at the bottom of the section.

Rationale: a host in a unique subnet (e.g. Vendor X) is more informative to
profile than the fifth host from the same Vendor Z subnet even if its cnt is
lower.

For each candidate host, run D1 and D2 **in parallel**. Run all candidates
in parallel with each other.

**D1 — Host inventory lookup:**

  list_hosts(filter='macAddress EQ "XX:XX:XX:XX:XX:XX"', limit=5)

Extract: all IPs seen, first seen, last seen, hostname (if resolved),
OS fingerprint, associated services.
If no result: note "Not in Mendel host inventory."

**D2 — Full traffic history for this host in the window:**

  list_detection_events(
      interval="INTERVAL",
      ts_since="TS_SINCE",
      ts_till="TS_TILL",
      filter='srcHostMac EQ "XX:XX:XX:XX:XX:XX" OR dstHostMac EQ "XX:XX:XX:XX:XX:XX"',
      filter_order_by="SEVERITY desc",
      limit=50,
  )

If you have an IP from D1, extend the filter:
  filter='srcHostMac EQ "XX:XX:XX:XX:XX:XX" OR dstHostMac EQ "XX:XX:XX:XX:XX:XX"
          OR srcHostAddr EQ "X.X.X.X" OR dstHostAddr EQ "X.X.X.X"'

**Note:** D2 returns detection events (intervals where a Mendel signature fired),
not raw flow content. Flow-level details such as specific destination URLs will
only appear if Mendel raised a signature on that connection.

**Skip Step D entirely if no hosts meet the trigger condition.**

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

{List all notable events. Grouping rules:
- Group only when the SAME signature fires between the SAME source host and
  the SAME destination host repeatedly — one row per unique (signature, src, dst)
  triple, with a count column.
- NEVER group different source MACs/IPs under the same signature — each unique
  source host gets its own row.
- Policy-violation and new-host-discovery events are NEVER grouped: each
  discovered MAC gets its own row, regardless of how many share the same signature.
Include OUI-enriched MAC inline in Src/Dst when applicable.}

#### Findings

- {2–4 bullets: what is happening, why it matters in OT/ICS context, what
  should be investigated next. Name specific hosts, subnets, signatures.
  Do not write generic security advice.}

#### Unknown Host Stories

{One subsection per host profiled in Step D. If Step D was skipped, omit
this section entirely.}

##### [MAC] [Vendor — OUI enriched] — [IP or "no IP in inventory"] ([Subnet name])

- **IPs seen:** [list from D1, or "not in Mendel inventory"]
- **First seen / Last seen:** [from D1]
- **Hostname:** [resolved name, or "not resolved"]
- **OS fingerprint:** [from D1, or "not detected"]

**Traffic in assessment window (top 5 by severity):**

| Severity | Signature | Direction | Counterpart | Timestamp |
|---------|-----------|-----------|-------------|-----------|
| ... | ... | outbound / inbound | IP or hostname | ... |

**Story:** [2–3 sentences connecting the dots: what this device is (OUI + subnet
context), what it actually did (signatures, counterparts, ports/protocols),
why this matters in the OT/ICS context of this sensor. Do not write generic
advice — name the specific hosts, destinations, and protocols observed.]

{If no detection events returned by D2: "No detection events for this host
in the assessment window."}

{After all profiled hosts, if candidates were skipped:}
> N additional hosts triggered discovery alerts but were not individually
> profiled (MACs: XX:XX:XX..., XX:XX:XX...). Review raw events for details.
---
"""
)
```

**If a sensor agent errors:** retry once for transport/timeout errors only.
If the retry also fails, or the agent returned malformed output (no retry
for malformed output), insert in the Per-Sensor Analysis section:

```
### Sensor: SENSOR — Agent error
_Agent error: <error message>. Sensor data unavailable for this assessment._
```

---

## Step 2 — Consolidate and write the report

Wait until all parallel work from Step 1 is complete — both the global MCP
calls (1a–1d) and all per-sensor agent Tasks (1e) — before writing anything.

**Output file:** Write the report to a file named
`mendel-assessment-YYYYMMDD-HHMMSS.md` in the current working directory,
where `YYYYMMDD-HHMMSS` is the UTC timestamp at report generation time
(e.g. `mendel-assessment-20260505-143022.md`). Use the Write tool to create
the file. After writing, tell the user the filename. Do not print the full
report body in chat — only the filename and a one-line summary of the top
finding.

---

```
# Mendel Security Assessment

**CEM:** {cem_host}
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

{Omit this section entirely if there are no incidents. Open incidents are
point-in-time state, listed regardless of the assessment window.}

**Total:** N  |  Critical: N  |  High: N  |  Unresolved: N

| ID | Caption | Risk | Status | Assignee |
|----|---------|------|--------|---------|
| ... | ... | ... | ... | ... |

{List up to 10 highest-risk. If > 10, note "N more not shown."}

## Top Detection Events

{Omit this section entirely if no events meet the severity threshold.
Only list events with severity ≥ SEVERITY_THRESHOLD. Group repeated
signatures — one row per unique signature with a count column.}

**Total ≥{SEVERITY_THRESHOLD}:** N  |  **High-severity (≥7):** N  |  **Critical (≥9):** N

| Severity | Signature | Type | Src → Dst | First Seen | Count |
|---------|-----------|------|-----------|------------|-------|
| ... | ... | ... | ... | ... | ... |

## OT Security Findings

{Omit this section entirely if no OT events were detected. When present,
summarize by signature and affected host — do not list every individual
event row.}

## Unknown Host Stories

{Omit this section if no per-sensor agent produced Unknown Host Story blocks.

Paste each host story block from the per-sensor agents verbatim.
If the same MAC appeared on multiple sensors, merge into one entry — use the
richest D1/D2 result and note both sensors.
Order: highest-severity triggering event first.}

## Threat Intelligence

{Only include this section if Step 1d returned at least one event with a
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

{Only include subsections for sensors that returned notable events or
errored. Paste each such sensor agent's markdown block verbatim. Order
subsections alphabetically by sensor name.

Sensors that returned "No notable activity" are not given their own
subsection — list them in a single line at the top of this section,
alphabetically: "No notable activity: sensor-a, sensor-b."

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

## Reference procedures (orchestrator)

These apply to unknown hosts the **orchestrator itself** encounters in
global data (incidents, CEM-aggregate events) during consolidation.
Per-sensor agents handle their own enrichment via Step C of their prompt —
they are context-isolated and never see these sections.

### MAC address OUI enrichment

Whenever an **unknown host** appears identified by MAC address only (no
hostname, no confirmed asset record), look up the OUI (first 3 octets) to
identify the manufacturer **before** reporting it as "unknown identity."

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

### Unknown host profiling

After OUI enrichment, immediately pull the host's Mendel profile and recent
detection events.

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
where the host appeared (incident or detection event), with:

- MAC + OUI enrichment line
- IPs seen / first seen / last seen
- Hostname or "not resolved"
- OS fingerprint or "not detected"
- Top 5 detection events by severity (signature, severity, timestamp)
- If no events: "No detection events for this host in the assessment window."

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
- Keep `limit` at 50 or below for all report-oriented calls. Sensor-discovery
  pagination in Step 0a may iterate past 50 total rows — that is the one
  intended exception.
- **No flow tools.** `list_network_flows`, `run_analysis_view`, and related
  endpoints are not available — flows are stored on individual sensors, not
  on the CEM.
- **Per-sensor agents are context-isolated.** Each agent sees only its own
  prompt — it does not inherit incidents, global events, or other agents'
  results. Cross-sensor correlation is the orchestrator's responsibility
  during consolidation (Step 2).
- Do not create, update, or delete any Mendel resources. This skill is
  strictly read-only.
