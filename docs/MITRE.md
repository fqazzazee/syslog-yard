# Sorting & MITRE ATT&CK

syslog-yard provides two related triage aids: richer **sorting/filtering** of
stored events, and **MITRE ATT&CK** mapping across the suite. Authentication is in
[AUTH.md](AUTH.md); the threat model is in [SECURITY.md](SECURITY.md).

## ATT&CK mapping at ingest (bucket)

The bucket maps every incoming event to zero or more ATT&CK **techniques** as
it is stored, using a curated detection table (`internal/mitre`) that reuses
the same condition grammar as buckets and rules. The mapping runs *after* the
parsers populate structured fields, so detections can match on parsed values
(`structured.subtype`, `structured.attack`, …) as well as message text. The
matched technique IDs are stored on the entry (`entries.mitre`, a GIN-indexed
array) and shown as chips in the log table and the entry detail.

The shipped detections recognise the suite's demo vocabulary (FortiGate
key=value, sshd/sudo, Cisco ASA) and cover, among others:

| Technique | Name | Recognised from |
|-----------|------|-----------------|
| T1190 | Exploit Public-Facing Application | IPS signatures naming a remote code execution (Log4j, Struts, SMB) |
| T1110 | Brute Force | sshd "Failed password", device login `status=failed` |
| T1078 | Valid Accounts | sshd "Accepted …", device login `status=success`, ASA AAA success |
| T1204 | User Execution | AV `subtype=virus` (infected download) |
| T1566 | Phishing | webfilter category Phishing |
| T1071 | Application Layer Protocol | a beaconing C2 signature (Cobalt Strike) |
| T1021 | Remote Services | firewall denies to SSH/RDP/SMB/TELNET/MSSQL |
| T1548 | Abuse Elevation Control Mechanism | `sudo` |
| T1499 | Endpoint Denial of Service | kernel "SYN flooding" |

Mapping happens before the rules engine, so a **rule can match on a technique**
(`mitre` condition) to tag, prioritise, or suppress — e.g. "auto-prioritise
anything mapped to T1190".

### The ATT&CK matrix view

The sidebar's **🎯 ATT&CK matrix** lays the mapped techniques out as the
familiar kill-chain: one column per tactic, technique cards showing how many
entries matched in the current time window (the matrix respects the filter
bar). Click a technique to open its entries. The catalog is served at
`GET /api/mitre`; per-technique counts at `GET /api/mitre/summary`.

## Sorting & device class (bucket)

- **Sortable columns.** Click a log-table header — Time, Severity, Pri, Host,
  App, or Class — to sort; click again to flip direction. Time sort keeps the
  streaming + "load older" behaviour; a column sort returns one ranked page and
  re-orders live arrivals client-side so nothing jumps out of place.
- **Device class.** Each event is tagged with a coarse class
  (`firewall`, `network`, `host`, `windows`, `ot`) derived from its app name,
  falling back to a vendor signature in the message for raw key=value formats
  whose program name doesn't parse cleanly (FortiGate, ASA, …). It is a
  sortable column and a filter-bar facet (**Any device**).

These ride the same condition grammar, so the new fields work in saved buckets,
rules, search, and live tail — `device_class` as a field, `mitre` as a leaf.

## Filtering by technique on the wire (valve)

The valve's **Filter** node gains a **MITRE ATT&CK technique** option. The
valve has no parsed fields — it sees the raw syslog line — so each technique is
expressed as a syslog-ng pattern (a PCRE over the message and/or a program
name) in its own `internal/mitre` catalog, kept in step with the bucket's
technique list. Picking a technique compiles into the node's filter, so a flow
can **route or drop by technique**: e.g. send everything matching T1190 to a
priority destination, or cache C2 beacons (T1071) to disk. Conditions on a
filter are ANDed, so you can combine a technique with a severity floor or
program. The catalog is served at the valve's `GET /api/mitre`.

> Keep the two technique lists in sync: `apps/syslog-bucket/internal/mitre`
> (condition-AST detections over parsed fields) and
> `apps/syslog-valve/internal/mitre` (syslog-ng patterns over the raw line)
> share the same IDs, names, and tactics by convention.

## OT alerts (Claroty CTD / xDome)

Industrial/OT monitoring tools — **Claroty CTD** (Continuous Threat Detection)
and **Claroty xDome** — raise alerts rather than raw flow logs, and group them
into two classes: **Security** (threat-oriented) and **Integrity** (changes to
asset/network/operational state). syslog-bucket mirrors that with a second
mapping alongside ATT&CK.

- **Generate** — syslog-hose ships `claroty-ctd` and `claroty-xdome` presets
  that emit CEF over syslog the way the real sensors do (ICS ports/protocols —
  Modbus, EtherNet/IP, S7comm, DNP3, BACnet — and OT/IoT/IoMT asset types),
  spanning the alert types below.
- **Map** — at ingest, `internal/otmap` stamps each entry with the Claroty
  alert-type codes it matches (stored in `entries.ot`), keyed off the CEF alert
  name. `internal/classify` marks these entries `device_class = ot`.
- **View** — the sidebar's **OT alerts** opens a matrix with a **Security** and
  an **Integrity** column; each alert type shows its count in the current
  window and drills into the matching entries. An `ot` condition leaf makes the
  codes usable in buckets, rules and search, exactly like `mitre`.

| Class | Alert types |
|-------|-------------|
| **Security** | Known Threat · Suspicious Activity · Network Scan · Unauthorized Access · Policy Violation · Malware / Exploit |
| **Integrity** | New Asset · Asset Change · Baseline Deviation · Configuration Download · PLC Mode Change · IP/MAC Conflict |

Endpoints: `GET /api/ot` (catalog) and `GET /api/ot/summary` (per-alert counts).

## Compliance frameworks (NIST CSF, CIS, IEC 62443)

On top of ATT&CK and the OT alerts, the bucket presents the same events through
**compliance frameworks**. A framework is a curated **crosswalk**, not a new
detector: each item lists the ATT&CK techniques and Claroty OT codes that map
onto it, so the views reuse the counts already computed (`entries.mitre` /
`entries.ot`) and drilling into a cell expands to a filter over those tags. No
extra per-entry storage — adding a framework is one entry in
`internal/frameworks`.

Shipped:

- **NIST CSF 2.0** — Functions as columns (Govern · Identify · Protect ·
  Detect · Respond), categories as cells (PR.AA, DE.CM, …).
- **CIS Controls v8** — the relevant controls (Account Mgmt, Access Control,
  Malware Defenses, Network Monitoring, …) grouped by the function they serve.
- **IEC 62443-3-3** — the seven Foundational Requirements (FR1–FR7), grouped
  into Access/Integrity/Monitoring themes; OT-centric, so mostly fed by the
  Claroty alerts.

Each opens from the sidebar's **Frameworks** section as a matrix (counts in the
current window; click a cell for the entries). The crosswalks are opinionated
and coarse — a standards-aligned overview of what the sensors see, not an
audit-grade control assessment. Catalogs are served at `GET /api/frameworks`.

## Rules: condition & tag by technique

A rule's condition builder has a **MITRE technique** row: pick a technique and
the rule matches entries mapped to it at ingest — so you can, e.g., auto-tag
everything mapped to **T1190** or page on **T1071**. Combine it with the tag /
priority / suppress / notify actions like any other condition.

## Default buckets

A fresh bucket seeds a curated set of saved searches reflecting a realistic SOC
triage workload — Critical & high, New / untriaged, Exploitation attempts,
Brute force, Suspicious logins, Malware & phishing, Command & control, Lateral
movement, Privilege escalation, and OT security / integrity — so an analyst has
somewhere useful to start. Seeding only runs when no buckets exist; it never
overwrites a deployment's own.
