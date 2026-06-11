# Sorting & MITRE ATT&CK

S8 adds two related triage aids: richer **sorting/filtering** of stored events,
and **MITRE ATT&CK** mapping across the suite. Authentication is in
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
