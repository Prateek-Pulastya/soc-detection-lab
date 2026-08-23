# Architecture

## Diagram

```
                 ┌───────────────────────────────────────────┐
                 │  Wazuh single-node stack (Docker on Ubuntu)│
                 │  manager + indexer(OpenSearch) + dashboard │
                 │  - decoders/rules, MITRE module, alerts    │
                 └───────────────▲───────────────────────────┘
                                 │ agent enrollment + events (1514/1515)
                                 │ (Host-only VMnet1, isolated)
                 ┌───────────────┴───────────────┐
                 │ Windows 10/11 VM              │
                 │ - Wazuh agent                 │
                 │ - Sysmon + tuned config       │  ← telemetry source
                 │ - Invoke-Atomic (ART)         │  ← detonates ATT&CK
                 └───────────────────────────────┘

 Isolated host-only network (VMware VMnet1). NAT used only for tool downloads,
 disconnected before every detonation. Snapshot before, revert after.
```

## Components and why

| Component | Role | Why this choice |
|-----------|------|-----------------|
| Wazuh single-node (Docker) | SIEM: collection, alerting, MITRE dashboards | Free, all-in-one, ships MITRE ATT&CK dashboards + Sysmon decoders |
| Ubuntu VM (Docker host) | Runs the Wazuh stack | Native path for `wazuh-docker`; `vm.max_map_count` for the indexer |
| Windows 10/11 VM | Primary victim | Most ATT&CK + Atomic content is Windows |
| Sysmon + tuned config | Rich endpoint telemetry | Without a good config, telemetry is thin and rules can't fire |
| Wazuh agent | Forwards `Microsoft-Windows-Sysmon/Operational` | The pipe from endpoint to SIEM |
| Invoke-AtomicRedTeam | Standard adversary emulation | Generates real, repeatable attack telemetry |

## The Sigma ↔ Wazuh bridge (the engineering-decision talking point)

**Detection source of truth = Sigma.** Wazuh's native engine uses XML rules and has **no
first-class Sigma backend**. Rather than abandon portability and hand-write everything in Wazuh
XML (locked to one SIEM, reads as amateur), each detection is:

1. **Authored once in Sigma** (`sigma/`, versioned in git) — the portable, reviewable artifact.
2. **Converted to an OpenSearch query** with `sigma-cli -p sysmon -t opensearch` — runs against
   the Wazuh indexer as a saved search / alerting monitor.
3. **Translated into a native Wazuh XML rule** (`deploy/wazuh/local_rules.xml`) for the real-time
   ones — this is what fires live alerts and auto-populates Wazuh's MITRE module via `<mitre>`.
4. **Proven portable** — for 2–3 rules, also converted to Elastic (lucene) and Splunk (SPL) to
   show the detection isn't locked to one platform.

Documenting *this bridge* — "Wazuh isn't Sigma-native; here's how I kept my detections portable
anyway" — is a genuine engineering decision, not a gap. Same detection, three SIEMs.

## Network & safety

- **Lab network:** Host-only `VMnet1` (VMware), fully isolated — VMs talk to each other and the
  host, never the real LAN/internet.
- **Downloads:** a temporary NAT adapter on each VM, **disconnected before any detonation**.
- **Snapshots:** Windows VM snapshot `clean-instrumented` taken once fully set up; reverted after
  every detonation (some atomics install persistence, drop tooling, or clear logs).
