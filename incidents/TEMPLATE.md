## Incident: <short title> (ATT&CK <Txxxx>)

**Summary.** At <time>, host <WIN-VM> triggered detection rule <id> — <one-line plain-English
description of what happened and why it matters>.

**ATT&CK.** <Txxxx> (<technique name>) — <tactic>.

**Detonation / how it was produced.** `Invoke-AtomicTest <Txxxx> -TestNumbers <n>`.
Evidence: Sysmon EID <n>, <key fields = values>.

**Detection logic.** <what the rule keys on — the behaviour, not the IOC — and what it excludes>.

**Triage steps (what an analyst does next).**
1. <confirm source process lineage / parent>
2. <check for persistence / related events>
3. <isolate host if unsigned/unknown source>

**False-positive analysis.** <who legitimately does this; what was allowlisted and how>.

**Recommended response / containment.** <isolate, rotate creds, hunt lateral movement, etc.>

**Evidence.**
- `![alert](../detections/<Txxxx>/screenshots/02-alert.png)`
- `![telemetry](../detections/<Txxxx>/screenshots/01-sysmon.png)`
