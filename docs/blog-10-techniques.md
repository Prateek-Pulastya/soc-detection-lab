# I emulated 10 ATT&CK techniques and wrote the detections — what fired, what didn't, and why

> Draft skeleton. Write the per-technique notes *during* the work; compress into this post at the end.

## Why I built DetectForge
Offensive portfolios prove you can *do* the attack. Detection-engineering roles screen for the
opposite: can you *catch* it? DetectForge is a small, real SOC — Wazuh SIEM + a
Sysmon-instrumented Windows endpoint — where I detonate ATT&CK techniques and turn each into a
tested, tuned, ATT&CK-mapped Sigma detection.

## The stack (2 minutes)
- Wazuh single-node (Docker) on Ubuntu; Sysmon-instrumented Windows victim; isolated network.
- Sigma as the source of truth; bridged to Wazuh (native XML) + OpenSearch, proven portable to
  Elastic and Splunk.

## The loop (the actual skill)
detonate → observe Sysmon events → author Sigma on the **behaviour, not the IOC** → deploy →
validate it fires → tune false positives → map to ATT&CK → write it up.

## The coverage picture
`![Navigator coverage](../navigator/coverage.png)` — X/10 detected.

## Three that taught me the most
1. **T1059.001 PowerShell cradle** — <what the encoded/cradle behaviour looked like; the tuning>.
2. **T1003.001 LSASS dump** — <GrantedAccess masks; excluding EDR; the marquee>.
3. **T1070.001 Clear Event Logs** — <detecting the attacker erasing evidence>.

## What didn't fire, and why
<the honest miss(es) — a documented miss with a reason is a stronger signal than a fake 10/10.>

## What I'd do next
<Linux/auditd coverage; automate detonate→validate; a second live SIEM.>

## Repo
<link to the public GitHub repo>
