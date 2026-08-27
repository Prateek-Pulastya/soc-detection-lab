# DetectForge — Detection-Engineering SOC Lab

Stand up a Wazuh SIEM, detonate MITRE ATT&CK techniques with Atomic Red Team, and turn each
attack into a **tested, ATT&CK-mapped Sigma detection** with a documented false-positive profile
and an analyst-ready incident report.

The blue-team mirror of offensive work: I don't just run attacks — I catch them.

---

## Coverage at a glance

> **TODO (Phase 3):** replace with your ATT&CK Navigator screenshot.
> `![DetectForge coverage](navigator/coverage.png)`

<!-- Navigator layer source: navigator/detectforge-coverage.json -->

## Results

> Full table: [RESULTS.md](RESULTS.md). Fill with real numbers as you go — an honest 9/10 with
> one explained miss beats a suspicious 10/10.

| Metric | Value |
|--------|-------|
| Techniques emulated | 10 (across 6 tactics) |
| **Detected (rule fired on live detonation)** | **7 / 10** |
| Documented gaps (rule authored, blocked/not exercised in lab) | 3 — T1003.001, T1055, T1021.001 |
| Rules with a false-positive tune-down | 1 (T1048/T1567 internal-destination) |
| Rules proven portable (≥2 SIEM backends) | 3 |
| Native Wazuh rules authored | 13 (10 techniques) |

## One detonation, one alert

> **TODO (Phase 4):** GIF of a detonation firing an alert. `![demo](docs/demo.gif)`

---

## Architecture (short)

Wazuh single-node (Docker) on an Ubuntu VM + a Sysmon-instrumented Windows victim VM on an
isolated host-only network. Atomic Red Team runs *on* the victim. Full diagram + the
**Sigma↔Wazuh bridge** rationale in [ARCHITECTURE.md](ARCHITECTURE.md).

**Detection source of truth = Sigma** (`sigma/`, versioned in git). Wazuh isn't Sigma-native, so
each rule is authored once in Sigma, then (a) converted to an OpenSearch query with `sigma-cli`
and (b) for real-time alerts, translated into a native Wazuh XML rule. That bridge is documented,
not hidden.

---

## Techniques

**Detected 7 / 10 on live detonation.** Status: ✅ detected · ❌ rule authored, technique blocked / not exercised in lab (documented gap).

| ATT&CK | Technique | Tactic | Telemetry | Wazuh rule | Status |
|--------|-----------|--------|-----------|-----------|--------|
| [T1059.001](detections/T1059.001/) | PowerShell (encoded / cradle) | Execution | Sysmon EID 1 | 100201 | ✅ |
| [T1547.001](detections/T1547.001/) | Registry Run Key | Persistence | Sysmon EID 13 | 100211 | ✅ |
| [T1053.005](detections/T1053.005/) | Scheduled Task | Persistence | Sysmon EID 1 / 4698 | 100221 | ✅ |
| [T1003.001](detections/T1003.001/) | LSASS memory dump (**marquee**) | Credential Access | Sysmon EID 10 | 100231 | ❌ LSASS blocked by Win protection/ASR |
| [T1055](detections/T1055/) | Process Injection | Defense Evasion | Sysmon EID 8 / 10 | 100241 | ❌ injection blocked in lab |
| [T1070.001](detections/T1070.001/) | Clear Windows Event Logs | Defense Evasion | Sysmon EID 1 / 1102 | 100251/2 | ✅ |
| [T1136.001](detections/T1136.001/) | Create Local Account | Persistence | 4720 / Sysmon EID 1 | 100261/2 | ✅ |
| [T1105](detections/T1105/) | Ingress Tool Transfer | Command & Control | Sysmon EID 3 / 11 | 100271 | ✅ |
| [T1021.001](detections/T1021.001/) | Remote Desktop | Lateral Movement | 4624 type 10 | 100281 | ❌ RDP listener wouldn't bind (0x204) |
| [T1048 / T1567](detections/T1048_T1567/) | Exfil over alt protocol / web | Exfiltration | Sysmon EID 3 | 100291/2 | ✅ |

---

## What I'd improve next

- _(fill in as you build — e.g. add Linux (auditd) coverage, a second SIEM validation,
  automate the detonate→validate loop in CI against a live agent.)_

---

## Repo layout

```
detectforge/
├── sigma/                    # detections — source of truth, one file per technique
├── detections/<Txxxx>/       # per-technique loop writeup + atomic cmd + converted queries
├── deploy/wazuh/             # native rules, agent config, compose override
├── deploy/sysmon/            # the Sysmon config used + why
├── navigator/                # ATT&CK Navigator coverage layer + screenshot
├── incidents/                # SOC-style incident reports
├── docs/                     # blog post + demo assets
└── .github/workflows/ci.yml  # sigma check (rule-syntax gate)
```

## Setup

See the companion `DetectForge-MANUAL-TASKS.md` for the full lab build. Quick version:
Ubuntu VM → Docker → `wazuh-docker` single-node; Windows VM → Sysmon + Wazuh agent +
Invoke-AtomicRedTeam; isolated host-only network; snapshot before every detonation.
