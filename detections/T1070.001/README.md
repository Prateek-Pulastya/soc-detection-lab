# T1070.001 — Clear Windows Event Logs (defense evasion / anti-forensics)

**Tactic:** Defense Evasion · **Telemetry:** Sysmon EID 1 (process) · Security 1102 ·
**Wazuh rules:** 100251 (process) + 100252 (EventID 1102) ·
**Sigma:** [`../../sigma/T1070.001_clear_event_logs.yml`](../../sigma/T1070.001_clear_event_logs.yml)

## 1. Detonate
See [atomic.md](atomic.md). **Clears logs — screenshot the Wazuh alert fast, then revert.**

## 2. Observe
- **Sysmon EID 1** → `wevtutil.exe` with `cl` (or `Clear-EventLog`).
- **Security EID 1102** → "the audit log was cleared" (fires 100252 — the high-fidelity one).

| Field | Value observed |
|-------|----------------|
| `win.eventdata.image` / `commandLine` | `____` |
| `win.system.eventID` | `____` (expect 1102 for the Security event) |

> **TODO:** `![alert 1102](screenshots/01-alert-1102.png)`

## 3. Author
Two detections: the process invocation (100251) and the authoritative 1102 audit event (100252).

## 4. Deploy
- **Native Wazuh:** rules 100251 + 100252. - **Sigma → OpenSearch:** [queries/opensearch.txt](queries/opensearch.txt)
  (process vector; 1102 is Security-channel, native rule only).

## 5. Validate
Re-detonate → confirm **100251 and/or 100252** fire.
> **TP:** ⬜ · **Latency:** `____ s`

## 6. Tune
Rare in normal ops → low FP. If a maintenance job clears logs, allowlist that specific host only.
**FP profile:** `____`

## 7. Map
Tagged `attack.t1070.001`. Score in the Navigator layer.

### Evidence checklist
- [ ] 1102 alert screenshot  - [ ] Alert 100251/100252 screenshot  - [ ] Latency  - [ ] Note: log-clear captured in SIEM despite local wipe (that's the point)
