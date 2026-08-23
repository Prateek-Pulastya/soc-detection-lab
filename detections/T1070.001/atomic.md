# Atomic — T1070.001 (Clear Windows Event Logs)

Run inside the Windows VM, admin PowerShell, **NAT adapter disconnected**, on/after the
`clean-instrumented` snapshot. **This wipes logs — capture the alert fast, then revert.**

```powershell
Invoke-AtomicTest T1070.001 -ShowDetailsBrief
Invoke-AtomicTest T1070.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1070.001 -TestNumbers 1          # wevtutil cl / Clear-EventLog
Invoke-AtomicTest T1070.001 -TestNumbers 1 -Cleanup
```

**Test used:** T1070.001-1 (record exact command). Two detections should fire:
- **100251** — Sysmon EID 1 on `wevtutil.exe cl` / `Clear-EventLog`.
- **100252** — Security **EventID 1102** (the audit log was cleared) — higher fidelity.
**Detonation timestamp:** `____`.
**Note:** because this clears logs, screenshot the Wazuh alert immediately (the alert is already in
the SIEM, not on the host) and revert.
