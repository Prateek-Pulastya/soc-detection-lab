# Atomic — T1053.005 (Scheduled Task)

Run inside the Windows VM, admin PowerShell, **NAT adapter disconnected**, on/after the
`clean-instrumented` snapshot.

```powershell
Invoke-AtomicTest T1053.005 -ShowDetailsBrief
Invoke-AtomicTest T1053.005 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1053.005 -TestNumbers 1          # schtasks /create (or Register-ScheduledTask)
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup
```

**Test used:** T1053.005-1 (record exact test + the schtasks CommandLine).
**Detonation timestamp:** `____`.
**Varied re-detonation:** try a PowerShell `Register-ScheduledTask` variant and confirm rule
100221 still fires (proves it keys on the behaviour, not on `schtasks.exe` alone).
