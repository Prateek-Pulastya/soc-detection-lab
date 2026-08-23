# Atomic — T1547.001 (Registry Run Key)

Run inside the Windows VM, admin PowerShell, **NAT adapter disconnected**, on/after the
`clean-instrumented` snapshot.

```powershell
Invoke-AtomicTest T1547.001 -ShowDetailsBrief
Invoke-AtomicTest T1547.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1547.001 -TestNumbers 1          # writes a Run key value
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup # then revert the snapshot anyway
```

**Test used:** T1547.001-1 (record exact test name/number + the TargetObject you saw).
**Detonation timestamp:** `____` (for latency vs the Wazuh alert timestamp).
**Varied re-detonation (behaviour-not-IOC):** run a different test number (RunOnce / HKCU vs HKLM
variant) and confirm rule 100211 still fires.
