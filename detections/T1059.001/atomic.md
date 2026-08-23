# Atomic — T1059.001 (PowerShell)

Run inside the Windows VM, admin PowerShell, **NAT adapter disconnected**, on/after the
`clean-instrumented` snapshot.

```powershell
# list available tests for this technique
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# fetch prerequisites for test 1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs

# detonate test 1 (encoded / IEX download cradle)
Invoke-AtomicTest T1059.001 -TestNumbers 1

# cleanup (then revert the snapshot anyway)
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

**Test used:** T1059.001-1 (record the exact test name/number you ran and its CommandLine here).

**Detonation timestamp:** `____` (for latency measurement vs the Wazuh alert timestamp).

**Varied re-detonation (proves behaviour-not-IOC):** run a *different* T1059.001 test number
(e.g. an `-EncodedCommand` variant) and confirm rule 100201 still fires. Note which:
`Invoke-AtomicTest T1059.001 -TestNumbers <n>`
