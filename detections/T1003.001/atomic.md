# Atomic — T1003.001 (LSASS Memory Dump) — MARQUEE

Run inside the Windows VM, admin PowerShell, **NAT adapter disconnected**, on/after the
`clean-instrumented` snapshot. **Touches credentials — always revert the snapshot after.**

```powershell
Invoke-AtomicTest T1003.001 -ShowDetailsBrief
Invoke-AtomicTest T1003.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1          # comsvcs.dll MiniDump of lsass (common)
Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup
```

**Test used:** T1003.001-1 (comsvcs MiniDump) — record SourceImage, TargetImage, GrantedAccess.
Expected Sysmon **EID 10**: SourceImage=…\rundll32.exe, TargetImage=…\lsass.exe,
GrantedAccess=`0x1010` (or similar memory-read mask).
**Detonation timestamp:** `____`.
**Varied re-detonation:** run a different LSASS-dump test number (e.g. procdump/direct) and
confirm rule 100231 still fires on the GrantedAccess mask, not the tool name.
