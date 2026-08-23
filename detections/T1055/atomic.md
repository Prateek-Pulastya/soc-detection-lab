# Atomic — T1055 (Process Injection)

Run inside the Windows VM, admin PowerShell, **NAT adapter disconnected**, on/after the
`clean-instrumented` snapshot. **May drop tooling — revert after.**

```powershell
Invoke-AtomicTest T1055 -ShowDetailsBrief
Invoke-AtomicTest T1055 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1055 -TestNumbers 1              # remote-thread injection into a host process
Invoke-AtomicTest T1055 -TestNumbers 1 -Cleanup
```

**Test used:** pick a CreateRemoteThread-based test (record test # + SourceImage/TargetImage).
Expected Sysmon **EID 8** (CreateRemoteThread); some variants also show **EID 10** with a broad
GrantedAccess. Note the TargetImage (svchost/explorer/notepad…).
**Detonation timestamp:** `____`.
**Varied re-detonation:** try a second injection test number targeting a different host process;
confirm rule 100241 still fires.
