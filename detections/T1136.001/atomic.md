# Atomic — T1136.001 (Create Local Account)

Run inside the Windows VM, admin PowerShell, **NAT adapter disconnected**, on/after the
`clean-instrumented` snapshot. Creates a local account (persistence) — revert after.

```powershell
Invoke-AtomicTest T1136.001 -ShowDetailsBrief
Invoke-AtomicTest T1136.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1136.001 -TestNumbers 1          # net user <name> <pw> /add
Invoke-AtomicTest T1136.001 -TestNumbers 1 -Cleanup
```

**Test used:** T1136.001-1 (record the net user CommandLine + account name). Two detections:
- **100261** — Sysmon EID 1 on `net.exe user … /add` / `New-LocalUser`.
- **100262** — Security **EventID 4720** (a user account was created).
**Detonation timestamp:** `____`.
**Varied re-detonation:** try the `New-LocalUser` PowerShell variant; confirm 100261 still fires.
