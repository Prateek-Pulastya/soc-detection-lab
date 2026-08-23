# Sysmon configuration

## Config used

**SwiftOnSecurity `sysmon-config`** (`sysmonconfig-export.xml`) —
https://github.com/SwiftOnSecurity/sysmon-config

Alternative for deeper, modular coverage: **Olaf Hartong `sysmonmodular`** —
https://github.com/olafhartong/sysmonmodular

## Why a tuned config (not the default)

Sysmon with no config logs almost nothing useful. A tuned config is what makes the following
Event IDs rich enough for detections to fire:

| Sysmon EID | What it captures | Techniques it powers here |
|------------|------------------|---------------------------|
| 1  | Process creation (Image, CommandLine, Parent, Hashes) | T1059.001, T1053.005, T1070.001, T1136.001 |
| 3  | Network connection | T1105, T1048/T1567 |
| 8  | CreateRemoteThread | T1055 |
| 10 | ProcessAccess (GrantedAccess to lsass.exe) | T1003.001 (marquee) |
| 11 | FileCreate | T1105 |
| 13 | Registry value set | T1547.001 |

## Install (inside the Windows VM, admin PowerShell)

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
# verify
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
```

> Commit the exact `sysmonconfig.xml` you used to this folder so the lab is reproducible, and
> credit the source above.
