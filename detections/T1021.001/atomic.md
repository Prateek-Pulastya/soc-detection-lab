# Atomic — T1021.001 (Remote Desktop)

Detection source is the **Security** channel (EventID 4624, LogonType 10), so ensure the agent
forwards Security (it does per `deploy/wazuh/ossec-agent-snippet.conf`). RDP needs a second host to
connect *from*; on an all-local lab the simplest real signal is an RDP session into the Windows VM.

Options to generate the logon:
- From the host (or the Ubuntu VM with an RDP client) connect via RDP to the Windows VM over
  **VMnet1** — enable Remote Desktop in the Windows VM first (System → Remote Desktop).
- Or run the atomic, which sets up / exercises RDP config:

```powershell
Invoke-AtomicTest T1021.001 -ShowDetailsBrief
Invoke-AtomicTest T1021.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1021.001 -TestNumbers 1
```

**What to capture:** Security **EventID 4624** with `LogonType 10` (RemoteInteractive) → rule
100281. Record the source IP + account.
**Detonation timestamp:** `____`.
**Note:** RDP alone isn't malicious — this is a context/hunting rule. Value = flag RDP from an
*unexpected* source; note the source IP in the incident writeup.
