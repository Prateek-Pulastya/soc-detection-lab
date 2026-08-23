# Atomic — T1105 (Ingress Tool Transfer)

Run inside the Windows VM, admin PowerShell, on/after the `clean-instrumented` snapshot.
**This test needs egress** — the download target must be reachable. Either temporarily allow the
NAT adapter for this one test (then disconnect + revert), or host the file on the Wazuh/Ubuntu VM
over VMnet1 and point the atomic at `http://<WAZUH_IP>/file`.

```powershell
Invoke-AtomicTest T1105 -ShowDetailsBrief
Invoke-AtomicTest T1105 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1105 -TestNumbers 1              # certutil/bitsadmin/curl/PowerShell download
Invoke-AtomicTest T1105 -TestNumbers 1 -Cleanup
```

**Test used:** pick a download test (record which LOLBin + the CommandLine). Expected Sysmon
**EID 1** (the downloader process) — rule 100271 keys on the command line. EID 3 (network) and
EID 11 (file created) corroborate.
**Detonation timestamp:** `____`.
**Varied re-detonation:** run a second downloader variant (e.g. certutil then curl); confirm
100271 still fires across tools.
