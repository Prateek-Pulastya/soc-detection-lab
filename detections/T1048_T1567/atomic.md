# Atomic — T1048 / T1567 (Exfiltration over alt protocol / web service)

Run inside the Windows VM, admin PowerShell, on/after the `clean-instrumented` snapshot.
**Needs egress** — temporarily reconnect NAT for the test, then disconnect + revert. Prefer a
destination you control.

```powershell
# T1048 — exfil over alternative protocol (DNS / ICMP / non-C2 port)
Invoke-AtomicTest T1048 -ShowDetailsBrief
Invoke-AtomicTest T1048 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1048 -TestNumbers 1

# T1567 — exfil over a web service (paste/cloud)
Invoke-AtomicTest T1567 -ShowDetailsBrief
Invoke-AtomicTest T1567 -TestNumbers 1
```

**What to capture:** Sysmon **EID 3** (network connection) from a script/LOLBin (powershell,
nslookup, curl, certutil) to an **external** IP → rule 100291. If the destination is internal,
100292 tunes it down.
**Detonation timestamp:** `____`.
**Honesty note:** this is the hardest to detect cleanly — network egress rarely *proves* exfil.
If your rule can't separate this from normal traffic without heavy tuning, that's a legitimate
**documented miss** in RESULTS.md (worth more than a fake 10/10). Say what you'd add (volume
baselining, destination reputation, DLP).
