# T1059.001 — PowerShell (encoded command / download cradle)

**Tactic:** Execution · **Primary telemetry:** Sysmon EID 1 (process creation) ·
**Wazuh rule:** 100201 · **Sigma:** [`../../sigma/T1059.001_powershell_cradle.yml`](../../sigma/T1059.001_powershell_cradle.yml)

The worked example / template. Every other technique repeats this loop.

---

## 1. Detonate
See [atomic.md](atomic.md). `Invoke-AtomicTest T1059.001 -TestNumbers 1`.

## 2. Observe
In the Wazuh dashboard, filter the agent → **Sysmon Event ID 1** → find `powershell.exe` with the
suspicious `CommandLine` (encoded blob / `IEX` / `Net.WebClient` / `DownloadString`).

Record the exact field values you saw (these are what the rule keys on):

| Field | Value observed |
|-------|----------------|
| `win.eventdata.image` | `____` |
| `win.eventdata.commandLine` | `____` |
| `win.eventdata.parentImage` | `____` |

> **TODO:** `![EID1 event](screenshots/01-sysmon-eid1.png)`

## 3. Author
Sigma rule keys on the technique (encoded command **or** download cradle), not the atomic's
filename. Source of truth: `sigma/T1059.001_powershell_cradle.yml`.

## 4. Deploy
- **Native Wazuh (real-time):** rule 100201 in `deploy/wazuh/local_rules.xml`.
- **Sigma → OpenSearch:** see [queries/](queries/) for the `sigma-cli` command + query.

## 5. Validate
Re-detonate → confirm alert **100201** fires with the matching CommandLine.

> **TODO:** `![alert fired](screenshots/02-alert-100201.png)`

**True positive:** ✅ / ⬜ · **Detection latency:** `____ s`

## 6. Tune
Run a *benign* encoded/download PowerShell and confirm the rule does **not** fire:

```powershell
# benign: legitimate DownloadString to an internal/known URL (adjust host)
powershell -Command "IEX (New-Object Net.WebClient).DownloadString('http://192.168.157.1/benign.ps1')"
# benign: base64-encoded but harmless command
$b=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Date')); powershell -EncodedCommand $b
```

If it fires on benign → add the `filter_benign` block in the Sigma rule and the 100202 override
in `local_rules.xml` (both stubbed). Document what you allowlisted:

**FP profile:** `____` (e.g. "internal automation host X pulls signed scripts; allowlisted by
ParentImage + URL prefix.")

## 7. Map
Tagged `attack.t1059.001`. Ensure T1059.001 is scored in
[`navigator/detectforge-coverage.json`](../../navigator/detectforge-coverage.json).

---

### Evidence checklist
- [ ] Sysmon EID 1 screenshot
- [ ] Alert 100201 screenshot (matching CommandLine)
- [ ] Benign case screenshot (no fire) or FP note
- [ ] Latency recorded
- [ ] Varied re-detonation still detected (behaviour-not-IOC proof)
