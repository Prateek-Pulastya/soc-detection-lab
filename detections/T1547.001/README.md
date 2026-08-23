# T1547.001 — Registry Run Key (persistence)

**Tactic:** Persistence · **Telemetry:** Sysmon EID 13 (RegistryEvent SetValue) ·
**Wazuh rule:** 100211 · **Sigma:** [`../../sigma/T1547.001_registry_run_key.yml`](../../sigma/T1547.001_registry_run_key.yml)

## 1. Detonate
See [atomic.md](atomic.md). `Invoke-AtomicTest T1547.001 -TestNumbers 1`.

## 2. Observe
Filter the agent → **Sysmon EID 13** → find the `TargetObject` ending in a `...CurrentVersion\Run\`
(or `RunOnce`) value.

| Field | Value observed |
|-------|----------------|
| `win.eventdata.targetObject` | `____` |
| `win.eventdata.details` (value data) | `____` |
| `win.eventdata.image` (who wrote it) | `____` |

> **TODO:** `![EID13 event](screenshots/01-sysmon-eid13.png)`

## 3. Author
Sigma keys on a write to any Run/RunOnce autostart location — not the payload path.

## 4. Deploy
- **Native Wazuh:** rule 100211 in `deploy/wazuh/local_rules.xml`.
- **Sigma → OpenSearch:** [queries/opensearch.txt](queries/opensearch.txt).

## 5. Validate
Re-detonate → confirm **100211** fires with the matching TargetObject.

> **TODO:** `![alert](screenshots/02-alert-100211.png)` · **TP:** ⬜ · **Latency:** `____ s`

## 6. Tune
Benign case — install/launch a legit app that writes a Run key (or `reg add` a real path):
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Benign /d "C:\Windows\System32\notepad.exe" /f
```
If it fires → add `filter_benign` (Image allowlist of signed installers) in the Sigma rule and note
it. **FP profile:** `____`

## 7. Map
Tagged `attack.t1547.001`. Score it in [`navigator/detectforge-coverage.json`](../../navigator/detectforge-coverage.json).

### Evidence checklist
- [ ] EID 13 screenshot  - [ ] Alert 100211 screenshot  - [ ] Benign no-fire / FP note  - [ ] Latency  - [ ] Varied re-detonation (RunOnce/HKLM) still detected
