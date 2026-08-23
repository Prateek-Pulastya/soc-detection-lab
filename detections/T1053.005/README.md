# T1053.005 — Scheduled Task (persistence)

**Tactic:** Persistence · **Telemetry:** Sysmon EID 1 (schtasks/PS) · Security 4698 ·
**Wazuh rule:** 100221 · **Sigma:** [`../../sigma/T1053.005_scheduled_task.yml`](../../sigma/T1053.005_scheduled_task.yml)

## 1. Detonate
See [atomic.md](atomic.md). `Invoke-AtomicTest T1053.005 -TestNumbers 1`.

## 2. Observe
**Sysmon EID 1** → `schtasks.exe` with `/create` (or `powershell.exe` with `Register-ScheduledTask`).

| Field | Value observed |
|-------|----------------|
| `win.eventdata.image` | `____` |
| `win.eventdata.commandLine` | `____` |
| `win.eventdata.parentImage` | `____` |

> **TODO:** `![EID1 event](screenshots/01-sysmon-eid1.png)`

## 3. Author
Keys on the task-creation verb across both `schtasks /create` and the PS cmdlets.

## 4. Deploy
- **Native Wazuh:** rule 100221. - **Sigma → OpenSearch:** [queries/opensearch.txt](queries/opensearch.txt).

## 5. Validate
Re-detonate → confirm **100221** fires.
> **TODO:** `![alert](screenshots/02-alert-100221.png)` · **TP:** ⬜ · **Latency:** `____ s`

## 6. Tune
Benign — create a real scheduled task (or let an installer do it):
```powershell
schtasks /create /tn "BenignBackup" /tr "notepad.exe" /sc daily /st 09:00 /f
```
If noisy → allowlist known parent Images / task-name prefixes. **FP profile:** `____`

## 7. Map
Tagged `attack.t1053.005`. Score in the Navigator layer.

### Evidence checklist
- [ ] EID 1 screenshot  - [ ] Alert 100221 screenshot  - [ ] Benign no-fire / FP note  - [ ] Latency  - [ ] PS `Register-ScheduledTask` variant still detected
