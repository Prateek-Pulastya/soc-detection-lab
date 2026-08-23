# T1055 — Process Injection (defense evasion)

**Tactic:** Defense Evasion / Priv Esc · **Telemetry:** Sysmon EID 8 (CreateRemoteThread) · EID 10 ·
**Wazuh rule:** 100241 · **Sigma:** [`../../sigma/T1055_process_injection.yml`](../../sigma/T1055_process_injection.yml)

## 1. Detonate
See [atomic.md](atomic.md). Pick a CreateRemoteThread-based test. **May drop tooling — revert after.**

## 2. Observe
**Sysmon EID 8** → note `SourceImage` (injector) and `TargetImage` (host being injected).

| Field | Value observed |
|-------|----------------|
| `win.eventdata.sourceImage` | `____` |
| `win.eventdata.targetImage` | `____` (expect svchost/explorer/notepad…) |
| `win.eventdata.startModule` / `startFunction` | `____` |

> **TODO:** `![EID8 event](screenshots/01-sysmon-eid8.png)`

## 3. Author
Keys on a **remote thread created in a common host process**, excluding system SourceImages.
CreateRemoteThread across process boundaries is inherently suspicious.

## 4. Deploy
- **Native Wazuh:** rule 100241. - **Sigma → OpenSearch:** [queries/opensearch.txt](queries/opensearch.txt).

## 5. Validate
Re-detonate → confirm **100241** fires.
> **TODO:** `![alert](screenshots/02-alert-100241.png)` · **TP:** ⬜ · **Latency:** `____ s`

## 6. Tune
Benign — some legit software injects. If a signed injector fires, add it to `filter_benign`
(SourceImage allowlist) and note it. **FP profile:** `____`

## 7. Map
Tagged `attack.t1055`. Score in the Navigator layer.

### Evidence checklist
- [ ] EID 8 screenshot  - [ ] Alert 100241 screenshot  - [ ] Benign no-fire / FP note  - [ ] Latency  - [ ] Second injection target still detected
