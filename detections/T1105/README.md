# T1105 — Ingress Tool Transfer (command & control)

**Tactic:** Command & Control · **Telemetry:** Sysmon EID 1 (downloader) · EID 3 / 11 ·
**Wazuh rule:** 100271 · **Sigma:** [`../../sigma/T1105_ingress_tool_transfer.yml`](../../sigma/T1105_ingress_tool_transfer.yml)

## 1. Detonate
See [atomic.md](atomic.md). Needs egress — allow NAT for this test or host the file on VMnet1.

## 2. Observe
**Sysmon EID 1** → a LOLBin downloader (`certutil urlcache`, `bitsadmin /transfer`, `curl`,
PowerShell `DownloadFile`/`Invoke-WebRequest`). EID 3 (net) + EID 11 (file) corroborate.

| Field | Value observed |
|-------|----------------|
| `win.eventdata.image` | `____` |
| `win.eventdata.commandLine` | `____` |
| EID 11 target filename (dropped) | `____` |

> **TODO:** `![EID1 event](screenshots/01-sysmon-eid1.png)`

## 3. Author
Keys on the **download verb** across the common LOLBins, not on the URL/filename.

## 4. Deploy
- **Native Wazuh:** rule 100271. - **Sigma → OpenSearch:** [queries/opensearch.txt](queries/opensearch.txt).

## 5. Validate
Re-detonate → confirm **100271** fires.
> **TODO:** `![alert](screenshots/02-alert-100271.png)` · **TP:** ⬜ · **Latency:** `____ s`

## 6. Tune
Benign — `curl`/`Invoke-WebRequest` are used legitimately. Tune by ParentImage (exclude known
updaters) or destination allowlist. **FP profile:** `____`

## 7. Map
Tagged `attack.t1105`. Score in the Navigator layer.

### Evidence checklist
- [ ] EID 1 screenshot  - [ ] Alert 100271 screenshot  - [ ] Benign no-fire / FP note  - [ ] Latency  - [ ] Second downloader (certutil→curl) still detected
