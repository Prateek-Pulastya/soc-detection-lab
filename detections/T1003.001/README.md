# T1003.001 — LSASS Memory Dump (credential access) — MARQUEE

**Tactic:** Credential Access · **Telemetry:** Sysmon EID 10 (ProcessAccess) ·
**Wazuh rule:** 100231 · **Sigma:** [`../../sigma/T1003.001_lsass_dump.yml`](../../sigma/T1003.001_lsass_dump.yml)

This is the marquee detection — it also gets a full incident report in
[`../../incidents/T1003.001-lsass-dump.md`](../../incidents/T1003.001-lsass-dump.md).

## 1. Detonate
See [atomic.md](atomic.md). `Invoke-AtomicTest T1003.001 -TestNumbers 1` (comsvcs MiniDump).
**Revert the snapshot after — this touches credentials.**

## 2. Observe
**Sysmon EID 10** → `TargetImage` = `…\lsass.exe`, note `GrantedAccess` and `SourceImage`.

| Field | Value observed |
|-------|----------------|
| `win.eventdata.targetImage` | `____` (expect …\lsass.exe) |
| `win.eventdata.grantedAccess` | `____` (expect 0x1010 / 0x1410 / …) |
| `win.eventdata.sourceImage` | `____` (expect …\rundll32.exe for comsvcs) |

> **TODO:** `![EID10 event](screenshots/01-sysmon-eid10.png)`

## 3. Author
Keys on **access to LSASS memory** (TargetImage lsass + memory-read GrantedAccess mask), excluding
known AV/EDR SourceImages — not on the dumping tool's name.

## 4. Deploy
- **Native Wazuh:** rule 100231. - **Sigma → OpenSearch / lucene / splunk:** [queries/](queries/) (portability set).

## 5. Validate
Re-detonate → confirm **100231** fires with the LSASS TargetImage + GrantedAccess.
> **TODO:** `![alert](screenshots/02-alert-100231.png)` · **TP:** ⬜ · **Latency:** `____ s`

## 6. Tune
Benign — AV/EDR/backup agents read LSASS. If your Defender (`MsMpEng.exe`) or the Wazuh agent fires
100231, extend `filter_known_av` (Sigma) / enable the 100232 tune-down (XML). **FP profile:** `____`

## 7. Map
Tagged `attack.t1003.001`. Score in the Navigator layer.

### Evidence checklist
- [ ] EID 10 screenshot  - [ ] Alert 100231 screenshot  - [ ] AV/EDR allowlisted (FP note)  - [ ] Latency  - [ ] Second dump method (procdump/direct) still detected  - [ ] Incident report written
