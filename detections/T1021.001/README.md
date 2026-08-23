# T1021.001 — Remote Desktop (lateral movement)

**Tactic:** Lateral Movement · **Telemetry:** Security EID 4624, LogonType 10 ·
**Wazuh rule:** 100281 · **Sigma:** [`../../sigma/T1021.001_rdp_logon.yml`](../../sigma/T1021.001_rdp_logon.yml)

> Uses the **Security** channel (not Sysmon). Confirm the agent forwards Security
> (`deploy/wazuh/ossec-agent-snippet.conf`).

## 1. Detonate
See [atomic.md](atomic.md). Enable RDP on the Windows VM, then RDP into it over VMnet1 (from the
host or Ubuntu VM) to generate a real RemoteInteractive logon.

## 2. Observe
**Security EID 4624** with `LogonType 10`. Record the source IP + account.

| Field | Value observed |
|-------|----------------|
| `win.system.eventID` | `____` (expect 4624) |
| `win.eventdata.logonType` | `____` (expect 10) |
| `win.eventdata.ipAddress` | `____` (source) |
| `win.eventdata.targetUserName` | `____` |

> **TODO:** `![alert 4624 type10](screenshots/01-alert-4624.png)`

## 3. Author
Keys on 4624 + LogonType 10 (RemoteInteractive). Context rule — the value is *which source*.

## 4. Deploy
- **Native Wazuh:** rule 100281. - **Sigma → OpenSearch:** [queries/opensearch.txt](queries/opensearch.txt)
  (security pipeline, not sysmon).

## 5. Validate
Establish an RDP session → confirm **100281** fires with LogonType 10.
> **TP:** ⬜ · **Latency:** `____ s`

## 6. Tune
Expected admin RDP is benign. Don't blanket-alert — restrict to RDP from **unexpected** subnets, or
allowlist known admin source hosts. **FP profile:** `____`

## 7. Map
Tagged `attack.t1021.001`. Score in the Navigator layer.

### Evidence checklist
- [ ] 4624/type-10 alert screenshot  - [ ] Source IP + account recorded  - [ ] Latency  - [ ] Tuning note (allowlist vs unexpected-subnet alerting)
