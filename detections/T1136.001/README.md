# T1136.001 — Create Local Account (persistence)

**Tactic:** Persistence · **Telemetry:** Sysmon EID 1 (net/PS) · Security 4720 ·
**Wazuh rules:** 100261 (process) + 100262 (EventID 4720) ·
**Sigma:** [`../../sigma/T1136.001_create_local_account.yml`](../../sigma/T1136.001_create_local_account.yml)

## 1. Detonate
See [atomic.md](atomic.md). `Invoke-AtomicTest T1136.001 -TestNumbers 1`.

## 2. Observe
- **Sysmon EID 1** → `net.exe user <name> <pw> /add` (or `New-LocalUser`).
- **Security EID 4720** → "a user account was created" (fires 100262).

| Field | Value observed |
|-------|----------------|
| `win.eventdata.commandLine` | `____` |
| `win.system.eventID` | `____` (expect 4720) |
| new account name | `____` |

> **TODO:** `![alert 4720](screenshots/01-alert-4720.png)`

## 3. Author
Process vector (100261) + authoritative 4720 audit event (100262).

## 4. Deploy
- **Native Wazuh:** rules 100261 + 100262. - **Sigma → OpenSearch:** [queries/opensearch.txt](queries/opensearch.txt).

## 5. Validate
Re-detonate → confirm **100261 and/or 100262** fire.
> **TP:** ⬜ · **Latency:** `____ s`

## 6. Tune
Benign — IT provisioning creates accounts. Correlate with actor/host; allowlist known provisioning
automation if noisy. **FP profile:** `____`

## 7. Map
Tagged `attack.t1136.001`. Score in the Navigator layer.

### Evidence checklist
- [ ] 4720 alert screenshot  - [ ] Alert 100261/100262 screenshot  - [ ] Benign/provisioning FP note  - [ ] Latency  - [ ] `New-LocalUser` variant still detected
