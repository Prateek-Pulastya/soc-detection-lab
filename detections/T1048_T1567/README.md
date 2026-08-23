# T1048 / T1567 — Exfiltration over alt protocol / web service

**Tactic:** Exfiltration · **Telemetry:** Sysmon EID 3 (network connection) · EID 22 (DNS) ·
**Wazuh rule:** 100291 (+ 100292 internal tune-down) ·
**Sigma:** [`../../sigma/T1048_T1567_exfiltration.yml`](../../sigma/T1048_T1567_exfiltration.yml)

> **Honest framing:** the hardest technique to detect cleanly. Egress alone rarely proves exfil.
> This is a low-fidelity heuristic and a strong candidate for the project's **documented partial
> miss** — which is a more credible portfolio signal than a fake 10/10.

## 1. Detonate
See [atomic.md](atomic.md). Needs egress — reconnect NAT for the test, then disconnect + revert.

## 2. Observe
**Sysmon EID 3** → a script/LOLBin (`powershell`, `nslookup`, `curl`, `certutil`) with
`Initiated=true` to an **external** `DestinationIp`. DNS-exfil variants show as **EID 22**.

| Field | Value observed |
|-------|----------------|
| `win.eventdata.image` | `____` |
| `win.eventdata.destinationIp` / `destinationPort` | `____` |
| `win.eventdata.initiated` | `____` (expect true) |

> **TODO:** `![EID3 event](screenshots/01-sysmon-eid3.png)`

## 3. Author
Heuristic: script/LOLBin initiating outbound to a non-private address (100291); internal
destinations tune down to 100292.

## 4. Deploy
- **Native Wazuh:** rules 100291 + 100292. - **Sigma → OpenSearch:** [queries/opensearch.txt](queries/opensearch.txt).

## 5. Validate
Detonate → confirm **100291** fires on external egress.
> **TP:** ⬜ / partial · **Latency:** `____ s`

## 6. Tune
**High FP** — scripts legitimately reach the internet. Treat as a lead, not a standalone alert.
Record honestly what tuning it would take to be production-usable (volume baselining, destination
reputation, DLP). **FP profile:** `____`

## 7. Map
Tagged `attack.t1048` + `attack.t1567`. Score honestly in the Navigator layer (partial/yellow if
it can't cleanly separate from benign).

### Evidence checklist
- [ ] EID 3 (external) screenshot  - [ ] Alert 100291 screenshot  - [ ] FP reality documented  - [ ] Decision: detected vs documented-miss (say which, and why)
