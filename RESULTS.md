# RESULTS

Honest numbers. Fill each cell after the technique passes its loop. A documented miss (and *why*)
is a stronger signal than a suspicious perfect score.

## Headline metrics

| Metric | Value |
|--------|-------|
| Techniques emulated | 10 (across 6 tactics) |
| **Detected (rule fired on live detonation)** | `_/10` |
| Rules with a documented false-positive profile | `_/10` |
| Mean detection latency (detonation → alert) | `_ s` |
| Rules proven portable (≥2 SIEM backends) | `_` |
| Native Wazuh rules authored | `_` |

## Per-technique

Status legend: ⬜ not started · 🟡 rule drafted (awaiting live detonation) · ✅ detected on live detonation.

| ATT&CK | Detected? | Wazuh rule id | Sigma file | FP tuned? | Latency (s) | Notes |
|--------|-----------|---------------|-----------|-----------|-------------|-------|
| T1059.001 | ✅ | 100201 | `sigma/T1059.001_powershell_cradle.yml` | ⬜ | `_` | worked example; fired lvl 12 |
| T1547.001 | 🟡 | 100211 | `sigma/T1547.001_registry_run_key.yml` | ⬜ | `_` | EID 13 |
| T1053.005 | ✅ | 100221 | `sigma/T1053.005_scheduled_task.yml` | ⬜ | `_` | schtasks/PS; fired lvl 10 |
| T1003.001 | 🟡 | 100231 | `sigma/T1003.001_lsass_dump.yml` | ⬜ | `_` | marquee; EID 10 |
| T1055 | 🟡 | 100241 | `sigma/T1055_process_injection.yml` | ⬜ | `_` | EID 8 |
| T1070.001 | 🟡 | 100251 / 100252 | `sigma/T1070.001_clear_event_logs.yml` | ⬜ | `_` | +1102 native |
| T1136.001 | 🟡 | 100261 / 100262 | `sigma/T1136.001_create_local_account.yml` | ⬜ | `_` | +4720 native |
| T1105 | ✅ | 100271 | `sigma/T1105_ingress_tool_transfer.yml` | ⬜ | `_` | LOLBins; fired lvl 10 |
| T1021.001 | 🟡 | 100281 | `sigma/T1021.001_rdp_logon.yml` | ⬜ | `_` | 4624 type 10 |
| T1048 / T1567 | ✅ | 100291 / 100292 | `sigma/T1048_T1567_exfiltration.yml` | ⬜ | `_` | heuristic fired lvl 6 on external dest (8.8.8.8) |

## Portability proof

Rules converted to a second/third backend (`sigma convert`), committed under
`detections/<Txxxx>/queries/`:

| Technique | opensearch | lucene (Elastic) | splunk |
|-----------|-----------|------------------|--------|
| T1059.001 | ✅ | ✅ | ✅ |
| T1003.001 | ✅ | ✅ | ✅ |
| T1547.001 | ✅ | ✅ | ✅ |

> The other seven ship an OpenSearch query; add lucene/splunk if you want more portability proof.
> (Shapes are committed; regenerate with `sigma convert` on your sigma-cli version to confirm.)

## How latency was measured

For each timed technique: detonation timestamp (from the atomic run) vs the alert's
`timestamp` in Wazuh. Record both, subtract, note here.
