# RESULTS

Honest numbers. Fill each cell after the technique passes its loop. A documented miss (and *why*)
is a stronger signal than a suspicious perfect score.

## Headline metrics

| Metric | Value |
|--------|-------|
| Techniques emulated | 10 (across 6 tactics) |
| **Detected (rule fired on live detonation)** | **7 / 10** |
| Documented gaps (rule authored, technique blocked/not exercised in lab) | 3 (T1003.001, T1055, T1021.001) |
| Rules with a false-positive tune-down | 1 (T1048/T1567 internal-destination) |
| Rules proven portable (≥2 SIEM backends) | 3 (T1059.001, T1003.001, T1547.001) |
| Native Wazuh rules authored | 13 (covering 10 techniques) |

## Per-technique

Status legend: ✅ detected on live detonation · ❌ rule authored but technique blocked / not exercised in lab (documented gap).

| ATT&CK | Detected? | Wazuh rule id | Sigma file | Notes |
|--------|-----------|---------------|-----------|-------|
| T1059.001 | ✅ | 100201 | `sigma/T1059.001_powershell_cradle.yml` | worked example; encoded/cradle PowerShell, fired lvl 12 |
| T1547.001 | ✅ | 100211 | `sigma/T1547.001_registry_run_key.yml` | EID 13 Run key; chained on built-in 92302 so the DetectForge rule fires (extend, don't duplicate the shipped ruleset) |
| T1053.005 | ✅ | 100221 | `sigma/T1053.005_scheduled_task.yml` | schtasks / Register-ScheduledTask, fired lvl 10 |
| T1003.001 | ❌ | 100231 | `sigma/T1003.001_lsass_dump.yml` | marquee; LSASS dump (comsvcs MiniDump) blocked by Windows LSASS protection / ASR even with real-time AV disabled — no Sysmon EID 10 produced. Rule authored + ready. |
| T1055 | ❌ | 100241 | `sigma/T1055_process_injection.yml` | CreateRemoteThread injection failed in lab — `VirtualAllocEx` access denied on the target process (protection). No EID 8. Rule authored + ready. |
| T1070.001 | ✅ | 100251 / 100252 | `sigma/T1070.001_clear_event_logs.yml` | wevtutil cl + Security EventID 1102, both fired lvl 12 |
| T1136.001 | ✅ | 100261 / 100262 | `sigma/T1136.001_create_local_account.yml` | net user /add → Sysmon EID 1 AND Security 4720; both rules fired lvl 10 |
| T1105 | ✅ | 100271 | `sigma/T1105_ingress_tool_transfer.yml` | LOLBin download (certutil/BITS/IWR), fired lvl 10 |
| T1021.001 | ❌ | 100281 | `sigma/T1021.001_rdp_logon.yml` | RDP listener would not bind on the Win10 Eval VM (client error 0x204); no RemoteInteractive 4624 type 10 generated. Rule authored + ready. |
| T1048 / T1567 | ✅ | 100291 / 100292 | `sigma/T1048_T1567_exfiltration.yml` | scripted outbound, fired lvl 6 on external destination (8.8.8.8); internal-destination tune-down (100292) documented |

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
