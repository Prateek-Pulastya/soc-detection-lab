# I emulated 10 ATT&CK techniques and wrote the detections — what fired, what didn't, and why

Offensive portfolios prove you can *do* the attack. Detection-engineering roles screen for the
opposite: can you *catch* it? So I built **DetectForge** — a small but real SOC — and put myself
through the loop: detonate an ATT&CK technique, watch the telemetry, write a detection, deploy it,
prove it fires on a live attack, tune the false positives, map it to ATT&CK. Ten techniques,
six tactics. **Seven fired on live detonation; three are honest, documented gaps.**

## The stack (2 minutes)

- **Wazuh** single-node SIEM (Docker) on an Ubuntu VM.
- A **Sysmon-instrumented Windows 10** victim (SwiftOnSecurity config) forwarding the
  `Microsoft-Windows-Sysmon/Operational` channel via the Wazuh agent.
- **Atomic Red Team** on the victim to generate real attack telemetry.
- Everything on an isolated host-only network; snapshot before every detonation.

## Sigma is the source of truth — but Wazuh isn't Sigma-native

This is the engineering decision I'd want to be asked about. Wazuh's engine uses XML rules and has
no first-class Sigma backend. Rather than abandon portability, I author each detection once in
**Sigma** (versioned in git, converted to OpenSearch/Elastic/Splunk with `sigma-cli`), then
translate the real-time ones into native Wazuh XML. Documenting *that bridge* — "here's how I kept
my detections portable on a SIEM that isn't Sigma-native" — is the point, not a gap.

## Detect the behaviour, not the IOC

A rule that matches the atomic's exact filename catches nothing real. My PowerShell rule (T1059.001)
keys on the *technique* — an encoded command or an in-memory download cradle — and I proved it by
firing a **different** shape (a `Net.WebClient().DownloadString` cradle) at it. It still fired. That
distinction is the whole skill.

## The lesson I didn't expect: the shipped ruleset already covers things

My Registry Run Key rule (T1547.001) stayed silent even though its fields matched perfectly. The
reason: Wazuh's **built-in** ruleset already detects and ATT&CK-maps the Run key (rule 92302), and
the engine fires one alert per event — the built-in won. The professional fix isn't to duplicate
it; it's to **chain my rule as a child** (`<if_sid>92302</if_sid>`) so my tagged detection fires
*and* I'm extending the shipped ruleset instead of fighting it. Knowing when to extend vs. author
from scratch is a real part of the job.

## What fired (7/10)

Execution (T1059.001 PowerShell), Persistence (T1547.001 Run Key, T1053.005 Scheduled Task,
T1136.001 Create Local Account), Defense Evasion (T1070.001 Clear Event Logs), C2 (T1105 Ingress
Tool Transfer), and Exfiltration (T1048/T1567) all fired on live detonation, each mapped to ATT&CK
and, where dual-use, given a documented false-positive tune-down.

## What didn't — and why (the honest part)

- **T1003.001 LSASS dump (the marquee).** The detection is authored and correct (Sysmon EID 10 on a
  memory-read handle to lsass). It never fired because Windows LSASS protection / ASR blocked the
  dumper *before* it could open the handle — so the telemetry the rule needs was never generated.
  A documented miss with a cause beats a suspicious 10/10.
- **T1055 Process Injection.** Every CreateRemoteThread atomic failed on `VirtualAllocEx: access
  denied` — the target processes were protected. Rule ready (EID 8); technique not exercised.
- **T1021.001 RDP.** The RDP listener wouldn't bind on the Win10 Eval VM (0x204), so no
  RemoteInteractive (LogonType 10) logon was ever produced. Rule ready; blocked by the lab host.

## The part that makes it more than a lab: AI-assisted triage, scored

On top of the detections I built an **LLM triage layer** (`ai-soc/`). It reads a Wazuh alert and
returns a structured, ATT&CK-mapped verdict — true/false positive, reasoning grounded in the alert
fields, triage and containment steps. Two things keep it from being "I piped logs to a chatbot":
it's **scored against ground truth** I control (precision, recall, false-positive suppression),
and it treats alert fields as **untrusted** — a crafted `CommandLine` that tries to talk the AI
into clearing itself is flagged, not obeyed.

## Takeaways

- Depth over breadth: seven techniques taken through the full loop, with three explained gaps,
  says more than fifteen half-done.
- A miss you can explain is a talking point, not a failure.
- The value isn't the SIEM — it's the tested, tuned, ATT&CK-mapped rules and the writeups.

Repo: https://github.com/Prateek-Pulastya/soc-detection-lab
