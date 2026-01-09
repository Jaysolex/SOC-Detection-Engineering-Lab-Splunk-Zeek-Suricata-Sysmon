# PowerShell Defense Evasion Detection

## Overview

This detection focuses on identifying **PowerShell-based defense evasion** using common Living-off-the-Land Binary (LOLBin) techniques.  
The goal is to detect **stealthy PowerShell execution** that attempts to bypass visibility and logging controls.

This detection leverages **endpoint telemetry** and is designed to be **high-confidence**, low-noise, and SOC-ready.

**MITRE ATT&CK Context:** This detection aligns with **T1059.001 (PowerShell)** under the **Defense Evasion** tactic.

---

## Adversary Behavior

Attackers frequently abuse `powershell.exe` with execution flags that reduce visibility, including:

- Disabling profile loading
- Hiding execution windows
- Executing commands inline without script files

These techniques are commonly used during:

- Initial access
- Post-exploitation
- Command and Control staging
- Defense evasion

---

## Attack Simulation

The following command was executed on the Windows endpoint to simulate malicious behavior:

```powershell
powershell.exe -nop -w hidden -c "Get-Process | Out-File C:\Users\Public\ps_test.txt"
```

### Why This Matters

- `-nop` bypasses PowerShell profile loading
- `-w hidden` suppresses user-visible windows
- Inline execution (`-c`) avoids script artifacts
- Writing output to a public directory is commonly abused

This execution pattern is frequently observed in real-world intrusions and post-exploitation activity.

---

## Telemetry Sources

### Endpoint Logs Used

- **Sysmon**
  - Event ID `1` — Process Creation
- **Windows Security Logs**
  - Event ID `4688` — New Process Created

These telemetry sources provide detailed command-line visibility, execution context, and parent/child process relationships.

---

## Detection Strategy

The detection logic focuses on identifying:

- Execution of `powershell.exe`
- Suspicious command-line flags:
  - `-nop`
  - `-w hidden`
- Non-interactive or stealth execution context
- LOLBin abuse patterns

---

## Example Detection Logic (Splunk SPL)

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| search Image="*powershell.exe*" CommandLine="*-nop*" CommandLine="*-w hidden*"
| table _time host User Image CommandLine ParentImage
| sort - _time
```

---

## Expected Detection Output

This detection reliably surfaces:

- Hidden PowerShell execution
- Defense evasion behavior
- Abuse of built-in Windows binaries
- Clear malicious intent with minimal false positives

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|---------|-------------|
| Defense Evasion | T1059.001 | PowerShell |
| Defense Evasion | TA0005 | Defense Evasion |

---

## SOC Analyst Notes

- This detection is **high-signal** and suitable for alerting
- False positives are uncommon outside of automation tooling
- Parent process context is critical for triage
- Recommended enrichment:
  - User context
  - Host role
  - Recent network activity

---

## Detection Engineering Takeaways

- Command-line logging is essential for endpoint detections
- LOLBins remain a primary attacker tradecraft
- Small execution flags often carry strong intent signals
- Combining Sysmon and Windows Security logs improves confidence

---

