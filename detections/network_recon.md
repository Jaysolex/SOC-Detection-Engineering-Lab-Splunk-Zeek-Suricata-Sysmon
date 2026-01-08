# Network Reconnaissance Detection

## Overview

This detection focuses on identifying **network-based reconnaissance activity** by analyzing connection patterns observed in **Zeek** and **Suricata** telemetry.

Rather than relying on signatures or payload inspection, this detection emphasizes **behavioral indicators** commonly associated with scanning and service enumeration.

The objective is to detect **early-stage attacker activity** with high confidence and minimal false positives.

---

## Adversary Behavior

During reconnaissance, attackers attempt to map a target environment by:

- Scanning for open ports
- Enumerating exposed services
- Identifying reachable hosts
- Testing firewall and IDS responses

This activity typically occurs **before exploitation** and is a critical opportunity for early detection.

Common tools and techniques include:

- Nmap SYN scans
- TCP connect scans
- Service/version probing
- Wide port sweeps from a single source

---

## Attack Simulation

Network reconnaissance was simulated from the **Kali Linux attack host** using tools such as:

- `nmap -sS`
- Targeted port scanning
- Service discovery against internal hosts

These scans generated **short-lived TCP connections** across multiple destination ports in a short time window.

---

## Telemetry Sources

### Network Logs Used

#### Zeek
- `conn.log`
  - Source IP (`id.orig_h`)
  - Destination IP (`id.resp_h`)
  - Destination port (`id.resp_p`)
  - Connection state
  - Duration

#### Suricata
- Flow events
  - Source/destination IPs
  - Protocol
  - Flow state
  - Packet counts

Using both sensors provides **visibility redundancy** and improves confidence.

---

## Detection Strategy

The detection logic focuses on identifying:

- High fan-out connections from a single source IP
- Numerous destination ports contacted in a short time period
- Short-duration TCP sessions
- Repeated failed or incomplete connections

These indicators are strongly correlated with scanning behavior.

---

## Example Detection Logic (Splunk SPL)

### Zeek-Based Detection

```spl
index=main sourcetype=zeek source="/opt/zeek/logs/current/conn.log"
| stats count by id.orig_h id.resp_h id.resp_p
| sort - count
```

Aggregated Recon Detection
```
index=main sourcetype=zeek
| stats dc(id.resp_p) as unique_ports count as total_connections by id.orig_h
| where unique_ports > 20 AND total_connections > 50
| sort - unique_ports
```
This logic highlights hosts exhibiting scanning-like behavior rather than normal client traffic.

---

Expected Detection Output

This detection reliably identifies:

Port scanning attempts

Service enumeration activity

Reconnaissance originating from internal or external sources

Early-stage attacker behavior prior to exploitation

False positives are rare outside of vulnerability scanners or asset discovery tools.

MITRE ATT&CK Mapping
Tactic	Technique	Description
Discovery	T1046	Network Service Scanning
Cross-Sensor Correlation

Reconnaissance events observed in Zeek were validated against Suricata flow telemetry, confirming:

Matching source IPs

Consistent destination patterns

Similar timing and volume characteristics

Correlating multiple sensors reduces false positives and increases detection confidence.

SOC Analyst Notes

Reconnaissance is often the earliest observable attack phase

Early detection enables proactive response

Baseline internal scanning tools to reduce noise

Combine with endpoint telemetry for stronger context

Detection Engineering Takeaways

Behavioral detections outperform signature-based approaches for recon

Network metadata alone is sufficient for high-quality detections

Correlation across Zeek and Suricata increases confidence

Detecting reconnaissance early reduces downstream risk
