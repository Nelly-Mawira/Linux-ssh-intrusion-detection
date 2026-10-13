# Automated Linux SSH Intrusion Detection & Incident Response

![OS](https://img.shields.io/badge/OS-Ubuntu_Linux-orange)
![Category](https://img.shields.io/badge/Category-Defensive_SOC_/_Detection_Engineering-blue)

## Project Overview
This project demonstrates an end-to-end SOC detection lifecycle: simulating an SSH brute-force attack on a local Linux host, analyzing `/var/log/auth.log` telemetry, building a custom Python log parser to flag volumetric anomalies, and executing firewall containment via UFW.

## MITRE ATT&CK Mapping
* **Tactic**: Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/))
* **Technique**: Brute Force ([T1110](https://attack.mitre.org/techniques/T1110/))
* **Mitigation**: Network Traffic Filtering ([M1037](https://attack.mitre.org/mitigations/M1037/))

## Architecture & Detection Pipeline

```text
[Attacker (Hydra)] ──> [Ubuntu SSH Service] ──> [/var/log/auth.log]
                                                       │
[UFW Firewall Block] <── [Alert Generated] <── [log_parser.py]
