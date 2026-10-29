# SOC Telemetry Detective — Incident Report

Generated: 2026-10-29 11:25:40 UTC

## Summary

- Alerts raised: 6
- Incidents after correlation: 1

## INC-001 — CRITICAL on WS-FIN-023

- Accounts: svc_backup
- Time range: 2026-10-29T09:58:10Z to 2026-10-29T10:04:22Z
- Evidence sources: authentication, network, process
- Alerts: 6

### Attack stages

- **Credential Access** (T1110 Brute Force)
- **Discovery** (T1033/T1016/T1087/T1007 System & Account Discovery)
- **Command and Control** (T1071 Application Layer Protocol)

### Alerts

- [HIGH] AUTH-001 Repeated failed logons followed by success: 5 failed logons were followed by a successful logon for svc_backup from 198.51.100.23.
- [MEDIUM] PROC-001 Discovery-oriented process execution: Discovery command 'whoami.exe /all' was observed. Validate the user and business context.
- [MEDIUM] PROC-001 Discovery-oriented process execution: Discovery command 'ipconfig.exe /all' was observed. Validate the user and business context.
- [MEDIUM] NET-001 High-severity network IDS alert: Suricata raised 'ET POLICY Simulated Unusual External Connection' for a connection to 203.0.113.77:443.
- [MEDIUM] PROC-001 Discovery-oriented process execution: Discovery command 'net.exe user' was observed. Validate the user and business context.
- [MEDIUM] PROC-001 Discovery-oriented process execution: Discovery command 'powershell.exe -NoProfile -Command "Get-Service"' was observed. Validate the user and business context.

### Timeline

| Time | Source | Event | Summary |
|------|--------|-------|---------|
| 2026-10-29T09:58:10Z | authentication | AUTH-001 | Network logon failed (EventID 4625) for svc_backup from 198.51.100.23 |
| 2026-10-29T09:58:42Z | authentication | AUTH-002 | Network logon failed (EventID 4625) for svc_backup from 198.51.100.23 |
| 2026-10-29T09:59:03Z | authentication | AUTH-003 | Network logon failed (EventID 4625) for svc_backup from 198.51.100.23 |
| 2026-10-29T09:59:28Z | authentication | AUTH-004 | Network logon failed (EventID 4625) for svc_backup from 198.51.100.23 |
| 2026-10-29T09:59:51Z | authentication | AUTH-005 | Network logon failed (EventID 4625) for svc_backup from 198.51.100.23 |
| 2026-10-29T10:00:16Z | authentication | AUTH-006 | Network logon succeeded (EventID 4624) for svc_backup from 198.51.100.23 |
| 2026-10-29T10:00:18Z | authentication | AUTH-007 | Special privileges assigned to new logon (EventID 4672) for svc_backup from 198.51.100.23 |
| 2026-10-29T10:01:02Z | process | PROC-001 | svc_backup ran: whoami.exe /all |
| 2026-10-29T10:02:15Z | process | PROC-002 | svc_backup ran: ipconfig.exe /all |
| 2026-10-29T10:02:40Z | network | NET-001 | Suricata: 192.0.2.45 -> 203.0.113.77:443 — ET POLICY Simulated Unusual External Connection |
| 2026-10-29T10:03:05Z | network | NET-002 | Zeek: 192.0.2.45 -> 203.0.113.77:443 |
| 2026-10-29T10:03:40Z | process | PROC-003 | svc_backup ran: net.exe user |
| 2026-10-29T10:04:22Z | process | PROC-004 | svc_backup ran: powershell.exe -NoProfile -Command "Get-Service" |

### Recommended actions

- Reset the affected account's password and review where the failed logons originated.
- Confirm with the account owner whether the commands were authorised administrative activity.
- Check the destination IP against threat intelligence and consider blocking it at the perimeter.
- Treat these findings as triage leads, not proof of compromise, until validated.

