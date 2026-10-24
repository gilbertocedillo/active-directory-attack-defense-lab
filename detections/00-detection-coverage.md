# Detection Coverage — Attack → Event IDs → Query → ATT&CK

How to read this: every attack playbook in `attacks/` has a matching detection here. Queries are given in **Splunk SPL** and **Elastic KQL**, followed by **Sigma-style notes** (the fields/logsource a Sigma rule would use — convert to formal Sigma YAML as a roadmap item). Assumes `Enable-Auditing.ps1` + Sysmon are in place and logs are centralized; field names follow the Windows Security log / Splunk Add-on for Windows conventions.

| # | Attack | ATT&CK | Must-have Event IDs | Where | Detection file |
|---|---|---|---|---|---|
| 1 | BloodHound / SharpHound enumeration | T1087.002, T1069.002 | 4661, 4662 (bursts), 4624, Sysmon 1/3 | DC01, WS01 | `04-bloodhound-collection.md` |
| 2 | Kerberoasting | T1558.003 | **4769** (TicketEncryptionType `0x17`), 4770 | DC01 | `01-kerberoasting.md` |
| 3 | Pass-the-Hash / lateral movement | T1550.002, T1021.002 | Sysmon **10** (LSASS), **4624 Type 9**, **4648**, 4672, 5140/5145 | WS01 + target | `03-pass-the-hash.md` |
| 4 | DCSync | T1003.006 | **4662** with replication GUIDs from non-DC subject | DC01 | `02-dcsync.md` |
| 5 | Golden Ticket (anomaly hunt) | T1558.001 | 4768 absent/anomalous, 4769 `0x17` in AES domain, lifetime > policy | DC01 | `attacks/04-golden-ticket-concepts.md` + `02`/`01` queries |
| 6 | Password spraying (bonus baseline) | T1110.003 | Many 4625 + 4771/4776 from one source | DC01 | Pattern reuses `03` logon queries with failure aggregation |

## Tuning principles used across all of these

1. **Behavior + context beats single-event alerts.** A lone 4769 is normal Kerberos. A 4769 with RC4 for a high-value SPN, from a workstation, at 2 a.m., after a BloodHound-shaped 4662 burst = incident.
2. **Known-noise allowlists are explicit** (backup service accounts doing legitimate replication-like reads, vulnerability scanners) — documented per rule, never silent.
3. **Every rule names its blind spot.** If Sysmon is not deployed, the rule says what it loses. Honest coverage > inflated coverage.
4. **Response is part of the detection:** each file ends with triage steps (scope the source account/host, check for follow-on 4769/4648/4662, preserve logs, snapshot before remediation).
