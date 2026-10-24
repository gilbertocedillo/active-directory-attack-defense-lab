# 🪪 Active Directory Attack & Defense Lab

A hands-on **identity security** lab: build a small Active Directory environment, run a controlled attack chain against it (enumeration → Kerberoasting → lateral movement → persistence concepts), **detect every step** in Windows Event Logs with Splunk/Elastic queries, and then **harden the domain** so the same attacks fail.

> Portfolio project by **Gilberto A. Cedillo Soto (Abisaíd)** — Cybersecurity Senior, BYU–Idaho (Class of 2027) · [github.com/gilbertocedillo](https://github.com/gilbertocedillo)
> `Active Directory` · `Windows Server 2022` · `Sysmon` · `BloodHound` · `Kerberoasting` · `Splunk SPL` · `Elastic KQL` · `Sigma` · `MITRE ATT&CK`

---

## ⚠️ Safety & Scope — Read First

- **LAB ONLY.** Every machine in this project is a virtual machine **you own**, on an **isolated host-only / internal network** with **no route to the internet and no route to your real LAN** (except a temporarily enabled NAT adapter for initial patching/tool downloads, which you disable before attacks start).
- **Never** run these tools against any network, domain, or system you do not own and control. Unauthorized access is a crime in most jurisdictions and ends careers in this field.
- Take **snapshots before every attack phase** and revert after. The domain in this lab is *intentionally* misconfigured (see `lab-setup/INTENTIONALLY-VULNERABLE.md`) — it must never be reused as a real environment.
- All accounts, names, and passwords in this repo are **fake lab values** marked `CHANGE_ME`.

---

## Lab Topology

```
                ┌───────────────────── Host-only network 192.168.56.0/24 ─────────────────────┐
                │                                                                               │
   ┌────────────┴────────────┐   ┌───────────────────────┐   ┌──────────────────┐   ┌─────────┴──────────┐
   │ DC01                    │   │ WS01                  │   │ KALI             │   │ SIEM (optional)    │
   │ Windows Server 2022     │   │ Windows 11 Pro        │   │ Kali Linux       │   │ Splunk Free /      │
   │ AD DS + DNS             │   │ Domain workstation    │   │ Attacker VM      │   │ Elastic / WEF      │
   │ Domain: lab.local       │   │ Joined to lab.local   │   │ BloodHound,      │   │ Collects: Security │
   │ 192.168.56.10           │   │ 192.168.56.20         │   │ Rubeus (on WS01),│   │ + Sysmon + PS logs │
   │ Advanced Audit + Sysmon │   │ Sysmon + PS logging   │   │ Impacket, mimikatz│  │ from DC01 + WS01   │
   └─────────────────────────┘   └───────────────────────┘   └──────────────────┘   └────────────────────┘
```

| VM | OS | Role | IP (suggested) |
|---|---|---|---|
| DC01 | Windows Server 2022 | Domain Controller, DNS | 192.168.56.10 |
| WS01 | Windows 11 Pro | Domain workstation (attack launch + lateral target) | 192.168.56.20 |
| KALI | Kali Linux | Attacker (enumeration tooling) | 192.168.56.30 |
| SIEM | Ubuntu / Windows (optional) | Splunk Free, Elastic, or Windows Event Forwarding collector | 192.168.56.40 |

Log pipeline (no SIEM required to start): DC01 + WS01 forward **Security**, **Sysmon (Microsoft-Windows-Sysmon/Operational)**, and **PowerShell (4104)** events via Windows Event Forwarding, or you review them locally with Event Viewer / `Get-WinEvent` while you build up to Splunk/Elastic.

---

## Attack Chain (mapped to MITRE ATT&CK)

| # | Phase | Technique | ATT&CK | Primary evidence | Detection |
|---|---|---|---|---|---|
| 1 | Enumeration | BloodHound / SharpHound collection, LDAP queries | T1087.002, T1069.002 | 4661/4662 bursts, LDAP traffic | `detections/04-bloodhound-collection.md` |
| 2 | Credential access | Kerberoasting (RC4 TGS for SPN account) | T1558.003 | **4769** with TicketEncryptionType `0x17` (RC4) | `detections/01-kerberoasting.md` |
| 3 | Lateral movement | Pass-the-Hash / explicit credentials | T1550.002, T1021.002 | **4624 LogonType 9**, **4648**, 4672 | `detections/03-pass-the-hash.md` |
| 4 | Replication abuse | DCSync (concept + detection focus) | T1003.006 | **4662** with replication GUIDs from a non-DC | `detections/02-dcsync.md` |
| 5 | Persistence | Golden Ticket (conceptual) | T1558.001 | Anomalous TGT lifetimes / 4768 anomalies | `attacks/04-golden-ticket-concepts.md` |

Full playbooks: [`attacks/`](attacks/) · Full queries (Splunk SPL + Elastic KQL + Sigma notes): [`detections/`](detections/)
End-to-end analyst write-up of one run: [`findings/sample-findings-report.md`](findings/sample-findings-report.md)

---

## Setup Order

1. Create the host-only network and the 4 VMs — [`lab-setup/manual-setup.md`](lab-setup/manual-setup.md) (or the experimental `Vagrantfile`)
2. Install AD DS on DC01, promote to `lab.local`, create the forest
3. Run [`lab-setup/Create-LabUsers.ps1`](lab-setup/Create-LabUsers.ps1) — OUs, users, helpdesk group, Domain Admin, and the intentionally Kerberoastable `svc_sql` service account
4. Run [`lab-setup/Enable-Auditing.ps1`](lab-setup/Enable-Auditing.ps1) — advanced audit policy + PowerShell logging, then install Sysmon
5. Join WS01 to the domain, snapshot **everything** ("clean-baseline")
6. Work the attack playbooks in order, running the matching detection after each one
7. Apply [`hardening/`](hardening/) (gMSA, AES-only, tiering, LAPS, SMB/LDAP signing, krbtgt rotation) and re-run the attacks — they should fail or light up immediately

---

## Hardening Summary (what "fixed" looks like)

- **Kerberoasting:** service accounts on **gMSA** (240-char auto-rotated passwords) or 25+ char passwords; **AES128/256 only**, RC4 disabled → no crackable `0x17` tickets
- **Pass-the-Hash:** Credential Guard, tiered administration (no DA logon on workstations), LAPS unique local admin passwords, SMB signing
- **DCSync:** alert on 4662 replication GUIDs from non-DCs; replication rights limited to DCs only
- **General:** LDAP signing + channel binding, PowerShell Script Block Logging (4104), Sysmon everywhere, krbtgt **double reset** on a schedule and after any suspected compromise

Details: [`hardening/gpo-checklist.md`](hardening/gpo-checklist.md) · [`hardening/Harden-AD.ps1`](hardening/Harden-AD.ps1)

## Roadmap
- [ ] Add a second workstation + a Tier-1 server to practice true tiered administration end-to-end
- [ ] Convert Sigma-style notes into tested Sigma YAML with a CI validation step (`sigma check`)
- [ ] Add AS-REP Roasting + delegation (RBCD) phases with matching detections
- [ ] Ingest everything into Splunk with the Splunk Add-on for Microsoft Windows and dashboard the coverage table

## License
MIT — see [LICENSE](LICENSE). Lab/educational use; you are responsible for using it only on systems you own.
