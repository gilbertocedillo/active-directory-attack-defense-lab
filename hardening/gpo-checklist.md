# GPO & Hardening Checklist — lab.local

The production-shaped companion to `Harden-AD.ps1`. Each item: setting → value → why → which attack it hurts. Deploy in the lab with the Group Policy Management Console on DC01; in production, stage in a test OU first.

## 1. Audit policy (Advanced Audit Policy Configuration)

| Subcategory | Setting | Primary events |
|---|---|---|
| Kerberos Service Ticket Operations | Success + Failure | **4769** (Kerberoasting) |
| Kerberos Authentication Service | Success + Failure | **4768** (TGT anomalies) |
| Logon / Special Logon / Account Lockout | Success + Failure | 4624/4625/4672/4740 |
| Credential Validation | Success + Failure | 4776 |
| Directory Service Access | Success + Failure | **4661/4662** (BloodHound, DCSync) |
| Directory Service Changes | Success + Failure | 5136/5137/4728 (AD changes, group adds) |
| File Share / Detailed File Share | Success + Failure | 5140/5145 (`C$` lateral use) |
| Sensitive Privilege Use | Success + Failure | 4673/4674 |
| Audit Policy Change | Success + Failure | 4719 (attacker turning logging off) |
| Process Creation (+ include command line) | Success | 4688 with full cmdline |

## 2. Logging deployment

- [ ] **PowerShell Script Block Logging** enabled (Computer Config → Admin Templates → Windows PowerShell) → Event **4104**; Module Logging on; transcription to a write-only share optional
- [ ] **Sysmon** deployed by GPO/SCCM/Intune to DCs + workstations with a maintained config (SwiftOnSecurity or Olaf Hartong's sysmon-modular); auto-update the config like software, because it *is* detection code
- [ ] Event log sizes raised (Security ≥ 1 GB on DCs) + **Windows Event Forwarding** or agent forwarding to the SIEM — a full Security log that wraps in 2 hours is a detection gap, not a control
- [ ] Time sync verified everywhere (Kerberos + log correlation both die without it)

## 3. Tiered administration

- [ ] Tier groups created (`Tier0/1/2-Admins` — `Harden-AD.ps1` scaffolding)
- [ ] GPO on Workstations OU: **Deny log on locally / via RDP** for Tier0 + Tier1 admin groups
- [ ] GPO on Servers OU: deny Tier0 logon except on DCs/PAWs
- [ ] Separate named admin accounts per tier (no human uses one account at two tiers)
- [ ] Domain Admins membership reviewed — standing membership minimized, JIT where possible

## 4. Credential & protocol protections

- [ ] **Credential Guard** enabled on supported workstations (UEFI/VBS prerequisites checked)
- [ ] **Windows LAPS** deployed: unique rotating local admin passwords, read access restricted
- [ ] **SMB signing required** (server + client) — staged, legacy devices inventoried first
- [ ] **LDAP signing = Require** + **channel binding = Always** on DCs
- [ ] RC4 disabled for service accounts (AES128/256 only); domain-wide `msDS-SupportedEncryptionTypes` reviewed
- [ ] All service accounts inventoried → each is gMSA, or has a 25+ char vaulted password, or is on the migration plan
- [ ] "Account is sensitive and cannot be delegated" set on all privileged accounts (script §5)
- [ ] Unconstrained delegation: **none** (query and prove it: `Get-ADComputer -Filter {TrustedForDelegation -eq $true}`)

## 5. krbtgt & lifecycle

- [ ] krbtgt **double reset** completed + dates recorded (runbook in `Harden-AD.ps1` §6)
- [ ] Calendar: krbtgt rotation every 180 days; DA password policy; stale-account review monthly
- [ ] BloodHound defensive collection scheduled — "attack paths to DA" tracked as a number that must trend down

## Verification (close the loop)

Re-run the repo's attacks after this checklist: Kerberoast should return only AES (unroastable in practice), PtH should find no DA material on WS01, and the DCSync *detection* should be proven with a canary test account in a change window. Record results in `findings/`.
