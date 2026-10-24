# Manual Lab Setup (VirtualBox / VMware / Hyper-V)

Vagrant boxes for Windows are unreliable (licensing + huge images), so this is the **primary** path. The `Vagrantfile` in this folder is an optional accelerator for the Kali VM only in practice — build the Windows VMs by hand with your own ISOs (evaluation editions are fine: Windows Server 2022 Evaluation 180 days, Windows 11 Enterprise Evaluation 90 days).

Time: ~90 minutes first build. Snapshot aggressively.

---

## 0. Network first (do not skip)

1. Create a **Host-Only** network `192.168.56.0/24` (VirtualBox: Tools → Network; VMware: VMnet with host-only; Hyper-V: Internal switch + manual IPs).
2. Every VM gets **one NIC on host-only only**. For initial Windows Update + tool downloads you may *temporarily* add a second NAT NIC — **remove/disable it before any attack step** and verify from KALI: `ping 8.8.8.8` must fail, `ping 192.168.56.10` must succeed.
3. Static IPs: DC01 `.10`, WS01 `.20`, KALI `.30`, SIEM `.40`. DNS for all Windows VMs = `192.168.56.10` (DC01, once promoted).

## 1. DC01 — Windows Server 2022

```powershell
# Rename + static IP (adjust adapter name)
Rename-Computer -NewName "DC01" -Restart
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1

# Install AD DS + DNS and promote to a new forest
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" `
  -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString "CHANGE_ME_DSRM!" -AsPlainText -Force) -Force
# Machine reboots; log on as LAB\Administrator
```

## 2. Populate the domain

```powershell
# From this repo, on DC01 as Domain Admin (review the script first!)
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Create-LabUsers.ps1
```

Creates OUs (`Lab Users`, `Lab Admins`, `Service Accounts`, `Workstations`), the test users in the table in that script (all passwords fake + `CHANGE_ME` in your notes), the Helpdesk group, one Domain Admin, and the Kerberoastable `svc_sql` (SPN `MSSQLSvc/dc01.lab.local:1433`, RC4 allowed — see `INTENTIONALLY-VULNERABLE.md` #1).

## 3. Auditing + Sysmon (DC01 and WS01)

```powershell
.\Enable-Auditing.ps1   # auditpol subcategories + PowerShell logging registry keys
```

Then install Sysmon on both machines:

```powershell
# Download Sysmon from Sysinternals (while NAT is temporarily enabled), plus a known config, e.g. SwiftOnSecurity/sysmon-config
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Verify on DC01: Event Viewer shows `Microsoft-Windows-Sysmon/Operational` filling with Event ID 1 (process create), and Security log shows **4768/4769** after a domain logon.

## 4. WS01 — Windows 11 Pro/Enterprise

```powershell
Rename-Computer -NewName "WS01" -Restart
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.20 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.56.10
Add-Computer -DomainName "lab.local" -Restart   # credentials: LAB\Administrator
```

After joining: log on once as `LAB\a.cedillo-admin` (Domain Admin) — **this is deliberate** for the baseline PtH scenario (see `INTENTIONALLY-VULNERABLE.md` #2) — then log on as `LAB\j.rodriguez` for daily use. Install Sysmon + run `Enable-Auditing.ps1` here too.

## 5. KALI

- Static IP `192.168.56.30/24`, no gateway. Tools used: `bloodhound`/`bloodhound.py` or SharpHound run from WS01, Impacket (`GetUserSPNs.py`, `secretsdump.py` for the *detection-focused* DCSync discussion), hashcat (mode 13100) for the Kerberoast demo, CrackMapExec/NetExec for enumeration validation.

## 6. Log review without a SIEM (start here)

```powershell
# On DC01 — pull the events each detection in /detections is built on:
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 20 |
  Format-Table TimeCreated, Id, Message -Wrap
```

With a SIEM: install **Splunk Free** on the SIEM VM (Universal Forwarders on DC01/WS01, `WinEventLog://Security`, `WinEventLog://Microsoft-Windows-Sysmon/Operational`, `WinEventLog://Microsoft-Windows-PowerShell/Operational`) or Elastic Agent with the **System + Windows** integrations. Every query in `detections/` is written for both.

## 7. Snapshot checklist

- [ ] `clean-baseline` — all VMs, domain built, auditing on, **before** any attack tool runs
- [ ] `pre-attack-N` — before each playbook phase
- [ ] `hardened` — after applying `hardening/` and re-testing

Disable the NAT NICs now. You're ready for `attacks/01-enumeration-bloodhound.md`.
