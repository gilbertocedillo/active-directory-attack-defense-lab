<#
.SYNOPSIS
  Enables the advanced audit policy + PowerShell logging this lab's detections depend on.

.DESCRIPTION
  Run as Administrator on DC01 AND WS01 (and any future lab machine).
  Without this, the attack playbooks succeed silently: no 4769/4662/4648 evidence exists.
  In production this is deployed via GPO (see hardening/gpo-checklist.md);
  auditpol here is the fast lab equivalent so a single VM works standalone.

  What gets enabled and WHY (detection in /detections that needs it):
    - Kerberos Service Ticket Operations (Success+Failure) -> 4769  Kerberoasting
    - Kerberos Authentication Service   (Success+Failure) -> 4768  Golden Ticket anomalies
    - Logon/Logoff: Logon, Special Logon, Account Lockout    -> 4624/4672/4740  PtH + spray
    - Account Logon: Credential Validation                   -> 4776
    - Directory Service Access                               -> 4662  DCSync + BloodHound
    - Directory Service Changes                              -> 5136/5137 audit of AD changes
    - Object Access: Detailed File Share / File Share      -> 5140/5145 lateral validation
    - Privilege Use: Sensitive Privilege Use                -> 4673/4674
    - Policy Change: Audit Policy Change                     -> 4719 (attacker blinding you)
    - System: Security State Change / System Integrity       -> 4616/4713
  Plus registry keys for PowerShell Script Block Logging (4104) and Module Logging.
#>
[CmdletBinding()]
param()

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

# Force advanced audit policy over legacy settings
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service"    /success:enable /failure:enable
auditpol /set /subcategory:"Logon"                              /success:enable /failure:enable
auditpol /set /subcategory:"Logoff"                             /success:enable /failure:disable
auditpol /set /subcategory:"Special Logon"                      /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout"                    /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation"              /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access"           /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes"          /success:enable /failure:enable
auditpol /set /subcategory:"File Share"                         /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share"                /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use"            /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change"                /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change"              /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension"          /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management"            /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"          /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation"                   /success:enable /failure:disable

# Include command line in 4688 process-creation events (huge for detection)
$procKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $procKey -Force | Out-Null
New-ItemProperty -Path $procKey -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force | Out-Null

# ---------- PowerShell logging: Script Block (4104) + Module + Transcription ----------
$psKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $psKey -Force | Out-Null
New-ItemProperty -Path $psKey -Name "EnableScriptBlockLogging" -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $psKey -Name "EnableScriptBlockInvocationLogging" -PropertyType DWord -Value 1 -Force | Out-Null

$modKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $modKey -Force | Out-Null
New-ItemProperty -Path $modKey -Name "EnableModuleLogging" -PropertyType DWord -Value 1 -Force | Out-Null

Write-Host ""
Write-Host "Audit policy applied. Verify with:  auditpol /get /category:*"
Write-Host "Test evidence: log off/on as a domain user, then check Security log for 4624 + 4768/4769."
Write-Host ""
Write-Host "NEXT (manual, one time): install Sysmon with a maintained config, e.g.:"
Write-Host "  .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml   # SwiftOnSecurity/sysmon-config on GitHub"
Write-Host "Sysmon gives you Event IDs this lab uses heavily: 1 (process), 3 (network), 10 (ProcessAccess -> LSASS), 11 (file create)."
Write-Host "In production all of the above belongs in GPO - see hardening/gpo-checklist.md."
