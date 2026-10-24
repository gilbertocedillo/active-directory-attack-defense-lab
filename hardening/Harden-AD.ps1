<#
.SYNOPSIS
  Hardens lab.local against the exact attacks in /attacks. Run on DC01 as
  Domain Admin, in sections, re-testing after each. LAB first - several of
  these changes are disruptive in production (krbtgt rotation, RC4 removal).

.DESCRIPTION
  Sections:
    1. Kill Kerberoasting value: gMSA guidance + AES-only on remaining svc accounts
    2. Tiered administration scaffolding (Tier groups + logon restrictions notes)
    3. LAPS (Windows LAPS) enablement notes + policy pointers
    4. SMB signing + LDAP signing / channel binding (registry/GPO values)
    5. Mark privileged accounts "sensitive and cannot be delegated"
    6. krbtgt double-reset RUNBOOK (deliberately NOT auto-executed - read it)

  Nothing here auto-rotates krbtgt or deletes accounts: those are human,
  scheduled, verified operations. This script prints as much as it changes.
#>
[CmdletBinding()]
param(
    [string]$DomainDN = "DC=lab,DC=local",
    [switch]$ApplyServiceAccountFix,
    [switch]$ApplySigning
)

Import-Module ActiveDirectory

Write-Host "=== 1. Service accounts: AES-only + the gMSA conversation ==="
Write-Host @"
PREFERRED FIX (do this, not password tweaks): migrate svc_sql to a Group
Managed Service Account. The DC manages a 240-char password, rotated
automatically; there is nothing human-memorable to roast and crack.

  # One-time per forest: KDS root key (lab: effective immediately with -EffectiveTime in the past)
  Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
  # Create and bind the gMSA (requires the SQL host to be a domain computer)
  New-ADServiceAccount -Name gmsa-sql -DNSHostName gmsa-sql.lab.local -PrincipalsAllowedToRetrieveManagedPassword "WS01$"
  # On the service host: Install-ADServiceAccount gmsa-sql; then reconfigure the
  # service to run as LAB\gmsa-sql$ with a blank password. Delete/retire svc_sql.

Use the switch -ApplyServiceAccountFix to set AES-only on the LEGACY svc_sql
account as an interim step (breaks RC4 roasting; test app compatibility!).
"@
if ($ApplyServiceAccountFix) {
    # 24 = AES128 (8) + AES256 (16) in msDS-SupportedEncryptionTypes
    Set-ADUser -Identity "svc_sql" -Replace @{"msDS-SupportedEncryptionTypes" = 24}
    Write-Host "svc_sql set to AES128+AES256 only (msDS-SupportedEncryptionTypes=24)."
    Write-Host "Also rotate its password NOW to 25+ random chars - the old one is cracked by definition of this lab."
}

Write-Host ""
Write-Host "=== 2. Tiered administration (structure) ==="
foreach ($tier in @("Tier0-Admins", "Tier1-Admins", "Tier2-Admins")) {
    if (-not (Get-ADGroup -Filter "Name -eq '$tier'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $tier -GroupScope Global -GroupCategory Security -Path "OU=Lab Admins,$DomainDN" `
            -Description "Tiered admin model - see hardening/gpo-checklist.md for logon restrictions per tier"
        Write-Host "Created group: $tier"
    }
}
Write-Host @"
ENFORCE WITH GPO (manual, checklist section 3):
  - 'Deny log on locally' + 'Deny log on through RDP' for Tier0-Admins on ALL
    workstations and member servers. DA material must never land on WS01 again.
  - Admin workstations (PAWs) for Tier 0. One tier never logs on to a lower tier.
"@

Write-Host ""
Write-Host "=== 3. LAPS ==="
Write-Host @"
Use Windows LAPS (built into modern Windows/Server, schema-extended):
  - Update-ADLAPSADSchema (once per forest)
  - Set a GPO: unique, rotating local Administrator password per machine,
    stored encrypted in AD, readable only by Tier2-Admins.
  This kills 'one local admin password works everywhere' lateral movement.
"@

Write-Host ""
Write-Host "=== 4. Signing: SMB required, LDAP signing + channel binding ==="
if ($ApplySigning) {
    $smb = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Set-ItemProperty -Path $smb -Name "RequireSecuritySignature" -Value 1
    Set-ItemProperty -Path $smb -Name "EnableSecuritySignature"  -Value 1
    Write-Host "SMB signing required on this host. (Deploy via GPO domain-wide.)"
    Write-Host "LDAP signing + EPA: set via GPO on DCs - 'Domain controller: LDAP server signing requirements = Require signing' and 'LDAP server channel binding token requirements = Always'. Registry mirrors: LdapEnforceChannelBinding=2 under HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2
} else {
    Write-Host "(Skipped - re-run with -ApplySigning after testing; LDAP signing breaks unsigned legacy clients.)"
}

Write-Host ""
Write-Host "=== 5. Protect privileged accounts from delegation ==="
Get-ADUser -Filter { AdminCount -eq 1 } -Properties AdminCount | ForEach-Object {
    Set-ADAccountControl -Identity $_ -AccountNotDelegated $true
    Write-Host "Marked 'sensitive, cannot be delegated': $($_.SamAccountName)"
}

Write-Host ""
Write-Host "=== 6. krbtgt DOUBLE-RESET RUNBOOK (NOT executed by this script) ==="
Write-Host @"
WHY TWICE: krbtgt retains current+previous hashes so tickets stay valid;
one reset leaves attacker-forged tickets valid against the previous hash.
PROCEDURE (from attacks/04-golden-ticket-concepts.md):
  1. Announce a maintenance window; verify replication health (repadmin /replsum).
  2. Reset krbtgt password #1 (strong random, via a DC you trust).
  3. WAIT: full replication convergence + max TGT lifetime (default 10h).
  4. Reset krbtgt password #2. Wait again before declaring eradication.
  5. Verify: PasswordLastSet updated twice; test normal logons; monitor 4768/4769.
SCHEDULE: repeat every 180 days even without an incident, and immediately
after any suspected DA-tier compromise. Check current age any time:
  Get-ADUser krbtgt -Properties PasswordLastSet
"@
Write-Host ""
Write-Host "Hardening pass complete. Re-run attacks/02 and attacks/03 - they should fail or alert immediately."
