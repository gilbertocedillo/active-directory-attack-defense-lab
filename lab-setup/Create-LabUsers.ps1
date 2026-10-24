<#
.SYNOPSIS
  Creates the lab.local population: OUs, users, groups, ONE Domain Admin,
  a Helpdesk group, and ONE intentionally Kerberoastable service account.

.DESCRIPTION
  LAB ONLY - run on DC01 as Domain Admin in the isolated lab.local forest.
  All passwords below are FAKE examples for a throwaway lab. Change them in
  your own build and record yours in a password manager, never in this repo.

  Test-user table (created by this script):
  +-------------------+---------------------------+------------------------------------------+
  | sAMAccountName    | Role                      | Notes                                    |
  +-------------------+---------------------------+------------------------------------------+
  | j.rodriguez       | Standard user (WS01 user) | Attacker foothold account for playbooks  |
  | m.chen            | Standard user             | Normal user, noise/realism               |
  | helpdesk.torres   | Helpdesk group member     | Can reset passwords (delegated)          |
  | a.cedillo-admin   | Domain Admin              | THE one DA. Standing membership is an    |
  |                   |                           | intentional weakness - see hardening.    |
  | svc_sql           | Service account, SPN set  | KERBEROASTABLE BY DESIGN: short password,|
  |                   | MSSQLSvc/dc01:1433        | RC4 allowed. Fix = gMSA + AES in hardening|
  +-------------------+---------------------------+------------------------------------------+
#>
[CmdletBinding()]
param(
    [string]$DomainDN = "DC=lab,DC=local"
)

Import-Module ActiveDirectory

# ---------- OUs ----------
$ous = @("Lab Users", "Lab Admins", "Service Accounts", "Workstations")
foreach ($ou in $ous) {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ou'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou -Path $DomainDN -ProtectedFromAccidentalDeletion $false
        Write-Host "Created OU: $ou"
    }
}
$usersOU  = "OU=Lab Users,$DomainDN"
$adminsOU = "OU=Lab Admins,$DomainDN"
$svcOU    = "OU=Service Accounts,$DomainDN"

function New-LabUser {
    param(
        [string]$Sam, [string]$Display, [string]$Path, [string]$FakePassword, [string]$Description
    )
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Write-Host "User exists, skipping: $Sam"; return
    }
    New-ADUser -SamAccountName $Sam -Name $Display -DisplayName $Display `
        -UserPrincipalName "$Sam@lab.local" -Path $Path -Description $Description `
        -AccountPassword (ConvertTo-SecureString $FakePassword -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true
    Write-Host "Created user: $Sam ($Description)"
}

# ---------- Standard users (FAKE passwords - CHANGE_ME in your build) ----------
New-LabUser -Sam "j.rodriguez"     -Display "J. Rodriguez"    -Path $usersOU -FakePassword "LabUser!2026"  -Description "Standard user - WS01 daily driver / attack foothold"
New-LabUser -Sam "m.chen"          -Display "M. Chen"         -Path $usersOU -FakePassword "LabUser!2026"  -Description "Standard user - realism/noise"
New-LabUser -Sam "helpdesk.torres" -Display "T. Torres (Helpdesk)" -Path $usersOU -FakePassword "Helpdesk!2026" -Description "Helpdesk - delegated password reset"

# ---------- The one Domain Admin ----------
New-LabUser -Sam "a.cedillo-admin" -Display "A. Cedillo (Admin)" -Path $adminsOU -FakePassword "LabAdmin!2026" -Description "Domain Admin - tiering violation by design in baseline"
Add-ADGroupMember -Identity "Domain Admins" -Members "a.cedillo-admin"

# ---------- Helpdesk group ----------
if (-not (Get-ADGroup -Filter "Name -eq 'Helpdesk'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name "Helpdesk" -GroupScope Global -GroupCategory Security -Path $usersOU `
        -Description "Delegated: reset passwords for Lab Users OU"
}
Add-ADGroupMember -Identity "Helpdesk" -Members "helpdesk.torres"

# ---------- Kerberoastable service account (INTENTIONAL - see INTENTIONALLY-VULNERABLE.md #1) ----------
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_sql'" -ErrorAction SilentlyContinue)) {
    New-ADUser -SamAccountName "svc_sql" -Name "svc_sql (SQL Service)" -DisplayName "svc_sql" `
        -UserPrincipalName "svc_sql@lab.local" -Path $svcOU `
        -Description "Service account with SPN - KERBEROASTABLE BY DESIGN (weak pw, RC4 allowed)" `
        -AccountPassword (ConvertTo-SecureString "LabSvc!2026" -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true
    # The SPN is what makes the account Kerberoastable: any authenticated user
    # can request a TGS for this service and crack it offline.
    Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add = "MSSQLSvc/dc01.lab.local:1433"}
    # NOTE: deliberately NOT setting AES-only here. msDS-SupportedEncryptionTypes
    # stays unset so RC4 (0x17) tickets are issued. hardening/Harden-AD.ps1 fixes this.
    Write-Host "Created svc_sql with SPN MSSQLSvc/dc01.lab.local:1433 (Kerberoastable by design)"
}

Write-Host ""
Write-Host "Lab population complete. Snapshot DC01 now (clean-baseline)."
Write-Host "Reminder: every password above is a fake lab value - change them in your build."
