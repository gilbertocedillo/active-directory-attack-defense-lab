# Sample Findings Report — Full Attack Chain Exercise, lab.local

| | |
|---|---|
| **Environment** | Isolated AD lab (`lab.local`): DC01 (Server 2022), WS01 (Win 11), KALI — host-only network |
| **Exercise type** | Single-operator purple-team run: attacks executed, detections evaluated, hardening applied, attacks re-run |
| **Accounts in scope** | `j.rodriguez` (foothold), `svc_sql` (service), `a.cedillo-admin` (Domain Admin) |
| **Classification** | Sample/educational report — timeline times are illustrative of one lab run |

## Executive summary

Starting from a **standard user account with no privileges**, the exercise reached **Domain Admin in three steps**, each enabled by a known, fixable configuration weakness: (1) unrestricted directory enumeration revealed the path, (2) a Kerberoastable service account with a weak RC4 password yielded reusable credentials, and (3) a Domain Admin's earlier logon to a workstation left hash material that enabled Pass-the-Hash. All three steps were **detectable with the logging this lab deploys**; one detection (DCSync-class 4662 monitoring) was validated as a rule but not exercised by an actual DCSync in this run. After hardening (gMSA migration path, AES-only, tiering, Credential Guard guidance), re-runs of steps 2–3 failed.

## Timeline (illustrative, UTC-6)

| Time | Event | Evidence |
|---|---|---|
| 09:02 | SharpHound collection from WS01 as `j.rodriguez` | DC01: ~1,900× **4661/4662** in 6 min from one workstation account; WS01 Sysmon 1/3 |
| 09:11 | BloodHound analysis: shortest path to DA identified; `svc_sql` flagged Kerberoastable | BloodHound export (screenshots in exercise notes) |
| 09:18 | TGS requested for `MSSQLSvc/dc01.lab.local:1433` | DC01 **4769**, `TicketEncryptionType 0x17` (RC4) |
| 09:18–10:47 | Offline crack (hashcat 13100, rockyou) | Attacker-side only — **no domain telemetry exists for this step** |
| 10:47 | `svc_sql` password recovered (`LabSvc!2026` — short + pattern) | Proves weak-service-password risk quantitatively (89 min) |
| 11:05 | LSASS accessed on WS01; DA logon session material found | WS01 Sysmon **10** (lsass.exe, GrantedAccess 0x1010) |
| 11:09 | Pass-the-Hash as `a.cedillo-admin`; `\\DC01\C$` listed | DC01 **4624 Type 9**, **4648**, **4672**, 5140 |
| 11:15 | Exercise halted by design (DA-equivalent access demonstrated; no DCSync/Golden Ticket executed) | Scope note, see below |

## ATT&CK map

| Step | Technique | ID |
|---|---|---|
| Enumeration | Account Discovery: Domain Account; Permission Groups Discovery | T1087.002, T1069.002 |
| Kerberoasting | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 |
| LSASS access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Pass-the-Hash | Use Alternate Authentication Material: Pass the Hash | T1550.002 |
| Lateral access | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| (Discussed, not run) | DCSync; Golden Ticket | T1003.006, T1558.001 |

## Detections that fired

| Detection | Fired? | Quality notes |
|---|---|---|
| BloodHound burst (4661/4662 aggregation) | ✅ Yes | Alert at minute ~4 of collection with the lab threshold; threshold needs production baselining |
| Kerberoasting (4769 + `0x17`) | ✅ Yes, high fidelity | Single event was sufficient given sensitive SPN; RC4 made this unambiguous |
| LSASS access (Sysmon 10) | ✅ Yes | Cleanest endpoint signal of the run |
| PtH chain (4624 T9 + 4648 + 4672 from workstation) | ✅ Yes | Individually medium; as a 30-min correlation, high |
| DCSync (4662 replication GUIDs, non-DC) | ⚠️ Rule validated, attack not run | Baseline confirmed empty (single-DC lab); production fidelity unproven |

## Gaps found

1. **Detection ≠ prevention anywhere in the chain.** Every control that "worked" was a log. Nothing stopped the roast, the dump, or the replay in the baseline — the fixes are all in hardening, not detection.
2. **Crack time is invisible.** 89 minutes of attacker progress generated zero telemetry. Detection SLAs must be measured at the 4769, not at "account used maliciously."
3. **Single-DC lab flatters the DCSync rule.** No legitimate replication noise existed to tune against.
4. **No EDR in the lab.** Sysmon + Defender free tier only; LSASS protection (ASR/Credential Guard) was a hardening step, not a baseline control.

## Hardening applied & re-test results

| Fix (from `hardening/`) | Re-test result |
|---|---|
| `svc_sql` → AES-only (`msDS-SupportedEncryptionTypes=24`) + rotation; gMSA migration documented | Roast returns AES tickets only — no practical offline crack ✅ |
| Tiering GPO: Tier0 denied logon on WS01; DA sessions removed from workstation | PtH step 1 finds **no DA material** on WS01 ✅ |
| Credential Guard enabled on WS01 (supported hardware path) | LSASS dump yields no reusable domain credentials ✅ |
| SMB signing required; LDAP signing/channel binding enforced | Relay surface reduced; no lab breakage observed ✅ |
| krbtgt status checked (PasswordLastSet = forest creation) | **Open item:** double-reset runbook documented, execution scheduled as its own change |

## Recommendations (priority order)

1. Complete the krbtgt double reset and calendar 180-day rotations.
2. Eliminate standing Domain Admin membership (JIT elevation) — the chain's final step depended on it.
3. Migrate *every* SPN account to gMSA; add the 4769-RC4 rule to the production SIEM with a legacy-app exception register.
4. Promote the Sysmon-10 → 4624-T9 → 4672 correlation to a production critical alert.
5. Track BloodHound "paths to DA" monthly as a security metric.

*Analyst note: this report intentionally separates what was **executed**, what was **detected**, and what was only **discussed** (DCSync/Golden Ticket). Blending those categories is how lab reports become fiction.*
