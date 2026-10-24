# Attack 04 — Golden Ticket & DCSync: Concepts, Detection, and the krbtgt Question

**ATT&CK:** Persistence / Credential Access — Forge Kerberos Tickets: Golden Ticket (T1558.001); OS Credential Dumping: DCSync (T1003.006)
**Scope of this file: CONCEPTUAL.** This playbook explains the mechanics, the evidence, and the response — using the standard descriptions found in public training (SANS, Microsoft, SpecterOps). It deliberately does **not** provide a copy-paste weaponized walkthrough: the professional value of this phase is *detection and eradication*, and both DCSync and Golden Ticket only become possible **after** a domain is already fully compromised. If you can do these, the game you're studying is incident response, not initial access.

---

## DCSync — the concept

- AD replication is how DCs sync directory data. Accounts holding **Replicating Directory Changes / GetChangesAll** rights (by default: Domain Admins, and DC computer accounts) can *ask* a DC to replicate to them — including password hashes.
- An attacker with DA-equivalent rights can therefore impersonate a DC (`mimikatz lsadump::dcsync` / Impacket `secretsdump.py -just-dc`) and pull **every** hash in the domain, including **krbtgt**.
- **Why detection is tractable:** legitimate replication only ever comes from **DC computer accounts**. A **4662** event on a DC carrying the replication GUIDs (`1131f6ad-…` GetChanges, `1131f6aa-…` GetChangesAll) where the subject is **not** a DC computer account is one of the highest-fidelity alerts in all of AD security. See `detections/02-dcsync.md`.

## Golden Ticket — the concept

- The **krbtgt** account's hash signs every Ticket Granting Ticket (TGT) in the domain. Whoever holds it can **forge TGTs offline** for any user, any groups, any lifetime — and every DC will trust them, because the signature checks out.
- Forged tickets classically betray themselves by *anomalies*, not by failed signatures: TGT lifetimes longer than policy (default max 10h), tickets for accounts that don't exist or with impossible group sets, a TGT presented **without a preceding 4768** (the AS-REQ that should have issued it), and RC4-forged tickets in an AES domain.
- Persistence property that makes this a board-level problem: **changing every user password does nothing.** The trust anchor itself (krbtgt) is compromised.

## Why the krbtgt DOUBLE reset matters

Resetting krbtgt once is not enough, and this is the detail interviewers probe:

1. krbtgt keeps the **current and previous** password hashes so in-flight tickets stay valid during rotation — by design.
2. An attacker holding the *current* hash therefore survives your first reset (their forged tickets validate against the now-*previous* hash).
3. You must reset krbtgt **twice**, waiting between resets for (a) full AD replication to converge and (b) the maximum TGT lifetime to pass (default 10h) — otherwise you invalidate every legitimate ticket in the enterprise at once and cause an outage.
4. Do it too fast and you break authentication domain-wide; skip the second reset and the attacker stays. That tension is why krbtgt rotation is a **planned IR procedure with a schedule** (`hardening/Harden-AD.ps1` documents it), not an impulse click.
5. Bonus rule: rotate krbtgt on a **schedule** (e.g., every 180 days) even without an incident, so a silently-stolen hash has a bounded useful life.

## Evidence summary (what you hunt)

| Signal | Source | Meaning |
|---|---|---|
| 4662 + replication GUIDs, subject ≠ DC computer account | DC Security | DCSync in progress or attempted |
| TGT used with **no matching 4768** for that user/time | DC Security (4768 vs 4769/4624 correlation) | Possible forged ticket |
| TGT lifetime > domain policy, or `TicketEncryptionType 0x17` in an AES-only domain | 4768/4769 fields | Forgery artifact / downgrade |
| krbtgt password last set = forest-creation date | `Get-ADUser krbtgt -Properties PasswordLastSet` | Rotation debt — finding in itself |

## Lab exercise (detection-side, safe)

1. On DC01, run the DCSync *detection query* in `detections/02-dcsync.md` and confirm it returns **zero** true replication events from non-DC subjects in your clean baseline (DC-to-DC only — and this lab has one DC, so it should be empty).
2. Check and record krbtgt's `PasswordLastSet`. Write the double-reset runbook steps into your findings report with timings — as an IR plan, not an execution.
3. In BloodHound, re-check the `GetChanges*` edges from Attack 01: list exactly which principals in *your* lab could DCSync, and confirm the hardening plan reduces that list to DC computer accounts only.

## Takeaway for the findings report

Golden Ticket/DCSync are **post-compromise persistence and exfiltration of the identity system itself**. The professional deliverable is: fidelity detection (4662 rule), a tested krbtgt double-reset runbook, and tiering that keeps DA hashes out of attacker reach in the first place.
