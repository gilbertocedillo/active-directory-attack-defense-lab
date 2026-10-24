# Interview Defense Guide — Active Directory Attack & Defense Lab

## Honest framing (your right to claim this)

You **designed and directed** this lab: the topology, the intentionally vulnerable settings, the attack order, the detection-first approach, and the hardening scope are your decisions. Implementation (scripts, queries, write-ups) was built with AI assistance and reviewed/validated by you — the same disclosure used across your portfolio.

**Say:** "I built an isolated AD lab to learn identity attacks *and* their detections. I can explain every Event ID I alert on and why each hardening step breaks a specific step of my own attack chain."
**Never say:** "I hand-wrote every script unaided," "I ran this in a production domain," or imply any tool was run anywhere but your own isolated VMs.

## 30-second pitch

> "Identity is where enterprise breaches are won or lost, so I built a small Active Directory lab — a Server 2022 DC, a Windows 11 workstation, and Kali on an isolated network. From a standard user I ran the classic chain: BloodHound enumeration, Kerberoasting a weak service account, then Pass-the-Hash using a Domain Admin session that had touched the workstation. For every step I wrote the detection first-class — Splunk and Elastic queries over 4769, Sysmon 10, 4624 Type 9, 4662 — and then I hardened the domain with gMSA, AES-only Kerberos, tiered admin, LAPS and signing, and re-ran my own attacks to prove they failed."

## Key decisions to defend

1. **Why identity first?** Most real intrusions don't "hack in" — they *log in*. AD is the credential and authorization store for the enterprise; whoever controls it controls everything joined to it. SOC work is AD-log work.
2. **Tiered administration is the control, not a slogan.** The lab's PtH works *because* a DA logged on to a workstation. Tiering (Tier 0 never touches Tier 2 machines, PAWs, JIT) removes the credential material instead of trying to protect it in place.
3. **gMSA vs "strong service passwords."** A 25-char password is a policy hope; a gMSA is a mechanism — 240-char, machine-managed, auto-rotated, can't be interactively used. Kerberoasting a gMSA ticket is computationally pointless. Choose mechanisms over hopes.
4. **Why is DCSync detection both easy and hard?** Easy: the rule (4662 + replication GUIDs + non-DC subject) is nearly false-positive-free in theory. Hard: 4662 volume, fragile field parsing, and legitimate sync tools (Entra Connect) mean you must baseline and test it — a rule nobody validated is a wish.
5. **Detection-first lab design.** The crack step of Kerberoasting is invisible; if your lab only teaches the attack, it teaches the wrong lesson. Every playbook here is paired with the telemetry it creates.

## Likely Q&A

**Q: How do you actually stop Kerberoasting?**
Remove the value: gMSA or 25+ char random service passwords (uncrackable in practice), AES-only encryption so no RC4 `0x17` tickets exist, minimize SPNs on user accounts, and alert on 4769+RC4 as a legacy-debt finder. You can't stop ticket *requests* — Kerberos working as designed — so you make the tickets worthless.

**Q: What stops Pass-the-Hash?**
Nothing "stops" NTLM hash replay by itself; you starve it: Credential Guard isolates LSASS so the hashes aren't extractable, tiering keeps DA hashes off endpoints, LAPS kills shared local-admin passwords, and SMB signing + disabling NTLM where feasible narrows replay. Detection (Sysmon 10 → Type 9 → 4672) covers the rest.

**Q: Isn't BloodHound an attacker tool?**
It's a *graph* tool — attackers use it to find paths, defenders use the same output as a work queue: every edge to Domain Admin is a ticket. Running it defensively on a schedule and trending "paths to DA" down is a mature identity-security practice.

**Q: Why does krbtgt need TWO resets?**
Because krbtgt retains the previous hash for ticket validity. One reset leaves forged tickets validating against the old hash; the second reset — after replication and the max TGT lifetime — actually evicts the attacker. And doing both back-to-back without waiting breaks domain authentication. (Full runbook: `attacks/04`, `hardening/Harden-AD.ps1`.)

**Q: What would break first if you deployed these detections in production?**
The BloodHound volume rule (needs baselining against IdP/sync noise) and 4662 field extraction after a SIEM add-on update. The 4769-RC4 and non-DC-4662 rules are the ones I'd ship first — lowest noise, highest fidelity.

**Q: Legal/ethical line for this kind of lab?**
Own VMs, isolated host-only network, no third-party systems, ever. The same techniques against a network you don't own are unauthorized access — the lab exists precisely so the skills are learned where they're legal.

## Pre-interview checklist
- [ ] Draw the topology + attack chain from memory in 2 minutes
- [ ] Recite the 5 anchor Event IDs cold: 4769 (roast), 4662 (DCSync), 4624 T9 + 4648 (PtH), Sysmon 10 (LSASS), 4661/4662 bursts (collection)
- [ ] Be able to explain one detection's false positives *and* its blind spot
- [ ] Re-run one attack + one detection in the lab the week of the interview so your answers are present-tense
