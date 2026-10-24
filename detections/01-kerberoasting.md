# Detection — Kerberoasting (T1558.003)

**Signal:** Kerberos **4769** (service ticket requested) where `TicketEncryptionType = 0x17` (RC4-HMAC). RC4 tickets are crackable offline; AES types are `0x11` (AES128) / `0x12` (AES256). Secondary signals: one account requesting tickets for **many distinct SPNs** in a short window, or *any* ticket request for a sensitive SPN (SQL, backup, admin tooling).

## Splunk SPL

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type="0x17"
| stats count, values(service_name) AS spns, dc(dest) AS dc BY src_ip, Account_Name
| where count >= 1
| sort - count
```

```spl
# Volume variant: one requester, many SPNs (roasting sweep)
index=wineventlog EventCode=4769
| bucket _time span=10m
| stats dc(service_name) AS distinct_spns, values(service_name) AS spns BY _time, Account_Name, src_ip
| where distinct_spns >= 5
```

## Elastic KQL

```
event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17"
```

Aggregation (ES|QL / Kibana lens): group `4769` by `winlog.event_data.TargetUserName` over 10m, `cardinality(winlog.event_data.ServiceName) >= 5` → sweep behavior.

## Sigma-style notes

- **Logsource:** `product: windows, service: security`
- **Detection:** `EventID: 4769` + `TicketEncryptionType: '0x17'` (+ optional count aggregation by `TargetUserName`/`IpAddress`, timeframe 10m, threshold ≥5 distinct `ServiceName`)
- **Level:** high for RC4-to-sensitive-SPN; medium for volume-only
- **False positives:** legacy apps genuinely requiring RC4 (document each — and treat each as a hardening ticket), some NAS/old Java Kerberos clients

## Triage

1. Which SPN(s)? Is the account supposed to run a service anyone requests interactively?
2. Source host + user: normal for that workstation? Correlate with 4661/4662 burst (enumeration first?) and any follow-on **4648/4624** using the service account (the crack may already be done — cracking itself is invisible).
3. If the SPN account has a human-set password: **assume it is cracked** — rotate immediately (or migrate to gMSA), then hunt the account's authentications domain-wide for the last 14 days.
