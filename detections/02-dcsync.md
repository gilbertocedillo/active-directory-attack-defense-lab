# Detection — DCSync (T1003.006)

**Signal:** Security **4662** (operation performed on a directory object) on a DC, where the event's `Properties` contain the directory-replication GUIDs and the **subject account is NOT a domain controller computer account**:

- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes
- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes-All (includes secrets)
- `89e95b76-444d-4c62-991a-0facbeda640c` — DS-Replication-Get-Changes-In-Filtered-Set

Legitimate replication subjects look like `DC01$`, `DC02$` (computer accounts ending in `$`). Anything else — a user, a workstation account, a "backup admin" — is an incident until proven otherwise. This is among the highest-fidelity detections in AD security.

## Splunk SPL

```spl
index=wineventlog EventCode=4662
  (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
| where NOT like(Subject_Account_Name, "%$")
| table _time, Subject_Account_Name, Subject_Domain_Name, src_ip, Object_Name, Properties
```

(If your field extraction names differ, `search Properties="*1131f6a*" Subject_Account_Name!="*$"` is the portable core of the rule.)

## Elastic KQL

```
event.code: "4662" and winlog.event_data.Properties: (*1131f6aa* or *1131f6ad*) and NOT winlog.event_data.SubjectUserName: *$
```

## Sigma-style notes

- **Logsource:** `product: windows, service: security`
- **Detection:** `EventID: 4662` + `Properties|contains` any replication GUID + filter `SubjectUserName|endswith: '$'` excluded
- **Level:** critical
- **False positives:** Azure AD Connect / Entra Cloud Sync servers (their computer/service accounts legitimately replicate — allowlist **by exact account name + host**, documented, and re-review quarterly), some AD migration/backup tools during approved windows

## Why this detection is *hard* (be honest about it)

- 4662 is **extremely high volume** on a DC — you need SACLs/audit policy that actually emit the replication access events, plus centralized collection that doesn't drop them under load.
- Field parsing of `Properties` is brittle across Windows versions and SIEM add-on versions; test the rule with a *known* replication event after every collector change.
- In a single-DC lab (like this one) the baseline is trivially empty — in production you must baseline DC-to-DC traffic first or the rule is deployable but unproven.

## Triage

Treat as **domain compromise until cleared**: the subject account had DA-equivalent rights. Scope everything that account touched, force krbtgt **double reset** per the runbook (`attacks/04`), rotate DA credentials, and hunt for the initial access that granted replication rights (start with 4728/4732 group changes + 4662 history for that subject).
