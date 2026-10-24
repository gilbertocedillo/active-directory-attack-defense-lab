# Detection — BloodHound / SharpHound Collection (T1087.002, T1069.002)

**Signal:** *Volume and breadth*, not a single event. One workstation account suddenly performs directory reads at a scale no human does: thousands of **4661** (handle to directory object) / **4662** (directory operation) events against a DC in minutes, LDAP queries touching many object classes, plus session/share enumeration against many hosts — often with a SharpHound execution artifact (Sysmon **1**) and dense LDAP/SMB connections (Sysmon **3**) on the collecting workstation.

## Splunk SPL

```spl
# Directory-read burst per subject (baseline-tune the threshold)
index=wineventlog (EventCode=4661 OR EventCode=4662) dest=DC01*
| bucket _time span=10m
| stats count AS dir_events, dc(Object_Name) AS distinct_objects BY _time, Subject_Account_Name, src_ip
| where dir_events > 500 AND distinct_objects > 200
| sort - dir_events
```

```spl
# Collector process on the endpoint
index=sysmon EventCode=1 (Image="*SharpHound*" OR CommandLine="*BloodHound*" OR CommandLine="*--CollectionMethods*")
| table _time, ComputerName, User, Image, CommandLine
```

## Elastic KQL

```
event.code: ("4661" or "4662")   /* aggregate in Kibana/ES|QL: count by winlog.event_data.SubjectUserName + source.ip per 10m, threshold-tuned */
```

```
winlog.event_data: *sharphound* or process.command_line: *CollectionMethods*
```

## Sigma-style notes

- **Logsources:** `service: security` (4661/4662 aggregation), `service: sysmon` (process/network)
- **Detection:** temporal aggregation — `count() by SubjectUserName > threshold in 10m` + optional process-name condition as a separate high rule
- **Level:** medium (volume-only), high (volume + collector process/known tooling)
- **False positives:** legitimate directory syncs (HR/identity systems), AD audit/migration tools, Entra Connect — allowlist by **service account + source host** pairs, and expect to re-tune after any IdP change. Interactive admin browsing never reaches these volumes, which is why the threshold approach is defensible.

## The defensive flip side (say this in interviews)

BloodHound is also a **defender's** tool: run collection on a schedule *yourself*, track "paths to Domain Admin" as a metric, and burn them down (remove the session, cut the group edge, fix the delegation). This detection then becomes your tripwire for anyone else doing the same collection outside that window — and the coverage story in `findings/` can show the lab's own path count going down after hardening.

## Triage

Which account/host collected, was it the scheduled defensive run, did collection precede 4769 roasting or 4648 lateral logons from the same source (the attack chain in this repo does exactly that — pivot on `src_ip` + account across `01`–`03`)?
