# Detection — Pass-the-Hash & LSASS Access (T1550.002, T1021.002)

**Signals (strongest first):**
1. **Sysmon 10 (ProcessAccess)** targeting `lsass.exe` with suspicious GrantedAccess (`0x1010`, `0x1410`, `0x147a`) from a non-system process — someone is reading credential material.
2. **4624 LogonType 9** (NewCredentials) — the logon type `sekurlsa::pth` creates when it spawns a process with replaced credentials.
3. **4648** (logon with explicit credentials) to a network target, followed by **4672** (admin logon) **originating from a workstation** — tiering violation in telemetry form.
4. **5140/5145** access to `ADMIN$`/`C$` from an unusual source host.

## Splunk SPL

```spl
# Sysmon LSASS access (run on endpoint data)
index=sysmon EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010","0x1410","0x147a","0x1fffff")
| where NOT SourceImage IN ("C:\\Windows\\System32\\*.exe", "*\\MsMpEng.exe")
| table _time, ComputerName, SourceImage, User, GrantedAccess
```

```spl
index=wineventlog (EventCode=4624 Logon_Type=9) OR EventCode=4648 OR EventCode=4672
| transaction Account_Name, src_ip maxspan=30m
| search EventCode=4624 AND EventCode=4672
| table _time, Account_Name, src_ip, ComputerName, EventCode
```

## Elastic KQL

```
( event.code: "10" and winlog.event_data.TargetImage: *lsass.exe ) or
( event.code: "4624" and winlog.event_data.LogonType: "9" ) or
( event.code: "4648" )
```

Correlate per `host.name` + `winlog.event_data.TargetUserName` within 30 minutes for the full chain.

## Sigma-style notes

- **Logsources:** `product: windows, service: sysmon` (Event 10) + `service: security` (4624/4648/4672)
- **Detection:** Sysmon 10 + `TargetImage|endswith: '\lsass.exe'` + GrantedAccess in set; correlation rule joins 4624 Type 9 within 30m on the same host/account
- **Level:** high (LSASS alone), critical (LSASS → Type 9 → 4672 chain)
- **False positives:** some EDR/AV and backup agents legitimately open LSASS (allowlist by exact signed SourceImage + hash, never by folder), admin tools using explicit credentials for scheduled maintenance (4648 alone is only medium/low without the chain)

## Platform mitigations that change this detection's job

- **Credential Guard** (VBS-isolated LSASS) doesn't stop the 4624/4648 telemetry — it makes step 1 yield nothing useful, so any Sysmon-10 hit becomes *more* important, not less.
- **Windows Defender ASR rule** "Block credential stealing from the Windows local security authority subsystem" prevents many dump attempts outright — log its block events as detections too.

## Triage

Identify the source process for the LSASS access (malware? red-team tool? admin utility?), freeze the workstation (snapshot, don't wipe), enumerate every account whose session existed on that host (they are all suspect), and force resets in tier order — DA-tier first, with krbtgt evaluation if DA material was present.
