# Attack 01 — Enumeration with BloodHound / SharpHound

**ATT&CK:** Discovery — Account Discovery: Domain Account (T1087.002), Permission Groups Discovery: Domain Groups (T1069.002)
**Goal:** As the low-privilege user `j.rodriguez`, map the whole domain: who is a Domain Admin, which accounts are Kerberoastable, and the shortest attack path to Domain Admin — *before touching anything*.
**Prereqs:** Lab built (`lab-setup/`), snapshot `clean-baseline` taken, auditing enabled. **Lab network only.**

---

## Why this matters

Almost every real AD compromise starts here. BloodHound turns LDAP data into a graph of **attack paths** — edges like `MemberOf`, `HasSPN`, `CanPSRemote`, `GenericAll`. Defenders use the *same* graph to find and cut those paths before attackers do. Running it in the lab teaches both sides at once.

## Steps

### 1. Collect (run SharpHound from WS01 as `j.rodriguez`)

```powershell
# On WS01, standard user session — no admin rights needed. That is the point:
# by default ANY authenticated domain user can read most of the directory.
.\SharpHound.exe --CollectionMethods All --Domain lab.local --OutputDirectory C:\Lab\loot
# Produces a timestamped *_BloodHound.zip
```

Linux alternative from KALI (same LDAP queries, different collector):

```bash
bloodhound-python -d lab.local -u j.rodriguez -p 'LabUser!2026' -ns 192.168.56.10 -c All
```

### 2. Ingest + explore (BloodHound on KALI)

```bash
# Start Neo4j + BloodHound (distro packages or Docker), upload the .zip, then run:
```

Built-in / Cypher queries to run and screenshot for your report:

```cypher
// Shortest path from owned/any user to Domain Admins
MATCH p=shortestPath((u:User {name:'J.RODRIGUEZ@LAB.LOCAL'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@LAB.LOCAL'})) RETURN p

// All Kerberoastable users (this should light up svc_sql)
MATCH (u:User {hasspn:true}) WHERE NOT u.name STARTS WITH 'KRBTGT' RETURN u.name, u.serviceprincipalnames

// Users with DCSync rights (GetChanges + GetChangesAll) — know this edge cold
MATCH (u)-[:GetChanges|GetChangesAll|GenericAll|AllExtendedRights]->(d:Domain) RETURN u.name

// Sessions: where have Domain Admins logged on? (drives the PtH playbook)
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf]->(g:Group {name:'DOMAIN ADMINS@LAB.LOCAL'}) RETURN c.name, u.name
```

## Expected result in this lab

- `svc_sql` appears as **Kerberoastable** (SPN `MSSQLSvc/dc01.lab.local:1433`)
- A path like `J.RODRIGUEZ → (session/credential reuse on WS01) → A.CEDILLO-ADMIN → DOMAIN ADMINS` becomes visible once the DA-logged-on-WS01 session is collected
- Take screenshots: the graph *is* your attack plan for playbooks 02–03

## Logs / Event IDs generated (feed `detections/04-bloodhound-collection.md`)

| Source | Event | Why |
|---|---|---|
| DC01 Security | **4661** (directory service object accessed) | SharpHound's mass LDAP object reads |
| DC01 Security | **4662** (operation on directory object, properties read) | Attribute enumeration incl. SPNs, group membership |
| DC01 Security | **4624 / 4776** | The collector's authenticated bind / credential validation |
| Network | LDAP (389/636) + SMB session enumeration bursts from one host | One workstation suddenly querying *everything* |
| Sysmon (WS01) | **1** (SharpHound process create), **3** (network connections to DC) | Collector execution on the endpoint |

> Honest limitation: BloodHound collection is *noisy by design* in volume but uses legitimate LDAP — detection is behavioral (volume + breadth from a non-admin workstation), never a single magic event. That's exactly what the detection file discusses.

## Cleanup
Note the collection timestamp for the findings report, keep the BloodHound export, snapshot `post-enumeration`. Do **not** delete the logs — they're your detection evidence.
