# Firewall Threat Hunting Pack (CommonSecurityLog)

> **Vendor-agnostic** Microsoft Sentinel detections and hunts for `CommonSecurityLog` (Fortinet, Palo Alto Networks, Zscaler, Check Point, Cisco). Drop in, enable, tune.

[![Status: Production](https://img.shields.io/badge/status-production-brightgreen)]()
[![Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?logo=microsoft-azure)]()
[![Tables](https://img.shields.io/badge/table-CommonSecurityLog-blue)]()
[![Rules](https://img.shields.io/badge/analytic_rules-27-orange)]()
[![Hunts](https://img.shields.io/badge/hunts-38-orange)]()

Are Your Firewall Logs Too Noisy? Stop Attacks with Sentinel https://youtu.be/_q_tG7GscZA

## Table of Contents

- [What's in this folder](#whats-in-this-folder)
- [Capabilities](#capabilities)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Staged deployment (recommended)](#staged-deployment-recommended)
- [Template parameters](#template-parameters)
- [NetworkAllowlist (trusted IPs)](#networkallowlist-trusted-ips)
- [Analytic rules (27)](#analytic-rules-27)
- [Hunting queries (38)](#hunting-queries-38)
- [MITRE ATT&CK coverage](#mitre-attack-coverage)
- [Tuning tips](#tuning-tips)
- [Optional: automated watchlist sync](#optional-automated-watchlist-sync)
- [Working on this content](#working-on-this-content)
- [Uninstall](#uninstall)
- [License](#license)

---

## What's in this folder

```
V2_Watchlist/
├── README.MD                           ← This file
├── Analytic-Rules/
│   ├── azuredeploy.json                ← Single ARM template, deploys everything
│   ├── deploy-rules.ps1                ← Helper script (ARM or YAML mode)
│   ├── build-arm-template-v2.py        ← Regenerates azuredeploy.json from source
│   ├── build-readme-tables.py          ← Regenerates the tables below
│   ├── validate-rules.py               ← Schema validator
│   ├── lint-kql.py                     ← KQL linter
│   └── rules/                          ← 27 standalone .yaml rule files
├── Hunting-Queries/                    ← .kql hunting queries (source of truth)
│   ├── CSL-Firewall-HuntingQueries.kql
│   └── CSL-Fortigate-HuntingQueries.kql
└── Watchlists/                         ← Optional named-location → watchlist sync
    ├── azuredeploy-automation.bicep
    ├── README.md
    └── Sync-NamedLocationsToWatchlist.ps1
```

> The rule YAML files here are identical to the base `Firewall/Analytic-Rules/rules/`
> files. The difference between the two solutions is the **deployment**, not the
> detection logic — see [Capabilities](#capabilities). The allowlist filter is
> injected into the queries at template-generation time only, so these YAML
> files stay portable and deployable without the watchlist function existing.

## Capabilities

- **27 analytic rules** spanning Beaconing, Exfiltration, TI matching, Port-scan, Geo-anomaly, Lateral Movement, Vendor-specific (Fortinet UTM/IPS, Fortinet SSL-VPN brute force, Fortinet UTM malware, web filter, DNS anomaly, app-control risk, SSL-VPN auth anomaly, admin config change, tunnel pivot, traffic anomaly/DoS, DLP, logging-disabled, Palo Alto Threat / Zone), Protocol Anomaly, Sign-in / Security Alert correlation, and per-user anomalous activity.
- **38 hunting queries** (Q01-Q26 plus FQ01-FQ16): same coverage broadened to 7/30/90-day windows plus DoH egress, crypto-miner ports, Tor/I2P, large-transfer detection, first-seen inbound external IPs, and a FortiGate-specific pack covering log-coverage census, UTM enforcement, SSL-VPN, admin, DNS, DLP and app control.
- **NetworkAllowlist watchlist** (`IPOrRange`, CIDR-aware) wired through every query via the scalar function `ExcludeAllowlistedIPs_Firewall(ip:string) -> bool` — silence corporate egress, VPN, NAT, partner ranges without editing KQL.
- **Staged-deploy switch** (`enableAnalyticRules`) — deploy disabled, baseline the allowlist, then flip the switch.
- **Single nested deployment** (`scope=inner`) wraps all alertRules so deploys are atomic and idempotent.

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Onboarded onto a Log Analytics workspace |
| Data connector | A CEF/Syslog forwarder producing `CommonSecurityLog` (Fortinet, Palo Alto, Zscaler, Check Point, Cisco supported out of the box) |
| Optional tables | `ThreatIntelIndicators` (rules 3 and 12, hunts Q03 and Q15) - needs the Defender Threat Intelligence or Threat Intelligence Platforms connector. `SigninLogs` (rule 10, hunt Q13). `SecurityAlert` (rule 11, hunt Q14). `IdentityInfo` (rule 16, hunt Q20) - needs Sentinel UEBA. Every other rule and hunt needs only `CommonSecurityLog`. |
| Permissions | `Microsoft Sentinel Contributor` + `Log Analytics Contributor` on the target resource group |

## Quick start

```bash
az deployment group create \
  --resource-group <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WORKSPACE_NAME>
```

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName <RG> `
  -TemplateFile .\Analytic-Rules\azuredeploy.json `
  -workspace <WORKSPACE_NAME>
```

## Staged deployment (recommended)

```bash
# 1) Deploy the watchlist, function, hunts. Rules created DISABLED.
az deployment group create -g <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=false

# 2) Seed NetworkAllowlist in the portal (or pass watchlistRawContent CSV).
#    Wait 5–15 min for the watchlist to materialize.

# 3) Enable rules.
az deployment group create -g <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=true
```

## Template parameters

| Parameter | Default | Description |
|---|---|---|
| `workspace` | *required* | Log Analytics workspace name |
| `location` | `[resourceGroup().location]` | Deploy region |
| `enableAnalyticRules` | `true` | Set `false` for staged deploy (rules created disabled) |
| `watchlistAlias` | `NetworkAllowlist` | Watchlist alias (rarely changed) |
| `functionAlias` | `ExcludeAllowlistedIPs_Firewall` | Scalar-function name (avoid collisions across solutions) |
| `watchlistRawContent` | *(empty)* | Optional CSV body to seed the watchlist. **Empty by default — see the warning below.** |

## NetworkAllowlist (trusted IPs)

The template provisions:

- **Watchlist** `NetworkAllowlist` — schema `IPOrRange,Description,Owner,AddedDate`; CIDR supported. **Ships empty.** Seed it with your own trusted ranges during the baseline stage — see the warning below.
- **Function** `ExcludeAllowlistedIPs_Firewall(ip:string) -> bool` — scalar; **isfuzzy-safe** when the watchlist hasn't yet materialized (returns `false` so queries don't error on first deploy, and returns `false` for every address while the watchlist is empty, so nothing is excluded until you opt in).

> ### The watchlist ships empty on purpose
>
> The original template seeded `NetworkAllowlist` with the RFC1918 private
> ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Every rule in
> this solution filters on `SourceIP` as well as `DestinationIP`, so with
> those ranges in the allowlist, **every rule that examines internal source
> traffic was suppressed** — which is most of them. Beaconing, exfiltration
> volume, port scan, lateral movement, VPN brute force and per-user activity
> all source from an internal address by definition, so with the old default
> they could not fire at all.
>
> The allowlist is for trusted **external** ranges — corporate egress NAT,
> partner networks, sanctioned proxy hops. Add them during the baseline
> stage of the staged deployment, not before.

Every analytic rule and hunt that references `SourceIP` or `DestinationIP` is filtered via this function (using `column_ifexists` so it works across vendors that may not populate every column). To customize:

```kql
// CSV row:
IPOrRange,Description,Owner,AddedDate
203.0.113.0/24,Office egress NAT,NetOps,2026-05-01
198.51.100.42,Partner SFTP,Vendor,2026-05-01
```

…and update the watchlist in Sentinel → Configuration → Watchlists. Function-side cache propagation is typically <15 minutes.

## Analytic rules (27)

| # | Rule | Severity | Tactics | ATT&CK |
|---|------|----------|---------|--------|
| 1 | Firewall Beaconing Detection - Regular Outbound Connections | High | Command and Control | T1071, T1571 |
| 2 | Firewall Anomalous Outbound Data Volume - Exfiltration Risk | High | Exfiltration | T1048 |
| 3 | Firewall Traffic to Threat Intelligence Flagged IP | High | Command and Control, Initial Access | T1071, T1078 |
| 4 | Firewall Port Scan Detection - Vertical and Horizontal Sweeps | Medium | Discovery | T1046 |
| 5 | Firewall Allowed Traffic to High-Risk Country | Medium | Initial Access, Exfiltration | T1078 |
| 6 | Lateral Movement - Internal Host Port Sweep on Admin/Pivot Ports | High | Lateral Movement | T1021, T1570 |
| 7 | Fortinet FortiGate - UTM, IPS and Malware Events by Source | High | Initial Access, Execution | T1190, T1105 |
| 8 | Palo Alto Networks - Threat Log Events (Spyware, Wildfire, Vulnerability) | High | Initial Access, Command and Control | T1190, T1071 |
| 9 | Firewall New First-Seen External IP Contacted | Medium | Command and Control | T1071 |
| 10 | Correlation: Firewall Allowed Traffic + Azure AD Sign-In from Same IP | High | Initial Access, Defense Evasion | T1078 |
| 11 | Correlation: Firewall Traffic + Active Security Alert - Shared IOC IP | High | Initial Access, Command and Control | T1078, T1071 |
| 12 | Correlation: Firewall Traffic Matching Threat Intelligence Domain / URL | High | Command and Control | T1071 |
| 13 | Palo Alto Networks - High-Volume Inter-Zone Policy Denies | Medium | Defense Evasion, Discovery | T1562, T1046 |
| 14 | Fortinet FortiGate - Authentication Brute Force and Credential Stuffing | High | Credential Access | T1110, T1110.003 |
| 15 | Protocol Anomaly - HTTP or HTTPS on Non-Standard Ports | High | Command and Control | T1571 |
| 16 | Correlation: Firewall Traffic from High-Risk Identity (IdentityInfo) | High | Initial Access, Defense Evasion | T1078 |
| 17 | Anomalous User Firewall Activity - High Request Count or Data Volume | High | Initial Access, Exfiltration | T1078, T1048 |
| 18 | Fortinet UTM Malware and IPS Detection Events | High | Command and Control, Execution | T1105, T1204.002 |
| 19 | Fortinet Web Filter Blocked Web Access | Medium | Initial Access, Command and Control | T1566.002, T1071.001 |
| 20 | Fortinet DNS Anomaly - Tunnelling, High Volume and NXDOMAIN Flooding | Medium | Command and Control, Defense Evasion | T1071.004, T1562.001 |
| 21 | Fortinet Application Control Block of High Risk Application | Medium | Exfiltration, Command and Control | T1048, T1090 |
| 22 | Fortinet SSL-VPN Successful Logon Anomaly | Medium | Initial Access, Persistence | T1078, T1078.002 |
| 23 | Fortinet Administrative and Configuration Change | High | Persistence, Privilege Escalation, Initial Access | T1098, T1078 |
| 24 | Fortinet VPN Tunnel Traffic Pivoting to Internal Destinations | High | Initial Access, Exfiltration | T1020, T1133 |
| 25 | Fortinet Traffic, IPS and Botnet Anomaly Events | Medium | Impact | T1498, T1499 |
| 26 | Fortinet DLP Sensitive Data Pattern Match | High | Exfiltration | T1041 |
| 27 | Fortinet Logging or Security Control Disabled | High | Defense Evasion | T1562.001, T1562.008 |

## Hunting queries (38)

| ID | Name | Tactics | ATT&CK |
|----|------|---------|--------|
| Q01 | Beaconing Detection - All Vendors | Command and Control | T1071, T1571 |
| Q02 | Data Exfiltration - Anomalous Outbound Volume | Exfiltration | T1048 |
| Q03 | Threat Intelligence IP Correlation | Command and Control, Initial Access | T1071 |
| Q04 | Port Scanning - Single Source to Many Destinations | Discovery | T1046 |
| Q05 | High-Risk Country Inbound and Outbound Traffic | Initial Access, Exfiltration | T1078 |
| Q06 | Lateral Movement - Internal Port Sweep | Lateral Movement | T1021 |
| Q07 | Fortinet - IPS and Application Control Blocks | Initial Access, Execution | T1190, T1059 |
| Q08 | Palo Alto - Threat Logs Breakdown | Execution | T1203 |
| Q12 | New and First-Seen External IP Allowed Through Firewall | Command and Control | T1071 |
| Q13 | Firewall Allow plus Azure AD Sign-In Correlation | Initial Access | T1078 |
| Q14 | CommonSecurityLog plus SecurityAlert IOC Correlation | Command and Control | T1071 |
| Q15 | CommonSecurityLog plus ThreatIntelligence Domain Match | Command and Control | T1071 |
| Q16 | Palo Alto - Zone Transfer Violations and Policy Denies | Initial Access | T1190 |
| Q17 | Fortinet - Repeated Auth Failures SSL-VPN and Admin | Credential Access | T1110 |
| Q19 | Protocol Anomaly - HTTP and HTTPS on Non-Standard Ports | Command and Control | T1571 |
| Q20 | Firewall plus IdentityInfo Risky User Correlation | Initial Access, Exfiltration | T1078 |
| FQ01 | FortiGate Log Coverage Census | - | - |
| FQ02 | FortiGate UTM and IPS Signature Leaderboard | Initial Access, Execution | T1190, T1105 |
| FQ03 | FortiGate UTM Detected But Not Enforced | Defense Evasion | T1562.001 |
| FQ04 | FortiGate SSL-VPN and Admin Successful Logons | Initial Access, Defense Evasion | T1078, T1078.002 |
| FQ05 | FortiGate SSL-VPN Tunnel Sessions | Initial Access, Exfiltration | T1078, T1048 |
| FQ06 | FortiGate Administrative Activity | Persistence, Initial Access | T1098, T1078 |
| FQ07 | FortiGate Web Filter Category Breakdown | Initial Access, Command and Control | T1566.002, T1071.001 |
| FQ08 | FortiGate DNS Telemetry and Tunneling Indicators | Command and Control | T1071.004 |
| FQ09 | FortiGate Policy Hit Analysis | Defense Evasion | T1562 |
| FQ10 | FortiGate Traffic Anomaly and Denial of Service Events | Impact | T1498, T1499 |
| FQ11 | FortiGate DLP Sensitive Data Matches | Exfiltration | T1041 |
| FQ12 | FortiGate Application Control - Risk Categories | Exfiltration, Command and Control | T1048, T1090 |
| FQ13 | FortiGate Internal to Internal Traffic (Zone Pivoting) | Lateral Movement | T1021, T1570 |
| FQ14 | FortiGate FortiClient Endpoint Telemetry | Discovery | T1082 |
| FQ15 | FortiGate External Inbound Session Exposure | Initial Access | T1190 |
| FQ16 | FortiGate SSL-VPN Auth Failures with Username Recovery | Credential Access, Initial Access | T1110, T1078 |
| Q21 | DNS-over-HTTPS Egress to Non-Standard Resolvers | Command and Control | n/a |
| Q22 | Egress on Crypto-Miner / Stratum Ports | Impact | n/a |
| Q23 | Inbound SSH/RDP Brute Force - Dispersed Targets | Credential Access | n/a |
| Q24 | Large Single-Session Outbound Transfer (>500MB) | Exfiltration | n/a |
| Q25 | Tor/I2P/Anonymizer Egress | Command and Control | n/a |
| Q26 | First-Seen Inbound Allowed from External IP (30d) | Initial Access | n/a |

## MITRE ATT&CK coverage

| Tactic | Rules | Hunts |
|--------|-------|-------|
| - | — | FQ01 |
| Command and Control | 1, 3, 8, 9, 11, 12, 15, 18, 19, 20, 21 | Q01, Q03, Q12, Q14, Q15, Q19, FQ07, FQ08, FQ12, Q21, Q25 |
| Credential Access | 14 | Q17, FQ16, Q23 |
| Defense Evasion | 10, 13, 16, 20, 27 | FQ03, FQ04, FQ09 |
| Discovery | 4, 13 | Q04, FQ14 |
| Execution | 7, 18 | Q07, Q08, FQ02 |
| Exfiltration | 2, 5, 17, 21, 24, 26 | Q02, Q05, Q20, FQ05, FQ11, FQ12, Q24 |
| Impact | 25 | FQ10, Q22 |
| Initial Access | 3, 5, 7, 8, 10, 11, 16, 17, 19, 22, 23, 24 | Q03, Q05, Q07, Q13, Q16, Q20, FQ02, FQ04, FQ05, FQ06, FQ07, FQ15, FQ16, Q26 |
| Lateral Movement | 6 | Q06, FQ13 |
| Persistence | 22, 23 | FQ06 |
| Privilege Escalation | 23 | — |

## Tuning tips

### Start here

1. **Run FQ01 before you trust any silence.** It is a log-coverage census: it shows which FortiGate log categories are actually arriving. A gateway forwarding only `traffic` logs returns nothing for every UTM, VPN, admin, DNS and DLP rule and hunt, and that silence is indistinguishable from a clean perimeter. Everything FortiGate-specific below depends on a log type being present.
2. **Deploy with `enableAnalyticRules=false` first.** The rules are created disabled, so you can baseline against live traffic before they start paging anyone.
3. **Seed `NetworkAllowlist` with external trusted ranges only** - corporate egress NAT, partner networks, sanctioned proxy hops. Do not add private space; see the warning above.

### Rule-level

4. **Beaconing (Rule 1 / Q01)** - Baseline is interval-regularity. If your DNS resolvers or NTP servers light it up, add their IPs to `NetworkAllowlist`.
5. **Data Volume (Rule 2 / Q02 / Q24)** - Backup egress and cloud-sync clients are recurring false positives. Allowlist the SaaS egress edge or backup target, not the corporate egress NAT.
6. **High-Risk Country (Rule 5 / Q05)** - The country list lives inline in the KQL as ISO 3166-1 alpha-2 codes. Edit and re-deploy to match your travel-risk policy.
7. **FortiGate UTM (Rule 7) / Palo Alto Threat (Rule 8)** - Read the `Enforcement` column. `Detected but NOT blocked` means the control exists and did not enforce; that is the finding, and it is a configuration issue rather than an attack.
8. **Authentication brute force (Rule 14 / Q17)** - `SprayPattern` marks credential stuffing across several account names, which is a different response from a single account being brute forced. A successful login from the same source IP is the escalation signal.
9. **DoH / Tor / Miner (Q21, Q22, Q25)** - These are *hunts*, not alerts. Promote to a rule once you've baselined.

### The `NetworkAllowlist` filter applies to both ends

The filter is injected as `not(ExcludeAllowlistedIPs_Firewall(SourceIP))` **and** the same for `DestinationIP`. Anything you allowlist is excluded from the analysis entirely - in both directions. This is deliberate for the external ranges it is meant for, but it means an allowlisted **source** also hides that source's outbound activity, and an allowlisted **destination** hides traffic to it. Keep the list as narrow as you can get away with.

## Optional: automated watchlist sync

`Watchlists/` contains a Bicep + PowerShell pair that creates an Azure Automation Account + Runbook that pulls Entra Named Locations on a schedule and pushes them to `NetworkAllowlist`. See [Watchlists/README.md](./Watchlists/README.md) for SP-auth deploy.

---

## Working on this content

The ARM template is **generated** from the rule YAML files and the hunting query files, so it cannot drift from them. Edit the sources, then regenerate:

```powershell
cd "V2_Watchlist\Analytic-Rules"

py -3 validate-rules.py rules      # schema contract
py -3 lint-kql.py ..               # KQL defect classes
py -3 build-arm-template-v2.py     # regenerate azuredeploy.json
py -3 build-readme-tables.py       # regenerate the tables in this README
```

`build-readme-tables.py` derives the rule table, the hunt table and the
ATT&CK coverage table from the rule YAML files and the generated ARM
template, so the documentation cannot drift from what is shipped.

`build-arm-template-v2.py` is the V2-specific generator. It differs from the base `build-arm-template.py` in that it:

- preserves the `NetworkAllowlist` watchlist resource, the
  `ExcludeAllowlistedIPs_Firewall` function, the `enableAnalyticRules`
  switch and the nested `scope=inner` deployment
- injects the allowlist filter into every rule query and every hunt query
- sets `enabled: [parameters('enableAnalyticRules')]` on every rule
- preserves the V2-only hunts that exist only in the template

The template was previously hand-maintained and had drifted badly — its
nested deployment still carried the original rule definitions, with the
type-mismatch bugs and the empty entity mappings, while the `.yaml` files
beside it had been corrected. That is now generated, so the two agree.

---

## Uninstall

```bash
az deployment group create -g <RG> \
  --template-file ./Analytic-Rules/azuredeploy.json \
  --parameters workspace=<WS> enableAnalyticRules=false
# then delete the rules in Sentinel → Analytics, and remove the watchlist / function via portal
```

## License

MIT — see top-level `LICENSE`. Detection content is provided as-is. Test in a non-production workspace before enabling broadly.
