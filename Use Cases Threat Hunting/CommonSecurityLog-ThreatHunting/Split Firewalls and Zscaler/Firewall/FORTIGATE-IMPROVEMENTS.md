# FortiGate-focused improvements to the CommonSecurityLog content

**Scope:** `Split Firewalls and Zscaler/Firewall/` — the 26 analytic rules
(plus the 27th rule that ships only in the watchlist variant), the
cross-vendor hunting queries, plus a new FortiGate-specific hunting pack.

**Date:** 2026-10-20

**Validator:** `Analytic-Rules/validate-rules.py` — run it before every deploy.
It checks the Sentinel rule schema contract, the entity identifier vocabulary,
MITRE ATT&CK vocabulary, schedule consistency, and entity/customDetail columns
against the query that actually produces them. It exits non-zero on error.

```powershell
cd "Split Firewalls and Zscaler\Firewall\Analytic-Rules"
py -3 validate-rules.py
```

Current state: **26 files, 0 errors, 0 warnings** (27 in the watchlist variant).

---

## 1. Findings that made rules silently inoperative

These are not tuning issues. Each one means the rule could not work as written.

| # | Rule | Defect | Effect |
|---|---|---|---|
| 1 | 06, 19 (and Q06, Q19) | `DestinationPort` compared against **integer** literals | `DestinationPort` is a **string** column in `CommonSecurityLog`. The comparison never matched, so lateral-movement and non-standard-port detection could not fire at all. |
| 2 | 13, Q13 | `ResultType == 0` (integer) | `ResultType` is a **string** in `SigninLogs`. The predicate was never true, the join was always empty, and the rule never fired. |
| 3 | 20, Q20 | Joined firewall `SourceUserName` directly to `AccountUPN` | FortiGate writes the user as `DOMAIN\user` or `user@domain`, never as a bare UPN. The join never matched. Now compares the **local part** of the account name on both sides. |
| 4 | 17, Q17 | `DeviceAction has_any ("failed","denied","reject","failure")` | FortiGate uses those verbs for **ordinary policy denies**. Every UTM block and every policy deny in the estate was counted as an authentication failure. Now requires an *authentication event* first, then a failure. |
| 5 | 05, Q05 | `geo_info_from_ip_address(...).country` matched against `"China"`, `"Russia"`, `"North Korea"` | The geolocation provider returns names such as `Russian Federation` and `Korea, Democratic People's Republic of`. Now uses **ISO 3166-1 alpha-2** (`country_2`). |
| 6 | 15, Q15 | `coalesce(DestinationHostName, RequestURL)` joined against a bare domain | `RequestURL` is a **full URL**, and `coalesce` returns the first non-null, not the first non-empty. Now extracts the hostname from the URL and lower-cases both sides. |
| 7 | 03, Q03 | TI IP joined on raw `ObservableValue` | Capitalisation differences between the TI feed and the firewall log silently dropped matches. Both sides are now lower-cased. |
| 8 | 19, Q19 | `Protocol in ("HTTP","http")` | `Protocol` in `CommonSecurityLog` is the **transport protocol** (TCP/UDP/ICMP). It is never HTTP, so those branches were dead code. Removed. |
| 9 | 07, 08, 16, 19 | `entityMappings: []` | The rule could never populate the investigation graph, and incident grouping had nothing to group on. |

## 2. The permitted-traffic filter (systemic)

Every rule that analyses "allowed" traffic used a **deny-list**:

```kusto
| where DeviceAction !in ("deny", "block", "drop", "BLOCK", "DROP", "Reset-Both")
```

This is wrong for FortiGate specifically. FortiGate reports **`act=blocked`**
when a UTM control enforces, and `act=accept` when it only detects. A
deny-list that omits `blocked` therefore counts every UTM-blocked session as
*permitted* traffic — inflating beacon scores, exfiltration volume, first-seen
IP counts and TI hit counts with traffic the gateway already stopped.

Replaced with a positive allow-list across every affected rule and the hunting file:

```kusto
| where tolower(DeviceAction) in ("accept", "allowed", "allow")
```

The same filter was **missing entirely** from Q14 and Q15, which matched
blocked traffic as well as permitted traffic.

## 3. Rules re-firing on every evaluation (systemic)

Every rule had `queryFrequency: 1h` with `queryPeriod: 1d` and an in-query
`ago(1d)`. The rule therefore re-processed the same 24 hours of traffic every
hour and re-alerted on the same events. Two rules were worse:

- **12 (new first-seen IP)** compared a 24 h recent window against a 7 d
  baseline on a 6 h schedule, so a genuinely new IP re-alerted for a full day.
- **03 and 15** used `ago(30d)` for the TI reference and `ago(1d)` for traffic
  on a 15-minute schedule.

The schedule model is now explicit and consistent: **`queryPeriod` equals
`queryFrequency`, and the in-query `ago()` equals the same window.** Where a
rule genuinely needs a long reference window (the TI feed, the UEBA identity
table, the historical-IP baseline) that window is a `let` constant inside the
query and is deliberately separate from the detection window.

## 4. Entity mappings

All four empty `entityMappings` were populated. Beyond that, several rules
pointed their entity mapping at a `make_set()` column:

```yaml
- entityType: IP
  fieldMappings:
    - identifier: Address
      columnName: SourceIPs     # <- make_set(), an array
```

Sentinel **cannot map an array to an entity** — the mapping silently never
resolves, so the alert still had no usable entity. Affected rules now project a
scalar representative column (`RepresentativeSourceIP = any(SourceIP)`) and
map that. The validator now detects this class of defect automatically by
checking whether a mapped column is produced by `make_set()` / `make_list()`.

## 5. FortiGate-specific rewrites

### 07 — Fortinet IPS → FortiGate UTM (rewritten)

Was: a generic `DeviceEventClassID has_any ("IPS", ...)` filter grouped by
activity, with no signature extraction, no enforcement signal and no entities.

Now:

- Matches the FortiGate log **category** (`utm`, `antivirus`, `webfilter`,
  `app-ctrl`, `ssl`) and **subtype** (`ips`, `ips-packet`, `av`, `antibot`,
  `file-block`, `appctrl`, `webfilter`, `fct-utm`, `ips-anomaly`,
  `av-anomaly`) — testing both fields, because which one is populated depends
  on the ingestion path.
- Extracts the **IPS signature name** from `DeviceCustomString1`, falling back
  to the `catdesc` key in `AdditionalExtensions`, falling back to the subtype.
- Reports the **enforcement split**: `Blocked` / `Detected but NOT blocked` /
  `Mixed`. A control that detected and did not enforce is the finding.
- Flags `BroadExploitation` when one source triggers several distinct
  signatures in the window.

### 17 — Fortinet VPN brute force → FortiGate auth brute force (rewritten)

Was: matched any deny in the log (finding 4 above) and grouped by
`DeviceEventClassID`, which is the log *category* and is therefore the same
value for every event — so the grouping was effectively meaningless.

Now requires an authentication event (FortiGate event id, recognised subtype,
or an `event`-category log carrying a user identity) **and** that it failed,
and groups by source address. Adds `SprayPattern` for credential stuffing
across several account names, and maps both the source IP and the attempted
account as entities.

> The FortiOS event ids in both rules are documented values, but they are not
> guaranteed identical across FortiOS releases. Confirm them against your
> estate — they are the one thing in this pack that must be checked per
> environment.

## 6. Detection quality improvements

| Rule | Change |
|---|---|
| 01 Beaconing | Requires an internal source; excludes CGNAT, link-local and multicast destinations; adds `ActiveMinutes` as a regularity signal; 6 h window on a 6 h schedule. |
| 02 Exfiltration | 500 MB flat threshold replaced with **volume AND** (fan-out to ≥10 destinations OR outbound/inbound byte ratio ≥5). Raw volume alone cannot distinguish exfiltration from a backup job. |
| 04 Port scan | Adds `AcceptedAttempts` / `DeniedAttempts` and a `ScanOutcome` column. A sweep the firewall **permitted** is the finding; a blocked sweep is the control working. |
| 13 AAD correlation | `ResultType` fix; both sides lower-cased before the join. |
| 14 IOC correlation | Alert-side IPs lower-cased before the join. |
| 15 TI domain | Hostname extraction, lower-casing, and a **permitted-traffic filter that was previously absent**. |
| 16 Zone denies | Entity mappings added; deny verbs matched case-insensitively so `Deny`, `Drop` and `reset-both` all count. |
| 05 High-risk country | ISO country codes; **both directions** evaluated, so inbound traffic from a high-risk geography is now surfaced. |

## 7. New content

### `Hunting-Queries/CSL-Fortigate-HuntingQueries.kql` — 15 new hunts

FortiGate-specific hunting that the cross-vendor pack did not cover:

| # | Hunt | ATT&CK |
|---|---|---|
| FQ01 | **Log coverage census** — which FortiGate log categories are actually arriving | — |
| FQ02 | UTM / IPS signature leaderboard with enforcement split | T1190, T1105 |
| FQ03 | **UTM detected but not enforced** — the control that did not fire | T1562.001 |
| FQ04 | SSL-VPN and admin **successful** logons, with source country | T1078, T1078.002 |
| FQ05 | SSL-VPN tunnel sessions, volume and duration | T1078, T1048 |
| FQ06 | Administrative activity audit trail | T1098, T1078 |
| FQ07 | Web filter category breakdown with block rate | T1566.002, T1071.001 |
| FQ08 | DNS telemetry, NXDOMAIN ratio, long-name tunneling indicators | T1071.004 |
| FQ09 | Policy hit analysis — including policies carrying **no** traffic | T1562 |
| FQ10 | Traffic anomaly, IPS anomaly and botnet events | T1498, T1499 |
| FQ11 | DLP sensitive-data matches with block rate | T1041 |
| FQ12 | Application control risk categories | T1048, T1090 |
| FQ13 | Internal-to-internal traffic (east-west across the firewall) | T1021, T1570 |
| FQ14 | FortiClient endpoint telemetry coverage | T1082 |
| FQ15 | External inbound exposure — internet-facing services | T1190 |

**Run FQ01 first.** A FortiGate that forwards only `traffic` logs returns
nothing for every UTM, VPN, admin, DNS and DLP query, and that silence looks
exactly like a clean perimeter.

### New analytic rules (38–47)

FortiGate-specific detection coverage that did not exist: UTM/malware,
web filter, DNS anomaly, application control risk, SSL-VPN authentication
anomaly, admin configuration change, VPN tunnel pivot, traffic anomaly / DoS,
DLP, and logging-disabled (control evasion).

---

## 8. Known items requiring environment confirmation

These are documented in the rules themselves rather than hidden:

1. **FortiOS event ids** in rules 07, 17 and 42 — documented values, but not
   identical across FortiOS releases.
2. **Where the IPS signature name lands** — `DeviceCustomString1` versus the
   `catdesc` key in `AdditionalExtensions`, depending on the connector. The
   rules try both; confirm which one your workspace populates.
3. **Which `DeviceAction` verbs your connector emits.** The allow-list
   assumes `accept` / `allowed` / `allow`. If your connector emits something
   else for permitted traffic, the rules will return nothing rather than
   everything, which is the safe failure direction — but you should verify.
4. **FortiGate `fct-*` log types** (FQ14) require FortiClient to be deployed
   and its logs forwarded.
5. **`geo_info_from_ip_address`** requires IP geolocation to be available in
   the workspace. It returns null for private addresses, which the queries
   handle.

## 9. Deployment

Nothing here has been deployed. To deploy, follow the existing pattern in
`Analytic-Rules/deploy-rules.ps1`:

```powershell
.\deploy-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod" `
    -DeploymentMode    YAML
```

`DeploymentMode YAML` preserves `customDetails`, `entityMappings` and the
incident grouping settings, all of which this pack relies on. The ARM
template mode does not preserve them.

**Deploy order:** the new rules (38–47) are independent and can go live
immediately. The reworked rules 01–20 have changed semantics — the permitted-
traffic filter and the schedule changes in particular alter what fires and how
often. Tune the thresholds against a fortnight of real traffic before you turn
on incident creation on the rules that were previously silent.

---

## 10. Zscaler rules — same defect classes, found by the new tooling

The validator and linter were run across the whole tree, not just the
FortiGate folder, and found three pre-existing upstream defects in the
Zscaler rule set. These are the same classes of bug as the FortiGate ones and
are fixed here:

| Rule | Defect | Effect |
|---|---|---|
| `09-CSL-Zscaler-MaliciousCategoryBlocks.yaml` | `entityMappings: []` | The rule could never populate the investigation graph. Now maps a source IP and the affected account. |
| `11-CSL-DNSTunneling-LongHostnames.yaml` | `DestinationPort == 53` (integer) | `DestinationPort` is a **string** column, so the port test could never match. The DNS-tunneling detection only worked on the protocol test. Now compared as a string. Same fix applied in `CSL-Zscaler-HuntingQueries.kql`. |
| `37-CSL-ZIA-ControlEvasion-VisibilityDegradation.yaml` | `customDetails` key `BaselineRequestsPerDay` is 22 characters | Sentinel limits custom detail keys to 20. Renamed to `BaselineRPDay`; the mapped query column is unchanged. |

---

## 11. New tooling

### `Analytic-Rules/validate-rules.py` — schema validator

Checks each rule against the Sentinel analytic-rule contract: required fields,
GUID ids, unique ids and names, severity, connectors, trigger operator,
schedule consistency, the entity identifier vocabulary, ATT&CK vocabulary,
`customDetails` limits, and incident grouping consistency.

The check worth calling out: **an `entityMapping` may not point at a
`make_set()` / `make_list()` column.** Those columns are dynamic arrays, and
Sentinel cannot map an array to an entity — the mapping silently never
resolves, so the alert still has no usable entity while looking correct.
Several rules in this pack had exactly that defect.

### `Analytic-Rules/lint-kql.py` — KQL linter

Catches the defect classes where a query parses fine and returns nothing:

- a string column compared against a numeric literal (`DestinationPort == 53`)
- `Protocol` used as if it carried an application protocol (it is TCP/UDP/ICMP)
- `coalesce()` where the first argument can be an empty string
- `.country` used in a list comparison instead of `.country_2`
- unbalanced brackets, unknown functions, empty allow-lists

It runs over both the YAML rules and the `.kql` hunting files.

```powershell
py -3 lint-kql.py "..\..\..\CommonSecurityLog-ThreatHunting"
```

### `Analytic-Rules/build-arm-template.py` — ARM template generator

The ARM template was hand-maintained and had already drifted from the YAML: it
carried different `customDetails` and the original queries, so deploying via
ARM would have shipped a different set of rules than the ones in the folder,
with no warning. It is now generated from the YAML and the `.kql` files, so
the two cannot disagree.

```powershell
py -3 build-arm-template.py
```

### `build-csl-bundle.py` — flat bundle generator

The flat, pre-split folder at the top of `CommonSecurityLog-ThreatHunting/`
was a hand-maintained duplicate of the split content and had the same defects.
It is now regenerated from the split sources.

---

## 12. Content drift that was removed

The repository shipped the same rule in **three** places — the flat folder,
the vendor split, and the V2_Watchlist variant. All three were byte-identical
copies, so every defect above was shipped three times, and the ARM template
was a fourth, slightly different copy.

All three are now synchronised, and the ARM templates in all three are
generated from the shared sources. Editing a rule in one place and
regenerating propagates it everywhere.

Current state:

| Location | Rules | Schema validator | KQL linter |
|---|---|---|---|
| `Firewall/Analytic-Rules/rules` | 26 | 0 errors, 0 warnings | 0 errors, 0 warnings |
| `Zscaler/Analytic-Rules/rules` | 21 | 0 errors, 33 warnings | 0 errors, 0 warnings |
| `Firewall/V2_Watchlist/Analytic-Rules/rules` | 27 | 0 errors, 0 warnings | 0 errors, 0 warnings |
| `Zscaler/V2_Watchlist/Analytic-Rules/rules` | 21 | 0 errors, 33 warnings | 0 errors, 0 warnings |
| Flat bundle | 47 | 0 errors, 33 warnings | 0 errors, 0 warnings |
| **Whole tree** | **142 files** | **0 errors** | **0 errors, 0 warnings** |

The whole-tree figure counts the rule YAML files, which exist in **five**
folders: the Firewall split (26), the Zscaler split (21), the Firewall
watchlist variant (27), the Zscaler watchlist variant (21), and the flat
pre-split bundle (47) — 26 + 21 + 27 + 21 + 47 = 142. The same logical rule is
therefore counted more than once across locations; 142 is a file count, not a
count of distinct detections.

The 33 schema warnings on the Zscaler rules are advisory only — they are the
`queryPeriod` being longer than `queryFrequency` on rules that aggregate over
a window, which is a deliberate design choice and not a defect. The rules
that were previously *inoperative* now report zero.

