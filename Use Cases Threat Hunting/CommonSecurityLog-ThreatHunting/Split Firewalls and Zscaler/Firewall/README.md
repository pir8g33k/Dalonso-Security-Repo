# Firewall — CommonSecurityLog Threat Hunting & Analytic Rules

Vendor content for **Microsoft Sentinel** `CommonSecurityLog` (CEF / Syslog).

| Folder | Contents |
|---|---|
| `Analytic-Rules/rules/` | **26** Scheduled analytic rule YAML files |
| `Analytic-Rules/azuredeploy.json` | ARM template - 26 alertRules + 32 savedSearches |
| `Analytic-Rules/deploy-rules.ps1` | Deployment script (ARM or YAML mode) |
| `Analytic-Rules/validate-rules.py` | Schema validator |
| `Analytic-Rules/lint-kql.py` | KQL linter |
| `Analytic-Rules/build-arm-template.py` | Regenerates the ARM template from the YAML + .kql sources |
| `Hunting-Queries/CSL-Firewall-HuntingQueries.kql` | 16 cross-vendor hunts (Q01–Q08, Q12–Q17, Q19–Q20) |
| `Hunting-Queries/CSL-Fortigate-HuntingQueries.kql` | **16 FortiGate-specific hunts (FQ01-FQ16)** |
| `V2_Watchlist/` | Watchlist-enhanced variant, with its own watchlist and ARM template |
| `FORTIGATE-IMPROVEMENTS.md` | **What changed, why, and what needs confirming per environment** |

Vendors covered: **Fortinet FortiGate**, **Palo Alto Networks**, **Zscaler ZIA/ZPA**.

---

## Working on this content

There is one source of truth per artefact. Edit the YAML or the `.kql`, then
regenerate the ARM template — never hand-edit `azuredeploy.json`.

```powershell
cd "Split Firewalls and Zscaler\Firewall\Analytic-Rules"

# 1. edit rules/*.yaml or ../Hunting-Queries/*.kql

# 2. validate
py -3 validate-rules.py rules
py -3 lint-kql.py ..

# 3. regenerate the ARM template from the sources
py -3 build-arm-template.py
```

`build-arm-template.py` exists because the template used to be hand-maintained
and had already drifted from the YAML — it carried different `customDetails`
and the original queries. Generating it removes that failure mode.

The flat, pre-split bundle at the top of `CommonSecurityLog-ThreatHunting/` is
regenerated the same way:

```powershell
py -3 ..\..\..\build-csl-bundle.py
```

---

## Validation

Both tools run offline and need only `pyyaml`.

**`validate-rules.py`** — the Sentinel rule schema contract:

- required fields, `kind: Scheduled`, GUID ids, unique ids and names
- severity, version, data connectors, trigger operator and threshold
- **schedule consistency** — `queryPeriod` must not be shorter than
  `queryFrequency`, and the in-query `ago()` window must not exceed
  `queryPeriod`
- **entity mapping vocabulary** — `entityType` and `identifier` must be from
  the Sentinel V3 list; at most 5 mappings, 3 identifiers each
- **entity columns must be scalar** — a `make_set()` column cannot be mapped
  to an entity, because the mapping silently never resolves
- **`customDetails`** — max 20 entries, keys max 20 characters, every value
  must be a column the query actually produces
- MITRE ATT&CK tactic and technique vocabulary
- `groupingConfiguration` consistency

**`lint-kql.py`** — the KQL itself:

- string columns compared against numeric literals (a type error that makes
  the comparison silently false)
- `Protocol` used as if it carried an application protocol
- `coalesce()` used where the first argument can be an empty string
- `.country` used in a list comparison
- unbalanced brackets, unknown functions, empty allow-lists

Current state across the whole `CommonSecurityLog-ThreatHunting` tree:

```
files: 142   errors: 0   warnings: 33
```

---

## The FortiGate pack

`Hunting-Queries/CSL-Fortigate-HuntingQueries.kql` - 16 hunts built around
FortiGate log types that the cross-vendor pack does not cover. **Run FQ01
first**: it is a coverage census showing which FortiGate log categories are
actually arriving. A gateway forwarding only `traffic` logs returns nothing
for every UTM, VPN, admin, DNS and DLP query, and that silence looks exactly
like a clean perimeter.

The 10 new analytic rules (38–47) add the matching detection coverage: UTM
and malware, web filter, DNS anomaly, application control risk, SSL-VPN
authentication anomaly, admin configuration change, VPN tunnel pivot, traffic
anomaly / DoS, DLP, and logging-disabled control evasion.

---

## Deployment

Nothing here has been deployed. To deploy:

```powershell
.\deploy-rules.ps1 `
    -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ResourceGroupName "rg-sentinel" `
    -WorkspaceName     "law-sentinel-prod" `
    -DeploymentMode    YAML
```

Use **YAML** mode. It deploys each file through the Sentinel REST API and
preserves `customDetails`, `entityMappings` and the incident grouping
settings, which this content depends on. ARM mode deploys the template, which
is generated from the same sources, so the two agree — but YAML mode is
easier to roll back per rule.

Before turning on incident creation for the rules that were previously
silent, tune their thresholds against a fortnight of real traffic. See
`FORTIGATE-IMPROVEMENTS.md` section 9.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| `CommonSecurityLog` ingestion | Not ingested by default. Enable the CEF/Syslog connector for each vendor. |
| `pyyaml` | `py -3 -m pip install pyyaml` — required by the validator and the ARM template generator. |
| `ThreatIntelIndicators` | Only for rules 03 and 15. Needs the Defender Threat Intelligence or Threat Intelligence Platforms connector. |
| `SigninLogs` | Only for rule 13. |
| `IdentityInfo` | Only for rule 20. Needs Sentinel UEBA. |
| `SecurityAlert` | Only for rule 14. |

The `requiredDataConnectors` block in each rule declares its own dependency.
