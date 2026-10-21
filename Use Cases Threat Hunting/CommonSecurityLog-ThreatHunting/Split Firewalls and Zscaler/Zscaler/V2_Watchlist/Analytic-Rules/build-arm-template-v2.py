#!/usr/bin/env python3
"""
Generate the V2_Watchlist ARM template for the Firewall solution.

The V2 solution is the watchlist-enhanced variant. It adds three things the
base template does not have:

  1. A `NetworkAllowlist` watchlist (CIDR-aware) of trusted IPs.
  2. A scalar function `ExcludeAllowlistedIPs_Firewall(ip:string) -> bool`
     that resolves the watchlist and tests an address against it.
  3. An `enableAnalyticRules` switch, so the rules can be deployed DISABLED,
     the allowlist baselined, and only then enabled - plus a nested
     deployment (scope=inner) wrapping the alertRules so the deploy is
     atomic and idempotent.

Every rule and hunt query in the template has the allowlist filter injected
at generation time:

    | where not(ExcludeAllowlistedIPs_Firewall(tostring(column_ifexists("SourceIP",""))))
    | where not(ExcludeAllowlistedIPs_Firewall(tostring(column_ifexists("DestinationIP",""))))

The standalone .yaml rule files stay clean, so they remain deployable on
their own without the watchlist function existing. The filter is a property
of the V2 *deployment*, not of the detection logic.

The template was previously hand-maintained and had drifted badly: its
nested deployment still carried the original rule definitions, with the
type-mismatch bugs and the empty entity mappings, while the .yaml files
beside it had been corrected. It is now generated from the same sources, so
the two cannot disagree.

Usage:
    py -3 build-arm-template-v2.py
"""
import os
import re
import json
import glob
import importlib.util

try:
    import yaml
except ImportError:
    print("pyyaml is required:  py -3 -m pip install pyyaml")
    raise SystemExit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.dirname(HERE)
RULES_DIR = os.path.join(HERE, "rules")
HUNT_DIR = os.path.join(V2, "Hunting-Queries")
OUT = os.path.join(HERE, "azuredeploy.json")

CREATED_BY = "CyberSOC Engineering"
CREATED_TIME = "2026-10-20T00:00:00Z"
HUNT_CATEGORY = "Hunting Queries"

ALLOWLIST_FILTER = [
    '| where not(ExcludeAllowlistedIPs_Firewall(tostring(column_ifexists("SourceIP",""))))',
    '| where not(ExcludeAllowlistedIPs_Firewall(tostring(column_ifexists("DestinationIP",""))))',
]

FUNCTION_QUERY = (
    "let _allow = toscalar(union isfuzzy=true (datatable(IPOrRange:string)[]), "
    "(_GetWatchlist('NetworkAllowlist') | project IPOrRange = tostring(IPOrRange)) "
    "| where isnotempty(IPOrRange) | summarize make_list(IPOrRange));\n"
    "iif(isempty(ip) or array_length(_allow) == 0, false, "
    "coalesce(ipv4_is_in_any_range(ip, _allow), false))"
)


def load_bat():
    """
    Locate the base ARM generator for this vendor.

    The vendor's own Analytic-Rules copy is canonical - it is the one kept in
    step with the source files. The copy sitting beside this script is only a
    fallback, because preferring it would let a stale copy silently win.
    """
    candidates = [
        os.path.join(os.path.dirname(V2), "Analytic-Rules", "build-arm-template.py"),
        os.path.join(HERE, "build-arm-template.py"),
        os.path.join(os.path.dirname(os.path.dirname(V2)), "Firewall",
                     "Analytic-Rules", "build-arm-template.py"),
    ]
    for path in candidates:
        if os.path.exists(path):
            spec = importlib.util.spec_from_file_location("bat", path)
            bat = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(bat)
            return bat
    raise SystemExit("cannot locate build-arm-template.py for this vendor")


bat = load_bat()


def inject_allowlist(query):
    """
    Insert the allowlist filter into a query.

    The anchor is the first time filter that follows the reference to the
    main firewall table. For a query whose main table is CommonSecurityLog
    that is the firewall session filter. For a correlation query that
    starts with a let-bound subquery it lands inside that subquery, which is
    where the firewall traffic actually is.
    """
    lines = query.split("\n")
    anchor = None
    for i, ln in enumerate(lines):
        if "CommonSecurityLog" in ln:
            for j in range(i, len(lines)):
                if "| where TimeGenerated" in lines[j]:
                    anchor = j
                    break
            break
    if anchor is None:
        for j, ln in enumerate(lines):
            if "| where TimeGenerated" in ln:
                anchor = j
                break
    if anchor is None:
        return query
    if any("ExcludeAllowlistedIPs" in ln for ln in lines):
        return query
    lines[anchor + 1:anchor + 1] = ALLOWLIST_FILTER
    return "\n".join(lines)


def build_alert_rule(doc):
    """Same shape as the base generator, plus the allowlist filter and the
    enableAnalyticRules switch."""
    rule = bat.build_alert_rule(doc)
    props = rule["properties"]
    props["query"] = inject_allowlist(props["query"])
    props["enabled"] = "[parameters('enableAnalyticRules')]"
    return rule


def build_saved_search(block):
    res = bat.build_saved_search(block)
    res["properties"]["query"] = inject_allowlist(res["properties"]["query"])
    return res


def main():
    resources = []

    # ---- parameters (unchanged from the original V2 template) -------------
    parameters = {
        "workspace": {
            "type": "string",
            "metadata": {
                "description": "Name of the Log Analytics workspace where "
                               "Microsoft Sentinel is deployed"
            },
        },
        "enableAnalyticRules": {"type": "bool", "defaultValue": True},
        "watchlistAlias": {"type": "string", "defaultValue": "NetworkAllowlist"},
        "functionAlias": {"type": "string",
                          "defaultValue": "ExcludeAllowlistedIPs_Firewall"},
        "watchlistRawContent": {"type": "string", "defaultValue": ""},
        "location": {"type": "string",
                     "defaultValue": "[resourceGroup().location]"},
    }

    # ---- watchlist -------------------------------------------------------
    resources.append({
        "type": "Microsoft.OperationalInsights/workspaces/providers/watchlists",
        "apiVersion": "2023-02-01-preview",
        "name": "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', "
                "parameters('watchlistAlias'))]",
        "properties": {
            "displayName": "[parameters('watchlistAlias')]",
            "description": "Trusted IPs/CIDRs to exclude from firewall traffic "
                           "detections.",
            "provider": "Customer",
            "source": "Local file",
            "itemsSearchKey": "IPOrRange",
            "contentType": "text/csv",
            "numberOfLinesToSkip": 0,
            "rawContent": "[variables('watchlistEffectiveContent')]",
        },
    })

    # ---- the allowlist function -----------------------------------------
    resources.append({
        "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
        "apiVersion": "2020-08-01",
        "name": "[concat(parameters('workspace'), '/', parameters('functionAlias'))]",
        "properties": {
            "etag": "*",
            "displayName": "ExcludeAllowlistedIPs_Firewall",
            "category": "Functions",
            "query": FUNCTION_QUERY,
            "functionAlias": "[parameters('functionAlias')]",
            "functionParameters": "ip:string",
            "version": 2,
        },
    })

    # ---- hunting queries -------------------------------------------------
    n_hunts = 0
    for path in sorted(glob.glob(os.path.join(HUNT_DIR, "*.kql"))):
        for block in bat.parse_hunt_blocks(path):
            resources.append(build_saved_search(block))
            n_hunts += 1

    # V2-only hunts that exist only in the template are preserved from the
    # previous template so they are not lost by regeneration. They are the
    # vendor-specific additions, named either CSL_Hunt_Qnn_Vendor_<name> or
    # CSL-Hunt-Qnn; anything that does not match the generated
    # CSL-Hunt-(Q|FQ)nn naming is one of them.
    n_preserved = 0
    if os.path.exists(OUT):
        with open(OUT, encoding="utf-8") as fh:
            old = json.load(fh)
        generated = {r.get("name") for r in resources}
        for res in old.get("resources", []):
            if not res.get("type", "").endswith("savedSearches"):
                continue
            name = res.get("name", "")
            if "functionAlias" in name:
                continue
            if re.search(r"/CSL-Hunt-(Q|FQ)\d+'\)$", name):
                continue
            if name in generated:
                continue
            # The preserved V2-only hunts came from a hand-maintained template
            # and carry incomplete tags. Normalise them so every hunt in the
            # solution has the same tag shape.
            props = res.setdefault("properties", {})
            tags = props.get("tags")
            if not isinstance(tags, list):
                tags = []

            # Collapse the tag list by name, preferring a tag that carries a
            # value over one that is present but empty. The V2-only hunts came
            # from a hand-maintained template and have empty createdBy and
            # createdTimeUtc entries that must be filled in, not duplicated.
            by_name = {}
            order = []
            for t in tags:
                if not isinstance(t, dict):
                    continue
                key = t.get("name")
                if key not in by_name:
                    by_name[key] = t
                    order.append(key)
                elif not str(by_name[key].get("value", "")).strip() \
                        and str(t.get("value", "")).strip():
                    by_name[key] = t

            def put(name, value):
                if name in by_name:
                    if not str(by_name[name].get("value", "")).strip():
                        by_name[name]["value"] = value
                else:
                    by_name[name] = {"name": name, "value": value}
                    order.append(name)

            if not str(by_name.get("description", {}).get("value", "")).strip():
                put("description",
                    f"{props.get('displayName', '')}. V2-specific hunt; see the "
                    "query for detection logic.")
            put("createdBy", CREATED_BY)
            put("createdTimeUtc", CREATED_TIME)
            if "techniques" in by_name:
                by_name["techniques"]["value"] = bat.technique_list(
                    by_name["techniques"].get("value", ""))

            props["tags"] = [by_name[k] for k in order if k in by_name]
            resources.append(res)
            n_preserved += 1

    # ---- analytic rules, inside the nested deployment --------------------
    rules = []
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yaml"))):
        with open(path, encoding="utf-8") as fh:
            for doc in yaml.safe_load_all(fh):
                if isinstance(doc, dict) and doc.get("kind") == "Scheduled":
                    rules.append(build_alert_rule(doc))

    nested = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/"
                   "deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {"type": "string"},
            "enableAnalyticRules": {"type": "bool"},
            "location": {"type": "string"},
        },
        "resources": rules,
    }

    resources.append({
        "type": "Microsoft.Resources/deployments",
        "apiVersion": "2022-09-01",
        "name": "deploy-Firewall-AnalyticRules",
        "dependsOn": [
            "[resourceId('Microsoft.OperationalInsights/workspaces/providers/"
            "watchlists', parameters('workspace'), 'Microsoft.SecurityInsights', "
            "parameters('watchlistAlias'))]",
            "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', "
            "parameters('workspace'), parameters('functionAlias'))]",
        ],
        "properties": {
            "mode": "Incremental",
            "expressionEvaluationOptions": {"scope": "inner"},
            "parameters": {
                "workspace": {"value": "[parameters('workspace')]"},
                "enableAnalyticRules": {
                    "value": "[parameters('enableAnalyticRules')]"},
                "location": {"value": "[parameters('location')]"},
            },
            "template": nested,
        },
    })

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/"
                   "deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": parameters,
        "variables": {
            # The watchlist ships EMPTY on purpose.
            #
            # The original template seeded it with the RFC1918 private ranges
            # (10/8, 172.16/12, 192.168/16). Every rule in this solution
            # filters on SourceIP as well as DestinationIP, so with those
            # ranges in the allowlist every rule that examines internal
            # source traffic was suppressed - which is most of them:
            # beaconing, exfiltration volume, port scan, lateral movement,
            # VPN brute force and per-user activity all source from an
            # internal address by definition.
            #
            # The allowlist is meant for trusted EXTERNAL ranges (corporate
            # egress NAT, partner networks), which the operator adds during
            # the baseline stage of the staged deployment. Seeding it with
            # private space by default silenced the solution.
            "watchlistEffectiveContent": "[if(empty(parameters('watchlistRawContent')), "
                                         "'IPOrRange,Description,Owner,AddedDate', "
                                         "concat('IPOrRange,Description,Owner,AddedDate', "
                                         "'\\r\\n', parameters('watchlistRawContent')))]"
        },
        "resources": resources,
    }

    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(template, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"alertRules (nested) : {len(rules)}")
    print(f"savedSearches       : {n_hunts + n_preserved} "
          f"({n_hunts} from .kql, {n_preserved} preserved V2-only)")
    print(f"watchlist + function : yes")
    print(f"written             : {OUT}")


if __name__ == "__main__":
    main()
