#!/usr/bin/env python3
"""
Generate azuredeploy.json for the CommonSecurityLog firewall content directly
from the rule YAML files and the hunting query files.

Why this exists
---------------
The ARM template was hand-maintained and had already drifted from the YAML
rule files - it carried different customDetails and the original (broken)
queries. Deploying via ARM would therefore have shipped a different set of
rules than the ones in the folder, with no warning.

Generating the template from the source of truth removes that failure mode
entirely: edit a YAML file or a .kql file, re-run this, and the template
matches.

Usage:
    py -3 build-arm-template.py
"""
import os
import re
import json
import glob
import datetime

try:
    import yaml
except ImportError:
    print("pyyaml is required:  py -3 -m pip install pyyaml")
    raise SystemExit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(HERE, "rules")
HUNT_DIR = os.path.join(HERE, os.pardir, "Hunting-Queries")
OUT = os.path.join(HERE, "azuredeploy.json")

CREATED_BY = "CyberSOC Engineering"
CREATED_TIME = "2026-10-20T00:00:00Z"
HUNT_CATEGORY = "Hunting Queries"
RULE_CATEGORY = "CSL Threat Hunting"

TRIGGER_OPS = {
    "gt": "GreaterThan",
    "eq": "Equals",
    "lt": "LessThan",
    "gte": "GreaterThanOrEqual",
    "lte": "LessThanOrEqual",
}


def to_iso_duration(value):
    """Convert a Sentinel duration ('1h', '1d', '15m') to ISO 8601 ('PT1H')."""
    s = str(value).strip()
    if s.upper().startswith("P"):
        return s.upper()
    m = re.match(r"^(\d+)\s*([smhdw])$", s, re.IGNORECASE)
    if not m:
        raise ValueError(f"cannot convert duration {value!r}")
    n, unit = int(m.group(1)), m.group(2).lower()
    if unit in ("s", "m", "h"):
        return f"PT{n}{unit.upper()}"
    return f"P{n}{unit.upper()}"


def one_line(text):
    """Collapse a multi-line description into a single line."""
    if not text:
        return ""
    return " ".join(str(text).split())


def technique_list(text):
    """Normalise a technique list to 'T1190,T1105' with no doubled commas."""
    if not text:
        return ""
    parts = [p.strip() for p in str(text).replace(",", " ").split() if p.strip()]
    return ",".join(parts)


# --------------------------------------------------------------------------
# Analytic rules
# --------------------------------------------------------------------------

def build_alert_rule(doc):
    name = doc["name"]
    rule_id = doc["id"]
    props = {
        "displayName": name,
        "description": one_line(doc.get("description", "")),
        "severity": doc.get("severity", "Medium"),
        "enabled": True,
        "queryFrequency": to_iso_duration(doc.get("queryFrequency", "1h")),
        "queryPeriod": to_iso_duration(doc.get("queryPeriod", "1h")),
        "triggerOperator": TRIGGER_OPS.get(doc.get("triggerOperator", "gt"), "GreaterThan"),
        "triggerThreshold": doc.get("triggerThreshold", 0),
        "suppressionEnabled": False,
        "suppressionDuration": "PT5H",
    }

    tactics = doc.get("tactics")
    if tactics:
        props["tactics"] = list(tactics)
    techniques = doc.get("relevantTechniques")
    if techniques:
        props["techniques"] = list(techniques)

    props["query"] = doc.get("query", "")

    entity_mappings = doc.get("entityMappings") or []
    if entity_mappings:
        props["entityMappings"] = entity_mappings

    custom_details = doc.get("customDetails")
    if custom_details:
        props["customDetails"] = custom_details

    override = doc.get("alertDetailsOverride")
    if override:
        props["alertDetailsOverride"] = override

    incident = doc.get("incidentConfiguration")
    if incident:
        props["incidentConfiguration"] = incident

    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "name": "[concat(parameters('workspace'), "
                f"'/Microsoft.SecurityInsights/{rule_id}')]",
        "apiVersion": "2022-11-01-preview",
        "kind": "Scheduled",
        "location": "[resourceGroup().location]",
        "properties": props,
    }


# --------------------------------------------------------------------------
# Hunting queries
# --------------------------------------------------------------------------

BLOCK_SEP = re.compile(r"(?m)^//\s*={10,}\s*$")
CONT = re.compile(r"^//\s{2,}(\S.*)$")


def parse_hunt_blocks(path):
    """
    Split a .kql file into hunt blocks.

    The banner layout is:

        // ====
        // Q01 - Title
        // MITRE Techniques: ...
        // Tactics        : ...
        // Description    : first line of the description
        //                  continuation of the description
        // ====
        <the query>

    The separator sits *between* the metadata and the query, so a naive split
    on the separator separates the two halves. A hunt therefore starts at the
    chunk that carries the hunt id, and the query continues in the chunks that
    follow until the next hunt id appears.

    A description that runs over several lines is continued on comment lines
    indented by two or more spaces after the '//'.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    chunks = BLOCK_SEP.split(text)
    hunts = []
    current = None

    meta_patterns = (
        ("id", re.compile(r"^//\s*((?:Q|FQ)\d+)\s*[-:]\s*(.*)$")),
        ("techniques", re.compile(r"^//\s*MITRE Techniques\s*:\s*(.*)$")),
        ("tactics", re.compile(r"^//\s*Tactics\s*:\s*(.*)$")),
        ("description", re.compile(r"^//\s*Description\s*:\s*(.*)$")),
    )

    for chunk in chunks:
        lines = chunk.split("\n")
        meta = {}
        body = []
        last_key = None

        for line in lines:
            s = line.strip()
            matched = False
            for key, pat in meta_patterns:
                m = pat.match(s)
                if m:
                    if key == "id":
                        meta["id"] = m.group(1)
                        meta["title"] = m.group(2).strip()
                    else:
                        meta[key] = m.group(1).strip()
                    last_key = key if key != "id" else None
                    matched = True
                    break
            if matched:
                continue
            if s.startswith("//"):
                # a continuation of the last metadata value
                m = CONT.match(line)
                if m and last_key:
                    meta[last_key] = (meta.get(last_key, "") + " " + m.group(1).strip()).strip()
                continue
            if not s:
                continue
            body.append(line)

        if meta.get("id"):
            if current and current["body"]:
                hunts.append(current)
            current = {
                "id": meta["id"],
                "title": meta.get("title") or meta["id"],
                "techniques": meta.get("techniques"),
                "tactics": meta.get("tactics"),
                "description": meta.get("description"),
                "body": list(body),
            }
        elif current is not None:
            current["body"].extend(body)
            for key in ("techniques", "tactics", "description"):
                if not current.get(key) and meta.get(key):
                    current[key] = meta[key]

    if current and current["body"]:
        hunts.append(current)

    out = []
    for h in hunts:
        h["query"] = "\n".join(h["body"]).strip()
        del h["body"]
        out.append(h)
    return out


def build_saved_search(block, prefix="CSL-Hunt"):
    tags = []
    if block.get("description"):
        tags.append({"name": "description", "value": one_line(block["description"])})
    if block.get("tactics"):
        tags.append({"name": "tactics", "value": one_line(block["tactics"])})
    if block.get("techniques"):
        tags.append({"name": "techniques", "value": technique_list(block["techniques"])})
    tags.append({"name": "createdBy", "value": CREATED_BY})
    tags.append({"name": "createdTimeUtc", "value": CREATED_TIME})

    return {
        "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
        "name": f"[concat(parameters('workspace'), '/{prefix}-{block['id']}')]",
        "apiVersion": "2020-08-01",
        "properties": {
            "displayName": f"{prefix.replace('-', ' ')} {block['id']} - {block['title']}",
            "category": HUNT_CATEGORY,
            "query": block["query"],
            "tags": tags,
        },
    }


# --------------------------------------------------------------------------
# Template
# --------------------------------------------------------------------------

def main():
    resources = []

    rule_files = sorted(glob.glob(os.path.join(RULES_DIR, "*.yaml")))
    if not rule_files:
        raise SystemExit(f"no rule YAML files in {RULES_DIR}")

    for path in rule_files:
        with open(path, encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d]
        for doc in docs:
            if doc.get("kind") != "Scheduled":
                continue
            resources.append(build_alert_rule(doc))
    n_rules = len(resources)

    n_hunts = 0
    for path in sorted(glob.glob(os.path.join(HUNT_DIR, "*.kql"))):
        for block in parse_hunt_blocks(path):
            resources.append(build_saved_search(block))
            n_hunts += 1

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/"
                   "deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {
                "type": "String",
                "metadata": {
                    "description": "Log Analytics workspace name "
                                   "(not the workspace ID)."
                }
            }
        },
        "resources": resources,
    }

    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(template, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"alertRules   : {n_rules}")
    print(f"savedSearches: {n_hunts}")
    print(f"written      : {OUT}")


if __name__ == "__main__":
    main()
