#!/usr/bin/env python3
"""
Regenerate the flat CommonSecurityLog bundle from the split sources.

The flat folder (the original, pre-split layout) is kept for backward
compatibility, but it was hand-maintained and had drifted: it carried the
original rules with the type-mismatch bugs, and its hunting-query text file
was a hand-merged copy of the two vendor .kql files.

This script rebuilds the flat artefacts from the split sources, so there is
exactly one place where content is edited:

    Split Firewalls and Zscaler/Firewall/Analytic-Rules/rules/*.yaml
    Split Firewalls and Zscaler/Firewall/Hunting-Queries/*.kql
    Split Firewalls and Zscaler/Zscaler/Analytic-Rules/rules/*.yaml
    Split Firewalls and Zscaler/Zscaler/Hunting-Queries/*.kql

Usage:
    py -3 build-csl-bundle.py
"""
import os
import re
import json
import glob
import shutil
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
SPLIT = os.path.join(HERE, "Split Firewalls and Zscaler")
FIREWALL = os.path.join(SPLIT, "Firewall")
ZSCALER = os.path.join(SPLIT, "Zscaler")

spec = importlib.util.spec_from_file_location(
    "bat", os.path.join(FIREWALL, "Analytic-Rules", "build-arm-template.py"))
bat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bat)


def hunt_sort_key(hunt_id):
    """Q01..Q31 first, then FQ01..FQ15."""
    m = re.match(r"^(FQ|Q)(\d+)$", hunt_id)
    if not m:
        return (99, 99, hunt_id)
    kind, num = m.group(1), int(m.group(2))
    return (0 if kind == "Q" else 1, num, hunt_id)


def main():
    # ---------------------------------------------------------------- rules
    copied = 0
    for vendor in (FIREWALL, ZSCALER):
        src = os.path.join(vendor, "Analytic-Rules", "rules")
        if not os.path.isdir(src):
            continue
        for path in sorted(glob.glob(os.path.join(src, "*.yaml"))):
            shutil.copy2(path, os.path.join(HERE, os.path.basename(path)))
            copied += 1
    print(f"rules synced to flat folder : {copied}")

    # ------------------------------------------------------------- hunts
    hunts = []
    for vendor in (FIREWALL, ZSCALER):
        hunt_dir = os.path.join(vendor, "Hunting-Queries")
        for path in sorted(glob.glob(os.path.join(hunt_dir, "*.kql"))):
            for block in bat.parse_hunt_blocks(path):
                block["_source"] = os.path.basename(path)
                hunts.append(block)
    hunts.sort(key=lambda h: hunt_sort_key(h["id"]))
    print(f"hunt blocks parsed          : {len(hunts)}")

    # Preserve the original file header, then rebuild the body.
    txt_path = os.path.join(HERE, "CSL-ThreatHunting-Queries.txt")
    header = ""
    if os.path.exists(txt_path):
        with open(txt_path, encoding="utf-8") as fh:
            text = fh.read()
        # the header runs to the first hunt block
        m = re.search(r"(?m)^//\s*(Q\d\d|FQ\d\d)\s*[-:]", text)
        if m:
            header = text[:m.start()]

    body = []
    for h in hunts:
        body.append("// " + "=" * 77)
        body.append(f"// {h['id']} - {h['title']}")
        if h.get("techniques"):
            body.append(f"// MITRE Techniques: {h['techniques']}")
        if h.get("tactics"):
            body.append(f"// Tactics        : {h['tactics']}")
        if h.get("description"):
            body.append(f"// Description    : {h['description']}")
        body.append("// " + "=" * 77)
        body.append(h["query"])
        body.append("")

    out = header + "\n".join(body)
    out = re.sub(r"// Queries:.*", f"// Queries: {len(hunts)} (Q + FQ) | Table: CommonSecurityLog",
                 out, count=1)
    with open(txt_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(out)
    print(f"rewrote                     : {os.path.basename(txt_path)}")

    # ------------------------------------------------------- ARM template
    resources = []
    for path in sorted(glob.glob(os.path.join(HERE, "*.yaml"))):
        with open(path, encoding="utf-8") as fh:
            for doc in yaml_docs(fh):
                if doc.get("kind") == "Scheduled":
                    resources.append(bat.build_alert_rule(doc))
    n_rules = len(resources)

    for h in hunts:
        resources.append(bat.build_saved_search(h))
    n_hunts = len(hunts)

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/"
                   "deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {
                "type": "String",
                "metadata": {"description": "Log Analytics workspace name "
                                             "(not the workspace ID)."},
            }
        },
        "resources": resources,
    }
    tpl_path = os.path.join(HERE, "azuredeploy.json")
    with open(tpl_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(template, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"azuredeploy.json            : {n_rules} alertRules, {n_hunts} savedSearches")


def yaml_docs(fh):
    import yaml
    return [d for d in yaml.safe_load_all(fh) if d]


if __name__ == "__main__":
    main()
