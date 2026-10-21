#!/usr/bin/env python3
"""
Regenerate the rule and hunt tables in the V2_Watchlist README from the
content itself.

The tables are derived from the rule YAML files and the deployed ARM
template, so they cannot drift from what is actually shipped. Re-run after
adding, removing or renaming a rule or hunt.
"""
import os
import re
import json
import glob
import importlib.util

try:
    import yaml
except ImportError:
    print("pyyaml is required")
    raise SystemExit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.dirname(HERE)
SPLIT = os.path.dirname(V2)
README = os.path.join(V2, "README.MD")
TPL = os.path.join(HERE, "azuredeploy.json")

TACTIC_DISPLAY = {
    "Reconnaissance": "Reconnaissance",
    "ResourceDevelopment": "Resource Development",
    "InitialAccess": "Initial Access",
    "Execution": "Execution",
    "Persistence": "Persistence",
    "PrivilegeEscalation": "Privilege Escalation",
    "DefenseEvasion": "Defense Evasion",
    "CredentialAccess": "Credential Access",
    "Discovery": "Discovery",
    "LateralMovement": "Lateral Movement",
    "Collection": "Collection",
    "CommandAndControl": "Command and Control",
    "Exfiltration": "Exfiltration",
    "Impact": "Impact",
    "Multiple": "Multiple",
}


def load_docs(path):
    with open(path, encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]


def build_rule_table():
    files = sorted(glob.glob(os.path.join(HERE, "rules", "*.yaml")))
    rows = []
    tactic_map = {}
    for path in files:
        for doc in load_docs(path):
            if doc.get("kind") != "Scheduled":
                continue
            name = doc.get("name", "")
            sev = doc.get("severity", "")
            tactics = doc.get("tactics") or []
            techs = doc.get("relevantTechniques") or []
            rows.append((name, sev, tactics, techs))
            for t in tactics:
                tactic_map.setdefault(t, []).append(len(rows))
    return rows, tactic_map


def build_hunt_table():
    with open(TPL, encoding="utf-8") as fh:
        tpl = json.load(fh)
    rows = []
    tactic_map = {}
    for res in tpl.get("resources", []):
        if not res.get("type", "").endswith("savedSearches"):
            continue
        name = res.get("name", "")
        if "functionAlias" in name:
            continue
        m = re.search(r"/CSL-Hunt-((?:Q|FQ)\d+)", name)
        if not m:
            m = re.search(r"/CSL_Hunt_(Q\d+)_[A-Za-z_]+", name)
        if not m:
            continue
        hunt_id = m.group(1)
        display = res.get("properties", {}).get("displayName", hunt_id)
        title = display
        for prefix in ("CSL Hunt ", "CSL hunt "):
            if title.startswith(prefix):
                title = title[len(prefix):]
                break
        # the display name carries the hunt id as a prefix - the ID column
        # already shows it
        title = re.sub(r"^(?:CSL_Hunt_)?(?:Q|FQ)\d+_?\s*[-:]?\s*", "", title)
        tags = {t.get("name"): t.get("value", "")
                for t in res.get("properties", {}).get("tags", [])}
        tactics = [t.strip() for t in tags.get("tactics", "").split(",")
                   if t.strip()]
        techs = [t.strip() for t in tags.get("techniques", "").split(",")
                 if t.strip()]
        rows.append((hunt_id, title, tactics, techs))
        for t in tactics:
            tactic_map.setdefault(t, []).append(hunt_id)
    return rows, tactic_map


def md_rules(rows):
    out = ["| # | Rule | Severity | Tactics | ATT&CK |",
           "|---|------|----------|---------|--------|"]
    for i, (name, sev, tactics, techs) in enumerate(rows, 1):
        tac = ", ".join(TACTIC_DISPLAY.get(t, t) for t in tactics) or "—"
        tech = ", ".join(techs) or "—"
        out.append(f"| {i} | {name} | {sev} | {tac} | {tech} |")
    return "\n".join(out)


def md_hunts(rows):
    out = ["| ID | Name | Tactics | ATT&CK |", "|----|------|---------|--------|"]
    for hid, title, tactics, techs in rows:
        tac = ", ".join(TACTIC_DISPLAY.get(t, t) for t in tactics) or "n/a"
        tech = ", ".join(techs) or "n/a"
        out.append(f"| {hid} | {title} | {tac} | {tech} |")
    return "\n".join(out)


def md_coverage(rule_tactic, hunt_tactic):
    out = ["| Tactic | Rules | Hunts |", "|--------|-------|-------|"]
    seen = set()
    for t in list(rule_tactic) + list(hunt_tactic):
        seen.add(TACTIC_DISPLAY.get(t, t))
    for disp in sorted(seen):
        rs = []
        for t, idxs in rule_tactic.items():
            if TACTIC_DISPLAY.get(t, t) == disp:
                rs += [str(i) for i in idxs]
        hs = []
        for t, ids in hunt_tactic.items():
            if TACTIC_DISPLAY.get(t, t) == disp:
                hs += list(ids)
        if not rs and not hs:
            continue
        out.append(f"| {disp} | {', '.join(rs) or '—'} | {', '.join(hs) or '—'} |")
    return "\n".join(out)


def replace_section(text, heading, body):
    """Replace the content under a '## heading' up to the next '## '.

    The numeric suffix on headings such as 'Hunting queries (37)' is ignored,
    so the section is found even when the hard-coded count has drifted.
    """
    base = re.sub(r"\s*\(\d+\)$", "", heading)
    pat = re.compile(rf"(^## {re.escape(base)}(?: \(\d+\))?\s*$.*?)(?=^## )",
                     re.MULTILINE | re.DOTALL)
    if not pat.search(text):
        raise SystemExit(f"section not found: {heading}")
    title = re.search(rf"^## {re.escape(base)}(?: \(\d+\))?\s*$",
                      text, re.MULTILINE).group(0)
    new_title = f"## {heading}"
    return pat.sub(lambda m: new_title + "\n\n" + body + "\n\n", text, count=1)


def main():
    rules, rule_tactic = build_rule_table()
    hunts, hunt_tactic = build_hunt_table()

    with open(README, encoding="utf-8") as fh:
        text = fh.read()

    text = replace_section(text, f"Analytic rules ({len(rules)})", md_rules(rules))
    text = replace_section(text, f"Hunting queries ({len(hunts)})", md_hunts(hunts))

    # Keep the badge, ToC link, capabilities bullet and heading counts in sync.
    text = re.sub(r"(hunts-)\d+(-orange)", rf"\g<1>{len(hunts)}\g<2>", text)
    text = re.sub(r"(analytic_rules-)\d+(-orange)", rf"\g<1>{len(rules)}\g<2>", text)
    text = re.sub(r"\[Hunting queries \(\d+\)\]\(#hunting-queries-\d+\)",
                  f"[Hunting queries ({len(hunts)})](#hunting-queries-{len(hunts)})", text)
    text = re.sub(r"\*\*\d+ analytic rules\*\*", f"**{len(rules)} analytic rules**", text)
    text = re.sub(r"\*\*\d+ hunting queries\*\*", f"**{len(hunts)} hunting queries**", text)
    fq_ids = sorted({h[0] for h in hunts if re.fullmatch(r"FQ\d+", h[0])})
    if fq_ids:
        text = re.sub(r"plus FQ\d+-FQ\d+\)", f"plus {fq_ids[0]}-{fq_ids[-1]})", text)
    text = replace_section(text, "MITRE ATT&CK coverage",
                            md_coverage(rule_tactic, hunt_tactic))

    with open(README, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)

    print(f"rules: {len(rules)}  hunts: {len(hunts)}  -> {README}")


if __name__ == "__main__":
    main()
