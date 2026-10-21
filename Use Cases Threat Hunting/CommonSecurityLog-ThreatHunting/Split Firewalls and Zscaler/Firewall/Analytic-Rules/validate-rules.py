#!/usr/bin/env python3
"""
Validator for CommonSecurityLog Scheduled Analytic Rules (Sentinel).

Checks a directory of analytics-rule YAML files against the Sentinel schema
contract and the MITRE ATT&CK vocabulary. Run it before deploying and after
editing any rule.

Usage:
    py -3 validate-rules.py [rules-dir] [-v]

Exit code 0 = no ERRORs (warnings may still be present).
Exit code 1 = at least one ERROR.
"""

import sys
import os
import re
import json
import glob
import argparse

try:
    import yaml
except ImportError:
    print("pyyaml is required:  py -3 -m pip install pyyaml")
    sys.exit(2)

# --------------------------------------------------------------------------
# Reference vocabulary (Microsoft Sentinel / MITRE ATT&CK)
# --------------------------------------------------------------------------

# https://learn.microsoft.com/azure/sentinel/map-data-to-fields-in-sentinel-entity
ENTITY_IDENTIFIERS = {
    "Account": ["Name", "FullName", "NTDomain", "DnsDomain", "UPNSuffix", "Sid",
                "AadTenantId", "AadUserId", "PUID", "IsDomainJoined", "DisplayName",
                "ObjectGuid"],
    "Host": ["DnsDomain", "NTDomain", "HostName", "FullName", "NetBiosName",
             "AzureID", "OMSAgentID", "OSFamily", "OSVersion", "IsDomainJoined"],
    "IP": ["Address"],
    "Malware": ["Name", "Category"],
    "File": ["Directory", "Name"],
    "Process": ["ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc"],
    "CloudApplication": ["AppId", "Name", "InstanceName"],
    "DNS": ["DomainName"],
    "AzureResource": ["ResourceId"],
    "FileHash": ["Algorithm", "Value"],
    "RegistryKey": ["Hive", "Key"],
    "RegistryValue": ["Name", "Value", "ValueType"],
    "SecurityGroup": ["DistinguishedName", "SID", "ObjectGuid"],
    "URL": ["Url"],
    "Mailbox": ["MailboxPrimaryAddress", "DisplayName", "Upn",
                "ExternalDirectoryObjectId", "RiskLevel"],
    "MailCluster": ["NetworkMessageIds", "CountByDeliveryStatus", "CountByThreatType",
                    "CountByProtectionStatus", "Threats", "Query", "QueryTime",
                    "MailCount", "IsVolumeAnomaly", "Source", "ClusterSourceIdentifier",
                    "ClusterSourceType", "ClusterQueryStartTime", "ClusterQueryEndTime",
                    "ClusterGroup"],
    "MailMessage": ["Recipient", "Urls", "Threats", "Sender", "P1Sender",
                    "P1SenderDisplayName", "P1SenderDomain", "ReceivedDate",
                    "NetworkMessageId", "InternetMessageId", "Subject",
                    "BodyFingerprintBin1", "BodyFingerprintBin2", "BodyFingerprintBin3",
                    "BodyFingerprintBin4", "BodyFingerprintBin5", "AntispamDirection",
                    "DeliveryAction", "DeliveryLocation", "Language",
                    "ThreatDetectionMethods"],
    "SubmissionMail": ["NetworkMessageId", "Timestamp", "Recipient", "Sender",
                       "SenderIp", "Subject", "ReportType", "SubmissionId",
                       "SubmissionDate", "Submitter"],
}

# Canonical tactic values as written in the Sentinel analytic-rule YAML.
# This is the camelCase, no-space form used by the official content hub.
VALID_TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact", "Multiple",
}

# Spaced spellings are seen in older content. Sentinel tolerates them but the
# camelCase form is canonical.
TACTIC_ALIASES = {
    "Resource Development": "ResourceDevelopment",
    "Initial Access": "InitialAccess",
    "Privilege Escalation": "PrivilegeEscalation",
    "Defense Evasion": "DefenseEvasion",
    "Credential Access": "CredentialAccess",
    "Lateral Movement": "LateralMovement",
    "Command and Control": "CommandAndControl",
}

VALID_SEVERITY = {"Informational", "Low", "Medium", "High"}

REQUIRED_FIELDS = [
    "id", "name", "description", "severity", "requiredDataConnectors",
    "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold",
    "tactics", "relevantTechniques", "query", "entityMappings", "version", "kind",
]

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                     r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DURATION_RE = re.compile(r"^P?(\d+D)?(T?(\d+H)?(\d+M)?(\d+(\.\d+)?S)?)?$", re.IGNORECASE)

# Kusto operators that take a duration literal
DUR_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
DUR_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def duration_seconds(value):
    """Parse a Sentinel duration into seconds. ISO-8601 or shorthand."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    # ISO-8601: P1DT2H / PT12H / PT6H
    m = re.match(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$",
                 s, re.IGNORECASE)
    if m and any(m.groups()):
        d, h, mi, sec = m.groups()
        return (int(d or 0) * 86400 + int(h or 0) * 3600 +
                int(mi or 0) * 60 + float(sec or 0))
    # shorthand: 1h, 30m, 1d
    m = DUR_RE.match(s)
    if m:
        return int(m.group(1)) * DUR_UNIT[m.group(2).lower()]
    # "1.5h" style
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([smhdw])$", s, re.IGNORECASE)
    if m:
        return float(m.group(1)) * DUR_UNIT[m.group(2).lower()]
    return None


# --------------------------------------------------------------------------
# KQL surface helpers
# --------------------------------------------------------------------------

# Columns a query is likely to project/extend. Used to sanity-check that a
# customDetails / entityMappings columnName actually exists in the query text.
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def query_identifiers(query):
    """All identifiers appearing anywhere in the query body."""
    return set(IDENT_RE.findall(query))


def projected_columns(query):
    """
    Best-effort extraction of the column names a query emits.

    Looks at `project`, `project-reorder`, `summarize ... by` and `extend`
    assignments. This is a heuristic - it cannot be perfect - but it catches
    the common failure where a columnName refers to something the query never
    produces.
    """
    cols = set()
    for line in query.splitlines():
        s = line.strip()
        # project / project-reorder: comma separated list, possibly "x = y"
        m = re.match(r"^project(-reorder)?\s+(.*)$", s, re.IGNORECASE)
        if m:
            body = m.group(2)
            body = body.split("|")[0]
            for part in body.split(","):
                part = part.strip()
                if not part:
                    continue
                if "=" in part:
                    part = part.split("=")[-1].strip()
                part = part.strip("`")
                if IDENT_RE.fullmatch(part):
                    cols.add(part)
        # extend assignment:  Name = expr
        m = re.match(r"^extend\s+(.*)$", s, re.IGNORECASE)
        if m:
            for part in m.group(1).split(","):
                part = part.strip()
                if "=" in part:
                    name = part.split("=")[0].strip().strip("`")
                    if IDENT_RE.fullmatch(name):
                        cols.add(name)
        # summarize ... by a, b
        m = re.match(r"^summarize\b.*\bby\s+(.*)$", s, re.IGNORECASE)
        if m:
            for part in m.group(1).split(","):
                part = part.strip()
                if IDENT_RE.fullmatch(part):
                    cols.add(part)
    return cols


def is_potentially_projected(query, col):
    """
    True if `col` looks like it survives to the output of `query`.

    Conservative: if the identifier appears anywhere in the query it is
    considered present, because a column can reach the output through a
    summarize `any()`/`make_set()` or an untargeted `project *`.
    """
    if col in query_identifiers(query):
        return True
    # `project *` or `project-reorder *` keeps everything
    if re.search(r"project(-reorder)?\s+\*", query, re.IGNORECASE):
        return True
    return False


def is_array_produced(query, col):
    """
    True if the column is an array-only output.

    A column produced by make_set() / make_list() is a dynamic array, and
    Sentinel cannot map an array to an entity - the mapping silently never
    resolves. If the same column is also a summarize group key it is a scalar
    in the output as well, so the group keys are collected first and excluded.
    """
    pat = re.compile(rf"make_(?:set|list)\(\s*{re.escape(col)}\b", re.IGNORECASE)
    if not pat.search(query):
        return False
    # group keys keep the column scalar
    for m in re.finditer(r"(?im)(?:^|\|)\s*by\s+([^\n]+)", query):
        keys = m.group(1)
        for part in keys.split(","):
            part = part.strip()
            if "=" in part:
                part = part.split("=")[-1].strip()
            if part.strip("`") == col:
                return False
    return True


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

class Issue:
    def __init__(self, level, code, message):
        self.level = level
        self.code = code
        self.message = message

    def __str__(self):
        return f"{self.level:<5} {self.code:<22} {self.message}"


def validate_rule(doc, filename, seen_ids, seen_names):
    issues = []

    def err(code, msg):
        issues.append(Issue("ERROR", code, msg))

    def warn(code, msg):
        issues.append(Issue("WARN", code, msg))

    # -- required fields ---------------------------------------------------
    for f in REQUIRED_FIELDS:
        if f not in doc or doc[f] in (None, ""):
            err("MISSING-FIELD", f"required field '{f}' is absent or empty")

    # -- kind --------------------------------------------------------------
    if doc.get("kind") != "Scheduled":
        err("KIND", f"kind is {doc.get('kind')!r}; expected 'Scheduled'")

    # -- id / name uniqueness ---------------------------------------------
    rid = doc.get("id")
    if rid and not GUID_RE.match(str(rid)):
        err("ID-FORMAT", f"id {rid!r} is not a GUID")
    if rid in seen_ids:
        err("ID-DUPLICATE", f"id {rid} already used by another rule")
    if rid:
        seen_ids.add(rid)
    name = doc.get("name")
    if name in seen_names:
        err("NAME-DUPLICATE", f"name {name!r} already used by another rule")
    if name:
        seen_names.add(name)

    # -- severity ----------------------------------------------------------
    if doc.get("severity") not in VALID_SEVERITY:
        err("SEVERITY", f"severity {doc.get('severity')!r} not in "
                         f"{sorted(VALID_SEVERITY)}")

    # -- version -----------------------------------------------------------
    ver = str(doc.get("version", ""))
    if not re.match(r"^\d+\.\d+\.\d+$", ver):
        warn("VERSION", f"version {ver!r} is not semver x.y.z")

    # -- data connectors ---------------------------------------------------
    rdc = doc.get("requiredDataConnectors")
    if isinstance(rdc, list):
        if not rdc:
            err("CONNECTORS", "requiredDataConnectors is an empty list")
        for c in rdc:
            if not isinstance(c, dict):
                err("CONNECTORS", f"connector entry is not a mapping: {c!r}")
                continue
            if not c.get("connectorId"):
                err("CONNECTORS", f"connector {c.get('connectorId')!r} has no connectorId")
            if not c.get("dataTypes"):
                warn("CONNECTORS", f"connector {c.get('connectorId')!r} has no dataTypes")
    elif rdc is not None:
        err("CONNECTORS", "requiredDataConnectors must be a list")

    # -- schedule ----------------------------------------------------------
    qf = duration_seconds(doc.get("queryFrequency"))
    qp = duration_seconds(doc.get("queryPeriod"))
    if qf is None:
        err("SCHEDULE", f"queryFrequency {doc.get('queryFrequency')!r} is not a "
                        "parseable duration")
    if qp is None:
        err("SCHEDULE", f"queryPeriod {doc.get('queryPeriod')!r} is not a parseable duration")
    if qf is not None and qp is not None:
        if qp < qf:
            err("SCHEDULE", f"queryPeriod ({doc.get('queryPeriod')}) is shorter than "
                            f"queryFrequency ({doc.get('queryFrequency')})")
        elif qp > qf:
            warn("SCHEDULE", f"queryPeriod ({doc.get('queryPeriod')}) is longer than "
                             f"queryFrequency ({doc.get('queryFrequency')}); the same "
                             "events will re-alert on every run unless the query "
                             "itself narrows the window to the last interval")
    if doc.get("triggerOperator") not in ("gt", "eq", "lt", "gte", "lte"):
        err("TRIGGER", f"triggerOperator {doc.get('triggerOperator')!r} is invalid")
    tt = doc.get("triggerThreshold")
    if not isinstance(tt, int):
        err("TRIGGER", f"triggerThreshold {tt!r} must be an integer")

    # -- query -------------------------------------------------------------
    query = doc.get("query") or ""
    if not query.strip():
        err("QUERY", "query is empty")
    else:
        if not re.search(r"\bTimeGenerated\b", query):
            err("QUERY", "query never references TimeGenerated")
        if not re.search(r"\bago\s*\(", query):
            warn("QUERY", "query has no ago() time filter; it will scan the full window")
        # Lookback windows. A query may legitimately reference several ago()
        # values (a long reference window for a TI feed, a short one for the
        # main table), so use the *tightest* window as the effective one.
        windows = []
        for m in re.finditer(r"ago\(\s*(\d+)\s*([smhdw])\s*\)", query, re.IGNORECASE):
            windows.append((int(m.group(1)) * DUR_UNIT[m.group(2).lower()],
                            f"ago({m.group(1)}{m.group(2)})"))
        if windows and qp is not None:
            tightest = min(windows, key=lambda w: w[0])
            if tightest[0] > qp:
                err("QUERY", f"the tightest in-query window {tightest[1]} is longer than "
                             f"queryPeriod ({doc.get('queryPeriod')}); rows outside the "
                             "scheduled period are being processed")
            elif qf is not None and tightest[0] > qf:
                warn("QUERY", f"the tightest in-query window {tightest[1]} is longer than "
                              f"queryFrequency ({doc.get('queryFrequency')}); the same "
                              "rows will re-alert on every run unless the rule is "
                              "deliberately stateful (e.g. new-vs-historical comparison)")

    # -- tactics -----------------------------------------------------------
    tactics = doc.get("tactics")
    if tactics is None:
        pass
    elif not isinstance(tactics, list):
        err("TACTICS", "tactics must be a list")
    else:
        for t in tactics:
            ts = str(t)
            if ts in TACTIC_ALIASES:
                warn("TACTIC-FORMAT",
                     f"tactic {ts!r} should be written {TACTIC_ALIASES[ts]!r}")
            elif ts not in VALID_TACTICS:
                err("TACTIC-VALUE", f"tactic {ts!r} is not a valid ATT&CK tactic name")
            if re.match(r"^TA\d{4}", ts):
                err("TACTIC-VALUE", f"tactic {ts!r} is a tactic ID; tactic IDs do not "
                                    "belong in the tactics list")

    # -- techniques --------------------------------------------------------
    techs = doc.get("relevantTechniques")
    if techs is None:
        pass
    elif not isinstance(techs, list):
        err("TECHNIQUES", "relevantTechniques must be a list")
    else:
        for t in techs:
            ts = str(t)
            if ts in ("N/A", "NA", ""):
                err("TECHNIQUE-VALUE", f"relevantTechniques contains {ts!r}")
            elif ts.upper().startswith("TA"):
                err("TECHNIQUE-VALUE", f"relevantTechniques contains tactic ID {ts!r}; "
                                       "it belongs in the tactics list")
            elif not re.match(r"^T\d{4}(\.\d{3})?$", ts):
                err("TECHNIQUE-VALUE", f"technique {ts!r} is not a Txxxx / Txxxx.xxx id")

    # -- entity mappings ---------------------------------------------------
    ems = doc.get("entityMappings")
    if ems is None:
        pass
    elif not isinstance(ems, list):
        err("ENTITIES", "entityMappings must be a list")
    elif len(ems) == 0:
        err("ENTITIES", "entityMappings is empty - the rule can never populate the "
                        "investigation graph")
    else:
        if len(ems) > 5:
            err("ENTITIES", f"{len(ems)} entity mappings; Sentinel allows a maximum of 5")
        has_core = False
        for em in ems:
            if not isinstance(em, dict):
                err("ENTITIES", f"entity mapping is not a mapping: {em!r}")
                continue
            et = em.get("entityType")
            if et not in ENTITY_IDENTIFIERS:
                err("ENTITY-TYPE", f"entityType {et!r} is not a valid Sentinel entity type")
                continue
            if et in ("Host", "Account", "IP"):
                has_core = True
            fms = em.get("fieldMappings")
            if not isinstance(fms, list) or not fms:
                err("ENTITY-FIELDS", f"entityType {et} has no fieldMappings")
                continue
            if len(fms) > 3:
                err("ENTITY-FIELDS", f"entityType {et} has {len(fms)} field mappings; "
                                     "Sentinel allows a maximum of 3")
            for fm in fms:
                ident = fm.get("identifier")
                col = fm.get("columnName")
                if ident not in ENTITY_IDENTIFIERS[et]:
                    err("ENTITY-IDENT",
                        f"entityType {et} + identifier {ident!r} is invalid; valid: "
                        f"{ENTITY_IDENTIFIERS[et]}")
                if not col:
                    err("ENTITY-COL", f"entityType {et} mapping has no columnName")
                elif is_array_produced(query, col):
                    err("ENTITY-ARRAY",
                        f"entityType {et} columnName {col!r} is produced by make_set() or "
                        "make_list() and is therefore an array. Sentinel cannot map an "
                        "array to an entity - project a scalar column (any() or arg_max) "
                        "and map that instead")
                elif not is_potentially_projected(query, col):
                    err("ENTITY-COL",
                        f"entityType {et} columnName {col!r} does not appear in the "
                        "query - the entity will never resolve")
        if not has_core:
            warn("ENTITIES", "no Host / Account / IP entity is mapped; Sentinel "
                             "recommends at least one")

    # -- custom details ----------------------------------------------------
    cd = doc.get("customDetails")
    if isinstance(cd, dict):
        if len(cd) > 20:
            err("CUSTOM-DETAILS", f"{len(cd)} custom details; maximum is 20")
        for k, v in cd.items():
            if len(k) > 20:
                err("CUSTOM-DETAILS", f"custom detail key {k!r} is {len(k)} chars; "
                                      "Sentinel limits keys to 20")
            if not is_potentially_projected(query, v):
                err("CUSTOM-DETAILS",
                    f"custom detail {k!r} points at column {v!r} which does not appear "
                    "in the query")

    # -- incident grouping -------------------------------------------------
    ic = doc.get("incidentConfiguration")
    if isinstance(ic, dict):
        gc = ic.get("groupingConfiguration")
        if isinstance(gc, dict):
            mm = gc.get("matchingMethod")
            if mm not in ("AllEntities", "AnyAlert", "Selected", "AllAlerts", "AnyEntity"):
                warn("GROUPING", f"groupingConfiguration.matchingMethod {mm!r} is not a "
                                 "recognised value")
            if mm == "Selected":
                if not (gc.get("groupByEntities") or gc.get("groupByAlertDetails")
                        or gc.get("groupByCustomDetails")):
                    err("GROUPING", "matchingMethod is 'Selected' but no groupBy* list "
                                    "is populated")

    # -- description --------------------------------------------------------
    desc = doc.get("description") or ""
    if len(desc.strip()) < 40:
        warn("DESCRIPTION", "description is very short; explain what an analyst "
                            "should do with the alert")
    if "MITRE" not in desc and "T1" not in desc:
        warn("DESCRIPTION", "description does not mention the MITRE technique")

    return issues


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rules_dir", nargs="?",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "rules"))
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    d = args.rules_dir
    if not os.path.isdir(d):
        print(f"not a directory: {d}")
        return 2

    files = sorted(glob.glob(os.path.join(d, "*.yaml")) +
                   glob.glob(os.path.join(d, "*.yml")))
    if not files:
        print(f"no .yaml rule files found in {d}")
        return 2

    seen_ids, seen_names = set(), set()
    total_err = total_warn = 0
    report = {}

    for path in files:
        base = os.path.basename(path)
        try:
            with open(path, encoding="utf-8") as fh:
                docs = [d for d in yaml.safe_load_all(fh) if d]
        except Exception as exc:  # noqa: BLE001
            report[base] = [Issue("ERROR", "YAML-PARSE", str(exc))]
            total_err += 1
            continue

        if not docs:
            report[base] = [Issue("ERROR", "EMPTY", "file contains no YAML documents")]
            total_err += 1
            continue

        issues = []
        for doc in docs:
            if not isinstance(doc, dict):
                issues.append(Issue("ERROR", "YAML-SHAPE",
                                    "document is not a mapping"))
                continue
            issues.extend(validate_rule(doc, base, seen_ids, seen_names))
        report[base] = issues
        total_err += sum(1 for i in issues if i.level == "ERROR")
        total_warn += sum(1 for i in issues if i.level == "WARN")

    # ---- print -------------------------------------------------------
    for base in sorted(report):
        issues = report[base]
        if not issues:
            print(f"PASS  {base}")
            continue
        print(f"{len(issues):>2} issue(s)  {base}")
        for i in issues:
            print("       " + str(i))

    print()
    print(f"files: {len(files)}   errors: {total_err}   warnings: {total_warn}")
    if total_err:
        print("RESULT: FAIL - fix the errors above before deploying.")
        return 1
    print("RESULT: PASS - no schema errors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
