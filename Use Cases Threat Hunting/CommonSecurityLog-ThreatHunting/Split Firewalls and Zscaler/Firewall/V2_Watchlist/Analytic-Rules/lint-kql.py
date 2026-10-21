#!/usr/bin/env python3
"""
Static KQL linter for CommonSecurityLog (Sentinel) content.

Catches the defect classes that make a query silently inoperative - the ones
where the query parses fine and returns nothing, which is far worse than a
syntax error because it looks like a clean environment.

Covers both analytics-rule YAML files and .kql hunting-query files.

Usage:
    py -3 lint-kql.py <path> [<path> ...] [-v]

Exit code 0 = no errors. Exit code 1 = at least one error.
"""
import os
import re
import sys
import glob
import argparse

try:
    import yaml
except ImportError:
    print("pyyaml is required:  py -3 -m pip install pyyaml")
    sys.exit(2)

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# Columns that are STRING typed in CommonSecurityLog / the Entra and UEBA
# tables these queries join against. Comparing one of these to a bare numeric
# literal is a type error that silently evaluates false.
STRING_COLUMNS = {
    # CommonSecurityLog
    "DestinationPort", "SourcePort", "DeviceAction", "Activity",
    "DeviceEventClassID", "DeviceEventID", "DeviceVendor", "DeviceProduct",
    "DeviceVersion", "LogSeverity", "SourceUserName", "DestinationUserName",
    "RequestURL", "RequestUrl", "DestinationHostName", "SourceHostName",
    "ApplicationProtocol", "Protocol", "Message", "AdditionalExtensions",
    "DeviceCustomString1", "DeviceCustomString2", "DeviceCustomString3",
    "DeviceCustomString4", "DeviceCustomString5", "EventOutcome",
    # ThreatIntelIndicators
    "ObservableValue", "ObservableKey", "Tags", "Confidence", "Id",
    # SigninLogs
    "ResultType", "UserPrincipalName", "AppDisplayName", "Location",
    "RiskLevelDuringSignIn", "CorrelationId", "IPAddress",
    # IdentityInfo
    "AccountUPN", "InvestigationPriority", "JobTitle", "Department",
    "Manager", "IsAccountEnabled", "AccountName", "AccountDisplayName",
    # SecurityAlert
    "AlertSeverity", "AlertName", "ProductName", "Entities",
    # CommonSecurityLog extras
    "EntityType", "PolicyName", "Category",
}

# KQL functions that must not receive an empty or null string.
NEEDS_NONEMPTY = ("parse_ipv4", "parse_ipv6", "ipv4_is_valid", "ipv4_is_private",
                  "ipv4_is_in_range", "is_ipv4", "parse_json", "parse_xml",
                  "geo_info_from_ip_address", "extract", "extract_all",
                  "base64_decode_tostring", "todynamic")

issues = []


def err(src, code, msg, line=None):
    issues.append(("ERROR", code, src, line, msg))


def warn(src, code, msg, line=None):
    issues.append(("WARN", code, src, line, msg))


# --------------------------------------------------------------------------
# Individual checks
# --------------------------------------------------------------------------

def strip_comments(query):
    """
    Remove // comments while preserving line numbering.

    Comments in these files carry prose that looks like code ("port sweep",
    "the transport protocol (TCP/UDP/ICMP)"), which a naive function-name
    scan picks up as function calls.
    """
    out = []
    for line in query.split("\n"):
        in_str = False
        cut = len(line)
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '"' and (i == 0 or line[i - 1] != "\\"):
                in_str = not in_str
            elif ch == "/" and not in_str and i + 1 < len(line) and line[i + 1] == "/":
                cut = i
                break
            i += 1
        out.append(line[:cut])
    return "\n".join(out)


def strip_strings(query):
    """Blank out the contents of string literals, keeping the quotes."""
    out = []
    in_str = False
    for ch in query:
        if ch == '"':
            in_str = not in_str
            out.append(ch)
        elif in_str:
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def check_parens(src, query, base_line=0):
    """Unbalanced parentheses or brackets."""
    depth = 0
    for i, ch in enumerate(query):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                line = base_line + query[:i].count("\n")
                err(src, "KQL-BRACKET",
                    f"unmatched closing '{ch}'", line)
                return
    if depth != 0:
        err(src, "KQL-BRACKET", f"{depth} unclosed bracket(s) in the query")


def check_string_vs_int(src, query, base_line=0):
    """A string column compared against a numeric literal."""
    # where <col> in (80, 443, ...)  /  where <col> == 0
    pat = re.compile(
        r"\b(" + "|".join(sorted(STRING_COLUMNS, key=len, reverse=True)) + r")\b"
        r"\s*(==|!=|in|!in)\s*\(?\s*(\d+)(?![\w.])")
    for m in pat.finditer(query):
        col, op, num = m.group(1), m.group(2), m.group(3)
        line = base_line + query[:m.start()].count("\n")
        err(src, "KQL-TYPE",
            f"'{col}' is a STRING column but is compared with the numeric "
            f"literal {num} using '{op}' - the comparison never matches. "
            f"Use a quoted literal or cast the column with tostring()")


def check_protocol_as_http(src, query, base_line=0):
    """Protocol carries the transport protocol, never the application one."""
    for m in re.finditer(r"\bProtocol\s+in\s*\(\s*[\"']HTTP", query, re.IGNORECASE):
        line = base_line + query[:m.start()].count("\n")
        err(src, "KQL-DEAD-BRANCH",
            "Protocol carries the transport protocol (TCP/UDP/ICMP) in "
            "CommonSecurityLog, never HTTP. Use ApplicationProtocol for the "
            "application layer. This branch can never match.", line)


def check_coalesce_empty(src, query, base_line=0):
    """coalesce() returns the first NON-NULL value, not the first non-empty."""
    for m in re.finditer(r"coalesce\(\s*(\w+)\s*,\s*(\w+)\s*\)", query):
        col = m.group(1)
        line = base_line + query[:m.start()].count("\n")
        if col in STRING_COLUMNS:
            warn(src, "KQL-COALESCE",
                f"coalesce({col}, ...) returns {col} even when it is an empty "
                "string, because coalesce skips NULL, not empty. Use "
                f"iff(isnotempty({col}), {col}, ...) instead", line)


def check_geo_country(src, query, base_line=0):
    """country name matching is unreliable; country_2 is the stable form.

    Only flagged when the country value is compared against a list - that is
    the failure pattern (a list of English country names never matching what
    the geolocation provider actually returns). Using .country for display is
    fine and is not flagged.
    """
    if ".country" not in query:
        return
    if not re.search(r"(?i)\blet\s+\w*countr\w*\s*=", query):
        return
    for m in re.finditer(r"geo_info_from_ip_address\([^)]*\)\.country(?![_2])", query):
        line = base_line + query[:m.start()].count("\n")
        warn(src, "KQL-GEO",
            "'.country' returns a display name such as 'Russian Federation' "
            "or 'Korea, Democratic People's Republic of'. Use '.country_2' for "
            "a stable ISO 3166-1 alpha-2 code when matching against a list", line)


def check_empty_allow(src, query, base_line=0):
    """An allow-list that ends up empty because the column is a string."""
    for m in re.finditer(r"tolower\((\w+)\)\s+in\s*\(\s*\)", query):
        line = base_line + query[:m.start()].count("\n")
        err(src, "KQL-EMPTY-LIST", "empty allow-list", line)


def check_functions(src, query, base_line=0):
    """Flag functions that do not exist in Kusto."""
    known = {
        "has_any", "has_all", "has", "contains", "contains_cs", "startswith",
        "endswith", "matches", "extract", "extract_all", "replace",
        "replace_string", "replace_regex", "split", "substring", "tolower",
        "toupper", "trim", "isnotempty", "isempty", "isnull", "notnull",
        "isnotnull", "dynamic", "todynamic", "toreal", "todouble", "tolong",
        "toint", "tostring", "tobool", "todatetime", "count",
        "countif", "dcount", "dcountif", "make_set", "make_list", "make_bag",
        "make_array", "sum", "avg", "stdev", "variance", "percentiles", "min",
        "max", "arg_max", "arg_min", "any", "bin", "bin_at", "case", "iff",
        "coalesce", "round", "strlen", "countof", "array_length", "array_slice",
        "array_index_of", "array_union", "array_concat", "array_distinct",
        "array_sort", "set_difference", "set_intersect", "set_union",
        "set_has_element", "parse_json", "parse_xml", "parse_csv",
        "parse_ipv4", "parse_ipv6", "ipv4_is_private", "ipv4_is_valid",
        "ipv4_is_in_range", "ipv4_is_in_any_range", "is_ipv4", "is_ipv6",
        "geo_info_from_ip_address", "mv-expand", "mv-apply", "summarize",
        "join", "union", "top", "top-nested", "range", "repeat",
        "datetime_add", "datetime_diff", "year", "month", "dayofyear",
        "dayofmonth", "dayofweek", "hour", "minute", "second", "week",
        "now", "ago", "rand", "guid", "toscalar", "bag_unpack", "evaluate",
        "column_ifexists", "url_decode", "url_encode",
        "base64_decode_tostring", "base64_encode_tostring", "zlib_decompress",
        "binary_and", "binary_shift_right", "hash_sha256", "hash_md5",
        "sha256", "md5", "series_stats", "series_fin", "series_seasonal",
        "seasonal", "series_outliers", "datetime_utc_to_local",
        "datetime_local_to_utc", "strcat_array", "strcat_delim",
        "print", "render", "search", "find",
        # Kusto operators and keywords that also take a parenthesised list
        "in", "notin", "has_any", "has_all", "between", "in~", "has_cs",
        "not", "and", "or", "where",
        # further valid Kusto scalars
        "abs", "indexof", "hourofday", "startofday", "endofday",
        "startofmonth", "endofmonth", "startofyear", "endofyear",
        "startofweek", "endofweek", "dayofweek", "dayofyear", "dayofmonth",
        "weekofyear", "monthofyear", "floor", "ceil", "exp", "log", "log2",
        "exp2", "sqrt", "sign", "pi", "e", "rand", "range", "repeat",
        "isempty", "isnotempty", "isnull", "notnull", "not", "in",
        "strcat", "strcat_array", "strcat_delim", "array_slice",
        "array_index_of", "array_union", "array_concat", "array_distinct",
        "array_sort", "array_remove_at", "array_slice", "array_zip",
        "set_difference", "set_intersect", "set_union", "set_has_element",
        "bin_at", "percentiles", "percentile", "stdevp", "variancep",
        "sumif", "minif", "maxif", "dcountif", "countif", "makelist",
        "make_bag", "make_set", "make_array", "pack", "pack_all",
        "pack_array", "unpack", "unpack_all", "unpack_array", "tolower",
        "toupper", "trim", "trim_end", "trim_start", "substring",
        "substring_index", "replace", "replace_string", "replace_regex",
        "extract", "extract_all", "split", "split_at",
    }
    scan = strip_strings(query)
    for m in re.finditer(r"(?<![.\w])([a-z_][a-z0-9_]*)\s*\(", scan, re.IGNORECASE):
        fn = m.group(1)
        if fn.lower() in known:
            continue
        line = base_line + query[:m.start()].count("\n")
        warn(src, "KQL-FUNCTION",
             f"function '{fn}()' is not a known Kusto function - verify it exists "
             "in the workspace", line)


def check_table(src, query, base_line=0):
    """The query must start from a table reference."""
    first = query.strip().splitlines()
    if not first:
        err(src, "KQL-EMPTY", "query is empty")
        return
    head = first[0].strip()
    if head.startswith("|") or head.startswith("let"):
        return  # let-first is fine
    if re.match(r"^[A-Za-z_]\w*$", head) and head not in {
            "CommonSecurityLog", "SecurityEvent", "WindowsEvent", "Syslog",
            "CommonSecurityLog_CL", "SigninLogs", "SigninLogs_CL",
            "ThreatIntelIndicators", "SecurityAlert", "IdentityInfo",
            "OfficeActivity", "AuditLogs", "AzureDiagnostics", "DeviceEvents",
            "DeviceProcessEvents", "DeviceNetworkEvents", "AADNonInteractiveUserSignInLogs",
            "AADUserRiskEvents", "CloudAppEvents", "W3CIISLog", "DnsEvents"}:
        warn(src, "KQL-TABLE",
             f"query starts with '{head}' which is not a known table - verify "
             "it exists in the target workspace", base_line)


ALL_CHECKS = (check_parens, check_string_vs_int, check_protocol_as_http,
              check_coalesce_empty, check_geo_country, check_empty_allow,
              check_functions, check_table)


def lint_query(src, query, base_line=0):
    clean = strip_comments(query)
    if not clean.strip():
        # a comment-only block (file header, banner) - nothing to check
        return
    for fn in ALL_CHECKS:
        fn(src, clean, base_line)


# --------------------------------------------------------------------------
# Extractors
# --------------------------------------------------------------------------

def lint_yaml_file(path):
    try:
        with open(path, encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d]
    except Exception as exc:  # noqa: BLE001
        err(os.path.basename(path), "YAML-PARSE", str(exc))
        return
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        q = doc.get("query")
        if isinstance(q, str) and q.strip():
            lint_query(os.path.basename(path), q)


def lint_kql_file(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # Blocks separated by a comment banner of ==== lines
    blocks = re.split(r"(?m)^//\s*={10,}\s*$", text)
    base = 0
    for block in blocks:
        # drop the comment header lines of the block
        lines = block.split("\n")
        start = 0
        for i, ln in enumerate(lines):
            s = ln.strip()
            if s.startswith("//") or not s:
                continue
            start = i
            break
        body = "\n".join(lines[start:])
        if not body.strip():
            base += block.count("\n") + 1
            continue
        lint_query(os.path.basename(path), body, base)
        base += block.count("\n") + 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    files = []
    for p in args.paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "**", "*.yaml"), recursive=True))
            files += sorted(glob.glob(os.path.join(p, "**", "*.yml"), recursive=True))
            files += sorted(glob.glob(os.path.join(p, "**", "*.kql"), recursive=True))
        else:
            files.append(p)

    files = [f for f in files if "azuredeploy" not in os.path.basename(f).lower()]

    if not files:
        print("no files to lint")
        return 2

    for f in files:
        if f.lower().endswith((".yaml", ".yml")):
            lint_yaml_file(f)
        elif f.lower().endswith(".kql"):
            lint_kql_file(f)

    errs = [i for i in issues if i[0] == "ERROR"]
    warns = [i for i in issues if i[0] == "WARN"]

    for level, code, src, line, msg in issues:
        loc = f"{src}:{line}" if line is not None else src
        print(f"{level:<5} {code:<18} {loc:<45} {msg}")

    print()
    print(f"files: {len(files)}   errors: {len(errs)}   warnings: {len(warns)}")
    if errs:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
