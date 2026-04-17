import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RETRIES = 5
BASE_DELAY_SECONDS = 5

KEYWORDS = [
    "LangChain",
    "LlamaIndex",
    "OpenAI",
    "Anthropic",
    "Prompt Injection",
    "CrewAI",
    "AutoGPT",
    "Vanna"
]

def map_cvss_to_severity(cvss_score):
    if not cvss_score:
        return "unknown"
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    else:
        return "low"

CWE_TYPE_MAP = {
    # Unsafe tool execution / code injection
    "CWE-78": "unsafe_tool_execution",   # OS Command Injection
    "CWE-94": "unsafe_tool_execution",   # Code Injection
    "CWE-95": "unsafe_tool_execution",   # Eval Injection
    "CWE-96": "unsafe_tool_execution",   # Static Code Injection
    "CWE-77": "unsafe_tool_execution",   # Command Injection
    "CWE-74": "unsafe_tool_execution",   # Injection (general)
    "CWE-116": "unsafe_tool_execution",  # Improper Encoding/Escaping of Output
    "CWE-502": "unsafe_tool_execution",  # Deserialization of Untrusted Data
    "CWE-913": "unsafe_tool_execution",  # Improper Control of Dynamically-Managed Code Resources
    "CWE-915": "unsafe_tool_execution",  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
    "CWE-1321": "unsafe_tool_execution", # Prototype Pollution
    # Prompt injection / input validation
    "CWE-79": "prompt_injection",        # Cross-site Scripting (injection via input)
    "CWE-20": "prompt_injection",        # Improper Input Validation
    "CWE-75": "prompt_injection",        # Failure to Sanitize Special Elements in a Different Plane
    "CWE-88": "prompt_injection",        # Improper Neutralization of Argument Delimiters
    "CWE-89": "prompt_injection",        # SQL Injection
    "CWE-90": "prompt_injection",        # LDAP Injection
    "CWE-91": "prompt_injection",        # XML Injection
    "CWE-93": "prompt_injection",        # CRLF Injection
    "CWE-113": "prompt_injection",       # HTTP Response Splitting
    "CWE-917": "prompt_injection",       # Expression Language Injection
    "CWE-1236": "prompt_injection",      # Formula Injection (CSV)
    # Data exfiltration / information disclosure
    "CWE-200": "data_exfiltration",      # Exposure of Sensitive Information
    "CWE-201": "data_exfiltration",      # Insertion of Sensitive Information into Sent Data
    "CWE-209": "data_exfiltration",      # Error Message Information Leak
    "CWE-213": "data_exfiltration",      # Exposure of Sensitive Information Due to Incompatible Policies
    "CWE-215": "data_exfiltration",      # Insertion of Sensitive Information into Debug Code
    "CWE-312": "data_exfiltration",      # Cleartext Storage of Sensitive Information
    "CWE-319": "data_exfiltration",      # Cleartext Transmission of Sensitive Information
    "CWE-532": "data_exfiltration",      # Insertion of Sensitive Information into Log Files
    "CWE-538": "data_exfiltration",      # Insertion of Sensitive Information into Externally-Accessible File/Dir
    "CWE-598": "data_exfiltration",      # Use of GET Request Method with Sensitive Query Strings
    "CWE-611": "data_exfiltration",      # XXE (can exfiltrate data)
    "CWE-918": "data_exfiltration",      # SSRF (can exfiltrate internal data)
    "CWE-22": "data_exfiltration",       # Path Traversal (can read arbitrary files)
    "CWE-23": "data_exfiltration",       # Relative Path Traversal
    "CWE-36": "data_exfiltration",       # Absolute Path Traversal
    # Denial of service
    "CWE-400": "model_denial_of_service",  # Uncontrolled Resource Consumption
    "CWE-770": "model_denial_of_service",  # Allocation of Resources Without Limits
    "CWE-776": "model_denial_of_service",  # Recursive Entity References (XML bomb)
    "CWE-835": "model_denial_of_service",  # Infinite Loop
    "CWE-674": "model_denial_of_service",  # Uncontrolled Recursion
    "CWE-1333": "model_denial_of_service", # ReDoS
    "CWE-405": "model_denial_of_service",  # Asymmetric Resource Consumption
    # Policy bypass / access control
    "CWE-284": "policy_bypass",          # Improper Access Control
    "CWE-285": "policy_bypass",          # Improper Authorization
    "CWE-287": "policy_bypass",          # Improper Authentication
    "CWE-290": "policy_bypass",          # Authentication Bypass by Spoofing
    "CWE-306": "policy_bypass",          # Missing Authentication for Critical Function
    "CWE-307": "policy_bypass",          # Improper Restriction of Excessive Auth Attempts
    "CWE-352": "policy_bypass",          # CSRF
    "CWE-639": "policy_bypass",          # Authorization Bypass Through User-Controlled Key (IDOR)
    "CWE-862": "policy_bypass",          # Missing Authorization
    "CWE-863": "policy_bypass",          # Incorrect Authorization
    "CWE-798": "policy_bypass",          # Use of Hard-coded Credentials
    "CWE-321": "policy_bypass",          # Use of Hard-coded Cryptographic Key
    # Dependency / supply chain
    "CWE-426": "dependency_vulnerability",  # Untrusted Search Path
    "CWE-427": "dependency_vulnerability",  # Uncontrolled Search Path Element
    "CWE-494": "dependency_vulnerability",  # Download of Code Without Integrity Check
    "CWE-829": "dependency_vulnerability",  # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-1104": "dependency_vulnerability", # Use of Unmaintained Third Party Components
    # Jailbreak patterns (less common via CWE, but map relevant ones)
    "CWE-693": "jailbreak",             # Protection Mechanism Failure
    "CWE-184": "jailbreak",             # Incomplete List of Disallowed Inputs
    # Additional privilege / access control CWEs
    "CWE-269": "policy_bypass",          # Improper Privilege Management
    "CWE-250": "policy_bypass",          # Execution with Unnecessary Privileges
    "CWE-264": "policy_bypass",          # Permissions, Privileges, Access Controls
    # Additional DoS CWEs
    "CWE-399": "model_denial_of_service", # Resource Management Errors
    # Memory corruption → RCE
    "CWE-119": "unsafe_tool_execution",  # Buffer Overflow
    "CWE-120": "unsafe_tool_execution",  # Buffer Copy without Size Checking
}

# Keyword patterns for description-based fallback classification
DESCRIPTION_TYPE_PATTERNS = [
    ("unsafe_tool_execution", [
        r"remote code execution", r"\bRCE\b", r"arbitrary code", r"code execution",
        r"code injection", r"command injection", r"os\.system", r"\bexec\b.*method",
        r"\beval\b", r"deserialization", r"pickle", r"arbitrary command",
        r"execute.*command", r"shell injection",
    ]),
    ("prompt_injection", [
        r"prompt injection", r"inject.*prompt", r"SQL injection",
        r"cross-site scripting", r"\bXSS\b", r"LDAP injection",
        r"XML injection", r"template injection", r"SSTI",
    ]),
    ("data_exfiltration", [
        r"information disclosure", r"sensitive information", r"data leak",
        r"path traversal", r"directory traversal", r"file read",
        r"unauthorized.*read", r"\bSSRF\b", r"server-side request forgery",
        r"\bXXE\b", r"XML external entity", r"exfiltrat",
    ]),
    ("jailbreak", [
        r"jailbreak", r"bypass.*guard", r"bypass.*filter", r"bypass.*restriction",
        r"escape.*sandbox", r"circumvent.*security",
    ]),
    ("model_denial_of_service", [
        r"denial.of.service", r"\bDoS\b", r"\bReDoS\b", r"resource consumption",
        r"infinite loop", r"memory exhaustion", r"crash.*service",
    ]),
    ("policy_bypass", [
        r"authentication bypass", r"authorization bypass", r"access control",
        r"privilege escalation", r"permission.*bypass", r"CSRF",
        r"hard.?coded.*credential", r"hard.?coded.*key",
    ]),
    ("dependency_vulnerability", [
        r"supply chain", r"dependency confusion", r"typosquat",
        r"untrusted.*package", r"malicious.*package", r"backdoor",
    ]),
]

import re
_DESCRIPTION_PATTERNS_COMPILED = [
    (threat_type, [re.compile(p, re.IGNORECASE) for p in patterns])
    for threat_type, patterns in DESCRIPTION_TYPE_PATTERNS
]


def map_cwe_to_type(cwes, description=""):
    """Map CWEs to Prismor threat types, with description-based fallback."""
    for cwe in cwes:
        if cwe in CWE_TYPE_MAP:
            return CWE_TYPE_MAP[cwe]

    # Fallback: keyword matching on description
    if description:
        for threat_type, patterns in _DESCRIPTION_PATTERNS_COMPILED:
            for pattern in patterns:
                if pattern.search(description):
                    return threat_type

    return "unknown"

def extract_cpe(configurations):
    """Extract affected CPE strings."""
    affected = []
    if not configurations:
        return affected
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                affected.append(match.get("criteria", "unknown-configuration"))
    return list(set(affected)) # deduplicate

def fetch_nvd_data(keyword, last_mod_start_date=None, last_mod_end_date=None):
    params = {
        "keywordSearch": keyword
    }
    # If delta dates are provided, use them. Need to ensure format is correctly ISO8601 for NVD.
    if last_mod_start_date and last_mod_end_date:
        params["lastModStartDate"] = last_mod_start_date
        params["lastModEndDate"] = last_mod_end_date

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
            elif response.status_code in [403, 429]:
                 # Rate limiting
                 delay = BASE_DELAY_SECONDS * (2 ** attempt)
                 print(f"Rate limited (status {response.status_code}). Retrying in {delay} seconds...", file=sys.stderr)
                 time.sleep(delay)
            else:
                print(f"Error fetching data from NVD: {response.status_code} - {response.text}", file=sys.stderr)
                return []
        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}. Retrying in {BASE_DELAY_SECONDS} seconds...", file=sys.stderr)
            time.sleep(BASE_DELAY_SECONDS)
            
    print(f"Failed to fetch data for {keyword} after {MAX_RETRIES} attempts.", file=sys.stderr)
    return []

TYPE_ACTION_MAP = {
    "unsafe_tool_execution": "Pin or upgrade the affected package to a patched version. Audit all uses of dynamic code execution (exec, eval, os.system, subprocess) and ensure untrusted input cannot reach them.",
    "prompt_injection": "Upgrade to a version that sanitizes inputs. Validate and sanitize all user-supplied input before passing it to LLM chains. Apply input/output guardrails.",
    "data_exfiltration": "Upgrade to a patched version. Review data access patterns and apply least-privilege principles. Ensure sensitive data is not exposed through error messages, logs, or API responses.",
    "jailbreak": "Upgrade the affected component. Review security filters and guardrails for bypass vectors. Implement defense-in-depth with multiple validation layers.",
    "policy_bypass": "Upgrade to a patched version. Review authentication and authorization controls. Ensure proper access control checks on all sensitive operations.",
    "dependency_vulnerability": "Upgrade the affected dependency to a patched version. Verify package integrity using checksums or signatures. Pin dependencies to known-good versions.",
    "model_denial_of_service": "Upgrade to a patched version. Implement resource limits, timeouts, and input size validation. Monitor for unusual resource consumption.",
    "unknown": "Investigate the vulnerability and upgrade the affected component to the latest patched version.",
}


def extract_title(vuln_id, description):
    """Extract a meaningful title from the CVE description."""
    if not description or description == "No description available":
        return vuln_id

    # Extract the component name from common NVD patterns
    component = ""
    component_patterns = [
        re.compile(r"^(?:An? (?:issue|vulnerability|flaw|bug) in |In )([A-Za-z][A-Za-z0-9_./-]+)", re.IGNORECASE),
        re.compile(r"^([A-Za-z][A-Za-z0-9_./-]+)\s+(?:before|through|up to|prior to|<=?|versions?)\s", re.IGNORECASE),
        re.compile(r"^([A-Za-z][A-Za-z0-9_./-]+)\s+(?:is vulnerable|has|contains|allows|was discovered)", re.IGNORECASE),
    ]
    for pattern in component_patterns:
        m = pattern.match(description)
        if m:
            component = m.group(1).rstrip(".,;:")
            break

    # Extract the vulnerability type
    vuln_type = ""
    type_patterns = [
        (r"remote code execution|arbitrary code execution|\bRCE\b", "RCE"),
        (r"command injection|OS command injection", "Command Injection"),
        (r"code injection", "Code Injection"),
        (r"SQL injection", "SQL Injection"),
        (r"prompt injection", "Prompt Injection"),
        (r"cross-site scripting|\bXSS\b", "XSS"),
        (r"path traversal|directory traversal", "Path Traversal"),
        (r"server-side request forgery|\bSSRF\b", "SSRF"),
        (r"XML external entity|\bXXE\b", "XXE"),
        (r"denial.of.service|\bDoS\b|\bReDoS\b", "Denial of Service"),
        (r"information disclosure|sensitive information.*expos", "Information Disclosure"),
        (r"authentication bypass", "Authentication Bypass"),
        (r"authorization bypass|access control", "Authorization Bypass"),
        (r"deserialization", "Insecure Deserialization"),
        (r"privilege escalation", "Privilege Escalation"),
        (r"open redirect", "Open Redirect"),
        (r"prototype pollution", "Prototype Pollution"),
    ]
    for pattern, label in type_patterns:
        if re.search(pattern, description, re.IGNORECASE):
            vuln_type = label
            break

    if component and vuln_type:
        title = f"{component}: {vuln_type}"
    elif component:
        # Take first sentence as summary
        first_sentence = description.split(". ")[0].split(",")[0]
        if len(first_sentence) <= 80:
            title = first_sentence
        else:
            title = f"{component}: Security Vulnerability"
    elif vuln_type:
        title = f"{vuln_id}: {vuln_type}"
    else:
        first_sentence = description.split(". ")[0]
        if len(first_sentence) <= 100:
            title = first_sentence
        else:
            title = first_sentence[:97] + "..."

    return title


def process_vulnerability(vuln_item):
    cve_data = vuln_item.get("cve", {})

    vuln_id = cve_data.get("id", "UNKNOWN-ID")

    descriptions = cve_data.get("descriptions", [])
    description_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available")

    # Extract CVSS
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics:
        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

    severity = map_cvss_to_severity(cvss_score)

    # Extract CWEs
    weaknesses = cve_data.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        cwes.extend([desc.get("value") for desc in w.get("description", []) if desc.get("lang") == "en"])

    threat_type = map_cwe_to_type(cwes, description=description_text)

    # Extract Affected
    configurations = cve_data.get("configurations", [])
    affected = extract_cpe(configurations)

    # Extract References (deduplicated, preserving order)
    references = list(dict.fromkeys(ref.get("url") for ref in cve_data.get("references", []) if ref.get("url")))

    # Published date
    published_nvd = cve_data.get("published", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    threat_object = {
        "id": vuln_id,
        "severity": severity,
        "type": threat_type,
        "title": extract_title(vuln_id, description_text),
        "description": description_text,
        "affected": affected,
        "action": TYPE_ACTION_MAP.get(threat_type, TYPE_ACTION_MAP["unknown"]),
        "published": published_nvd,
        "references": references,
    }

    return threat_object

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Fetch AI-ecosystem vulnerabilities from the NVD API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s                          Fetch all keywords (full run)
  %(prog)s --keyword LangChain      Fetch a single keyword
  %(prog)s --dry-run                Show what would be fetched without calling NVD
  %(prog)s --keyword "Prompt Injection" --keyword OpenAI
""",
    )
    parser.add_argument(
        "--keyword", "-k",
        action="append",
        metavar="TERM",
        help="Fetch a specific keyword instead of all defaults. Can be repeated.",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Print the keywords that would be queried without making API calls.",
    )
    args = parser.parse_args()

    keywords = args.keyword if args.keyword else KEYWORDS

    if args.dry_run:
        print("Dry run — would query the following keywords:", file=sys.stderr)
        for kw in keywords:
            print(f"  - {kw}", file=sys.stderr)
        print(json.dumps([]), file=sys.stdout)
        return

    all_threats = []
    seen_ids = set()

    print(f"Starting NVD vulnerability fetch ({len(keywords)} keywords)...", file=sys.stderr)

    for keyword in keywords:
        print(f"Querying for keyword: {keyword}...", file=sys.stderr)
        vulns = fetch_nvd_data(keyword)

        for vuln in vulns:
            threat = process_vulnerability(vuln)
            vuln_id = threat["id"]

            if vuln_id not in seen_ids:
                all_threats.append(threat)
                seen_ids.add(vuln_id)

        # Respect NVD API limits (even with API key, play nice)
        time.sleep(2)

    print(f"Fetched {len(all_threats)} unique advisories.", file=sys.stderr)
    # Output raw JSON to stdout so it can be piped
    print(json.dumps(all_threats), file=sys.stdout)


if __name__ == "__main__":
    main()
