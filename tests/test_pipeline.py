"""Tests for the intelligence pipeline."""

import sys
import os
import unittest

import pytest

# The pipeline pulls in `requests` (and `jsonschema`); they ship in the `dev`
# extra, but guard here too so a bare install skips these tests cleanly instead
# of aborting collection for the entire suite (audit F-1).
pytest.importorskip("requests")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.fetch_nvd_intel import (
    map_cvss_to_severity,
    map_cwe_to_type,
    extract_title,
    process_vulnerability,
    extract_cpe,
)


class TestCvssSeverity(unittest.TestCase):
    """Test CVSS score to severity mapping."""

    def test_critical(self):
        self.assertEqual(map_cvss_to_severity(9.8), "critical")
        self.assertEqual(map_cvss_to_severity(10.0), "critical")
        self.assertEqual(map_cvss_to_severity(9.0), "critical")

    def test_high(self):
        self.assertEqual(map_cvss_to_severity(8.5), "high")
        self.assertEqual(map_cvss_to_severity(7.0), "high")

    def test_medium(self):
        self.assertEqual(map_cvss_to_severity(6.5), "medium")
        self.assertEqual(map_cvss_to_severity(4.0), "medium")

    def test_low(self):
        self.assertEqual(map_cvss_to_severity(3.9), "low")
        self.assertEqual(map_cvss_to_severity(0.1), "low")

    def test_unknown(self):
        self.assertEqual(map_cvss_to_severity(None), "unknown")
        self.assertEqual(map_cvss_to_severity(0), "unknown")


class TestCweTypeMapping(unittest.TestCase):
    """Test CWE to threat type mapping."""

    def test_command_injection(self):
        self.assertEqual(map_cwe_to_type(["CWE-78"]), "unsafe_tool_execution")

    def test_code_injection(self):
        self.assertEqual(map_cwe_to_type(["CWE-94"]), "unsafe_tool_execution")

    def test_xss(self):
        self.assertEqual(map_cwe_to_type(["CWE-79"]), "prompt_injection")

    def test_info_disclosure(self):
        self.assertEqual(map_cwe_to_type(["CWE-200"]), "data_exfiltration")

    def test_dos(self):
        self.assertEqual(map_cwe_to_type(["CWE-400"]), "model_denial_of_service")

    def test_access_control(self):
        self.assertEqual(map_cwe_to_type(["CWE-284"]), "policy_bypass")

    def test_deserialization(self):
        self.assertEqual(map_cwe_to_type(["CWE-502"]), "unsafe_tool_execution")

    def test_ssrf(self):
        self.assertEqual(map_cwe_to_type(["CWE-918"]), "data_exfiltration")

    def test_path_traversal(self):
        self.assertEqual(map_cwe_to_type(["CWE-22"]), "data_exfiltration")

    def test_supply_chain(self):
        self.assertEqual(map_cwe_to_type(["CWE-494"]), "dependency_vulnerability")

    def test_protection_mechanism_failure(self):
        self.assertEqual(map_cwe_to_type(["CWE-693"]), "jailbreak")

    def test_unknown_cwe(self):
        self.assertEqual(map_cwe_to_type(["CWE-99999"]), "unknown")

    def test_empty_cwes(self):
        self.assertEqual(map_cwe_to_type([]), "unknown")

    def test_first_match_wins(self):
        # Should return the type of the first matched CWE
        result = map_cwe_to_type(["CWE-78", "CWE-200"])
        self.assertEqual(result, "unsafe_tool_execution")

    # Description-based fallback
    def test_description_fallback_rce(self):
        self.assertEqual(
            map_cwe_to_type([], description="allows remote code execution via crafted input"),
            "unsafe_tool_execution",
        )

    def test_description_fallback_prompt_injection(self):
        self.assertEqual(
            map_cwe_to_type([], description="prompt injection vulnerability in the chat endpoint"),
            "prompt_injection",
        )

    def test_description_fallback_ssrf(self):
        self.assertEqual(
            map_cwe_to_type([], description="server-side request forgery allows reading internal services"),
            "data_exfiltration",
        )

    def test_description_fallback_dos(self):
        self.assertEqual(
            map_cwe_to_type([], description="ReDoS vulnerability in the regex parser"),
            "model_denial_of_service",
        )

    def test_description_fallback_auth_bypass(self):
        self.assertEqual(
            map_cwe_to_type([], description="authentication bypass allows unauthorized access"),
            "policy_bypass",
        )

    def test_description_no_match(self):
        self.assertEqual(
            map_cwe_to_type([], description="a minor cosmetic issue in the UI"),
            "unknown",
        )

    def test_cwe_takes_precedence_over_description(self):
        # CWE-78 is unsafe_tool_execution, description says "prompt injection"
        result = map_cwe_to_type(["CWE-78"], description="prompt injection vulnerability")
        self.assertEqual(result, "unsafe_tool_execution")


class TestExtractTitle(unittest.TestCase):
    """Test title extraction from CVE descriptions."""

    def test_component_with_vuln_type(self):
        title = extract_title("CVE-2023-1234", "In LangChain through 0.0.131, remote code execution is possible")
        self.assertIn("LangChain", title)
        self.assertIn("RCE", title)

    def test_component_before_version(self):
        title = extract_title("CVE-2023-5678", "LlamaIndex before 0.9.0 allows SQL injection")
        self.assertIn("LlamaIndex", title)
        self.assertIn("SQL Injection", title)

    def test_no_description(self):
        self.assertEqual(extract_title("CVE-2023-0000", ""), "CVE-2023-0000")
        self.assertEqual(extract_title("CVE-2023-0000", "No description available"), "CVE-2023-0000")

    def test_short_description_used_as_title(self):
        title = extract_title("CVE-2023-9999", "OpenAI SDK has a minor issue")
        self.assertNotEqual(title, "")
        self.assertTrue(len(title) <= 100)

    def test_long_description_truncated(self):
        long_desc = "A " * 200
        title = extract_title("CVE-2023-0001", long_desc)
        self.assertTrue(len(title) <= 103)  # 100 + "..."


class TestProcessVulnerability(unittest.TestCase):
    """Test the full vulnerability processing pipeline."""

    def test_basic_vuln(self):
        mock = {
            "cve": {
                "id": "CVE-2024-TEST",
                "descriptions": [{"lang": "en", "value": "LangChain allows remote code execution via eval"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-94"}]}],
                "configurations": [],
                "references": [
                    {"url": "https://example.com/1"},
                    {"url": "https://example.com/1"},  # duplicate
                    {"url": "https://example.com/2"},
                ],
                "published": "2024-01-01T00:00:00",
            }
        }
        result = process_vulnerability(mock)

        self.assertEqual(result["id"], "CVE-2024-TEST")
        self.assertEqual(result["severity"], "critical")
        self.assertEqual(result["type"], "unsafe_tool_execution")
        self.assertNotEqual(result["title"], "NVD Entry for CVE-2024-TEST")  # No longer generic
        self.assertNotEqual(result["action"], "Investigate and update affected component.")  # No longer generic
        self.assertEqual(len(result["references"]), 2)  # Deduplicated

    def test_no_metrics(self):
        mock = {
            "cve": {
                "id": "CVE-2024-NOMETRIC",
                "descriptions": [{"lang": "en", "value": "Test vuln"}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
                "references": [],
                "published": "2024-01-01T00:00:00",
            }
        }
        result = process_vulnerability(mock)
        self.assertEqual(result["severity"], "unknown")


if __name__ == "__main__":
    unittest.main()
