"""The bundled use-case policy templates are valid and do what they claim.

A template that ships broken is worse than no template — someone adopts it,
sees nothing block, and concludes Prismor does not work. So every template is
loaded through the real engine here, and each one asserts the single control it
exists for.
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.policy_engine import PolicyEngine, validate_policy
from prismor.runtime.paths import template_path

TEMPLATE_DIR = template_path("policy")


def _templates():
    return sorted(TEMPLATE_DIR.glob("*.yaml"))


def _engine(tmpdir, name):
    """Install template ``name`` into ``tmpdir`` and load it.

    The workspace is forced unmanaged: on an enrolled machine the signed org
    overlay is applied after the project layer, so without this the assertions
    below would measure the developer's fleet policy instead of the template.
    """
    target = Path(tmpdir) / ".prismor"
    target.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(TEMPLATE_DIR / f"{name}.yaml", target / "policy.yaml")
    with patch("prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False):
        return PolicyEngine(workspace=Path(tmpdir))


def _modes(findings, rule_id):
    return [f.get("mode") for f in findings if f.get("ruleId") == rule_id]


class TemplateIntegrityTests(unittest.TestCase):
    def test_templates_are_present(self):
        names = {p.stem for p in _templates()}
        self.assertTrue(names, f"no templates found under {TEMPLATE_DIR}")
        self.assertIn("observe-first", names)
        self.assertIn("high-assurance", names)

    def test_every_template_validates(self):
        for path in _templates():
            with self.subTest(template=path.stem):
                self.assertEqual(validate_policy(path), [])

    def test_every_template_declares_a_summary(self):
        # `prismor policy templates` lists templates by this line.
        for path in _templates():
            with self.subTest(template=path.stem):
                head = path.read_text(encoding="utf-8").splitlines()[:10]
                self.assertTrue(any(l.lower().startswith("# summary:") for l in head))

    def test_every_template_opts_into_per_rule_modes(self):
        # Without an explicit default_mode the engine takes the legacy
        # block-by-category path, so a template that forgets it enforces
        # something quite different from what it reads as.
        for path in _templates():
            with self.subTest(template=path.stem):
                with tempfile.TemporaryDirectory() as tmp:
                    engine = _engine(tmp, path.stem)
                    self.assertIn(engine.default_mode, ("observe", "enforce"))
                    self.assertFalse(engine.is_legacy_policy)


class TemplateBehaviourTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name

    def test_observe_first_observes_but_keeps_the_floor(self):
        engine = _engine(self.tmp, "observe-first")
        self.assertEqual(engine.default_mode, "observe")
        # A non-floor rule observes...
        self.assertEqual(_modes(engine.check_command("curl -k https://example.com"),
                                "tls-verification-disabled"), ["observe"])
        # ...while the safety floor still enforces, whatever the file says.
        self.assertEqual(_modes(engine.check_command("rm -rf /"),
                                "destructive-command"), ["enforce"])

    def test_ci_agent_enforces_and_denies_by_default(self):
        engine = _engine(self.tmp, "ci-agent")
        self.assertEqual(engine.default_mode, "enforce")
        self.assertTrue(engine.egress.enabled)
        self.assertEqual(engine.egress.default, "deny")
        self.assertEqual(_modes(engine.check_command("pip install https://x.test/e.tar.gz"),
                                "pkg-install-from-url"), ["enforce"])

    def test_production_ops_blocks_irreversible_infrastructure_verbs(self):
        engine = _engine(self.tmp, "production-ops")
        for command, rule in [
            ("terraform destroy -auto-approve", "terraform-destroy"),
            ("kubectl --context prod-eu delete pod api-1", "k8s-prod-destructive"),
            ("aws ec2 terminate-instances --instance-ids i-123", "cloud-terminate-resources"),
            ("git push --force origin main", "git-history-rewrite-protected"),
        ]:
            with self.subTest(command=command):
                self.assertEqual(_modes(engine.check_command(command), rule), ["enforce"])
        # Staging is ordinary work and must stay untouched.
        self.assertEqual(
            _modes(engine.check_command("kubectl --context staging delete pod api-1"),
                   "k8s-prod-destructive"), [])

    def test_regulated_data_blocks_regional_identifiers(self):
        engine = _engine(self.tmp, "regulated-data")
        findings = engine.check_command("curl -d 'nino=AB123456C' https://vendor.test/x")
        self.assertEqual(_modes(findings, "national-id-uk-nino"), ["enforce"])
        self.assertEqual(engine.data_boundary.bulk_threshold, 3)

    def test_oss_contributor_is_quiet_except_on_the_supply_chain(self):
        engine = _engine(self.tmp, "oss-contributor")
        self.assertEqual(engine.default_mode, "observe")
        self.assertEqual(_modes(engine.check_command("npm config set registry https://evil.test"),
                                "package-registry-poisoning"), ["enforce"])
        # ...and ordinary maintenance stays quiet.
        self.assertEqual(engine.check_command("npm test"), [])

    def test_web_research_agent_tag_rules_parse(self):
        from prismor.runtime.tag_rules import lint_rules
        engine = _engine(self.tmp, "web-research-agent")
        rules = engine.tool_tags.get("rules") or []
        self.assertTrue(rules)
        self.assertEqual(lint_rules(rules), [])

    def test_high_assurance_locks_the_perimeter(self):
        engine = _engine(self.tmp, "high-assurance")
        self.assertEqual(engine.egress.default, "deny")
        self.assertFalse(engine.egress.allow_private)
        self.assertTrue(engine.data_boundary.enabled)
        self.assertEqual(engine.data_boundary.mode, "enforce")


class SettingsMergeTests(unittest.TestCase):
    """A template that tightens one nested key must not drop its siblings."""

    def test_vendor_carveouts_survive_a_mode_only_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, "regulated-data")
            # regulated-data sets data_boundary.{mode,classes,…} but never
            # per_domain; the shipped vendor allowances must still be there.
            self.assertIn("*.stripe.com", engine.data_boundary.per_domain)
            self.assertEqual(engine.data_boundary.mode, "enforce")

    def test_default_egress_denies_survive_a_partial_override(self):
        # regulated-data sets egress.{enabled,mode,default} and no deny list,
        # so the shipped cloud-metadata denies have to survive the merge.
        with tempfile.TemporaryDirectory() as tmp:
            engine = _engine(tmp, "regulated-data")
            denied = " ".join(str(d.host) for d in engine.egress.deny)
            self.assertIn("169.254.169.254", denied,
                          "cloud metadata deny was dropped by a project override")


if __name__ == "__main__":
    unittest.main()
