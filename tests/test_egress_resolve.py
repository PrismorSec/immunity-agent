"""Egress name resolution: a hostname must not hide the address it dials.

``deny: ["169.254.0.0/16"]`` is worthless if fetching ``imds.example.com``
skips it, so deny CIDRs and the metadata carve-out are re-checked against
resolved addresses. The invariant that keeps that from backfiring is
one-directional: resolution may turn an allow into a deny, never the reverse.
Extending the ``allow_private`` carve-out to resolved addresses would let an
attacker point a public name at 10.0.0.1 and be waved through — the very SSRF
the egress policy exists to stop.
"""
from __future__ import annotations

import pytest

from prismor.runtime import egress
from prismor.runtime.egress import Destination, EgressPolicy


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor-home"))
    monkeypatch.delenv("PRISMOR_EGRESS_RESOLVE", raising=False)
    egress._resolve_cache.clear()
    yield
    egress._resolve_cache.clear()


@pytest.fixture
def dns(monkeypatch):
    """Deterministic resolver. Unmapped names resolve to nothing."""
    table: dict = {}
    calls: list = []

    def _fake(host):
        calls.append(host)
        return tuple(table.get(host, ()))

    monkeypatch.setattr(egress, "_raw_resolve", _fake)
    _fake.table = table      # type: ignore[attr-defined]
    _fake.calls = calls      # type: ignore[attr-defined]
    return _fake


def _policy(**cfg):
    cfg.setdefault("enabled", True)
    return EgressPolicy.from_settings({"egress": cfg}, source="project")


def _dest(host, port=None, scheme="https"):
    return Destination(host, port=port, scheme=scheme, origin="url")


# ── the bypass ───────────────────────────────────────────────────────────────

def test_hostname_resolving_into_denied_cidr_is_denied(dns):
    """The core gap: a deny CIDR was only ever matched against IP literals."""
    dns.table["imds.example.com"] = ("169.254.169.254",)
    pol = _policy(default="allow", deny=[{"host": "169.254.0.0/16",
                                          "reason": "link-local"}])

    assert pol.verdict(_dest("169.254.169.254"))[0] == "deny"   # already worked
    assert pol.verdict(_dest("imds.example.com"))[0] == "deny"  # the fix


def test_hostname_resolving_into_denied_rfc1918_is_denied(dns):
    dns.table["intranet.example.com"] = ("10.4.5.6",)
    pol = _policy(default="allow", deny=[{"host": "10.0.0.0/8"}])

    assert pol.verdict(_dest("intranet.example.com"))[0] == "deny"


def test_internal_suffix_pointed_at_imds_loses_the_private_carveout(dns):
    """`.internal` gets the private carve-out; pointing it at IMDS must not."""
    dns.table["imds.corp.internal"] = ("169.254.169.254",)
    dns.table["files.corp.internal"] = ("10.0.0.9",)
    pol = _policy(default="deny", allow_private=True, allow=["*.github.com"])

    # An ordinary internal name still takes the carve-out.
    assert pol.verdict(_dest("files.corp.internal"))[0] == "allow"
    # One aimed at the metadata service does not, and falls to default deny.
    assert pol.verdict(_dest("imds.corp.internal"))[0] == "off-allowlist"


def test_metadata_ipv6_and_alibaba_literals_are_recognised(dns):
    dns.table["meta.example.com"] = ("fd00:ec2::254",)
    pol = _policy(default="deny", allow_private=True)

    assert _dest("meta.example.com").is_metadata(resolve=True) is True
    assert _dest("100.100.100.200").is_metadata() is True


def test_any_resolved_address_in_a_denied_range_blocks(dns):
    """Round-robin DNS must not become a coin flip."""
    dns.table["mixed.example.com"] = ("93.184.216.34", "10.0.0.5")
    pol = _policy(default="allow", deny=[{"host": "10.0.0.0/8"}])

    assert pol.verdict(_dest("mixed.example.com"))[0] == "deny"


# ── the invariant: resolution never loosens ──────────────────────────────────

def test_public_name_pointed_at_private_ip_is_not_waved_through(dns):
    """The reverse direction is the SSRF, not the fix."""
    dns.table["rebind.evil.test"] = ("10.0.0.5",)
    pol = _policy(default="deny", allow_private=True, allow=["*.github.com"])

    # Would be "allow" if the private carve-out consulted DNS.
    assert pol.verdict(_dest("rebind.evil.test"))[0] == "off-allowlist"


def test_allow_cidr_is_not_extended_by_resolution(dns):
    dns.table["sneaky.evil.test"] = ("192.0.2.7",)
    pol = _policy(default="deny", allow=[{"host": "192.0.2.0/24"}])

    assert pol.verdict(_dest("192.0.2.7"))[0] == "allow"          # literal, as before
    assert pol.verdict(_dest("sneaky.evil.test"))[0] == "off-allowlist"


def test_resolution_failure_leaves_the_verdict_unchanged(dns):
    """Unknown must read as unknown, never as safe — and never as a new block."""
    pol = _policy(default="allow", deny=[{"host": "10.0.0.0/8"}])

    assert pol.verdict(_dest("nxdomain.example.com"))[0] == "allow"


# ── cost control ─────────────────────────────────────────────────────────────

def test_ip_literals_never_hit_the_resolver(dns):
    pol = _policy(default="allow", deny=[{"host": "10.0.0.0/8"}])
    pol.verdict(_dest("10.0.0.5"))
    pol.verdict(_dest("93.184.216.34"))

    assert dns.calls == []


def test_no_cidr_entries_means_no_lookups(dns):
    """A host-only policy has nothing a resolved address could change."""
    pol = _policy(default="deny", allow=["*.github.com"],
                  deny=[{"host": "*.pastebin.com"}])
    pol.verdict(_dest("api.github.com"))
    pol.verdict(_dest("evil.example.com"))

    assert dns.calls == []


def test_resolution_is_memoized_per_destination(dns):
    dns.table["repeat.example.com"] = ("10.0.0.5",)
    pol = _policy(default="allow", deny=[{"host": "10.0.0.0/8"},
                                         {"host": "172.16.0.0/12"}])
    dest = _dest("repeat.example.com")
    pol.verdict(dest)
    pol.verdict(dest)

    assert dns.calls == ["repeat.example.com"]


def test_resolution_is_cached_across_destinations(dns):
    dns.table["cached.example.com"] = ("10.0.0.5",)
    pol = _policy(default="allow", deny=[{"host": "10.0.0.0/8"}])
    pol.verdict(_dest("cached.example.com"))
    pol.verdict(_dest("cached.example.com"))

    assert dns.calls == ["cached.example.com"]


def test_slow_resolver_is_bounded_and_does_not_block(monkeypatch):
    """getaddrinfo has no timeout of its own; the wait must still be bounded."""
    import time

    def _slow(host):
        time.sleep(5)
        return ("10.0.0.5",)

    monkeypatch.setattr(egress, "_raw_resolve", _slow)
    started = time.monotonic()
    assert egress.resolve_host("slow.example.com", timeout=0.15) == ()
    assert time.monotonic() - started < 2.0


def test_negative_result_is_cached_so_one_slow_name_costs_once(monkeypatch):
    calls = []

    def _slow(host):
        calls.append(host)
        import time
        time.sleep(2)
        return ()

    monkeypatch.setattr(egress, "_raw_resolve", _slow)
    egress.resolve_host("slow.example.com", timeout=0.1)
    egress.resolve_host("slow.example.com", timeout=0.1)

    assert len(calls) == 1


# ── kill switches ────────────────────────────────────────────────────────────

def test_env_kill_switch_disables_resolution(dns, monkeypatch):
    monkeypatch.setenv("PRISMOR_EGRESS_RESOLVE", "0")
    dns.table["imds.example.com"] = ("169.254.169.254",)
    pol = _policy(default="allow", deny=[{"host": "169.254.0.0/16"}])

    assert pol.verdict(_dest("imds.example.com"))[0] == "allow"
    assert dns.calls == []


def test_policy_can_opt_out_of_resolution(dns):
    dns.table["imds.example.com"] = ("169.254.169.254",)
    pol = _policy(default="allow", resolve=False,
                  deny=[{"host": "169.254.0.0/16"}])

    assert pol.verdict(_dest("imds.example.com"))[0] == "allow"
    assert dns.calls == []


def test_resolve_settings_survive_agent_overrides(dns):
    dns.table["imds.example.com"] = ("169.254.169.254",)
    pol = EgressPolicy.from_settings({"egress": {
        "enabled": True,
        "default": "allow",
        "resolve_timeout": 0.25,
        "deny": [{"host": "169.254.0.0/16"}],
        "agents": {"release-bot": {"default": "deny"}},
    }}, source="project")
    sub = pol.for_agent("release-bot")

    assert sub.resolve is True
    assert sub.resolve_timeout == 0.25
    assert sub.verdict(_dest("imds.example.com"), "release-bot")[0] == "deny"


def test_malformed_resolve_timeout_falls_back(dns):
    pol = _policy(default="allow", resolve_timeout="not-a-number")
    assert pol.resolve_timeout == 1.0


# ── end to end through evaluate() ────────────────────────────────────────────

def test_finding_is_emitted_for_a_resolved_deny(dns):
    dns.table["imds.example.com"] = ("169.254.169.254",)
    pol = _policy(mode="enforce", default="allow",
                  deny=[{"host": "169.254.0.0/16", "reason": "link-local"}])

    findings = pol.evaluate(
        {"type": "network", "url": "https://imds.example.com/latest/meta-data/"},
        0, default_mode="enforce",
    )

    assert len(findings) == 1
    assert findings[0]["action"] == "block"
    assert findings[0]["egressHost"] == "imds.example.com"
    assert "link-local" in findings[0]["title"]


def test_shipped_default_deny_list_resists_a_hostname(dns):
    """The default policy already denies IMDS by IP — that must now cover names."""
    import yaml

    from prismor.runtime.policy_engine import _DEFAULT_POLICY_PATH

    raw = yaml.safe_load(_DEFAULT_POLICY_PATH.read_text())
    settings = raw.get("settings", raw)
    settings["egress"]["enabled"] = True   # ships disabled; enable to evaluate

    dns.table["imds.example.com"] = ("169.254.169.254",)
    dns.table["ali.example.com"] = ("100.100.100.200",)
    pol = EgressPolicy.from_settings(settings, source="remote")

    assert pol.resolve is True
    assert pol.verdict(_dest("169.254.169.254"))[0] == "deny"
    assert pol.verdict(_dest("imds.example.com"))[0] == "deny"
    assert pol.verdict(_dest("ali.example.com"))[0] == "deny"
    assert pol.verdict(_dest("api.github.com"))[0] == "allow"


def test_shell_command_reaching_imds_by_name_is_caught(dns):
    dns.table["imds.example.com"] = ("169.254.169.254",)
    pol = _policy(mode="enforce", default="allow",
                  deny=[{"host": "169.254.0.0/16"}])

    findings = pol.evaluate(
        {"type": "shell", "command": "curl -s https://imds.example.com/creds"},
        0, default_mode="enforce",
    )

    assert len(findings) == 1
    assert findings[0]["action"] == "block"
