"""Org (console-pushed) pause/resume and how it resolves against a local one.

The precedence here is the whole feature, and every case is a way for a machine
to end up enforcing when it shouldn't (or not enforcing when it should), so each
one is pinned separately.
"""

import os
import sys
import time
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import pause


def iso(ts: float) -> str:
    """Control-plane wire format: UTC ISO-8601 with a trailing Z."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def org(state, at, until=None, reason=""):
    rec = {"state": state, "at": iso(at)}
    if until is not None:
        rec["until"] = iso(until)
    if reason:
        rec["reason"] = reason
    return rec


class OrgPauseBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._env = patch.dict(os.environ, {"PRISMOR_HOME": self._tmp})
        self._env.start()
        # Stand in for the signed-policy read; the real one goes through
        # remote_policy.verify_and_load, which is covered by its own tests.
        self._remote = patch("prismor.runtime.enterprise.remote_policy.remote_pause")
        self.remote_pause = self._remote.start()
        self.remote_pause.return_value = None

    def tearDown(self):
        self._remote.stop()
        self._env.stop()


class TestOrgPause(OrgPauseBase):
    def test_org_pause_alone_suspends_enforcement(self):
        self.remote_pause.return_value = org("paused", time.time() - 60)
        state = pause.active_state()
        self.assertIsNotNone(state)
        self.assertEqual(state["source"], "org")
        self.assertTrue(state["paused"])

    def test_local_resume_cannot_lift_an_org_pause(self):
        # The developer pauses, then runs `prismor resume` — which clears the
        # local marker. The org pause must survive that.
        pause.set_paused(reason="local")
        self.remote_pause.return_value = org("paused", time.time() - 60, reason="incident 412")
        pause.clear_paused()
        state = pause.active_state()
        self.assertIsNotNone(state)
        self.assertEqual(state["source"], "org")
        self.assertEqual(state["reason"], "incident 412")

    def test_org_pause_outranks_a_live_local_pause(self):
        pause.set_paused(reason="local")
        self.remote_pause.return_value = org("paused", time.time() - 10, reason="org")
        self.assertEqual(pause.active_state()["source"], "org")

    def test_expired_org_pause_heals_itself(self):
        now = time.time()
        self.remote_pause.return_value = org("paused", now - 7200, until=now - 60)
        self.assertIsNone(pause.active_state())

    def test_org_pause_inside_its_window_still_applies(self):
        now = time.time()
        self.remote_pause.return_value = org("paused", now - 60, until=now + 3600)
        self.assertIsNotNone(pause.active_state())

    def test_malformed_org_record_is_ignored(self):
        # Fail toward enforcing: anything we can't read means "no pause".
        for bad in ({}, {"state": "paused"}, {"state": "nonsense", "at": iso(time.time())},
                    {"state": "paused", "at": "not-a-date"}):
            self.remote_pause.return_value = bad
            self.assertIsNone(pause.active_state(), bad)

    def test_unreadable_policy_does_not_pause(self):
        self.remote_pause.side_effect = RuntimeError("bad signature")
        self.assertIsNone(pause.active_state())


class TestOrgResume(OrgPauseBase):
    def test_org_resume_clears_an_older_local_pause(self):
        # The admin's "spin it up again from here" case: no shell access to the
        # machine, but the local marker still has to go.
        pause.set_paused(reason="local")
        self.remote_pause.return_value = org("resumed", time.time() + 5)
        self.assertIsNone(pause.active_state())
        # And converges — the marker is gone, not merely ignored.
        self.assertFalse(pause.pause_path().exists())

    def test_a_newer_local_pause_wins_over_an_older_org_resume(self):
        # Developers keep the ability to pause their own box after an admin has
        # resumed it; otherwise one console click locks them out for good.
        self.remote_pause.return_value = org("resumed", time.time() - 3600)
        pause.set_paused(reason="local, after the resume")
        state = pause.active_state()
        self.assertIsNotNone(state)
        self.assertEqual(state["source"], "local")

    def test_org_resume_with_no_local_pause_is_a_no_op(self):
        self.remote_pause.return_value = org("resumed", time.time())
        self.assertIsNone(pause.active_state())

    def test_org_resume_never_expires(self):
        # A resume is a point-in-time event; an `until` on it must not make it
        # lapse back into a pause.
        now = time.time()
        pause.set_paused()
        # The resume is unambiguously newer than the local marker, so only its
        # long-past `until` could bring the pause back — and must not.
        self.remote_pause.return_value = org("resumed", now + 5, until=now - 60)
        self.assertIsNone(pause.active_state())


class TestOrgHeartbeat(OrgPauseBase):
    def test_no_heartbeat_for_an_org_pause(self):
        # The control plane set it, so reporting it back tells it nothing — and
        # there's no local marker to stamp last_beat onto, so an unguarded beat
        # would re-upload on every single tool call.
        self.remote_pause.return_value = org("paused", time.time() - 60)
        state = pause.active_state()
        with patch("prismor.runtime.sinks.upload_telemetry") as up:
            self.assertFalse(pause.beat(agent="claude", state=state))
            up.assert_not_called()


if __name__ == "__main__":
    unittest.main()
