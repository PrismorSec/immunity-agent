"""Tests for local pause/resume (prismor/runtime/pause.py)."""

import os
import sys
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import pause


class TestParseDuration(unittest.TestCase):
    def test_units(self):
        self.assertEqual(pause.parse_duration("90s"), 90)
        self.assertEqual(pause.parse_duration("30m"), 1800)
        self.assertEqual(pause.parse_duration("2h"), 7200)
        self.assertEqual(pause.parse_duration("1d"), 86400)

    def test_bare_number_is_minutes(self):
        self.assertEqual(pause.parse_duration("5"), 300)

    def test_fractional(self):
        self.assertEqual(pause.parse_duration("1.5h"), 5400)

    def test_garbage_raises(self):
        for bad in ("", "abc", "10x", "m"):
            with self.assertRaises(ValueError):
                pause.parse_duration(bad)


class TestPauseState(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._env = patch.dict(os.environ, {"PRISMOR_HOME": self._tmp})
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def test_not_paused_initially(self):
        self.assertIsNone(pause.active_state())
        self.assertFalse(pause.is_paused())

    def test_pause_indefinite_roundtrip(self):
        rec = pause.set_paused(reason="cloak debug")
        self.assertTrue(pause.is_paused())
        st = pause.active_state()
        self.assertEqual(st["reason"], "cloak debug")
        self.assertIsNone(st["until"])
        self.assertTrue(pause.pause_path().exists())

    def test_resume_is_idempotent(self):
        pause.set_paused()
        self.assertTrue(pause.clear_paused())
        self.assertFalse(pause.clear_paused())
        self.assertFalse(pause.is_paused())

    def test_for_window_auto_expires(self):
        pause.set_paused(duration_seconds=1)
        self.assertTrue(pause.is_paused())
        time.sleep(1.2)
        # active_state() clears the marker once the window has elapsed.
        self.assertIsNone(pause.active_state())
        self.assertFalse(pause.pause_path().exists())

    def test_corrupt_marker_reads_as_not_paused(self):
        pause.pause_path().parent.mkdir(parents=True, exist_ok=True)
        pause.pause_path().write_text("{not json", encoding="utf-8")
        self.assertIsNone(pause.active_state())

    def test_reason_is_truncated(self):
        rec = pause.set_paused(reason="x" * 500)
        self.assertLessEqual(len(rec["reason"]), 300)


class TestBeatGating(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._env = patch.dict(os.environ, {"PRISMOR_HOME": self._tmp})
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def test_beat_noops_when_not_paused(self):
        self.assertFalse(pause.beat(agent="claude"))

    def test_beat_noops_when_not_enrolled(self):
        rec = pause.set_paused()
        # Not enrolled → no device to attribute the heartbeat to → no upload.
        with patch("prismor.runtime.enterprise.identity.is_enrolled", return_value=False):
            self.assertFalse(pause.beat(agent="claude", state=rec))

    def test_beat_uploads_once_then_debounces(self):
        rec = pause.set_paused()
        uploads = []
        with patch("prismor.runtime.enterprise.identity.is_enrolled", return_value=True), \
             patch("prismor.runtime.sinks.upload_telemetry", side_effect=lambda recs, **k: uploads.append(recs)):
            self.assertTrue(pause.beat(agent="claude", state=rec))
            # Re-read state from disk: last_beat was persisted, so a second
            # call within the debounce window uploads nothing.
            self.assertFalse(pause.beat(agent="claude"))
        self.assertEqual(len(uploads), 1)
        sent = uploads[0][0]
        self.assertEqual(sent["type"], "paused_heartbeat")
        self.assertTrue(sent["detail"]["paused"])


if __name__ == "__main__":
    unittest.main()
