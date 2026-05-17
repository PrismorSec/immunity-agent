"""Regression tests for warden.store session-log concurrency and reader robustness."""

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from warden.store import append_session_event, read_session_events, session_log_path


class TestSessionLogConcurrency(unittest.TestCase):
    """Concurrent appends from multiple threads must not interleave on a single line.

    Before the fix, large events (>PIPE_BUF, ~4 KiB on Linux) could be spliced
    by the kernel when two writers ran in parallel, producing JSONL lines that
    contained two concatenated objects. The reader's old splitlines + json.loads
    path then crashed with ``Extra data: line 1 column N``.
    """

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name)
        self.session_id = "concurrent-session"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_parallel_large_appends_round_trip(self):
        n_threads = 8
        events_per_thread = 50
        # Payload size deliberately >PIPE_BUF (4096 on Linux) to exercise
        # the non-atomic write path.
        payload_filler = "x" * 8192

        def writer(thread_idx: int):
            for i in range(events_per_thread):
                event = {
                    "thread": thread_idx,
                    "seq": i,
                    "filler": payload_filler,
                }
                append_session_event(self.workspace, self.session_id, event)

        threads = [
            threading.Thread(target=writer, args=(t,)) for t in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        events = read_session_events(self.workspace, self.session_id)
        self.assertEqual(len(events), n_threads * events_per_thread)

        seen = {(e["thread"], e["seq"]) for e in events}
        self.assertEqual(len(seen), n_threads * events_per_thread)

        log_path = session_log_path(self.workspace, self.session_id)
        with log_path.open("r", encoding="utf-8") as fh:
            for line_no, raw in enumerate(fh, start=1):
                text = raw.strip()
                if not text:
                    continue
                try:
                    json.loads(text)
                except json.JSONDecodeError as exc:
                    self.fail(
                        f"Line {line_no} is not a single JSON object after "
                        f"concurrent writes ({exc}); size={len(raw)}"
                    )


class TestSessionLogReaderRobustness(unittest.TestCase):
    """The reader must tolerate pre-existing concatenated-object corruption."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmpdir.name)
        self.session_id = "legacy-corrupt"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_reader_recovers_concatenated_objects_on_one_line(self):
        log_path = session_log_path(self.workspace, self.session_id)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        a = json.dumps({"id": 1, "kind": "first"})
        b = json.dumps({"id": 2, "kind": "second"})
        c = json.dumps({"id": 3, "kind": "third"})
        log_path.write_text(a + b + "\n" + c + "\n", encoding="utf-8")

        events = read_session_events(self.workspace, self.session_id)
        self.assertEqual([e["id"] for e in events], [1, 2, 3])

    def test_reader_skips_trailing_garbage(self):
        log_path = session_log_path(self.workspace, self.session_id)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        good = json.dumps({"id": 1})
        log_path.write_text(good + "\n" + "{not json", encoding="utf-8")

        events = read_session_events(self.workspace, self.session_id)
        self.assertEqual(events, [{"id": 1}])


if __name__ == "__main__":
    unittest.main()
