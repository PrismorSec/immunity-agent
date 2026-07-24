"""Concurrent writers must not drop session security state.

Every hook invocation is a separate process, and an agent that spawns
subagents runs several of them at once, so multiple processes race on one
session's tag ledger and taint file. The failure mode is a fail-*open*: a
dropped tag record silently un-taints the session, ``TagLedger.completes``
then sees a clean slate, and the forbidden tool combination is never blocked.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from multiprocessing import Process
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prismor.runtime.policy_engine import _TaintStore  # noqa: E402
from prismor.runtime.trifecta import (  # noqa: E402
    CRITICAL,
    UNTRUSTED,
    TagLedger,
    normalize_incompatible,
)

SESSION = "sess"
INCOMPATIBLE = normalize_incompatible(None)  # the default red/blue pair


def _record_worker(home: str, tag: str, index: int, tool: str, barrier: str) -> None:
    """Runs in a child process, mimicking one hook invocation."""
    os.environ["PRISMOR_HOME"] = home
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from prismor.runtime.trifecta import TagLedger as Ledger

    while not Path(barrier).exists():  # collide the writes as hard as possible
        pass
    Ledger(Path(home), SESSION).record({tag}, index, tool)


class _HomeIsolated(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="prismor-test-"))
        self._prior = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.home)

    def tearDown(self) -> None:
        if self._prior is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._prior
        shutil.rmtree(self.home, ignore_errors=True)

    def run_concurrently(self, specs) -> None:
        barrier = self.home / "GO"
        procs = [
            Process(target=_record_worker, args=(str(self.home), tag, idx, tool, str(barrier)))
            for tag, idx, tool in specs
        ]
        for p in procs:
            p.start()
        barrier.write_text("go")
        for p in procs:
            p.join()


class ConcurrentLedgerWrites(_HomeIsolated):
    def test_no_lost_updates_under_concurrent_writers(self):
        n = 12
        self.run_concurrently([(f"tag{i}", i, f"tool{i}") for i in range(n)])
        ledger = TagLedger(self.home, SESSION)
        missing = {f"tag{i}" for i in range(n)} - set(ledger.seen)
        self.assertEqual(missing, set(), f"lost {len(missing)} concurrent records")

    def test_ledger_file_never_tears(self):
        self.run_concurrently([(f"tag{i}", i, f"tool{i}") for i in range(12)])
        path = self.home / "trifecta" / f"{SESSION}.json"
        # A torn file is swallowed by the loader's except-and-continue, which
        # resets the session to clean state — so it must be impossible, not rare.
        json.loads(path.read_text(encoding="utf-8"))

    def test_concurrent_writers_do_not_open_the_trifecta_gate(self):
        """One subagent fetches untrusted content while others write
        concurrently; a later critical action must still be blocked."""
        specs = [(UNTRUSTED, 0, "WebFetch")]
        specs += [(f"noise{i}", i + 1, f"tool{i}") for i in range(11)]
        self.run_concurrently(specs)
        done = TagLedger(self.home, SESSION).completes(
            {CRITICAL}, INCOMPATIBLE, current_index=99
        )
        self.assertIsNotNone(done, "forbidden combination was not detected")

    def test_record_still_updates_the_in_memory_view(self):
        ledger = TagLedger(self.home, SESSION)
        ledger.record({UNTRUSTED}, 0, "WebFetch")
        self.assertIn(UNTRUSTED, ledger.seen)
        self.assertEqual(ledger.hist[UNTRUSTED], [0])
        # …and a re-read sees the same committed state.
        self.assertIn(UNTRUSTED, TagLedger(self.home, SESSION).seen)

    def test_earliest_introduction_wins(self):
        """`seen` answers "who first tainted this session", so a later writer
        must not overwrite an earlier index."""
        TagLedger(self.home, SESSION).record({UNTRUSTED}, 5, "late")
        TagLedger(self.home, SESSION).record({UNTRUSTED}, 1, "early")
        ledger = TagLedger(self.home, SESSION)
        self.assertEqual(ledger.seen[UNTRUSTED]["index"], 1)
        self.assertEqual(ledger.seen[UNTRUSTED]["tool"], "early")


class ConcurrentTaintWrites(_HomeIsolated):
    def test_injection_flag_survives_and_is_monotonic(self):
        store = _TaintStore(self.home, SESSION)
        store.mark_injection(3)
        self.assertTrue(_TaintStore(self.home, SESSION).injection_detected)

    def test_domains_accumulate_rather_than_replace(self):
        _TaintStore(self.home, SESSION).add_domain("a.example")
        # A second store loaded before the first wrote would, unlocked, clobber
        # the first domain with only its own.
        _TaintStore(self.home, SESSION).add_domain("b.example")
        seen = _TaintStore(self.home, SESSION).seen_domains
        self.assertEqual(seen, {"a.example", "b.example"})

    def test_taint_file_is_valid_json(self):
        _TaintStore(self.home, SESSION).mark_injection(1)
        path = self.home / "taint" / f"{SESSION}.json"
        json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
