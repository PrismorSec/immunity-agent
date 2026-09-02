"""Re-analysing a session must not drop findings (issue #345).

``finding_id`` is a TEXT PRIMARY KEY derived as ``<session>:<rule>-<eventIndex>``,
and ``persist_runtime_findings`` writes that same id for a finding the runtime has
already enforced on. ``save_session_snapshot`` deletes the *analysis* findings for
a session before re-inserting them but deliberately spares the runtime ones, so a
re-analysis re-derives an id that is still in the table.

With a bare ``INSERT`` that was a UNIQUE violation, and because the write is an
``executemany`` the entire batch aborted -- the caller caught it and printed
``[prismor] analysis error: UNIQUE constraint failed: findings.finding_id``, so
every *other* finding in that batch was silently lost as well.

Run:  python3 tests/test_store_finding_id_collision.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import store

_SESSION = "sess-345"


def _finding(rule: str, index: int, severity: str = "HIGH") -> dict:
    return {
        "id": f"{_SESSION}:{rule}-{index}",
        "ruleId": rule,
        "eventIndex": index,
        "severity": severity,
        "category": "security_bypass",
        "title": f"{rule} fired",
        "evidence": f"evidence for {rule}",
        "action": "block",
        "mode": "enforce",
    }


def _analysis(findings) -> dict:
    return {
        "findings": findings,
        "feedMatches": [],
        "summary": {"riskScore": 90, "totalFindings": len(findings)},
    }


def _events(n: int):
    return [{"type": "shell", "command": f"echo {i}", "ts": f"2026-01-01T00:00:0{i}Z"}
            for i in range(n)]


class TestFindingIdCollision(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="prismor-345-"))
        os.environ["PRISMOR_HOME"] = str(self.workspace)

    def _rows(self):
        db = store.initialize_database(self.workspace)
        conn = sqlite3.connect(db)
        try:
            return conn.execute(
                "SELECT finding_id, enrichment_json FROM findings WHERE session_id = ?",
                (_SESSION,),
            ).fetchall()
        finally:
            conn.close()

    def _snapshot(self, findings):
        store.save_session_snapshot(
            workspace=self.workspace,
            session_id=_SESSION,
            agent="claude",
            source="test",
            repo_url=None,
            events=_events(3),
            analysis=_analysis(findings),
        )

    def test_reanalysis_after_a_runtime_finding_keeps_the_whole_batch(self):
        """The reported failure: one colliding id must not take the batch with it."""
        batch = [_finding("rule-a", 0), _finding("rule-b", 1), _finding("rule-c", 2)]

        # The runtime enforced rule-b first and persisted it with source=runtime.
        store.persist_runtime_findings(self.workspace, _SESSION, [_finding("rule-b", 1)], 1)
        self.assertEqual(len(self._rows()), 1)

        # Whole-session analysis now re-derives all three, one of which collides.
        self._snapshot(batch)

        ids = {r[0] for r in self._rows()}
        self.assertEqual(
            ids,
            {f"{_SESSION}:rule-a-0", f"{_SESSION}:rule-b-1", f"{_SESSION}:rule-c-2"},
            "the non-colliding findings must survive the collision",
        )

    def test_colliding_row_stays_the_runtime_one(self):
        """IGNORE, not REPLACE: the runtime row is what the snapshot DELETE spares.

        Overwriting its `source: runtime` enrichment would put it back in scope
        for the next snapshot's DELETE, which is how enforced blocks used to
        vanish from `prismor status`.
        """
        store.persist_runtime_findings(self.workspace, _SESSION, [_finding("rule-b", 1)], 1)
        self._snapshot([_finding("rule-a", 0), _finding("rule-b", 1)])

        enrichment = dict(self._rows())[f"{_SESSION}:rule-b-1"]
        self.assertIn("runtime", enrichment)

        # And it still survives a second snapshot.
        self._snapshot([_finding("rule-a", 0), _finding("rule-b", 1)])
        self.assertIn(f"{_SESSION}:rule-b-1", {r[0] for r in self._rows()})

    def test_repeated_reanalysis_is_stable(self):
        batch = [_finding("rule-a", 0), _finding("rule-b", 1)]
        for _ in range(3):
            self._snapshot(batch)
        self.assertEqual(len(self._rows()), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
