"""Session log durability under concurrent writers.

Several hook processes can fire for one tool call (a hook registered in both
user and project settings, parallel agents sharing a session id) and every one
of them appends to the same session log. Records regularly exceed the pipe
buffer below which O_APPEND writes are atomic, so unserialized appends tear and
weld two records onto one line. A single welded line used to raise
JSONDecodeError out of read_session_events, which runs in the hook path, so one
torn write broke every later tool call in that session.

Session logs live under $PRISMOR_HOME, not under the workspace argument, so
every test here repoints PRISMOR_HOME at a tmp dir to stay off the real one.
"""
from __future__ import annotations

import json
import multiprocessing as mp
from pathlib import Path

import pytest

from prismor.runtime.store import (
    _decode_welded_line,
    append_session_event,
    read_session_events,
    session_log_path,
)

# Comfortably past PIPE_BUF, so a bare write() is free to tear.
BIG = "x" * 200_000


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    return tmp_path


def _spam(args) -> None:
    home, workspace, tag, count = args
    import os

    os.environ["PRISMOR_HOME"] = home  # fork copies the parent env; be explicit
    for i in range(count):
        append_session_event(Path(workspace), "sess", {"ts": f"{tag}-{i}", "blob": BIG})


def test_concurrent_appends_keep_one_record_per_line(home, monkeypatch):
    ctx = mp.get_context("fork")
    tags = ("a", "b", "c", "d")
    per_writer = 8
    prismor_home = str(home / "home")
    with ctx.Pool(len(tags)) as pool:
        pool.map(_spam, [(prismor_home, str(home), t, per_writer) for t in tags])

    log = session_log_path(home, "sess")
    lines = [ln for ln in log.read_text().splitlines() if ln.strip()]
    assert len(lines) == len(tags) * per_writer
    for line in lines:
        json.loads(line)  # raises if two records were welded together

    events = read_session_events(home, "sess")
    assert {e["ts"] for e in events} == {
        f"{t}-{i}" for t in tags for i in range(per_writer)
    }


def test_welded_line_is_recovered_not_raised(home):
    """Logs written before the lock existed must still be readable."""
    log = session_log_path(home, "sess")
    log.parent.mkdir(parents=True, exist_ok=True)
    welded = json.dumps({"ts": "1"}) + json.dumps({"ts": "2"})
    log.write_text(json.dumps({"ts": "0"}) + "\n" + welded + "\n")

    assert [e["ts"] for e in read_session_events(home, "sess")] == ["0", "1", "2"]


def test_decode_welded_line_skips_junk_between_records():
    line = json.dumps({"ts": "1"}) + "<torn>" + json.dumps({"ts": "2"})
    assert [e["ts"] for e in _decode_welded_line(line)] == ["1", "2"]


def test_truncated_tail_does_not_lose_earlier_records():
    line = json.dumps({"ts": "1"}) + '{"ts": "2"'  # writer died mid-record
    assert [e["ts"] for e in _decode_welded_line(line)] == ["1"]
