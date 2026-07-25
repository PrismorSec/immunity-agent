"""Contextual verification for shell findings.

A regex rule matches the raw command string, so a pattern that appears inside an
inert string literal -- a commit message, a PR body, a grep pattern -- fires the
same as one in executable position. This module answers a narrower question for
a finding that already matched: does the match live in data, or in code?

The check is deliberately asymmetric. It downgrades only on positive evidence of
inertness and defaults to confirming the finding, so every ambiguous or
unparseable form (unclosed quote, unknown command, any interpreter anywhere in
the pipeline) keeps blocking.
"""
from __future__ import annotations

import re
from typing import List, Tuple

# Commands whose quoted argument is executed, not printed. A match inside one of
# these payloads is code and must never be downgraded.
_INTERPRETERS = frozenset({
    "bash", "sh", "zsh", "ksh", "dash", "csh", "tcsh", "fish",
    "python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php",
    "psql", "mysql", "mariadb", "sqlite3", "mongosh", "redis-cli",
    "eval", "exec", "source", "xargs", "env", "sudo", "doas", "timeout", "nohup",
    "ssh", "docker", "kubectl", "awk", "sed",
})

# Commands that emit their argument as text. Only a match inside one of these,
# with no interpreter anywhere in the command, may be downgraded.
_INERT_SINKS = frozenset({
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "jq", "pbcopy", "gh",
})

# git subcommands that take a human-authored message argument.
_GIT_MESSAGE_SUBCOMMANDS = frozenset({"commit", "tag", "notes", "stash"})

# gh subcommands whose quoted argument is prose (a PR body, an issue comment).
_GH_TEXT_SUBCOMMANDS = frozenset({"pr", "issue", "release", "gist"})

# A payload-bearing flag: -c, -e, and clustered forms such as -lc or -xec.
_PAYLOAD_FLAG = re.compile(r"^-[a-zA-Z]*[ce]$")

_SEPARATORS = ";|&"
_QUOTES = "\"" + chr(39)


def quoted_spans(command: str) -> List[Tuple[int, int, bool, bool]]:
    """Return (start, end, is_payload, is_closed) for each quoted span.

    ``start``/``end`` are the indices of the opening and closing quote. A span is
    a *payload* when it is the argument of an interpreter (so its contents are
    executed); ``is_closed`` is False for an unterminated quote, which callers
    must treat as unparseable rather than inert.
    """
    spans: List[Tuple[int, int, bool, bool]] = []
    words: List[str] = []
    token = ""
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if ch in _QUOTES:
            j = i + 1
            # POSIX: a single-quoted string has no escapes; a double-quoted one does.
            if ch == chr(39):
                while j < n and command[j] != ch:
                    j += 1
            else:
                while j < n and command[j] != ch:
                    j += 2 if command[j] == chr(92) else 1
            if token:
                words.append(token)
                token = ""
            recent = words[-3:]
            is_payload = any(_PAYLOAD_FLAG.match(w) for w in words[-2:]) and any(
                w.rsplit("/", 1)[-1] in _INTERPRETERS for w in recent
            )
            if words and words[-1].rsplit("/", 1)[-1] in ("eval", "exec", "source", "xargs"):
                is_payload = True
            spans.append((i, min(j, n), is_payload, j < n))
            i = j + 1
            continue
        if ch.isspace() or ch in _SEPARATORS:
            if token:
                words.append(token)
            if ch in _SEPARATORS:
                words = []
            token = ""
        else:
            token += ch
        i += 1
    return spans


def _outside_quotes(command: str, spans) -> str:
    """The command with every quoted span blanked, for structural scanning."""
    chars = list(command)
    for start, end, _payload, _closed in spans:
        for k in range(start, min(end + 1, len(chars))):
            chars[k] = " "
    return "".join(chars)


def is_inert_match(command: str, match_start: int, match_end: int) -> bool:
    """True when the match lies wholly inside an inert quoted argument.

    All of the following must hold, else the finding stands:
      * the match is inside a closed, non-payload quoted span;
      * no interpreter appears anywhere in the command (blocks the
        ``echo "..." | bash`` form, where quoted text is still executed);
      * the enclosing pipeline segment has no redirect (``echo "..." > run.sh``
        writes the text to a script rather than displaying it);
      * that segment starts with a known text-emitting command.
    """
    if match_start < 0 or match_end > len(command):
        return False
    spans = quoted_spans(command)
    if not spans:
        return False
    bare = _outside_quotes(command, spans)

    for word in bare.replace(_SEPARATORS[0], " ").replace(_SEPARATORS[1], " ").replace(_SEPARATORS[2], " ").split():
        if word.rsplit("/", 1)[-1] in _INTERPRETERS:
            return False

    for start, end, is_payload, is_closed in spans:
        if is_payload or not is_closed:
            continue
        # +1 tolerance: a pattern anchored on a trailing delimiter may consume
        # the closing quote itself.
        if not (match_start >= start and match_end <= end + 1):
            continue
        seg_start = 0
        for k in range(start):
            if bare[k] in _SEPARATORS:
                seg_start = k + 1
        seg_end = len(command)
        for k in range(start, len(command)):
            if bare[k] in _SEPARATORS:
                seg_end = k
                break
        segment = bare[seg_start:seg_end]
        if ">" in segment or "<" in segment:
            return False
        tokens = segment.split()
        if not tokens:
            return False
        argv0 = tokens[0].rsplit("/", 1)[-1]
        if argv0 == "gh":
            return len(tokens) > 1 and tokens[1] in _GH_TEXT_SUBCOMMANDS
        if argv0 == "git":
            return len(tokens) > 1 and tokens[1] in _GIT_MESSAGE_SUBCOMMANDS
        return argv0 in _INERT_SINKS
    return False

