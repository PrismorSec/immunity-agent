"""Tag-rule expression language — policy-as-code over tool tags.

A tiny, dependency-free rule DSL for ``settings.tool_tags.rules``. One rule per
line-string; whitespace-tokenized; three connectors with fixed precedence
(``with`` binds tightest, then ``or``, then ``then``):

    rule      := disj ( "then" disj )* [ "->" action ]
    disj      := conj ( "or" conj )*
    conj      := TAG ( "with" TAG )*      # TAG = [a-z0-9][a-z0-9_.-]*
    action    := "block" | "warn"         # omitted -> "block"

Semantics:
  * ``with`` groups adjacent tags into one unordered conjunction — all must
    co-occur in the session (exactly the legacy ``incompatible`` semantics).
  * ``or`` offers alternative conjunctions at the same position — any one of
    them satisfies that step.
  * ``then`` separates ordered steps: some alternative of step N must be
    satisfied by occurrences before those satisfying step N+1.
  * The call that satisfies the *final* step is the one blocked/warned.

An ``or`` rule is compiled to its **variants** — the cross-product of one
alternative per step — each an ordinary ``or``-free step sequence. The rule
fires when *any* variant is completed, so alternation reuses the exact
ordered-subsequence matcher and adds no new matching semantics.

Examples:
    untrusted_content with critical_action -> block
    untrusted_content then critical_action -> block
    untrusted_content then send_email or post_message -> block
    secrets_access with external_comms or customer_pii with external_comms -> warn
    customer_pii then external_comms          (implicit -> block)

``not``, ``within`` and ``count`` are reserved for future grammar growth and
raise a ParseError today.

Legacy compatibility: :func:`compile_tool_tag_rules` is the single funnel that
compiles both the new ``rules:`` strings and the legacy ``incompatible:`` lists
into one internal representation (:class:`CompiledRule`), so existing policies
keep working byte-for-byte.
"""
from __future__ import annotations

import hashlib
import itertools
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from prismor.runtime.trifecta import DEFAULT_INCOMPATIBLE, _as_list

ACTIONS = ("block", "warn")
CONNECTORS = ("then", "with", "or")
RESERVED = ("not", "within", "count")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]*$")


class ParseError(ValueError):
    """Raised on an invalid rule expression. Carries ``pos`` (0-based char
    offset into the source string) for caret diagnostics."""

    def __init__(self, message: str, expr: str = "", pos: int = 0) -> None:
        super().__init__(message)
        self.expr = expr
        self.pos = pos

    def caret(self) -> str:
        """Two-line diagnostic: the expression and a caret under the error."""
        return f"{self.expr}\n{' ' * self.pos}^ {self.args[0]}"


def _variants_signature(variants: List[List[Set[str]]]) -> str:
    """Order-insensitive (within a step's alternatives, and across variants)
    signature of a rule's variants — the stable basis for ``rule_id``."""
    per_variant = [
        ";".join(",".join(sorted(s)) for s in variant) for variant in variants
    ]
    return "&".join(sorted(per_variant))


@dataclass
class CompiledRule:
    """Internal representation shared by DSL rules and legacy incompatible sets.

    ``steps`` is the primary (first) variant — a flat ordered list of unordered
    tag sets, unchanged from before, so display/legacy consumers keep working.
    ``variants`` holds every ``or``-free step sequence the rule expands to (just
    ``[steps]`` for a rule without ``or``); the matcher fires on any of them."""

    steps: List[Set[str]]  # primary variant: ordered steps, each an unordered tag set
    action: str = "block"  # "block" | "warn"
    source: str = ""  # original expression, or "incompatible" for legacy rows
    rule_id: str = field(default="")
    variants: List[List[Set[str]]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.variants:
            self.variants = [self.steps]
        if not self.steps and self.variants:
            self.steps = self.variants[0]
        if not self.rule_id:
            norm = _variants_signature(self.variants) + "|" + self.action
            self.rule_id = hashlib.sha256(norm.encode("utf-8")).hexdigest()[:10]

    @property
    def ordered(self) -> bool:
        return any(len(v) > 1 for v in self.variants)

    @property
    def has_alternatives(self) -> bool:
        return len(self.variants) > 1

    @property
    def all_tags(self) -> Set[str]:
        out: Set[str] = set()
        for variant in self.variants:
            for s in variant:
                out |= s
        return out


def _tokenize(expr: str) -> List[Tuple[str, int]]:
    """Split on whitespace, keeping each token's start offset."""
    toks: List[Tuple[str, int]] = []
    for m in re.finditer(r"\S+", expr):
        toks.append((m.group(0), m.start()))
    return toks


def compile_rule(expr: str) -> CompiledRule:
    """Compile one rule expression string into a :class:`CompiledRule`."""
    if not isinstance(expr, str):
        raise ParseError("rule must be a string", str(expr), 0)
    toks = _tokenize(expr)
    if not toks:
        raise ParseError("empty rule", expr, 0)

    # Optional trailing "-> action".
    action = "block"
    if any(t == "->" for t, _ in toks):
        arrow_i = next(i for i, (t, _) in enumerate(toks) if t == "->")
        tail = toks[arrow_i + 1 :]
        if arrow_i != len(toks) - 2 or not tail:
            pos = toks[arrow_i][1]
            raise ParseError("'->' must be followed by exactly one action", expr, pos)
        act_tok, act_pos = tail[0]
        if act_tok not in ACTIONS:
            raise ParseError(
                f"unknown action '{act_tok}' (expected {' or '.join(ACTIONS)})",
                expr, act_pos,
            )
        action = act_tok
        toks = toks[:arrow_i]
        if not toks:
            raise ParseError("rule has no tags before '->'", expr, 0)

    # Parse into steps, each a list of alternative conjunctions (tag sets):
    #   step_alts : List[step]        step : List[alt]        alt : Set[tag]
    step_alts: List[List[Set[str]]] = []
    cur_alts: List[Set[str]] = []  # alternatives collected in the current step
    cur_set: Set[str] = set()  # tags of the current conjunction
    expect_term = True
    for tok, pos in toks:
        if expect_term:
            low = tok.lower()
            if low in RESERVED:
                raise ParseError(f"'{tok}' is reserved for future use", expr, pos)
            if low in CONNECTORS or tok == "->":
                raise ParseError(f"expected a tag, got '{tok}'", expr, pos)
            if not _TAG_RE.match(tok):
                raise ParseError(
                    f"invalid tag '{tok}' (allowed: [a-z0-9][a-z0-9_.-]*)",
                    expr, pos,
                )
            cur_set.add(tok)
            expect_term = False
        else:
            low = tok.lower()
            if low == "with":
                expect_term = True  # another tag in the same conjunction
            elif low == "or":
                cur_alts.append(cur_set)  # close this conjunction, start another
                cur_set = set()
                expect_term = True
            elif low == "then":
                cur_alts.append(cur_set)  # close the step and start the next
                step_alts.append(cur_alts)
                cur_alts = []
                cur_set = set()
                expect_term = True
            else:
                raise ParseError(
                    f"expected 'then', 'with', 'or' or '->', got '{tok}'", expr, pos
                )
    if expect_term:
        # Trailing connector like "a then" / "a or".
        tok, pos = toks[-1]
        raise ParseError(f"dangling '{tok}' at end of rule", expr, pos)
    cur_alts.append(cur_set)
    step_alts.append(cur_alts)

    # Expand to variants: one alternative chosen per step. Dedup identical
    # variants (repeated alternatives) so rule_id stays stable.
    seen_sig: Set[str] = set()
    variants: List[List[Set[str]]] = []
    for combo in itertools.product(*step_alts):
        variant = [set(s) for s in combo]
        sig = ";".join(",".join(sorted(s)) for s in variant)
        if sig in seen_sig:
            continue
        seen_sig.add(sig)
        variants.append(variant)

    # Every variant must be a real combination — a single tag (one step, one
    # tag) can never be a "combination", so reject rules any alternative of
    # which would fire on one tag alone.
    for variant in variants:
        if len(variant) == 1 and len(variant[0]) < 2:
            raise ParseError(
                "a rule needs at least two tags (a single tag can never be a "
                "combination)", expr, 0,
            )

    return CompiledRule(
        steps=variants[0], action=action, source=expr.strip(), variants=variants
    )


def lint_rules(exprs: List[str]) -> List[Tuple[str, ParseError]]:
    """Validate rule strings; return (expr, error) pairs for the invalid ones."""
    errors: List[Tuple[str, ParseError]] = []
    for expr in exprs:
        try:
            compile_rule(expr)
        except ParseError as e:
            errors.append((expr, e))
    return errors


def _coerce_rule_entry(entry: Any) -> Optional[CompiledRule]:
    """Compile one ``rules:`` entry — a DSL string or an {expr, action} map."""
    if isinstance(entry, str):
        return compile_rule(entry)
    if isinstance(entry, dict):
        expr = entry.get("expr")
        if not isinstance(expr, str):
            raise ParseError("rule map needs an 'expr' string", str(entry), 0)
        rule = compile_rule(expr)
        act = entry.get("action")
        if act in ACTIONS and act != rule.action:
            # Explicit map action overrides the expression's (or the default).
            rule = CompiledRule(
                steps=rule.steps, action=act, source=rule.source,
                variants=rule.variants,
            )
        return rule
    raise ParseError("rule must be a string or an {expr, action} map", str(entry), 0)


def compile_tool_tag_rules(tt: Optional[Dict[str, Any]]) -> List[CompiledRule]:
    """Compile ``settings.tool_tags`` (both ``rules`` and legacy ``incompatible``)
    into one rule list. Invalid DSL entries are skipped (policy loading must not
    crash the engine); use :func:`lint_rules` to surface them. Falls back to the
    default red/blue pair only when both lists yield nothing — mirroring
    ``normalize_incompatible``."""
    tt = tt or {}
    out: List[CompiledRule] = []

    raw_rules = tt.get("rules")
    if isinstance(raw_rules, (list, tuple)):
        for entry in raw_rules:
            try:
                rule = _coerce_rule_entry(entry)
            except ParseError:
                continue
            if rule is not None:
                out.append(rule)

    raw_incompat = tt.get("incompatible")
    if isinstance(raw_incompat, (list, tuple)):
        for item in raw_incompat:
            tags = {str(t) for t in _as_list(item)}
            if len(tags) >= 2:  # single-tag "set" can never be a combination
                out.append(
                    CompiledRule(steps=[tags], action="block", source="incompatible")
                )

    if not out:
        out = [
            CompiledRule(steps=[set(s)], action="block", source="default")
            for s in DEFAULT_INCOMPATIBLE
        ]
    return out
