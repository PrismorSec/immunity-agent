<!--
Thanks for contributing to Prismor.

Fill in every section. The structure is here so a reviewer can answer two
questions fast: did you reuse what already exists, and what is the smallest
thing that changed? PRs that answer both get merged quickly.

Delete the HTML comments as you go. Keep the headings.
-->

## Problem

<!--
What is broken, missing, or unsafe today? Be concrete and specific.

Describe the actual current behavior, not the abstract shape of it. Include a
reproduction, a command, a log line, or a scenario if you have one. A reviewer
should be able to feel the problem without reading the diff.

Bad:  "Improves handling of agent configs."
Good: "`prismor install-hooks --agent gemini` writes the hook block to
       settings.json, but _strip_gemini never removes it, so uninstall leaves
       a dead entry that makes the next install fail with a duplicate key."
-->

Closes #

## Prior art — what already exists

<!--
REQUIRED. Prismor is built so most new behavior is configuration, not code.
Before adding anything, you should have checked whether an existing rule,
module, or pattern already covers this. Tell us what you found.

Pick the line that matches and delete the others.
-->

- [ ] **I reused an existing mechanism.** Which one, and how:
      <!-- e.g. "Added a rule to default_policy.yaml — no Python changes needed." -->

- [ ] **I extended an existing pattern.** Which one, and what I followed:
      <!-- e.g. "Followed the _merge_<agent>/_strip_<agent> pair used by the
           other adapters in hooks.py." -->

- [ ] **An existing mechanism was close but not sufficient.** What I looked at,
      and specifically why it fell short:
      <!-- Give a real reason, not a preference. Good reasons look like:
           - partial coverage: "the rule matches on `fields: [command]`, but this
             payload arrives on `tool_input.file_path`, which the rule can't reach"
           - wrong layer: "this has to happen pre-dispatch; the policy engine only
             sees the event after normalization"
           - no hook exists: "transforms.py has no way to signal back a deny"
           "It felt cleaner" and "the abstraction was awkward" are not reasons. -->

- [ ] **This introduces a new module / abstraction.** Justify it here:
      <!-- Say which of the existing seams you tried first and why each one
           did not work. New frameworks are a last resort in this repo. -->

**Tangential updates:** <!-- If reusing the existing mechanism meant touching
adjacent code — a shared helper, a nearby rule, a doc that went stale — list it
here so the reviewer knows it was deliberate and not scope creep. Write "none"
if there were none. -->

## Solution — high level

<!-- 3–4 bullets. What the change does, graspable without reading the diff. -->

-
-
-

## Deep dive — how it works

<!--
The mechanics. Aim this at a reviewer who will read the diff right after.

Cover:
  - the control flow / order of operations
  - the tricky case, edge case, or failure mode you had to handle
  - anything you deliberately chose NOT to do, and why
  - for detection rules: what it matches, and what benign lookalike it must
    NOT match (false positives make people disable the tool)
-->

## Files changed

<!-- Every changed file, and why it had to change. Keep the "why" specific —
     "updated logic" tells a reviewer nothing. -->

| File | Why it changed |
|------|----------------|
| `path/to/file.py` | |
| | |

## Testing

<!-- What you ran, and what new coverage you added. New behavior needs a test. -->

```
# commands you ran
```

- [ ] `bash scripts/run_security_tests.sh` passes
- [ ] Added or updated tests covering the new behavior
- [ ] If a policy rule changed: `prismor policy validate prismor/runtime/default_policy.yaml`
- [ ] If an integration changed: `bash scripts/verify_registry.sh`

## Security checklist

<!-- Prismor is security software. A change here can affect what gets blocked,
     logged, or leaked. Confirm these before requesting review. -->

- [ ] No detection patterns hardcoded in Python — all rules live in YAML
- [ ] No real secrets, keys, or credentials in code, tests, fixtures, or docs
- [ ] No real secret values printed, logged, or serialized (used `@@SECRET:<name>@@`)
- [ ] No guardrail weakened; if one was, it is called out and justified above
- [ ] Docs that describe this behavior (`SKILL.md`, `docs/`, `AGENTS.md`) are still accurate

## Diff size

<!--
Smaller diffs get merged faster. If this PR is large, say why — a generated
file, a mechanical rename, a genuinely large feature. If a chunk of it could
ship separately, consider splitting it instead.
-->

Lines changed: <!-- e.g. +42 / -8 --> · Justification if large:
