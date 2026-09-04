# Policy templates

Prismor ships with a working policy out of the box, but "working" is not the
same as "right for what your agent does". A CI runner and a research agent that
reads the open web need almost opposite settings, and writing either from a
blank `.prismor/policy.yaml` means learning the whole schema first.

The bundled templates are complete, adoptable policies for common shapes of
agent. Each one is a single YAML file you copy into your workspace, read, and
edit. There is no template runtime and nothing is hidden — what you adopt is
exactly what the engine loads.

```bash
prismor policy templates                       # what's available
prismor policy templates production-ops        # read one before adopting it
prismor policy init --template production-ops  # write it to .prismor/policy.yaml
prismor policy show                            # the merged, effective result
```

## The templates

| Template | For | The control it exists for |
|---|---|---|
| `observe-first` | Rolling Prismor out to a team | Nothing blocks except the safety floor. Produces the telemetry you need before choosing anything else. |
| `ci-agent` | Unattended agents in CI/CD | No human to approve, so ambiguity resolves to block. Deny-by-default egress over a known registry/VCS set. |
| `web-research-agent` | Agents that browse, scrape, read tickets and email | Bounds what a session may *do* after reading untrusted input, by tag-rule sequence rather than by pattern. |
| `regulated-data` | PHI, cardholder data, customer PII | Screens what an outbound call carries, not only where it goes. Regulated identifiers cannot leave. |
| `production-ops` | Agents holding cloud, k8s or database credentials | The handful of irreversible verbs — destroy, terminate, drop, force-push — against production-named targets. |
| `oss-contributor` | Public repos, contributor PRs, third-party packages | Supply-chain integrity and contributor content treated as instructions. Quiet everywhere else. |
| `high-assurance` | Autonomous or long-running agents where one bad action is unacceptable | Deny by default on every surface, shell sandboxed, nothing implicit. |

Adopting one is not a commitment. A template is a starting point that you own
from the moment it lands in your repo — it is checked in, diffable, and
reviewable like any other config.

## The one thing to get right first

**Start at `observe-first` unless you already know your traffic.**

The enforcing templates contain guesses — a list of hosts a build "should"
reach, an environment naming convention, a set of vendors. Adopting
`high-assurance` or `ci-agent` cold, with a guessed `egress.allow`, produces an
agent that cannot work and a team that turns Prismor off. That failure mode is
much more common than being under-protected.

The sequence that works:

```bash
prismor policy init --template observe-first
# ... a week of real work ...
prismor egress report          # the destinations your agents ACTUALLY contacted
prismor sessions               # what was screened, and which rules were noisy
prismor policy init --template ci-agent --force   # now paste the real hosts in
```

## Customizing one

Every template ends with a `── Customize ──` section naming the specific lines
worth editing for that use case. The general moves:

**Promote or demote a single rule.** A sparse entry that names an existing rule
id merges field by field — you do not restate its patterns.

```yaml
rules:
  - id: risky-write
    mode: observe        # keep the finding, stop it blocking
  - id: db-modification
    mode: enforce
```

**Carve out one path instead of disabling a rule.** An allowlist is narrower,
auditable, and can expire.

```yaml
allowlists:
  - id: allow-security-fixtures
    rule_ids: ["prompt-injection", "skill-encoded-payload"]
    patterns: ["tests/fixtures/attacks/"]
    reason: "adversarial corpus — these strings are the test input"
    expires: "2027-01-01T00:00:00Z"
```

**Add patterns to an existing rule** rather than redefining it:

```yaml
rules:
  - id: secret-access
    add_patterns:
      - 'internal-signing-key\.pem$'
```

**Write a new rule.** Give it an id no default rule uses, and remember that a
rule's `patterns` are one alternation across *all* its `fields` — keep each rule
about a single subject and split rather than widen.

```yaml
rules:
  - id: block-legacy-admin-cli
    severity: HIGH
    category: privilege_escalation
    title: Legacy admin CLI is retired and unaudited
    event_types: [shell]
    fields: [command]
    patterns: ['\badminctl\s+(?:grant|impersonate)\b']
    action: block
```

Validate and test what you changed:

```bash
prismor policy validate .prismor/policy.yaml
prismor check "adminctl grant root"     # dry-run one command
prismor policy test                     # declarative cases; see templates/policy-tests-owasp.yaml
prismor tags lint .prismor/policy.yaml  # if you edited tool_tags.rules
```

## Things worth knowing before you edit

**The bundled OWASP test pack assumes default egress.** `prismor policy test`
with no `.prismor/policy-tests.yaml` falls back to
`templates/policy-tests-owasp.yaml`, which expects a permissive network. Under
`ci-agent`, `production-ops` or `high-assurance` several of its `warn` cases
come back as `block`, because `egress.default: deny` refuses the destination
before the rule verdict matters. That is the template working, not a regression
— write your own cases in `.prismor/policy-tests.yaml` once you have adopted a
deny-by-default template.

**`default_mode` decides how the whole file behaves.** Every template sets it.
A policy that sets neither `default_mode` nor `mode` falls back to the legacy
block-by-category path, which enforces a different set than the file appears to
say. If you write a policy from scratch, set it.

**The safety floor is not yours to turn off.** Core rules (`rm -rf /`, reverse
shells, secret exfiltration, privilege escalation, and anything that tampers
with Prismor's own wiring) enforce regardless of `default_mode`, `enabled:
false`, or an allowlist. Templates never pretend otherwise, and neither should
your edits. A custom rule you give a core category (`destructive_command`,
`rce_canary`, …) inherits that behaviour — it will enforce even when the rest of
your policy observes, so tune it with `enabled: false` while you measure.

**Lists replace, `egress` and `data_boundary` maps merge.** Writing
`egress.allow` in your policy gives you exactly the list you wrote — it does not
append to anything. But writing `data_boundary: {mode: enforce}` keeps the
shipped `per_domain` vendor carve-outs beneath it, and naming an `egress.allow`
without a `deny` keeps the default cloud-metadata denies. Every other settings
key (`sandbox`, `tool_tags`, …) replaces wholesale, because for those "unset" is
meaningful.

**An org policy outranks your file.** On an org-managed workspace the signed
remote policy is merged after yours and can tighten anything here. A template is
the right shape for a *project* policy; it is not a way to opt out of a fleet
policy.

## Contributing a template

Templates live in [`templates/policy/`](../templates/policy) — one YAML file per
use case. A useful one:

- names a real, recognisable job (not a severity level),
- carries a `# summary:` line in its first ten lines (the listing reads it),
- sets `default_mode` explicitly,
- explains *why* each block is there, not what the keys are called,
- ends with a `── Customize ──` section naming what the adopter must edit,
- and adds a behaviour assertion to
  [`tests/test_policy_templates.py`](../tests/test_policy_templates.py) for the
  one control it exists for. A template that silently stops working is worse
  than no template.
