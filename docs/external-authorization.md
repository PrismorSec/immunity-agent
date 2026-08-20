# External authorization

Prismor governs the agent side: a hook inside the coding agent, a gateway in
front of its MCP servers. That leaves the traffic a production proxy is already
carrying — MCP calls crossing a service mesh, where there is no agent process to
hook and no gateway in the path.

`prismor authz-server` answers that case without Prismor becoming a proxy. Any
proxy implementing the standard external-authorization callout can delegate its
per-request decision to Prismor, so the same `policy.yaml` that governs a
developer's Claude Code governs the fleet's MCP traffic.

```
MCP client ──▶ your proxy ──▶ MCP server
                   │
                   ├─ authorization callout ──▶ prismor authz-server
                   ▼                                     │
             200 allow / 403 deny  ◀────────────────────┘
```

## Start it

```bash
prismor authz-server --port 7073 --workspace /path/to/repo
```

| flag | meaning |
|---|---|
| `--mode observe` | evaluate and log, always allow — the safe first deploy |
| `--api-key` | require `X-Prismor-Authz-Key` (or `$PRISMOR_AUTHZ_KEY`) |
| `--workspace` | whose `.prismor/policy.yaml` is enforced |

`GET /health` reports liveness, the mode, and **whether a request body has ever
been seen** — see the next section for why that matters.

## Configure the proxy

Two settings decide whether this works at all.

**1. Buffer the request body.** By default most proxies send the authorization
callout with *no body*, and an MCP tool call is entirely body: method,
tool name, and arguments all live in the JSON-RPC frame. Without it Prismor sees
a POST to a path and nothing else.

- Envoy: `with_request_body: { max_request_bytes: 65536, allow_partial_message: false }`
- agentgateway: `includeRequestBody: { maxRequestBytes: 65536, allowPartialMessage: false }`
  — note its default cap is **8192 bytes**, small for real MCP payloads.

Prefer `allow_partial_message: false`, so the proxy rejects an oversized body
itself. If you set it `true`, Prismor **denies** any request the proxy flagged as
truncated: screening the first N bytes and answering "allow" would misreport
what was actually checked.

**2. Raise the callout timeout.** Envoy's default is 200ms. Policy evaluation
is not a sub-millisecond operation — a semantic check can take much longer.
Budget generously (1–2s) or you will get timeouts that, depending on your
`failure_mode_allow` setting, either break traffic or silently allow it.

### Envoy sketch

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      failure_mode_allow: false          # deny if Prismor is unreachable
      with_request_body:
        max_request_bytes: 65536
        allow_partial_message: false
      http_service:
        server_uri:
          uri: http://127.0.0.1:7073
          cluster: prismor_authz
          timeout: 2s                    # NOT the 200ms default
        authorization_response:
          allowed_upstream_headers:
            patterns: [{ exact: "x-prismor-verdict" }]
```

`failure_mode_allow: false` is Envoy's default and the right choice: if Prismor
is unreachable, refuse rather than wave everything through. Verify your proxy's
behaviour here empirically — not every implementation documents it.

## What it can and cannot do

**It can refuse. It cannot rewrite a request body.** No authorization callout
can, in either the HTTP or gRPC protocol — the allow path carries header and
query mutations only.

That one fact decides the verdict mapping:

| Prismor verdict | response | why |
|---|---|---|
| `allow` | `200` | proceed |
| `block` | `403` | refuse |
| `modify` | `403` | the payload is only safe *once redacted*, and this surface cannot redact. Answering 200 would forward the unredacted body while reporting success. |
| `step_up` | `403` | no approval channel on a synchronous callout |
| `defer` | `403` | adjudication does not fit inside the callout's timeout |

If `modify` denials are costing you real traffic, that is a routing signal, not
a tuning problem: put those MCP servers behind `prismor mcp-gateway`, which
carries the response and can redact instead of refuse. The denial message says
so.

Denials come back as a JSON-RPC error (`code: -32000`) rather than an HTML error
page, so an MCP client renders the reason instead of choking on it. The rule id
rides along in `error.data.rule` and in the `x-prismor-rule` response header.

## Fail-closed behaviour

Three cases deny that might look like "nothing to see":

- **Unparseable body** — unreadable is not empty.
- **Truncated body** — the proxy flagged that it buffered only part.
- **Engine error in enforce mode** — matching the MCP gateway's rule. In
  `--mode observe` a broken engine allows, because observe is a dry run.

A request carrying **no body at all** allows, but logs loudly to stderr and is
visible in `/health` as `body_seen: false`. That combination is almost always a
misconfigured proxy rather than genuinely bodiless traffic.

## Verdict provenance

On allow, the response carries `x-prismor-verdict: allow`. Forward it upstream
(`allowed_upstream_headers`) if you want the MCP server to see that Prismor
cleared the call.

## Known gap: MCP arguments are not screened as egress

A tool call whose *argument* is a hostile URL — `fetch(url:
"http://169.254.169.254/latest/meta-data/…")` — is **not** blocked by the
bundled policy today.

This is not specific to this surface. The MCP gateway allows the identical call:
both shape a remote MCP call as a `network` event whose `url` is the MCP
*server's* address, with the arguments in `outbound_payload`, and no rule in
`default_policy.yaml` is scoped to `outbound_payload` or `mcp_args`. So the
egress allowlist sees the server you meant to talk to, not the destination the
tool was asked to reach.

The two surfaces agreeing is the correct behaviour — one policy, one verdict —
and `tests/test_mcp_shape.py` pins that agreement so a fix moves them together.
Closing the gap means adding a rule scoped to the MCP argument fields, which
needs false-positive measurement against real traffic before it ships, not a
quick regex. Until then, write your own guardrail if you front tools that take
a URL:

```yaml
rules:
  - id: mcp-arg-metadata-endpoint
    severity: CRITICAL
    category: secret_exfiltration
    title: MCP tool argument targets the cloud metadata endpoint
    event_types: [network]
    fields: [outbound_payload]
    patterns:
      - '169\.254\.169\.254|metadata\.google\.internal'
    action: block
    mode: enforce
```

Note `patterns` is a **list** — a rule written with a singular `pattern:` key
raises at evaluation time, and in enforce mode that denies every request
(fail-closed, by design). Validate policy edits with `prismor policy show`
before deploying them in front of live traffic.

## Limits

- HTTP callout only today. The gRPC protocol carries the same information and
  the same body-rewrite limitation; it is not implemented because it would add a
  protobuf dependency for no new capability.
- The server name is derived from the `Host` header. A single proxy fronting
  many MCP servers under one hostname will tag them all alike; route them on
  distinct hostnames to keep per-server rules meaningful.
- Session correlation is per-process unless the proxy forwards
  `X-Prismor-Session`. Without it, cross-call detections that depend on session
  history (taint, staged execution) have less to work with than they do on the
  hook or gateway surfaces.
