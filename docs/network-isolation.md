# Network Isolation

AI agents frequently make outbound network calls by fetching URLs, installing packages, and calling APIs. Without controls, a prompt injection or malicious skill can silently exfiltrate data to an attacker-controlled endpoint. Warden's network isolation rules make your agent's network activity visible and controllable.

## What it detects at runtime

- Outbound connections to raw IP addresses (not domains). This is often a sign of exfiltration or C2.
- Services binding to `0.0.0.0`. Warden warns before the agent exposes a port to all network interfaces.
- Reverse tunnels and port forwarding (`ssh -R`, ngrok, cloudflared)
- Data upload patterns (`curl --data`, `wget --post-data`)

## Egress allowlist

Lock down which domains the agent can contact by configuring an allowlist in your project's `.prismor-warden/policy.yaml`:

```yaml
settings:
  egress_allowlist:
    - "*.github.com"
    - "*.googleapis.com"
    - "registry.npmjs.org"
    - "pypi.org"
    - "api.anthropic.com"
    - "api.openai.com"
```

When the allowlist is set, any outbound request to a domain not on the list produces a warning. Wildcards are supported: `*.github.com` matches `api.github.com`, `raw.github.com`, and so on. Leave it empty (the default) to allow all domains.

## Bind detection

The `0.0.0.0` bind detection is particularly important. If an agent starts a dev server bound to all interfaces instead of `127.0.0.1`, it becomes reachable from outside your machine. Warden catches this at the shell command level, before the port opens.
