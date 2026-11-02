# Deployment

PPE is the enforcement point, but where that point sits is your choice. The same
APL policy enforces whether PPE runs as a gateway in front of a tool server, as
an egress sidecar beside an agent, or inside an agent framework. You move the
boundary; the policy does not change.

## The same policy, any enforcement point

Take the `get_compensation` route. It is identical whether PPE fronts the
backend, guards the agent's egress, or runs inside the agent runtime:

```yaml
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
        - "taint(secret, session)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

As a gateway, PPE sits in front of the tool server and enforces on inbound
calls: every request to the backend passes through it. As an egress sidecar,
PPE sits beside the agent and enforces on the agent's outbound calls: the
agent's tool invocations leave through the sidecar's proxy. In-framework,
PPE runs inside the agent runtime and enforces operations as the runtime issues
them. The enforcement point moves; the route above runs unchanged in all three.

## Route forms

Routes are a list of `- tool:` entries (or `resource:`, `prompt:`,
`llm:`), with the `authorization:`, `args:`, and `result:` blocks under
each. This is the form the runtime loads at every placement: the
enforcement point changes, the config shape does not. See
[Configuration](configuration.md) for the full structure.

A placement that also carries plain HTTP traffic can select on the
request line with an `http:` route, so one document covers both the
agent's tool calls and the ordinary HTTP around them. See
[HTTP Routing](http-routing.md).

## Placement guidance

| Placement | Controls | Use when |
|-----------|----------|----------|
| Gateway (inbound) | every call reaching a backend, from any client | you own the tool server and want one chokepoint in front of it |
| Egress sidecar (outbound) | every call an agent makes, to any backend | you own the agent and want to guard what it can reach |
| In-framework | operations as the agent runtime issues them | you control the runtime and want enforcement inline |

The decision is about which boundary you control and trust, not about policy
capability. Identity resolution, PDP calls, Token Exchange / Delegation,
redaction, and Session Taint
all work the same at each. For what each placement does and does not defend
against, see the [Threat
Model](threat-model.md#where-the-boundary-sits-and-what-each-placement-covers).

## Inference traffic

When PPE guards an agent's egress, route inference calls directly to the model
provider rather than through the policy path, unless you intend to apply policy
to them. Otherwise model traffic is evaluated as if it were a tool call. Reserve
the enforced path for the operations you want mediated.

## Crypto provenance and FIPS hosts

The engine's digests — API-key indexing and caching, session ids, decision
cache keys, payload provenance — are computed by the **platform OpenSSL**,
dynamically linked. No crypto is compiled into the binary for these paths:
the `openssl` crate never enables its `vendored` feature, so the library the
host's operating system provides (and configures, for example into FIPS mode)
is the one that runs.

A deployment that must run under a FIPS enforcement therefore needs:

- an operating system OpenSSL built on the FIPS module path (RHEL/UBI 9 with
  `openssl-fips-provider`, and equivalents), and
- a feature selection whose remaining builtins carry no bundled crypto.
  API-key identity is the verified selection. The JWT backend, the OAuth
delegator, the Vault delegator, and the Valkey session store still hash with
RustCrypto crates and are excluded from a FIPS build until they migrate.

A host can check what a build actually compiled, rather than what it
requested, with the facade's capability report:

```rust
let crypto = praxis_policy::compiled_crypto();
let bundled: Vec<_> = crypto
    .iter()
    .filter(|dep| dep.source == praxis_policy::CryptoSource::Bundled)
    .collect();
```

The report comes from the crates that own each dependency edge, so it reflects
feature unification across the whole graph: a builtin enabled through another
consumer's dependency edge is reported all the same. A FIPS startup check
admits a report whose entries are all `SystemOpenssl` and refuses one that
names any bundled crypto. Selecting the optional `http-hyper` transport also
reports its bundled `ring` TLS provider.

Digest compatibility is preserved: the SHA-256 and HMAC-SHA256 values are the
same bytes the previous implementation produced, so key files, persisted
session keys, and recorded provenance digests keep resolving.

## Related documentation

- [Patterns](patterns.md): production patterns for rollout and layered
  enforcement.
- [Upgrading APL](upgrade-apl.md): migrate existing policy before deployment.
- [Configuration](configuration.md): the full configuration structure.
- [Identity](apl/identity.md) and [Delegation](apl/delegation.md): wiring IdP
  verification and token exchange in a real stack.
