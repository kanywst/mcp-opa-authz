# mcp-opa-authz

[![ci](https://github.com/kanywst/mcp-opa-authz/actions/workflows/ci.yml/badge.svg)](https://github.com/kanywst/mcp-opa-authz/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/kanywst/mcp-opa-authz.svg)](https://pkg.go.dev/github.com/kanywst/mcp-opa-authz)
[![Go Report Card](https://goreportcard.com/badge/github.com/kanywst/mcp-opa-authz)](https://goreportcard.com/report/github.com/kanywst/mcp-opa-authz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

**Stop letting your agent guess at authorization.** This is an [MCP](https://modelcontextprotocol.io) server that answers "is this allowed?" from real policy code — either Rego you hand it, or the [OpenID AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) PDP that actually governs your system.

Ask a model whether Alice may delete that document and it will produce a confident, plausible, unfalsifiable answer. Give it these tools and the answer comes from the policy.

```bash
brew install kanywst/tap/mcp-opa-authz
# or, without Homebrew:
go install github.com/kanywst/mcp-opa-authz@latest

claude mcp add opa-authz -- mcp-opa-authz
```

That is enough for `evaluate_policy`. Point it at a PDP to get the rest:

```bash
claude mcp add opa-authz \
  --env AUTHZEN_PDP_URL=http://localhost:8181/access/v1/evaluation \
  -- mcp-opa-authz
```

## Two layers, same question

| Tool | Answers | Needs |
| --- | --- | --- |
| `evaluate_policy` | "What does this Rego say?" Evaluated in-process by [OPA](https://www.openpolicyagent.org/). | Nothing external |
| `authzen_evaluate` | "What does the PDP that governs this system say?" | A reachable PDP |
| `authzen_evaluate_batch` | The same, over a list — which of these may the subject touch? | A reachable PDP |
| `authzen_discover` | "Which endpoints does this PDP offer?" | A reachable PDP |

Use `evaluate_policy` while authoring or debugging a policy you have the source of. Use `authzen_evaluate` when the decision has to come from production, not from a policy pasted into the chat. The server's MCP instructions tell the model the same thing, so it usually picks correctly on its own.

## What makes this different from `opa eval` in a shell tool

An agent given shell access can already run `opa eval`. What it cannot do is get an answer it is allowed to trust:

- **Undefined is not false.** A Rego query with no matching rule and no default returns `[]`. Every model reads that as a deny. `evaluate_policy` returns `defined` alongside `value`, so "the policy denied" and "the policy has no opinion" stop being the same answer.
- **A PDP that did not answer is not a deny.** AuthZEN makes `decision` a required member. A response missing it decodes into a Go `bool` as `false` — a broken PDP would look like a strict one. This server treats a missing `decision` as a failure, never as a deny. Same for a 401: that means *this server* failed to authenticate, not that the subject was denied, and the error says so.
- **The policy runs in a sandbox.** Rego handed to an MCP server was written by a model, from text that may have come from a web page. OPA's `http.send` would let that policy make arbitrary HTTP requests from your laptop, and `opa.runtime()` would hand it your environment. Both are compiled out. See [Security](#security).
- **Batch decisions carry their index.** `permit_on_first_permit` legitimately returns fewer decisions than you sent. Zipping the arrays would attach a decision to the wrong resource.

## Demo

Debugging a policy that is denying when it should not:

```text
> Why is bob getting denied on doc-1? Here's the policy and the input.

  evaluate_policy(rego=…, query="data.rbac.allow", input_json=…, trace=true)

  {
    "defined": true,
    "value": false,
    "printed": ["checking roles for", "bob"],
    "trace": [
      "Enter data.rbac.allow",
      "| Eval some role in roles[input.user]",
      "| Fail roles[\"bob\"]",
      …
    ]
  }

Bob has no entry in `roles` at all — the rule never reaches the permission
check. Adding "bob": {"viewer"} fixes it.
```

Then confirming against the PDP that actually runs:

```text
> Does production agree?

  authzen_evaluate(subject={"type":"user","id":"bob"}, …)

  { "decision": false, "context": { "reason": "no role binding" },
    "request_id": "3f9c…", "pdp_url": "https://pdp.internal/access/v1/evaluation" }
```

## Tools

### `evaluate_policy`

| Param | Required | Description |
| --- | --- | --- |
| `rego` | yes | Rego source with a `package` declaration. |
| `query` | yes | Rego query, e.g. `data.example.allow`. |
| `input_json` | no | JSON-encoded `input` document. |
| `data_json` | no | JSON-encoded base document for the `data` namespace. |
| `rego_version` | no | `v1` (default) or `v0` for pre-OPA-1.0 syntax. |
| `trace` | no | Return a pretty-printed evaluation trace. Verbose; bounded at 4000 events, 200 lines, 1 KiB per line. |

Returns `defined`, `value`, the raw OPA `result_set` (omitted with `result_set_omitted` past 256 KiB encoded), any `print()` output (200 lines of 1 KiB), and the trace when asked for.

### `authzen_evaluate`

| Param | Required | Description |
| --- | --- | --- |
| `subject` | yes | JSON object. AuthZEN requires `type` and `id`. |
| `action` | yes | JSON object. AuthZEN requires `name`. |
| `resource` | yes | JSON object. AuthZEN requires `type` and `id`. |
| `context` | no | JSON object with runtime context (IP, time, MFA strength). |
| `pdp_url` | no | Override `AUTHZEN_PDP_URL` for this call. |

Returns `decision`, the PDP's `context` if any, the `pdp_url` that answered, and the `request_id` sent as `X-Request-ID` — so a decision in a transcript can be found in the PDP's logs.

### `authzen_evaluate_batch`

Same arguments, plus `evaluations` (a JSON array whose entries override the top-level defaults) and `evaluations_semantic` (`execute_all`, `deny_on_first_deny`, `permit_on_first_permit`). Capped at 100 entries per call.

```json
{
  "subject": "{\"type\":\"user\",\"id\":\"alice\"}",
  "action": "{\"name\":\"read\"}",
  "evaluations": "[{\"resource\":{\"type\":\"doc\",\"id\":\"1\"}},{\"resource\":{\"type\":\"doc\",\"id\":\"2\"}}]"
}
```

### `authzen_discover`

Fetches `/.well-known/authzen-configuration` from a PDP root. `pdp_url` may be a root or an evaluation endpoint — the known AuthZEN path suffix is stripped, and a PDP mounted under a prefix keeps its prefix.

## Standards conformance

Implements [Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html), approved as an OpenID **Final Specification** in January 2026:

| Section | Status |
| --- | --- |
| Access Evaluation (`POST /access/v1/evaluation`) | `authzen_evaluate` |
| Access Evaluations, batch (`POST /access/v1/evaluations`) | `authzen_evaluate_batch` |
| PDP Metadata (`GET /.well-known/authzen-configuration`) | `authzen_discover` |
| Subject / Action / Resource information model | Required members validated before the request is sent |
| `X-Request-ID` correlation | Sent on every call, returned in the result |
| Search APIs (subject / resource / action) | Not implemented — [open an issue](https://github.com/kanywst/mcp-opa-authz/issues) if you need them |

Related work worth knowing about: the AuthZEN working group's [COAZ profile](https://github.com/openid/authzen/blob/main/profiles/authzen-coaz-mcp-binding-1_0.md) binds AuthZEN to MCP tool calls themselves, so a gateway can authorize `tools/call` with an `x-authzen-mapping` declared in a tool's `inputSchema`. That is the enforcement side of the same problem — this server is the *inspection* side, and the two compose.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `AUTHZEN_PDP_URL` | — | Default Access Evaluation endpoint. |
| `AUTHZEN_PDP_TOKEN` | — | `Authorization` header value. A value with no scheme is sent as `Bearer <token>`. |
| `AUTHZEN_PDP_TIMEOUT` | `10s` | Per-request timeout. |
| `AUTHZEN_PDP_MAX_RESPONSE_BYTES` | `1048576` | Response read limit. |
| `MCP_OPA_EVAL_TIMEOUT` | `5s` | Wall-clock limit on one Rego evaluation. |
| `MCP_MAX_ARG_BYTES` | `1048576` | Per-argument size limit. |
| `MCP_OPA_ALLOW_NETWORK_BUILTINS` | `false` | Re-enable the network built-ins. See below. |

A malformed value stops the server at startup rather than being silently replaced by the default — a bound an operator believes is in place should be in place.

## Security

`evaluate_policy` compiles and runs Rego that a model produced, inside this process. Three OPA built-ins are removed from the capability set for that reason:

| Built-in | Why |
| --- | --- |
| `http.send` | Arbitrary HTTP from wherever the server runs — a laptop or CI runner, inside whatever network boundary that sits behind. It is the whole SSRF surface, and it contradicts the tool's own description. |
| `net.lookup_ip_addr` | Enough to exfiltrate `input` one DNS label at a time, with no port reachable. |
| `opa.runtime` | Returns the runtime configuration, including the process environment and every credential in it. |

Time, JWT, UUID and random built-ins are untouched — those appear in real authorization policies. A policy using a removed built-in fails to compile with a message naming it, and pointing at `MCP_OPA_ALLOW_NETWORK_BUILTINS` for the cases where you genuinely want it.

The PDP client is constrained too: `pdp_url` must be an absolute `http(s)` URL with a host and no userinfo, redirects are refused rather than followed with the `Authorization` header attached, responses are read through a byte cap, and PDP error bodies are truncated before they reach the model's context.

Reporting a vulnerability: see [SECURITY.md](./SECURITY.md).

## Running it

### From source

```bash
make smoke
```

Builds the binary, stands up a fake AuthZEN PDP, drives one real MCP stdio session through all four tools, and asserts each answered — including that `http.send` is still rejected. No MCP client and no real PDP needed.

### Container

```bash
docker run -i --rm \
  -e AUTHZEN_PDP_URL=https://pdp.example.com/access/v1/evaluation \
  ghcr.io/kanywst/mcp-opa-authz
```

### Cursor and other MCP clients

```jsonc
{
  "mcpServers": {
    "opa-authz": {
      "command": "mcp-opa-authz",
      "env": { "AUTHZEN_PDP_URL": "http://localhost:8181/access/v1/evaluation" }
    }
  }
}
```

A local [opa-authzen-plugin](https://github.com/kanywst/opa-authzen-plugin) on `:8181` works as the PDP. So does [Topaz](https://www.topaz.sh/), [Cerbos](https://www.cerbos.dev/), [Keycloak](https://www.keycloak.org/2026/05/authzen-as-experimental-feature) with its experimental AuthZEN support, or anything else on the [interop list](https://authzen-interop.net/).

## Examples

[`examples/`](./examples/) has reference Rego policies for `evaluate_policy`:

- [`rbac.rego`](./examples/rbac.rego) — role to permission mapping
- [`abac.rego`](./examples/abac.rego) — clearance level comparison
- [`k8s_admission.rego`](./examples/k8s_admission.rego) — admission control: required labels

## Layout

Flat on purpose. A single-binary MCP server does not need `cmd/`, `internal/` or `pkg/`.

```text
main.go               server bootstrap, CLI, tool registration
config.go             environment, bounds, defaults
args.go               tool argument decoding
tool_opa.go           evaluate_policy
opa_capabilities.go   the Rego sandbox
authzen.go            AuthZEN 1.0 wire types and PDP client
tool_authzen.go       authzen_evaluate, _batch, _discover
scripts/smoke.sh      end-to-end MCP session
```

## Verifying a release

Releases ship a `cosign`-signed checksum file (Sigstore keyless via GitHub OIDC) and a CycloneDX SBOM per archive. The signature and its certificate travel together in one Sigstore bundle, `*-checksums.txt.sigstore.json`.

```bash
TAG=v0.3.0
gh release download "$TAG" -R kanywst/mcp-opa-authz -p '*-checksums.txt*'

cosign verify-blob \
  --bundle "mcp-opa-authz-${TAG#v}-checksums.txt.sigstore.json" \
  --certificate-identity-regexp 'https://github.com/kanywst/mcp-opa-authz/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "mcp-opa-authz-${TAG#v}-checksums.txt"
```

Then check the archive you downloaded against that file:

```bash
sha256sum -c "mcp-opa-authz-${TAG#v}-checksums.txt" --ignore-missing
```

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). Good first contributions: another example policy, a PDP this has not been tried against, or a gap against the AuthZEN text.

This repo is the merge of the former `0-draft/mcp-opa` and `0-draft/mcp-authzen`. Both histories are preserved here.

## License

MIT. See [LICENSE](./LICENSE).
