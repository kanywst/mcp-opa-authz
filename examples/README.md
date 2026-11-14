# Examples

Reference Rego policies for `evaluate_policy`. Each carries a header comment with its query and a sample input, so you can hand a file and its header to the tool and get an answer without reading the rest.

| File | Pattern | Query |
| --- | --- | --- |
| [`rbac.rego`](./rbac.rego) | Role-based: roles → permissions | `data.rbac.allow` |
| [`abac.rego`](./abac.rego) | Attribute-based: clearance level comparison | `data.abac.allow` |
| [`k8s_admission.rego`](./k8s_admission.rego) | Admission control: required labels | `data.k8s.admission.violation` |

All three are Rego v1 — rule bodies use `if`, multi-value rules use `contains`. Pass `rego_version: "v0"` if you are debugging a pre-OPA-1.0 policy of your own.

## In a session

```bash
claude mcp add opa-authz -- mcp-opa-authz
```

Then ask for what you actually want to know:

> Evaluate examples/rbac.rego for alice trying to delete doc-1. Why does it answer that?

The model reads the file, picks `data.rbac.allow`, sends `{"user":"alice","action":"delete","resource":"doc-1"}`, and reads back the decision. Adding "why" gets it to pass `trace: true`, which returns the evaluation trace — usually enough to see which rule body failed.

Note the difference between `"defined": true, "value": false` and `"defined": false`. The first is a deny; the second means nothing matched and there was no default, which is a different bug.

## Over stdio, by hand

MCP is JSON-RPC over stdin/stdout, so the tools are reachable without a client. The `initialize` handshake is required before any `tools/call`.

Keep stdin open until the reply arrives: when stdin closes, the server cancels calls that are still running, and a bare `printf | mcp-opa-authz` gets `eval_cancel_error: context canceled` back. The `sleep` does that.

```bash
{ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cli","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  "$(jq -nc --arg r "$(cat examples/rbac.rego)" \
      '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"evaluate_policy",arguments:{
         rego:$r,
         query:"data.rbac.allow",
         input_json:"{\"user\":\"alice\",\"action\":\"read\"}"
       }}}')"; sleep 2; } \
  | mcp-opa-authz | jq -r 'select(.id==2) | .result.content[0].text'
```

```json
{
  "defined": true,
  "value": true,
  "result_set": [ … ]
}
```

## Against a real PDP

The same question, asked of the PDP that actually governs a system, needs `AUTHZEN_PDP_URL` set and uses `authzen_evaluate`. [`opa-authzen-plugin`](https://github.com/kanywst/opa-authzen-plugin) serves these same policies over the AuthZEN API if you want to compare the two answers directly — which is the point of having both tools in one server.
