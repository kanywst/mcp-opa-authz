# Changelog

All notable changes to mcp-opa-authz are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`authzen_evaluate_batch` uses the endpoint the PDP advertises.** AuthZEN 1.0 §Transport says the request URL MUST be the endpoint from the PDP's metadata when one is advertised; the batch tool always derived `/access/v1/evaluations` from `AUTHZEN_PDP_URL`. Without `pdp_url`, it now resolves `access_evaluations_endpoint` exactly as `authzen_search` resolves its endpoints since v0.5.0: from the configured PDP's metadata, cached five minutes, held to the PDP's own origin, falling back to the default path. The result gains `endpoint_source`.

## [v0.5.0] - 2026-10-03

AuthZEN 1.0 metadata conformance. `authzen_search` now goes where the PDP says
its search endpoints are, and metadata is found and trusted the way the
specification says.

### Changed

- **`authzen_search` uses the endpoint the PDP advertises.** AuthZEN 1.0 §Transport says the request URL MUST be the endpoint from the PDP's metadata when one is advertised; v0.4.0 always used the default path. Without `pdp_url`, the tool now reads `/.well-known/authzen-configuration` from the configured PDP's root and uses `search_{subject,resource,action}_endpoint`, falling back to the default path when the PDP has no usable metadata or advertises none for that search. The document is cached per PDP root for five minutes, so searches do not pay a metadata round trip each; on a cold cache a search makes two round trips, each bounded by `AUTHZEN_PDP_TIMEOUT`. Only a definite answer is cached: a timeout or 5xx while refreshing keeps the previous document in use rather than falling back to the default path for five minutes. An advertised endpoint must be on the PDP's own origin (same scheme and host), since the PDP token is sent to it; pass a cross-origin endpoint as `pdp_url` to use it deliberately. The result's new `endpoint_source` (`pdp_url`, `metadata` or `default`) says which was used.

### Fixed

- **The metadata URL for a PDP under a path prefix was in the wrong place.** AuthZEN 1.0 inserts `/.well-known/authzen-configuration` between the host and the path (RFC 8615), so a PDP at `https://gw.example.com/pdp` publishes `https://gw.example.com/.well-known/authzen-configuration/pdp`. Earlier releases appended it after the prefix. The specification's location is now tried first and the appended one second, only on a 404, so a deployment set up for the old form keeps working. A root without a path is unaffected.
- **`authzen_discover` used metadata that named a different PDP.** AuthZEN 1.0 requires the document's `policy_decision_point` to be identical to the PDP identifier the well-known URL was built from, and says a document that fails that MUST NOT be used. It is now checked, tolerating only a trailing slash, and a mismatch is a tool error instead of a set of endpoints for some other PDP.

### Compatibility

- No configuration change is needed. A PDP that advertises no search endpoints, or serves no metadata, is searched at the same default paths as in v0.4.0.
- A PDP under a path prefix that served its metadata only at the appended location (`…/pdp/.well-known/authzen-configuration`) is still found, one 404 later.
- `authzen_discover` now refuses a metadata document whose `policy_decision_point` is not the PDP it was fetched from, where v0.4.0 returned it.

## [v0.4.0] - 2026-10-03

A fifth tool, `authzen_search`, completes the AuthZEN 1.0 Final surface, and a
schema fix makes structured results usable by clients that validate them.

### Added

- **`authzen_search`, the AuthZEN 1.0 Search APIs.** One tool for Subject, Resource and Action Search, selected by `search`: "who may read this document", "which documents may Alice read", "what may Alice do to this document". The endpoint defaults to the specification's `/access/v1/search/{subject,resource,action}` under the root of `AUTHZEN_PDP_URL`, so no new configuration is needed. Pagination is passed through as `page_limit` / `page_token` and reported as `has_more` / `next_page_token`.
- The search tool holds the same line as the evaluation tools: a response without `results` is an error rather than "nothing is permitted", a `page` object without `next_token` is an error rather than a guess about completeness, and a result whose `type` is not the one searched for is rejected. A search argument that would be silently ignored by the PDP — an `id` on the searched-for entity, an `action` on an action search — is rejected before the request is sent.

### Fixed

- **The advertised `outputSchema` rejected real results.** Every member passed through from the PDP — `context` on `authzen_evaluate` and on each `authzen_evaluate_batch` decision, `capabilities` and `supported_evaluation_options` from `authzen_discover` — was declared as an array of integers 0–255, because the schema was inferred from `json.RawMessage` as if it were `[]byte`. A client that validates `structuredContent` against `outputSchema`, as the MCP specification says it should, rejected the result whenever the PDP sent one of them. Those members are now declared as any JSON value; nothing else in the schemas changed.

### Compatibility

- No configuration change is needed to upgrade from v0.3.x. `authzen_search` derives its endpoints from `AUTHZEN_PDP_URL`, and needs a PDP that implements the Search APIs.
- The existing four tools keep their arguments and results. Their advertised `outputSchema` changes only for the pass-through members listed above.

## [v0.3.1] - 2026-09-29

Dependencies only. The four tools, their arguments, their output schemas and
the sandbox are what v0.3.0 shipped.

### Changed

- `github.com/mark3labs/mcp-go` v1.0.0 → v1.1.1. The stdio transport now cancels in-flight tool calls when the client closes stdin, so a client that hangs up mid-call no longer leaves a PDP request running after the session has ended.
- `github.com/open-policy-agent/opa` v1.20.2 → v1.21.0.

### Compatibility

- No configuration change is needed to upgrade from v0.3.0.

## [v0.3.0] - 2026-09-11

Distribution and dependencies. No tool behaviour changed: the four tools, their
arguments, their output schemas and the sandbox are what v0.2.1 shipped.

### Added

- **A Homebrew formula, `kanywst/tap/mcp-opa-authz`.** `brew install kanywst/tap/mcp-opa-authz` is now an alternative to `go install`, so installing the server no longer requires a Go toolchain. GoReleaser writes `Formula/mcp-opa-authz.rb` into `kanywst/homebrew-tap` as part of the release run, using a fine-grained token scoped to `contents: write` on the tap and nothing else. A Formula rather than a Cask, to match `spiffe-compliance-checker` — the other Go CLI in the tap, built and installed the same way.

### Changed

- `github.com/mark3labs/mcp-go` v0.58.0 → **v1.0.0**. A major version on the dependency, not on its use here: the server registers the same four tools through the same API, and `make check` — including the end-to-end stdio smoke test — passes unchanged.
- `github.com/open-policy-agent/opa` v1.19.1 → v1.20.2.
- The build stage of both Dockerfiles moves to `golang:1.27-alpine`. The runtime image is still `gcr.io/distroless/static-debian12:nonroot`.

### Compatibility

- `AUTHZEN_PDP_URL`, `AUTHZEN_PDP_TOKEN`, `MCP_OPA_EVAL_TIMEOUT` and `MCP_OPA_ALLOW_NETWORK_BUILTINS` keep their names and meaning. No configuration change is needed to upgrade from v0.2.x.

## [v0.2.1] - 2026-08-20

Release plumbing only. The binaries, the container image's behaviour and every
tool are byte-for-byte what v0.2.0 shipped; nothing about the server changed.

### Fixed

- **The container image now carries `io.modelcontextprotocol.server.name`.** The MCP registry refuses to list an image that does not name the server it belongs to — it is how the registry proves the `io.github.kanywst` namespace owns the image — so v0.2.0's listing was rejected and never happened. The label is on both Dockerfiles, and CI now checks it against `name` in `server.json`.
- **`server.json` puts the OCI tag in `identifier`** rather than in a separate `version` field, which the registry rejects outright for OCI packages, and its `description` is under the registry's 100-character limit.

### Changed

- The registry publish is called from `release.yml` rather than triggered by `release: published`. goreleaser creates the release with `GITHUB_TOKEN`, and GitHub does not start workflows from a `GITHUB_TOKEN` action, so that trigger never fired — the listing silently never ran, with nothing red to show for it.
- CI gained `release-snapshot`, which runs the whole goreleaser release without publishing and then makes the image it produced answer over stdio; a `server.json` check against the schema the file itself declares; and shellcheck. The v0.2.0 release broke on a `COPY` that could not resolve, because nothing had ever run the release path.

## [v0.2.0] - 2026-08-19

The first release since the `mcp-opa` / `mcp-authzen` merge. It brings the AuthZEN surface up to the 1.0 final specification, modernises the MCP surface, and closes a set of holes that came from evaluating model-supplied policy in-process.

### Added

- **`authzen_evaluate_batch`** — the AuthZEN Access Evaluations (batch) API, `POST /access/v1/evaluations`. Answers "which of these may the subject touch" in one round trip instead of a loop of single calls. Top-level subject/action/resource/context act as defaults each entry may override; `evaluations_semantic` selects `execute_all`, `deny_on_first_deny` or `permit_on_first_permit`. Decisions carry an explicit index, and a short response from an early-exit semantic is reported as `truncated` rather than silently zipped against the request list. Capped at 100 entries.
- **`authzen_discover`** — PDP metadata discovery, `GET /.well-known/authzen-configuration`. Accepts a PDP root or an evaluation endpoint (the known AuthZEN suffix is stripped) and preserves a mount prefix.
- **`X-Request-ID`** on every PDP call, as the specification recommends, and returned in the tool result so a decision in a transcript can be found in the PDP's logs.
- **AuthZEN entity validation.** `subject.type`, `subject.id`, `resource.type`, `resource.id` and `action.name` are required by the specification and are now checked before the request is sent, so a missing member produces a message naming it instead of an opaque PDP `400`.
- **Tool annotations** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, `title`) on every tool, so an MCP client can decide what it may run without prompting. `evaluate_policy` is closed-world; the `authzen_*` tools are not.
- **Output schemas and structured content.** Every tool declares an output schema and returns `structuredContent` alongside the text fallback, so a client does not have to re-parse prose.
- **Server instructions**, telling the model which layer answers which question — the common failure was reaching for a PDP when the policy source was already in the conversation.
- **`evaluate_policy` returns `defined` and `value`.** An undefined Rego query returns an empty result set, which reads as "false" to anything not already fluent in Rego. "The policy denied" and "the policy has no opinion" are now distinguishable.
- **`print()` output is captured** and returned, and **`trace`** optionally returns a pretty-printed evaluation trace, capped at 200 lines. Both exist because this tool is for debugging a policy, and "why did this rule not fire" was previously unanswerable.
- **`rego_version`** argument, `v1` (default) or `v0`, for debugging pre-OPA-1.0 policies.
- **Container image** at `ghcr.io/kanywst/mcp-opa-authz`, multi-arch, distroless, non-root — for MCP clients that launch servers with `docker run`.
- **`server.json`** and a publish workflow for the official MCP registry.
- **Configurable bounds**: `AUTHZEN_PDP_TIMEOUT`, `AUTHZEN_PDP_MAX_RESPONSE_BYTES`, `MCP_OPA_EVAL_TIMEOUT`, `MCP_MAX_ARG_BYTES`, `MCP_OPA_ALLOW_NETWORK_BUILTINS`. A malformed value stops the server at startup instead of being silently replaced by the default.
- `CONTRIBUTING.md`, `SECURITY.md` with a threat model, `CODE_OF_CONDUCT.md`, issue and PR templates, `CODEOWNERS`, and a `Claude review` workflow.

### Security

- **The Rego sandbox.** `evaluate_policy` compiles and runs policy source that came from a language model, inside this process. `http.send`, `net.lookup_ip_addr` and `opa.runtime` are removed from the OPA capability set: the first was the tool's entire SSRF surface and contradicted its own description, the second is enough to exfiltrate `input` over DNS, and the third returns the process environment. Time, JWT, UUID and random built-ins are untouched — they appear in real policies. `MCP_OPA_ALLOW_NETWORK_BUILTINS=true` restores them deliberately.
- **A Rego evaluation deadline** (`MCP_OPA_EVAL_TIMEOUT`, 5s). Previously an expensive comprehension wedged the server for the life of the session with no way to recover short of killing the subprocess.
- **Redirects from a PDP are refused** rather than followed. Following one would send the `Authorization` header to a host the operator never configured and take a decision from an origin nobody chose.
- **`pdp_url` rejects userinfo** (`http://user:pass@host`), which would otherwise be sent to a host the configured token was not issued for and echoed into error messages.
- **PDP error bodies are truncated** to 512 bytes before reaching the model's context; the read limit alone allowed a megabyte of an error page through.
- **Everything an evaluated policy can put into a tool result is bounded.** `print()` at 200 lines of 1 KiB each (`printed_truncated`), the trace at 4000 collected events and 200 rendered lines of 1 KiB (`trace_truncated`), the query result at 256 KiB encoded (`result_set_omitted`, with `defined` still reported because whether the query had an answer is knowable even when the answer is not returnable). The first two are bounded where they are collected, not only where they are rendered: the policy is model-supplied and runs in-process for the whole evaluation budget, so a cap applied at the end limited the response while the buffer grew unchecked.
- **Panic recovery** on tool handlers, so a panic inside OPA cannot take down the client's whole session.

### Fixed

- **A PDP response with no `decision` was reported as a deny.** The member is REQUIRED by AuthZEN 1.0, and decoding it into a Go `bool` made a PDP that failed to answer indistinguishable from one that said no. It is now a tool error. This is the most consequential fix in this release.
- **Only `200` is treated as carrying a decision.** Any other status is an error, and `401`/`403` say explicitly that *this server* failed to authenticate to the PDP rather than that the subject was denied — the two have completely different fixes, and the old message did not distinguish them.
- **A clean shutdown exited non-zero.** `ServeStdio` reports the client closing stdin, or SIGINT/SIGTERM, as a context cancellation; that was passed to `log.Fatalf`, so every normal exit looked like a crash in the client's log.
- **Failing built-ins no longer become a silent deny.** `StrictBuiltinErrors` is on, so a type error in a policy is reported as an error instead of making the expression undefined.
- **The `Authorization` scheme check is case-insensitive** and tolerates surrounding whitespace, per RFC 9110. A token configured as `bearer x` was previously re-prefixed into `Bearer bearer x`.
- **Argument size limits.** `rego`, `input_json`, `data_json` and the AuthZEN entities are bounded; previously any of them could be arbitrarily large.

### Changed

- **Breaking: tool result shapes.** `evaluate_policy` returned the bare OPA `ResultSet` as JSON text and now returns an object with `defined`, `value`, `result_set`, `printed` and `trace`. `authzen_evaluate` returned `{decision, context}` and now also carries `pdp_url` and `request_id`. Anything parsing the text content of these tools needs updating; the raw result set is still there under `result_set`.
- **Breaking: AuthZEN entities are validated.** A `subject` of `{"id":"alice"}` with no `type` was previously forwarded and is now rejected.
- Configuration is read once at startup rather than per tool call, so behaviour no longer depends on when a call happened.
- Restructured into `config.go`, `args.go`, `authzen.go` and `opa_capabilities.go` alongside the tool files. Still a flat `package main`.
- `make smoke` drives all four tools plus `tools/list`, and asserts the sandbox rejects `http.send` end to end.
- `.golangci.yml` added; the linter previously ran on defaults.

### Compatibility

- Built against OPA v1.19.1 and mcp-go v0.58.0 (MCP protocol 2025-11-25, with backward compatibility to 2024-11-05).
- `AUTHZEN_PDP_URL` and `AUTHZEN_PDP_TOKEN` keep their names and meaning.

---

## [v0.1.0] - 2026-08-19

First release after merging `0-draft/mcp-opa` and `0-draft/mcp-authzen` into one binary. Two tools, `evaluate_policy` and `authzen_evaluate`, over MCP stdio.

[Unreleased]: https://github.com/kanywst/mcp-opa-authz/compare/v0.5.0...HEAD
[v0.5.0]: https://github.com/kanywst/mcp-opa-authz/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/kanywst/mcp-opa-authz/compare/v0.3.1...v0.4.0
[v0.3.1]: https://github.com/kanywst/mcp-opa-authz/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/kanywst/mcp-opa-authz/compare/v0.2.1...v0.3.0
[v0.2.1]: https://github.com/kanywst/mcp-opa-authz/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/kanywst/mcp-opa-authz/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/kanywst/mcp-opa-authz/releases/tag/v0.1.0
