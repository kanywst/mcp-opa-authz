package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// maxBatchEvaluations bounds one batch call. The specification sets no limit;
// this one exists because the list is model-generated and each entry is work
// the PDP has to do.
const maxBatchEvaluations = 100

// evaluateOutput is the structured result of authzen_evaluate.
type evaluateOutput struct {
	// Decision is the PDP's answer. False means denied — never "the PDP could
	// not be reached", which is an error result instead.
	Decision bool `json:"decision"`
	// Context is whatever additional information the PDP chose to return, such
	// as a reason or an obligation. Passed through unmodified.
	Context json.RawMessage `json:"context,omitempty"`
	// PDPURL is the endpoint that produced this decision, so a decision in a
	// transcript can be traced to a PDP.
	PDPURL string `json:"pdp_url"`
	// RequestID is the X-Request-ID sent with the call, for correlating it
	// against the PDP's own logs.
	RequestID string `json:"request_id"`
}

// batchOutput is the structured result of authzen_evaluate_batch.
type batchOutput struct {
	// Decisions are aligned by index with the `evaluations` argument.
	Decisions []batchDecision `json:"decisions"`
	// Semantic is the evaluation semantic the PDP was asked to apply.
	Semantic string `json:"evaluations_semantic"`
	// Truncated reports that the PDP returned fewer decisions than there were
	// evaluations, which the deny_on_first_deny and permit_on_first_permit
	// semantics allow.
	Truncated bool   `json:"truncated"`
	PDPURL    string `json:"pdp_url"`
	RequestID string `json:"request_id"`
}

type batchDecision struct {
	Index    int             `json:"index"`
	Decision bool            `json:"decision"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// discoverOutput is the structured result of authzen_discover.
type discoverOutput struct {
	MetadataURL string      `json:"metadata_url"`
	Metadata    pdpMetadata `json:"metadata"`
}

func registerAuthZENTools(s *server.MCPServer, client *pdpClient) {
	registerEvaluateTool(s, client)
	registerBatchTool(s, client)
	registerDiscoverTool(s, client)
	registerSearchTool(s, client)
}

// --- authzen_evaluate ------------------------------------------------------

func registerEvaluateTool(s *server.MCPServer, client *pdpClient) {
	s.AddTool(
		mcp.NewTool("authzen_evaluate",
			mcp.WithDescription(
				"Ask an OpenID AuthZEN 1.0 Policy Decision Point whether a subject may "+
					"perform an action on a resource. Use this when the answer has to come "+
					"from the PDP that actually governs the system, rather than from a "+
					"policy pasted into the conversation. Returns the PDP's decision and "+
					"any context it attached."),
			mcp.WithTitleAnnotation("Ask an AuthZEN PDP for a decision"),
			// Asking for a decision does not change anything at the PDP, but it
			// does leave this process to reach a service the client did not
			// name, which is exactly what openWorldHint describes.
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(true),
			withOutputSchema[evaluateOutput](),
			mcp.WithString("subject",
				mcp.Required(),
				mcp.Description(`JSON object identifying the principal. AuthZEN requires `+
					`"type" and "id"; "properties" is optional. Example: `+
					`{"type":"user","id":"alice","properties":{"department":"sales"}}`),
			),
			mcp.WithString("action",
				mcp.Required(),
				mcp.Description(`JSON object naming the action. AuthZEN requires "name"; `+
					`"properties" is optional. Example: {"name":"read"}`),
			),
			mcp.WithString("resource",
				mcp.Required(),
				mcp.Description(`JSON object identifying the target. AuthZEN requires `+
					`"type" and "id"; "properties" is optional. Example: `+
					`{"type":"document","id":"doc-1","properties":{"classification":"secret"}}`),
			),
			mcp.WithString("context",
				mcp.Description(`Optional JSON object of runtime context the policy may `+
					`read — IP address, time of day, MFA strength. Example: `+
					`{"ip":"10.0.0.7","mfa":"webauthn"}`),
			),
			mcp.WithString("pdp_url",
				mcp.Description("Override the configured "+envPDPURL+" for this call. "+
					"Must be an absolute http(s) URL to an Access Evaluation endpoint."),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return authzenEvaluate(ctx, req, client)
		},
	)
}

func authzenEvaluate(ctx context.Context, req mcp.CallToolRequest, client *pdpClient) (*mcp.CallToolResult, error) {
	endpoint, err := client.resolveEndpoint(req.GetString("pdp_url", ""))
	if err != nil {
		return toolErrorf("%v", err), nil
	}

	body, err := readEvaluationArgs(req, client.cfg, true)
	if err != nil {
		return toolErrorf("%v", err), nil
	}

	var decoded evaluationResponse
	requestID, err := client.postJSON(ctx, endpoint, body, &decoded)
	if err != nil {
		return toolErrorf("%v", err), nil
	}
	if decoded.Decision == nil {
		return toolErrorf(
			"PDP response has no `decision` member, which AuthZEN 1.0 requires. "+
				"Treating this as a failure rather than a deny; endpoint %s, request id %s.",
			endpoint, requestID), nil
	}

	out := evaluateOutput{
		Decision:  *decoded.Decision,
		Context:   decoded.Context,
		PDPURL:    endpoint,
		RequestID: requestID,
	}
	return structuredResult(out)
}

// --- authzen_evaluate_batch ------------------------------------------------

func registerBatchTool(s *server.MCPServer, client *pdpClient) {
	s.AddTool(
		mcp.NewTool("authzen_evaluate_batch",
			mcp.WithDescription(
				"Ask an OpenID AuthZEN 1.0 PDP for several decisions in one round trip "+
					"(the Access Evaluations API). Use this to answer \"which of these may "+
					"the subject do\" — filtering a list of resources, or checking every "+
					"action on one resource — instead of calling authzen_evaluate in a "+
					"loop. Top-level subject/action/resource/context act as defaults that "+
					"each entry may override."),
			mcp.WithTitleAnnotation("Ask an AuthZEN PDP for many decisions"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(true),
			withOutputSchema[batchOutput](),
			mcp.WithString("evaluations",
				mcp.Required(),
				mcp.Description(`JSON array of evaluation objects. Each may carry its own `+
					`"subject", "action", "resource" and "context"; anything omitted falls `+
					`back to the top-level argument of the same name. Example: `+
					`[{"resource":{"type":"doc","id":"1"}},{"resource":{"type":"doc","id":"2"}}]`),
			),
			mcp.WithString("subject",
				mcp.Description(`Default JSON subject for entries that omit one. `+
					`Requires "type" and "id".`),
			),
			mcp.WithString("action",
				mcp.Description(`Default JSON action for entries that omit one. Requires "name".`),
			),
			mcp.WithString("resource",
				mcp.Description(`Default JSON resource for entries that omit one. `+
					`Requires "type" and "id".`),
			),
			mcp.WithString("context",
				mcp.Description("Default JSON context object for entries that omit one."),
			),
			mcp.WithString("evaluations_semantic",
				mcp.Description("How the PDP should process the list. `execute_all` "+
					"(default) evaluates every entry; `deny_on_first_deny` and "+
					"`permit_on_first_permit` let the PDP stop early and return fewer "+
					"decisions than there were entries."),
				mcp.Enum(semanticExecuteAll, semanticDenyOnFirstDeny, semanticPermitOnFirstPerm),
			),
			mcp.WithString("pdp_url",
				mcp.Description("Override the configured "+envPDPURL+" for this call. "+
					"Must point at an Access Evaluations (plural) endpoint."),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return authzenEvaluateBatch(ctx, req, client)
		},
	)
}

func authzenEvaluateBatch(ctx context.Context, req mcp.CallToolRequest, client *pdpClient) (*mcp.CallToolResult, error) {
	endpoint := req.GetString("pdp_url", "")
	if endpoint == "" {
		// The configured URL names the single-evaluation endpoint. Deriving the
		// plural one from it is what an operator would do by hand, and saves
		// every client config from having to carry both.
		var err error
		if endpoint, err = batchEndpointFrom(client.cfg.PDPURL); err != nil {
			return toolErrorf("%v", err), nil
		}
	}
	if err := validatePDPURL(endpoint); err != nil {
		return toolErrorf("%v", err), nil
	}

	// Defaults are optional here — an entry may carry everything itself — so
	// they are validated only when present.
	defaults, err := readEvaluationArgs(req, client.cfg, false)
	if err != nil {
		return toolErrorf("%v", err), nil
	}

	entries, err := readEvaluationEntries(req, client.cfg, defaults)
	if err != nil {
		return toolErrorf("%v", err), nil
	}

	semantic := req.GetString("evaluations_semantic", semanticExecuteAll)
	switch semantic {
	case semanticExecuteAll, semanticDenyOnFirstDeny, semanticPermitOnFirstPerm:
	default:
		return toolErrorf("evaluations_semantic must be one of %q, %q, %q; got %q",
			semanticExecuteAll, semanticDenyOnFirstDeny, semanticPermitOnFirstPerm, semantic), nil
	}

	body := evaluationsRequest{
		Subject:     defaults.Subject,
		Action:      defaults.Action,
		Resource:    defaults.Resource,
		Context:     defaults.Context,
		Evaluations: entries,
		Options:     &evaluationsOption{Semantic: semantic},
	}

	var decoded evaluationsResponse
	requestID, err := client.postJSON(ctx, endpoint, body, &decoded)
	if err != nil {
		return toolErrorf("%v", err), nil
	}
	if decoded.Evaluations == nil {
		return toolErrorf(
			"PDP response has no `evaluations` member, which AuthZEN 1.0 requires for a "+
				"batch request. Endpoint %s, request id %s.", endpoint, requestID), nil
	}
	if len(decoded.Evaluations) > len(entries) {
		return toolErrorf(
			"PDP returned %d decisions for %d evaluations; the extra decisions cannot be "+
				"matched to a request, so none of them are reported. Endpoint %s, request id %s.",
			len(decoded.Evaluations), len(entries), endpoint, requestID), nil
	}

	// Index is carried explicitly rather than left implicit in the array
	// position: an early-exit semantic returns a short list, and a decision
	// silently re-associated with the wrong resource is the worst outcome this
	// tool has.
	decisions := make([]batchDecision, 0, len(decoded.Evaluations))
	for i, e := range decoded.Evaluations {
		if e.Decision == nil {
			return toolErrorf(
				"evaluation %d in the PDP response has no `decision` member, which "+
					"AuthZEN 1.0 requires. Endpoint %s, request id %s.", i, endpoint, requestID), nil
		}
		decisions = append(decisions, batchDecision{
			Index:    i,
			Decision: *e.Decision,
			Context:  e.Context,
		})
	}

	out := batchOutput{
		Decisions: decisions,
		Semantic:  semantic,
		Truncated: len(decisions) < len(entries),
		PDPURL:    endpoint,
		RequestID: requestID,
	}
	return structuredResult(out)
}

// batchEndpointFrom derives the Access Evaluations endpoint from a configured
// Access Evaluation endpoint.
func batchEndpointFrom(configured string) (string, error) {
	return siblingEndpoint(configured, pathEvaluations)
}

// siblingEndpoint derives another default AuthZEN endpoint from the configured
// one: same PDP root, the specification's default path for the other API.
func siblingEndpoint(configured, path string) (string, error) {
	if configured == "" {
		return "", pdpErrorf("no PDP endpoint: set %s in the MCP server environment, or pass pdp_url", envPDPURL)
	}
	root, err := rootOf(configured)
	if err != nil {
		return "", err
	}
	return resolveFromRoot(root, path)
}

// --- authzen_discover ------------------------------------------------------

func registerDiscoverTool(s *server.MCPServer, client *pdpClient) {
	s.AddTool(
		mcp.NewTool("authzen_discover",
			mcp.WithDescription(
				"Fetch a PDP's AuthZEN metadata document from "+pathMetadata+" to find "+
					"out which endpoints and capabilities it offers. Use this when a PDP "+
					"URL is known but its evaluation endpoint is not, or to check whether "+
					"a PDP supports batch evaluation before calling authzen_evaluate_batch."),
			mcp.WithTitleAnnotation("Discover an AuthZEN PDP's endpoints"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(true),
			withOutputSchema[discoverOutput](),
			mcp.WithString("pdp_url",
				mcp.Description("The PDP root, e.g. `https://pdp.example.com`. An "+
					"evaluation endpoint URL is also accepted — the known AuthZEN path "+
					"suffix is stripped. Defaults to the configured "+envPDPURL+"."),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return authzenDiscover(ctx, req, client)
		},
	)
}

func authzenDiscover(ctx context.Context, req mcp.CallToolRequest, client *pdpClient) (*mcp.CallToolResult, error) {
	raw := req.GetString("pdp_url", "")
	if raw == "" {
		raw = client.cfg.PDPURL
	}
	if raw == "" {
		return toolErrorf("no PDP URL: set %s in the MCP server environment, or pass pdp_url", envPDPURL), nil
	}

	root, err := rootOf(raw)
	if err != nil {
		return toolErrorf("%v", err), nil
	}
	metadataURL, err := resolveFromRoot(root, pathMetadata)
	if err != nil {
		return toolErrorf("%v", err), nil
	}

	var meta pdpMetadata
	if err := client.getJSON(ctx, metadataURL, &meta); err != nil {
		return toolErrorf("%v", err), nil
	}
	if meta.AccessEvaluationEndpoint == "" {
		return toolErrorf(
			"metadata at %s has no `access_evaluation_endpoint`, which AuthZEN 1.0 "+
				"requires; this does not look like an AuthZEN PDP", metadataURL), nil
	}

	return structuredResult(discoverOutput{MetadataURL: metadataURL, Metadata: meta})
}

// --- shared argument handling ----------------------------------------------

// readEvaluationArgs reads the subject/action/resource/context arguments shared
// by the single and batch tools. When required is false the three entities may
// be absent, which is how the batch tool's per-entry overrides work.
func readEvaluationArgs(req mcp.CallToolRequest, cfg *config, required bool) (evaluationRequest, error) {
	var out evaluationRequest
	var err error

	if out.Subject, err = jsonObjectArg(req, "subject", cfg.MaxArgBytes, required); err != nil {
		return out, err
	}
	if out.Action, err = jsonObjectArg(req, "action", cfg.MaxArgBytes, required); err != nil {
		return out, err
	}
	if out.Resource, err = jsonObjectArg(req, "resource", cfg.MaxArgBytes, required); err != nil {
		return out, err
	}
	if out.Context, err = jsonObjectArg(req, "context", cfg.MaxArgBytes, false); err != nil {
		return out, err
	}

	if err := validateEntities(out, "argument"); err != nil {
		return out, err
	}
	return out, nil
}

// readEvaluationEntries reads and validates the `evaluations` array against the
// top-level defaults each entry falls back to.
func readEvaluationEntries(req mcp.CallToolRequest, cfg *config, defaults evaluationRequest) ([]json.RawMessage, error) {
	var entries []json.RawMessage
	// The array can be large — one entry per resource being filtered — so it
	// gets the same byte bound as a policy rather than the entity bound.
	ok, err := optionalJSON(req, "evaluations", cfg.MaxArgBytes, &entries)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("missing required argument %q", "evaluations")
	}
	if entries == nil {
		return nil, fmt.Errorf("argument %q must be a JSON array of evaluation objects", "evaluations")
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("argument %q is empty; there is nothing to evaluate", "evaluations")
	}
	if len(entries) > maxBatchEvaluations {
		return nil, fmt.Errorf("argument %q has %d entries, over the limit of %d",
			"evaluations", len(entries), maxBatchEvaluations)
	}

	for i, raw := range entries {
		if _, err := asJSONObject(raw); err != nil {
			return nil, fmt.Errorf("evaluations[%d]: %w", i, err)
		}
		var entry evaluationRequest
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, fmt.Errorf("evaluations[%d]: %w", i, err)
		}
		// What the PDP will actually evaluate is the entry over the defaults, so
		// that is what gets checked. Validating the two halves separately would
		// pass a request where neither half carries a subject.
		effective := evaluationRequest{
			Subject:  firstPresent(entry.Subject, defaults.Subject),
			Action:   firstPresent(entry.Action, defaults.Action),
			Resource: firstPresent(entry.Resource, defaults.Resource),
			Context:  firstPresent(entry.Context, defaults.Context),
		}
		where := fmt.Sprintf("evaluations[%d]", i)
		for _, missing := range []struct {
			raw  json.RawMessage
			name string
		}{
			{effective.Subject, "subject"},
			{effective.Action, "action"},
			{effective.Resource, "resource"},
		} {
			if len(missing.raw) == 0 {
				return nil, fmt.Errorf(
					"%s has no %q and no top-level %q to fall back to; AuthZEN 1.0 requires one",
					where, missing.name, missing.name)
			}
		}
		if err := validateEntities(effective, where); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// firstPresent returns the first non-empty raw message.
func firstPresent(entry, fallback json.RawMessage) json.RawMessage {
	if len(entry) > 0 {
		return entry
	}
	return fallback
}

// validateEntities checks the required members of each present entity.
//
// The specification makes subject.type, subject.id, resource.type, resource.id
// and action.name REQUIRED. Checking them here rather than letting the PDP do
// it turns an opaque 400 into a message naming the missing member — and a model
// that omitted `type` will otherwise re-send the same request, having no way to
// know which of four arguments the PDP objected to.
func validateEntities(r evaluationRequest, where string) error {
	if err := requireMembers(r.Subject, where+" subject", "type", "id"); err != nil {
		return err
	}
	if err := requireMembers(r.Action, where+" action", "name"); err != nil {
		return err
	}
	return requireMembers(r.Resource, where+" resource", "type", "id")
}

// requireMembers checks that raw, when present, is an object carrying every
// named member as a non-empty string.
func requireMembers(raw json.RawMessage, what string, members ...string) error {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%s is not a JSON object: %w", what, err)
	}
	for _, m := range members {
		v, ok := obj[m]
		if !ok {
			return fmt.Errorf("%s is missing %q, which AuthZEN 1.0 requires", what, m)
		}
		// Decoded through `any` rather than straight into a string, because
		// json.Unmarshal of a literal null into a string succeeds and leaves
		// "" — which would be reported as an empty value rather than as the
		// wrong type.
		var decoded any
		if err := json.Unmarshal(v, &decoded); err != nil {
			return fmt.Errorf("%s: %q is not valid JSON: %w", what, m, err)
		}
		s, ok := decoded.(string)
		if !ok {
			return fmt.Errorf("%s: %q must be a string, which AuthZEN 1.0 requires; got %s",
				what, m, jsonKind(decoded))
		}
		if s == "" {
			return fmt.Errorf("%s: %q must not be empty, which AuthZEN 1.0 requires", what, m)
		}
	}
	return nil
}

// structuredResult returns a result carrying both the structured value — for
// clients on a spec revision that supports it — and its JSON rendering as text,
// for those that do not.
func structuredResult(v any) (*mcp.CallToolResult, error) {
	text, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolErrorf("failed to encode result: %v", err), nil
	}
	return mcp.NewToolResultStructured(v, string(text)), nil
}
