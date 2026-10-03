package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func callEvaluate(t *testing.T, client *pdpClient, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := authzenEvaluate(context.Background(), newRequest("authzen_evaluate", args), client)
	if err != nil {
		t.Fatalf("authzenEvaluate returned a non-nil error, which the transport would "+
			"report as a fault instead of showing the model: %v", err)
	}
	return res
}

func callBatch(t *testing.T, client *pdpClient, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := authzenEvaluateBatch(context.Background(), newRequest("authzen_evaluate_batch", args), client)
	if err != nil {
		t.Fatalf("authzenEvaluateBatch returned a non-nil error: %v", err)
	}
	return res
}

func callDiscover(t *testing.T, client *pdpClient, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := authzenDiscover(context.Background(), newRequest("authzen_discover", args), client)
	if err != nil {
		t.Fatalf("authzenDiscover returned a non-nil error: %v", err)
	}
	return res
}

// --- authzen_evaluate -------------------------------------------------------

func TestEvaluate_Allow(t *testing.T) {
	pdp, got := decisionPDP(t, true)
	_, client := clientFor(pdp.URL, pathEvaluation)

	out := structured[evaluateOutput](t, callEvaluate(t, client, evaluateArgs(nil)))
	if !out.Decision {
		t.Fatal("decision = false, want true")
	}
	if out.PDPURL != pdp.URL+pathEvaluation {
		t.Fatalf("pdp_url = %q, want the endpoint that answered", out.PDPURL)
	}
	if out.RequestID == "" {
		t.Fatal("no request id was reported, so a decision cannot be correlated with a PDP log")
	}
	if got.Method != http.MethodPost {
		t.Fatalf("method = %s, want POST", got.Method)
	}
}

func TestEvaluate_Deny(t *testing.T) {
	pdp, _ := decisionPDP(t, false)
	_, client := clientFor(pdp.URL, pathEvaluation)

	out := structured[evaluateOutput](t, callEvaluate(t, client, evaluateArgs(nil)))
	if out.Decision {
		t.Fatal("decision = true, want false")
	}
}

// The entities must reach the PDP byte for byte. A decode/re-encode round trip
// would reorder properties and turn integers into floats, and a policy keyed on
// either would then answer a different question than the one asked.
func TestEvaluate_ForwardsEntitiesVerbatim(t *testing.T) {
	pdp, got := decisionPDP(t, true)
	_, client := clientFor(pdp.URL, pathEvaluation)

	subject := `{"type":"user","id":"alice","properties":{"level":7,"tags":["b","a"]}}`
	res := callEvaluate(t, client, evaluateArgs(map[string]any{
		"subject": subject,
		"context": `{"ip":"10.0.0.7","mfa":"webauthn"}`,
	}))
	requireNoToolError(t, res)

	var sent evaluationRequest
	if err := json.Unmarshal(got.Body, &sent); err != nil {
		t.Fatalf("PDP received a body that is not an evaluation request: %v (%s)", err, got.Body)
	}
	if string(sent.Subject) != subject {
		t.Fatalf("subject was rewritten in transit:\n sent: %s\nwant: %s", sent.Subject, subject)
	}
	if string(sent.Action) != validAction {
		t.Fatalf("action = %s, want %s", sent.Action, validAction)
	}
	if string(sent.Resource) != validResource {
		t.Fatalf("resource = %s, want %s", sent.Resource, validResource)
	}
	if !strings.Contains(string(sent.Context), "webauthn") {
		t.Fatalf("context did not reach the PDP: %s", sent.Context)
	}
}

func TestEvaluate_PassesThroughPDPContext(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{
		"decision": false,
		"context":  map[string]any{"reason": "clearance too low", "id": "R42"},
	})
	_, client := clientFor(pdp.URL, pathEvaluation)

	out := structured[evaluateOutput](t, callEvaluate(t, client, evaluateArgs(nil)))
	if out.Decision {
		t.Fatal("decision = true, want false")
	}
	if !strings.Contains(string(out.Context), "clearance too low") {
		t.Fatalf("the PDP's reason was dropped: %s", out.Context)
	}
}

// A response with no `decision` is a PDP that did not answer. Decoding it into
// a plain bool would make it a deny, so a broken PDP would look like a strict
// one — the single most dangerous way for this tool to be wrong.
func TestEvaluate_MissingDecisionIsAnErrorNotADeny(t *testing.T) {
	for name, body := range map[string]string{
		"empty object": `{}`,
		"only context": `{"context":{"reason":"x"}}`,
		"null":         `null`,
	} {
		t.Run(name, func(t *testing.T) {
			pdp, _ := rawPDP(t, http.StatusOK, body)
			_, client := clientFor(pdp.URL, pathEvaluation)

			msg := requireToolError(t, callEvaluate(t, client, evaluateArgs(nil)), "decision")
			if strings.Contains(strings.ToLower(msg), "denied") {
				t.Fatalf("a missing decision must not be reported as a deny: %s", msg)
			}
		})
	}
}

func TestEvaluate_NoEndpointConfigured(t *testing.T) {
	cfg := testConfig()
	requireToolError(t, callEvaluate(t, newPDPClient(cfg), evaluateArgs(nil)), envPDPURL)
}

func TestEvaluate_PDPURLOverridesConfig(t *testing.T) {
	configured, _ := decisionPDP(t, false)
	override, _ := decisionPDP(t, true)
	_, client := clientFor(configured.URL, pathEvaluation)

	out := structured[evaluateOutput](t, callEvaluate(t, client, evaluateArgs(map[string]any{
		"pdp_url": override.URL + pathEvaluation,
	})))
	if !out.Decision {
		t.Fatal("the pdp_url override was ignored")
	}
}

// --- AuthZEN entity validation ----------------------------------------------

// type, id and name are REQUIRED by AuthZEN 1.0. Rejecting here names the
// missing member; letting the PDP reject produces an opaque 400 that a model
// cannot act on.
func TestEvaluate_RequiresSpecMandatedMembers(t *testing.T) {
	cases := map[string]map[string]any{
		"subject without type":   {"subject": `{"id":"alice"}`},
		"subject without id":     {"subject": `{"type":"user"}`},
		"resource without type":  {"resource": `{"id":"doc-1"}`},
		"resource without id":    {"resource": `{"type":"document"}`},
		"action without name":    {"action": `{"properties":{}}`},
		"empty subject id":       {"subject": `{"type":"user","id":""}`},
		"non-string action name": {"action": `{"name":42}`},
	}

	pdp, _ := decisionPDP(t, true)
	_, client := clientFor(pdp.URL, pathEvaluation)

	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			requireToolError(t, callEvaluate(t, client, evaluateArgs(override)), "AuthZEN")
		})
	}
}

func TestEvaluate_RejectsNonObjectEntities(t *testing.T) {
	pdp, _ := decisionPDP(t, true)
	_, client := clientFor(pdp.URL, pathEvaluation)

	for name, override := range map[string]map[string]any{
		"array subject":  {"subject": `["alice"]`},
		"string action":  {"action": `"read"`},
		"number context": {"context": `42`},
		"malformed json": {"subject": `{not json}`},
	} {
		t.Run(name, func(t *testing.T) {
			requireToolError(t, callEvaluate(t, client, evaluateArgs(override)), "")
		})
	}
}

func TestEvaluate_MissingRequiredArgs(t *testing.T) {
	pdp, _ := decisionPDP(t, true)
	_, client := clientFor(pdp.URL, pathEvaluation)

	for _, missing := range []string{"subject", "action", "resource"} {
		t.Run(missing, func(t *testing.T) {
			args := evaluateArgs(nil)
			delete(args, missing)
			requireToolError(t, callEvaluate(t, client, args), missing)
		})
	}
}

// --- authzen_evaluate_batch -------------------------------------------------

func TestBatch_AlignsDecisionsWithRequests(t *testing.T) {
	pdp, got := jsonPDP(t, map[string]any{
		"evaluations": []map[string]any{
			{"decision": true},
			{"decision": false, "context": map[string]any{"reason": "not owner"}},
			{"decision": true},
		},
	})
	_, client := clientFor(pdp.URL, pathEvaluation)

	res := callBatch(t, client, map[string]any{
		"subject": validSubject,
		"action":  validAction,
		"evaluations": `[
			{"resource":{"type":"document","id":"1"}},
			{"resource":{"type":"document","id":"2"}},
			{"resource":{"type":"document","id":"3"}}
		]`,
	})

	out := structured[batchOutput](t, res)
	if len(out.Decisions) != 3 {
		t.Fatalf("got %d decisions, want 3", len(out.Decisions))
	}
	for i, d := range out.Decisions {
		if d.Index != i {
			t.Fatalf("decision %d carries index %d", i, d.Index)
		}
	}
	if out.Decisions[1].Decision {
		t.Fatal("decision 1 should be a deny")
	}
	if !strings.Contains(string(out.Decisions[1].Context), "not owner") {
		t.Fatalf("per-entry context was dropped: %s", out.Decisions[1].Context)
	}
	if out.Truncated {
		t.Fatal("nothing was truncated")
	}

	// The configured URL names the singular endpoint; the batch tool has to
	// find the plural one on its own.
	if got.Path != pathEvaluations {
		t.Fatalf("batch went to %q, want %q", got.Path, pathEvaluations)
	}
}

func TestBatch_SendsDefaultsAndEntries(t *testing.T) {
	pdp, got := jsonPDP(t, map[string]any{"evaluations": []map[string]any{{"decision": true}}})
	_, client := clientFor(pdp.URL, pathEvaluation)

	res := callBatch(t, client, map[string]any{
		"subject":              validSubject,
		"action":               validAction,
		"evaluations":          `[{"resource":{"type":"document","id":"1"}}]`,
		"evaluations_semantic": semanticDenyOnFirstDeny,
	})
	requireNoToolError(t, res)

	var sent evaluationsRequest
	if err := json.Unmarshal(got.Body, &sent); err != nil {
		t.Fatalf("body is not an evaluations request: %v (%s)", err, got.Body)
	}
	if string(sent.Subject) != validSubject {
		t.Fatalf("default subject = %s, want %s", sent.Subject, validSubject)
	}
	if len(sent.Evaluations) != 1 {
		t.Fatalf("sent %d evaluations, want 1", len(sent.Evaluations))
	}
	if sent.Options == nil || sent.Options.Semantic != semanticDenyOnFirstDeny {
		t.Fatalf("evaluations_semantic did not reach the PDP: %+v", sent.Options)
	}
}

// An early-exit semantic is allowed to return fewer decisions than there were
// entries. Reporting that is the difference between "the rest were permitted"
// and "the rest were not evaluated".
func TestBatch_ShortResponseIsReportedAsTruncated(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{
		"evaluations": []map[string]any{{"decision": false}},
	})
	_, client := clientFor(pdp.URL, pathEvaluation)

	out := structured[batchOutput](t, callBatch(t, client, map[string]any{
		"subject":              validSubject,
		"action":               validAction,
		"evaluations":          `[{"resource":{"type":"d","id":"1"}},{"resource":{"type":"d","id":"2"}}]`,
		"evaluations_semantic": semanticDenyOnFirstDeny,
	}))
	if !out.Truncated {
		t.Fatal("a short response must be reported as truncated")
	}
	if len(out.Decisions) != 1 {
		t.Fatalf("got %d decisions, want the 1 the PDP returned", len(out.Decisions))
	}
}

// More decisions than requests means the indices cannot be trusted at all.
// Silently zipping them would attach a decision to the wrong resource.
func TestBatch_RejectsOverlongResponse(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{
		"evaluations": []map[string]any{{"decision": true}, {"decision": true}},
	})
	_, client := clientFor(pdp.URL, pathEvaluation)

	requireToolError(t, callBatch(t, client, map[string]any{
		"subject":     validSubject,
		"action":      validAction,
		"evaluations": `[{"resource":{"type":"d","id":"1"}}]`,
	}), "cannot be matched")
}

func TestBatch_RejectsEntryMissingDecision(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{
		"evaluations": []map[string]any{{"decision": true}, {"context": map[string]any{}}},
	})
	_, client := clientFor(pdp.URL, pathEvaluation)

	requireToolError(t, callBatch(t, client, map[string]any{
		"subject":     validSubject,
		"action":      validAction,
		"evaluations": `[{"resource":{"type":"d","id":"1"}},{"resource":{"type":"d","id":"2"}}]`,
	}), "decision")
}

func TestBatch_RejectsMissingEvaluationsMember(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{"decision": true})
	_, client := clientFor(pdp.URL, pathEvaluation)

	requireToolError(t, callBatch(t, client, map[string]any{
		"subject":     validSubject,
		"action":      validAction,
		"evaluations": `[{"resource":{"type":"d","id":"1"}}]`,
	}), "evaluations")
}

func TestBatch_ValidatesEntries(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{"evaluations": []map[string]any{{"decision": true}}})
	_, client := clientFor(pdp.URL, pathEvaluation)

	cases := map[string]any{
		"not an array":       `{"resource":{"type":"d","id":"1"}}`,
		"empty":              `[]`,
		"entry not object":   `["doc-1"]`,
		"entry bad resource": `[{"resource":{"id":"1"}}]`,
		"malformed":          `[{`,
	}
	for name, evaluations := range cases {
		t.Run(name, func(t *testing.T) {
			requireToolError(t, callBatch(t, client, map[string]any{
				"subject":     validSubject,
				"action":      validAction,
				"evaluations": evaluations,
			}), "")
		})
	}
}

func TestBatch_RejectsOversizedList(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{"evaluations": []map[string]any{}})
	_, client := clientFor(pdp.URL, pathEvaluation)

	entries := make([]string, maxBatchEvaluations+1)
	for i := range entries {
		entries[i] = `{"resource":{"type":"d","id":"x"}}`
	}
	requireToolError(t, callBatch(t, client, map[string]any{
		"subject":     validSubject,
		"action":      validAction,
		"evaluations": "[" + strings.Join(entries, ",") + "]",
	}), "over the limit")
}

func TestBatch_RejectsUnknownSemantic(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{"evaluations": []map[string]any{{"decision": true}}})
	_, client := clientFor(pdp.URL, pathEvaluation)

	requireToolError(t, callBatch(t, client, map[string]any{
		"subject":              validSubject,
		"action":               validAction,
		"evaluations":          `[{"resource":{"type":"d","id":"1"}}]`,
		"evaluations_semantic": "whatever",
	}), "evaluations_semantic")
}

// What the PDP evaluates is the entry merged over the defaults. Validating the
// two halves separately would let a request through where neither half carries
// a subject, and the model would get an opaque 400 back from the PDP instead of
// a message naming what is missing.
func TestBatch_ValidatesTheMergedEvaluation(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{"evaluations": []map[string]any{{"decision": true}}})
	_, client := clientFor(pdp.URL, pathEvaluation)

	// No subject anywhere: not in the entry, not in the defaults.
	requireToolError(t, callBatch(t, client, map[string]any{
		"action":      validAction,
		"evaluations": `[{"resource":{"type":"d","id":"1"}}]`,
	}), "subject")

	// An entry that overrides a valid default with an invalid entity must still
	// be rejected — the override is what the PDP will see.
	requireToolError(t, callBatch(t, client, map[string]any{
		"subject":     validSubject,
		"action":      validAction,
		"resource":    validResource,
		"evaluations": `[{"subject":{"id":"alice"}}]`,
	}), "type")

	// Defaults alone are enough when every entry only narrows the resource.
	requireNoToolError(t, callBatch(t, client, map[string]any{
		"subject":     validSubject,
		"action":      validAction,
		"evaluations": `[{"resource":{"type":"d","id":"1"}}]`,
	}))
}

// Batch entries can carry everything themselves, so the top-level defaults are
// genuinely optional — requiring them would make the tool unusable for the case
// it exists to serve.
func TestBatch_DefaultsAreOptional(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{"evaluations": []map[string]any{{"decision": true}}})
	_, client := clientFor(pdp.URL, pathEvaluation)

	res := callBatch(t, client, map[string]any{
		"evaluations": `[{"subject":{"type":"user","id":"alice"},"action":{"name":"read"},"resource":{"type":"d","id":"1"}}]`,
	})
	requireNoToolError(t, res)
}

// --- authzen_discover -------------------------------------------------------

func TestDiscover_ReadsMetadata(t *testing.T) {
	pdp, got := metadataPDP(t, "", map[string]any{
		"access_evaluations_endpoint": "https://pdp.example.com/access/v1/evaluations",
	})
	cfg := testConfig()
	client := newPDPClient(cfg)

	out := structured[discoverOutput](t, callDiscover(t, client, map[string]any{"pdp_url": pdp.URL}))
	if got.Path != pathMetadata {
		t.Fatalf("fetched %q, want %q", got.Path, pathMetadata)
	}
	if got.Method != http.MethodGet {
		t.Fatalf("method = %s, want GET", got.Method)
	}
	if out.Metadata.AccessEvaluationsEndpoint == "" {
		t.Fatal("the batch endpoint was dropped from the metadata")
	}
	_ = cfg
}

// A server configured only with an evaluation endpoint must still be able to
// discover, or the tool is useless in the configuration everyone actually uses.
func TestDiscover_StripsKnownEndpointPaths(t *testing.T) {
	pdp, got := metadataPDP(t, "", nil)

	for _, configured := range []string{pathEvaluation, pathEvaluations, ""} {
		t.Run("configured"+configured, func(t *testing.T) {
			_, client := clientFor(pdp.URL, configured)
			requireNoToolError(t, callDiscover(t, client, nil))
			if got.Path != pathMetadata {
				t.Fatalf("fetched %q, want %q", got.Path, pathMetadata)
			}
		})
	}
}

func TestDiscover_RejectsDocumentWithoutEvaluationEndpoint(t *testing.T) {
	pdp, _ := metadataPDP(t, "", map[string]any{"access_evaluation_endpoint": ""})
	_, client := clientFor(pdp.URL, pathEvaluation)

	requireToolError(t, callDiscover(t, client, nil), "access_evaluation_endpoint")
}

func TestDiscover_NoURL(t *testing.T) {
	cfg := testConfig()
	requireToolError(t, callDiscover(t, newPDPClient(cfg), nil), envPDPURL)
}

func TestDiscover_PreservesMountPrefix(t *testing.T) {
	pdp, got := metadataPDP(t, "/pdp", nil)
	_, client := clientFor(pdp.URL, "/pdp"+pathEvaluation)

	requireNoToolError(t, callDiscover(t, client, nil))
	if got.Path != "/pdp"+pathMetadata {
		t.Fatalf("fetched %q; a PDP mounted under a prefix keeps it", got.Path)
	}
}

// AuthZEN 1.0 §PDP Metadata: a document whose policy_decision_point is not the
// PDP it was fetched from MUST NOT be used.
func TestDiscover_RejectsMetadataForAnotherPDP(t *testing.T) {
	pdp, _ := jsonPDP(t, map[string]any{
		"policy_decision_point":      "https://other.example.com",
		"access_evaluation_endpoint": "https://other.example.com/access/v1/evaluation",
	})
	_, client := clientFor(pdp.URL, pathEvaluation)
	requireToolError(t, callDiscover(t, client, nil), "MUST NOT be used")
}

func TestDiscover_ToleratesTrailingSlashOnPDPIdentifier(t *testing.T) {
	pdp, _ := fakePDP(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"policy_decision_point":      "http://" + r.Host + "/",
			"access_evaluation_endpoint": "http://" + r.Host + pathEvaluation,
		})
	})
	_, client := clientFor(pdp.URL, pathEvaluation)
	requireNoToolError(t, callDiscover(t, client, nil))
}
