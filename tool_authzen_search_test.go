package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func callSearch(t *testing.T, client *pdpClient, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := authzenSearch(context.Background(), newRequest("authzen_search", args), client)
	if err != nil {
		t.Fatalf("authzenSearch returned a non-nil error: %v", err)
	}
	return res
}

// searchArgs returns a valid argument set for the given kind of search, with
// overrides applied. A nil override value deletes the argument.
func searchArgs(kind string, overrides map[string]any) map[string]any {
	args := map[string]any{"search": kind}
	switch kind {
	case searchSubject:
		args["subject"] = `{"type":"user"}`
		args["action"] = validAction
		args["resource"] = validResource
	case searchResource:
		args["subject"] = validSubject
		args["action"] = validAction
		args["resource"] = `{"type":"document"}`
	case searchAction:
		args["subject"] = validSubject
		args["resource"] = validResource
	}
	for k, v := range overrides {
		if v == nil {
			delete(args, k)
			continue
		}
		args[k] = v
	}
	return args
}

func TestSearch_EachKindHitsItsDefaultEndpoint(t *testing.T) {
	for kind, path := range searchPaths {
		t.Run(kind, func(t *testing.T) {
			results := []any{map[string]any{"type": "user", "id": "alice"}}
			switch kind {
			case searchResource:
				results = []any{map[string]any{"type": "document", "id": "doc-1"}}
			case searchAction:
				results = []any{map[string]any{"name": "read"}}
			}
			pdp, got := jsonPDP(t, map[string]any{"results": results})
			// Configured with the evaluation endpoint, as every client is.
			_, client := clientFor(pdp.URL, pathEvaluation)

			out := structured[searchOutput](t, callSearch(t, client, searchArgs(kind, nil)))
			if got.Path != path {
				t.Fatalf("request went to %s, want %s", got.Path, path)
			}
			if out.Search != kind || len(out.Results) != 1 || out.HasMore {
				t.Fatalf("out = %+v", out)
			}
			if out.PDPURL != pdp.URL+path || out.RequestID == "" {
				t.Fatalf("pdp_url = %q, request_id = %q", out.PDPURL, out.RequestID)
			}
		})
	}
}

func TestSearch_ForwardsEntitiesVerbatimAndOmitsActionForActionSearch(t *testing.T) {
	pdp, got := jsonPDP(t, map[string]any{"results": []any{}})
	_, client := clientFor(pdp.URL, pathEvaluation)

	// An integer property and member order are what a decode/re-encode round
	// trip would damage.
	subject := `{"type":"user","id":"alice","properties":{"z":1,"a":9007199254740993}}`
	requireNoToolError(t, callSearch(t, client, searchArgs(searchAction, map[string]any{
		"subject": subject,
		"context": `{"ip":"10.0.0.7"}`,
	})))

	var sent map[string]json.RawMessage
	if err := json.Unmarshal(got.Body, &sent); err != nil {
		t.Fatal(err)
	}
	if string(sent["subject"]) != subject {
		t.Fatalf("subject sent as %s, want it byte-for-byte", sent["subject"])
	}
	if _, ok := sent["action"]; ok {
		t.Fatal("an action search request must not carry an action member")
	}
	if _, ok := sent["page"]; ok {
		t.Fatal("no page object should be sent when no pagination argument was given")
	}
	if string(sent["context"]) != `{"ip":"10.0.0.7"}` {
		t.Fatalf("context = %s", sent["context"])
	}
}

// The search counterpart of the decision invariant: a PDP that did not answer
// must not look like a PDP that permits nothing.
func TestSearch_MissingResultsIsAnErrorNotAnEmptyAnswer(t *testing.T) {
	for _, body := range []string{`{}`, `{"results":null}`, `{"page":{"next_token":""}}`} {
		pdp, _ := rawPDP(t, 200, body)
		_, client := clientFor(pdp.URL, pathEvaluation)
		requireToolError(t, callSearch(t, client, searchArgs(searchResource, nil)), "results")
	}
}

func TestSearch_EmptyResultsIsASuccess(t *testing.T) {
	pdp, _ := rawPDP(t, 200, `{"results":[]}`)
	_, client := clientFor(pdp.URL, pathEvaluation)

	res := callSearch(t, client, searchArgs(searchResource, nil))
	out := structured[searchOutput](t, res)
	if out.Results == nil || len(out.Results) != 0 {
		t.Fatalf("results = %v, want an empty array", out.Results)
	}
	// Encoded as [], not null: a client reading the text should see "none
	// permitted", not "no answer".
	if !strings.Contains(resultText(t, res), `"results": []`) {
		t.Fatalf("results not encoded as an empty array: %s", resultText(t, res))
	}
}

func TestSearch_Pagination(t *testing.T) {
	pdp, got := rawPDP(t, 200,
		`{"page":{"next_token":"a3M9NDU2","count":1,"total":3},"results":[{"type":"document","id":"doc-1"}]}`)
	_, client := clientFor(pdp.URL, pathEvaluation)

	out := structured[searchOutput](t, callSearch(t, client, searchArgs(searchResource, map[string]any{
		"page_token": "prev",
		"page_limit": float64(1),
	})))
	if !out.HasMore || out.NextPageToken != "a3M9NDU2" || out.Total == nil || *out.Total != 3 {
		t.Fatalf("out = %+v", out)
	}

	var sent struct {
		Page map[string]any `json:"page"`
	}
	if err := json.Unmarshal(got.Body, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Page["token"] != "prev" || sent.Page["limit"] != float64(1) {
		t.Fatalf("page sent as %v", sent.Page)
	}
}

func TestSearch_LastPage(t *testing.T) {
	pdp, _ := rawPDP(t, 200, `{"page":{"next_token":""},"results":[{"name":"read"}]}`)
	_, client := clientFor(pdp.URL, pathEvaluation)

	out := structured[searchOutput](t, callSearch(t, client, searchArgs(searchAction, nil)))
	if out.HasMore || out.NextPageToken != "" {
		t.Fatalf("an empty next_token is the last page; out = %+v", out)
	}
}

func TestSearch_PageWithoutNextTokenIsAnError(t *testing.T) {
	pdp, _ := rawPDP(t, 200, `{"page":{"count":1},"results":[{"name":"read"}]}`)
	_, client := clientFor(pdp.URL, pathEvaluation)
	requireToolError(t, callSearch(t, client, searchArgs(searchAction, nil)), "next_token")
}

func TestSearch_RejectsResultsOfTheWrongKind(t *testing.T) {
	cases := []struct {
		kind, body, want string
	}{
		{searchResource, `{"results":[{"type":"folder","id":"f1"}]}`, `type "folder"`},
		{searchResource, `{"results":[{"type":"document"}]}`, `"id"`},
		{searchSubject, `{"results":["alice"]}`, "JSON object"},
		{searchSubject, `{"results":[{"type":"group","id":"admins"}]}`, `type "group"`},
		{searchAction, `{"results":[{"type":"user","id":"alice"}]}`, `"name"`},
	}
	for _, tc := range cases {
		t.Run(tc.kind+" "+tc.body, func(t *testing.T) {
			pdp, _ := rawPDP(t, 200, tc.body)
			_, client := clientFor(pdp.URL, pathEvaluation)
			requireToolError(t, callSearch(t, client, searchArgs(tc.kind, nil)), tc.want)
		})
	}
}

func TestSearch_ValidatesArgumentsPerKind(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"unknown kind", searchArgs("everything", nil), "search must be one of"},
		{"missing kind", searchArgs(searchSubject, map[string]any{"search": nil}), "search must be one of"},
		{"subject search with a subject id", searchArgs(searchSubject, map[string]any{"subject": validSubject}), `"id"`},
		{"subject search without a subject type", searchArgs(searchSubject, map[string]any{"subject": `{}`}), `"type"`},
		{"subject search without an action", searchArgs(searchSubject, map[string]any{"action": nil}), `"action"`},
		{"resource search with a resource id", searchArgs(searchResource, map[string]any{"resource": validResource}), `"id"`},
		{"resource search without a subject id", searchArgs(searchResource, map[string]any{"subject": `{"type":"user"}`}), `"id"`},
		{"action search with an action", searchArgs(searchAction, map[string]any{"action": validAction}), "takes no"},
		{"action search without a resource id", searchArgs(searchAction, map[string]any{"resource": `{"type":"document"}`}), `"id"`},
		{"action without a name", searchArgs(searchResource, map[string]any{"action": `{}`}), `"name"`},
		{"missing resource", searchArgs(searchSubject, map[string]any{"resource": nil}), `"resource"`},
		{"negative limit", searchArgs(searchResource, map[string]any{"page_limit": float64(-1)}), "non-negative"},
		{"fractional limit", searchArgs(searchResource, map[string]any{"page_limit": 2.5}), "non-negative"},
		{"non-numeric limit", searchArgs(searchResource, map[string]any{"page_limit": "ten"}), "integer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A PDP that would answer, so only argument validation can fail.
			pdp, _ := rawPDP(t, 200, `{"results":[]}`)
			_, client := clientFor(pdp.URL, pathEvaluation)
			requireToolError(t, callSearch(t, client, tc.args), tc.want)
		})
	}
}

func TestSearch_PDPURLOverridesConfig(t *testing.T) {
	pdp, got := rawPDP(t, 200, `{"results":[]}`)
	_, client := clientFor("https://unused.example.com", pathEvaluation)

	requireNoToolError(t, callSearch(t, client, searchArgs(searchResource, map[string]any{
		"pdp_url": pdp.URL + "/custom/search",
	})))
	if got.Path != "/custom/search" {
		t.Fatalf("request went to %s", got.Path)
	}
}

func TestSearch_NoEndpointConfigured(t *testing.T) {
	client := newPDPClient(testConfig())
	requireToolError(t, callSearch(t, client, searchArgs(searchResource, nil)), envPDPURL)
}

func TestSearch_RejectsUnsafePDPURL(t *testing.T) {
	client := newPDPClient(testConfig())
	requireToolError(t, callSearch(t, client, searchArgs(searchResource, map[string]any{
		"pdp_url": "https://user:pw@pdp.example.com/access/v1/search/resource",
	})), "userinfo")
}

func TestSearch_HTTPFailureIsAnError(t *testing.T) {
	pdp, _ := rawPDP(t, 401, `{"error":"nope"}`)
	_, client := clientFor(pdp.URL, pathEvaluation)
	requireToolError(t, callSearch(t, client, searchArgs(searchResource, nil)), "not that the subject was denied")
}

func TestSearch_PDPURLForAnotherKindIsRejected(t *testing.T) {
	pdp, _ := rawPDP(t, 200, `{"results":[]}`)
	_, client := clientFor(pdp.URL, pathEvaluation)
	requireToolError(t, callSearch(t, client, searchArgs(searchSubject, map[string]any{
		"pdp_url": pdp.URL + pathSearchResource,
	})), "resource search endpoint")
}

func TestSearch_NullNextTokenIsAnError(t *testing.T) {
	pdp, _ := rawPDP(t, 200, `{"page":{"next_token":null},"results":[]}`)
	_, client := clientFor(pdp.URL, pathEvaluation)
	requireToolError(t, callSearch(t, client, searchArgs(searchResource, nil)), "next_token")
}

// count and total are informational; a PDP that encodes them loosely must not
// lose its results over it.
func TestSearch_ToleratesLooseCountAndTotal(t *testing.T) {
	pdp, _ := rawPDP(t, 200,
		`{"page":{"next_token":"","count":1.0,"total":1e3},"results":[{"type":"document","id":"doc-1"}]}`)
	_, client := clientFor(pdp.URL, pathEvaluation)
	out := structured[searchOutput](t, callSearch(t, client, searchArgs(searchResource, nil)))
	if len(out.Results) != 1 {
		t.Fatalf("out = %+v", out)
	}
}

func TestSearch_ZeroLimitIsSent(t *testing.T) {
	pdp, got := rawPDP(t, 200, `{"results":[]}`)
	_, client := clientFor(pdp.URL, pathEvaluation)
	requireNoToolError(t, callSearch(t, client, searchArgs(searchResource, map[string]any{
		"page_limit": float64(0),
	})))
	if !strings.Contains(string(got.Body), `"page":{"limit":0}`) {
		t.Fatalf("a limit of 0 must be sent, not dropped: %s", got.Body)
	}
}

func TestSearch_RejectsOversizedPageToken(t *testing.T) {
	cfg := testConfig()
	cfg.MaxArgBytes = 24
	pdp, _ := rawPDP(t, 200, `{"results":[]}`)
	cfg.PDPURL = pdp.URL + pathEvaluation
	// The entities have to fit the smaller bound for the token to be reached.
	requireToolError(t, callSearch(t, newPDPClient(cfg), map[string]any{
		"search":     searchResource,
		"subject":    `{"type":"u","id":"a"}`,
		"action":     `{"name":"r"}`,
		"resource":   `{"type":"d"}`,
		"page_token": strings.Repeat("x", 25),
	}), "page_token")
}

func TestSearch_OutputSchemaAcceptsRealResults(t *testing.T) {
	pdp, _ := rawPDP(t, 200,
		`{"page":{"next_token":"n","total":2},"context":{"took_ms":4},"results":[{"type":"document","id":"doc-1","properties":{"k":1}}]}`)
	cfg, client := clientFor(pdp.URL, pathEvaluation)
	res := callSearch(t, client, searchArgs(searchResource, nil))
	requireNoToolError(t, res)
	validateAgainstOutputSchema(t, newServer(cfg).ListTools()["authzen_search"].Tool, res.StructuredContent)
}
