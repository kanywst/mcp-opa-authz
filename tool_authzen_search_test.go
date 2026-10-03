package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// searchPDPWithMetadata serves a metadata document (built by meta from the
// root the PDP is reached at) and answers every POST with an empty search
// result. It reports how many metadata fetches it served.
func searchPDPWithMetadata(t *testing.T, meta func(root string) map[string]any) (*httptest.Server, *capturedRequest, *atomic.Int32) {
	t.Helper()
	var fetches atomic.Int32
	srv, got := fakePDP(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fetches.Add(1)
			if r.URL.Path != pathMetadata {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, meta("http://"+r.Host))
			return
		}
		writeJSON(w, map[string]any{"results": []any{}})
	})
	return srv, got, &fetches
}

func TestSearch_UsesTheEndpointTheMetadataAdvertises(t *testing.T) {
	pdp, got, _ := searchPDPWithMetadata(t, func(root string) map[string]any {
		return map[string]any{
			"policy_decision_point":      root,
			"access_evaluation_endpoint": root + pathEvaluation,
			"search_resource_endpoint":   root + "/v2/find-resources",
		}
	})
	_, client := clientFor(pdp.URL, pathEvaluation)

	out := structured[searchOutput](t, callSearch(t, client, searchArgs(searchResource, nil)))
	if got.Path != "/v2/find-resources" {
		t.Fatalf("POST went to %s; AuthZEN 1.0 says the advertised endpoint MUST be used", got.Path)
	}
	if out.EndpointSource != endpointFromMetadata || out.PDPURL != pdp.URL+"/v2/find-resources" {
		t.Fatalf("out = %+v", out)
	}
}

func TestSearch_FallsBackToTheDefaultPath(t *testing.T) {
	cases := map[string]func(root string) map[string]any{
		// The PDP has metadata, but advertises no endpoint for this search.
		"not advertised": func(root string) map[string]any {
			return map[string]any{
				"policy_decision_point":      root,
				"access_evaluation_endpoint": root + pathEvaluation,
				"search_subject_endpoint":    root + "/elsewhere",
			}
		},
		// A document for a different PDP MUST NOT be used.
		"metadata for another PDP": func(string) map[string]any {
			return map[string]any{
				"policy_decision_point":    "https://other.example.com",
				"search_resource_endpoint": "https://other.example.com/x",
			}
		},
	}
	for name, meta := range cases {
		t.Run(name, func(t *testing.T) {
			pdp, got, _ := searchPDPWithMetadata(t, meta)
			_, client := clientFor(pdp.URL, pathEvaluation)
			out := structured[searchOutput](t, callSearch(t, client, searchArgs(searchResource, nil)))
			if got.Path != pathSearchResource || out.EndpointSource != endpointFromDefault {
				t.Fatalf("POST went to %s (source %q)", got.Path, out.EndpointSource)
			}
		})
	}

	t.Run("no metadata document", func(t *testing.T) {
		pdp, got := fakePDP(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, map[string]any{"results": []any{}})
		})
		_, client := clientFor(pdp.URL, pathEvaluation)
		out := structured[searchOutput](t, callSearch(t, client, searchArgs(searchResource, nil)))
		if got.Path != pathSearchResource || out.EndpointSource != endpointFromDefault {
			t.Fatalf("POST went to %s (source %q)", got.Path, out.EndpointSource)
		}
	})
}

func TestSearch_ExplicitPDPURLSkipsMetadata(t *testing.T) {
	pdp, _, fetches := searchPDPWithMetadata(t, func(root string) map[string]any {
		return map[string]any{"policy_decision_point": root, "search_resource_endpoint": root + "/x"}
	})
	_, client := clientFor(pdp.URL, pathEvaluation)
	out := structured[searchOutput](t, callSearch(t, client, searchArgs(searchResource, map[string]any{
		"pdp_url": pdp.URL + pathSearchResource,
	})))
	if out.EndpointSource != endpointFromArgument || fetches.Load() != 0 {
		t.Fatalf("source %q, %d metadata fetches", out.EndpointSource, fetches.Load())
	}
}

func TestSearch_CachesMetadataPerRoot(t *testing.T) {
	pdp, _, fetches := searchPDPWithMetadata(t, func(root string) map[string]any {
		return map[string]any{"policy_decision_point": root, "search_resource_endpoint": root + "/x"}
	})
	_, client := clientFor(pdp.URL, pathEvaluation)
	clock := time.Unix(0, 0)
	client.now = func() time.Time { return clock }

	for range 3 {
		requireNoToolError(t, callSearch(t, client, searchArgs(searchResource, nil)))
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d metadata fetches for 3 searches, want 1", n)
	}

	clock = clock.Add(metadataCacheTTL)
	requireNoToolError(t, callSearch(t, client, searchArgs(searchResource, nil)))
	if n := fetches.Load(); n != 2 {
		t.Fatalf("%d metadata fetches after the TTL, want 2", n)
	}
}

// The advertised endpoint is whatever the PDP's host served, so it gets the
// same URL checks as a model-supplied one.
func TestSearch_ValidatesTheAdvertisedEndpoint(t *testing.T) {
	pdp, _, _ := searchPDPWithMetadata(t, func(root string) map[string]any {
		return map[string]any{
			"policy_decision_point":    root,
			"search_resource_endpoint": "https://user:pw@evil.example.com/search",
		}
	})
	_, client := clientFor(pdp.URL, pathEvaluation)
	requireToolError(t, callSearch(t, client, searchArgs(searchResource, nil)), "userinfo")
}

// An advertised endpoint on another origin, or plain http under an https PDP,
// would carry the PDP token somewhere the operator never configured it for.
func TestCheckAdvertisedEndpoint(t *testing.T) {
	root := "https://pdp.example.com"
	for endpoint, want := range map[string]string{
		"https://pdp.example.com/v2/search":           "",
		"https://PDP.example.com/v2/search":           "",
		"http://pdp.example.com/v2/search":            "origin",
		"https://evil.example.com/v2/search":          "origin",
		"https://pdp.example.com:8443/search":         "origin",
		"https://pdp.example.com" + pathSearchSubject: "subject search endpoint",
	} {
		err := checkAdvertisedEndpoint(endpoint, root, searchResource)
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", endpoint, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: error %v, want one mentioning %q", endpoint, err, want)
		}
	}
}

func TestSearch_RejectsACrossOriginAdvertisedEndpoint(t *testing.T) {
	pdp, got, _ := searchPDPWithMetadata(t, func(root string) map[string]any {
		return map[string]any{
			"policy_decision_point":    root,
			"search_resource_endpoint": "https://evil.example.com/search",
		}
	})
	_, client := clientFor(pdp.URL, pathEvaluation)
	msg := requireToolError(t, callSearch(t, client, searchArgs(searchResource, nil)), "PDP metadata advertises")
	if got.Method == http.MethodPost {
		t.Fatalf("a search was sent despite: %s", msg)
	}
}

// flakyMetadataPDP serves the metadata document while ok is true and a 503
// otherwise; searches always succeed.
func flakyMetadataPDP(t *testing.T, ok *atomic.Bool) (*httptest.Server, *capturedRequest, *atomic.Int32) {
	t.Helper()
	var fetches atomic.Int32
	srv, got := fakePDP(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fetches.Add(1)
			if !ok.Load() {
				http.Error(w, "busy", http.StatusServiceUnavailable)
				return
			}
			root := "http://" + r.Host
			writeJSON(w, map[string]any{"policy_decision_point": root, "search_resource_endpoint": root + "/v2/find"})
			return
		}
		writeJSON(w, map[string]any{"results": []any{}})
	})
	return srv, got, &fetches
}

// A transient failure says nothing about the PDP's layout. It must not replace
// a good document with "no metadata" for the whole TTL.
func TestSearch_TransientMetadataFailureKeepsTheCachedDocument(t *testing.T) {
	var ok atomic.Bool
	ok.Store(true)
	pdp, got, _ := flakyMetadataPDP(t, &ok)
	_, client := clientFor(pdp.URL, pathEvaluation)
	clock := time.Unix(0, 0)
	client.now = func() time.Time { return clock }

	requireNoToolError(t, callSearch(t, client, searchArgs(searchResource, nil)))
	ok.Store(false)
	clock = clock.Add(metadataCacheTTL)

	out := structured[searchOutput](t, callSearch(t, client, searchArgs(searchResource, nil)))
	if got.Path != "/v2/find" || out.EndpointSource != endpointFromMetadata {
		t.Fatalf("after a 503 on refresh, POST went to %s (source %q)", got.Path, out.EndpointSource)
	}
}

func TestSearch_TransientMetadataFailureIsNotCached(t *testing.T) {
	var ok atomic.Bool
	pdp, got, fetches := flakyMetadataPDP(t, &ok)
	_, client := clientFor(pdp.URL, pathEvaluation)

	out := structured[searchOutput](t, callSearch(t, client, searchArgs(searchResource, nil)))
	if out.EndpointSource != endpointFromDefault {
		t.Fatalf("source %q with no metadata available", out.EndpointSource)
	}
	// The PDP recovers: the next search must look again, not sit on a cached
	// failure for the TTL.
	ok.Store(true)
	out = structured[searchOutput](t, callSearch(t, client, searchArgs(searchResource, nil)))
	if got.Path != "/v2/find" || out.EndpointSource != endpointFromMetadata || fetches.Load() != 2 {
		t.Fatalf("POST to %s (source %q) after %d fetches", got.Path, out.EndpointSource, fetches.Load())
	}
}

// A PDP that says it has no metadata is a definite answer, cached like a
// document, and looked at again once the TTL is up.
func TestSearch_NoMetadataIsCachedUntilTheTTL(t *testing.T) {
	var fetches atomic.Int32
	pdp, _ := fakePDP(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fetches.Add(1)
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{"results": []any{}})
	})
	_, client := clientFor(pdp.URL, pathEvaluation)
	clock := time.Unix(0, 0)
	client.now = func() time.Time { return clock }

	requireNoToolError(t, callSearch(t, client, searchArgs(searchResource, nil)))
	requireNoToolError(t, callSearch(t, client, searchArgs(searchResource, nil)))
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d metadata fetches inside the TTL, want 1", n)
	}
	clock = clock.Add(metadataCacheTTL)
	requireNoToolError(t, callSearch(t, client, searchArgs(searchResource, nil)))
	if n := fetches.Load(); n != 2 {
		t.Fatalf("%d metadata fetches after the TTL, want 2", n)
	}
}

// Run under -race: searches share one client and its metadata cache.
func TestSearch_ConcurrentSearchesShareTheCache(t *testing.T) {
	// Not fakePDP: its request capture is not meant for concurrent requests.
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		root := "http://" + r.Host
		if r.Method == http.MethodGet {
			writeJSON(w, map[string]any{"policy_decision_point": root, "search_resource_endpoint": root + "/x"})
			return
		}
		writeJSON(w, map[string]any{"results": []any{}})
	}))
	t.Cleanup(pdp.Close)
	_, client := clientFor(pdp.URL, pathEvaluation)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			res, err := authzenSearch(context.Background(), newRequest("authzen_search", searchArgs(searchResource, nil)), client)
			if err != nil || res.IsError {
				t.Errorf("search failed: %v %v", err, res)
			}
		})
	}
	wg.Wait()
}
