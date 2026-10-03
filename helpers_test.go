package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// testConfig is the configuration a test runs under unless it says otherwise:
// the production defaults, with no PDP and no environment involved.
func testConfig() *config {
	return &config{
		PDPTimeout:  defaultPDPTimeout,
		PDPMaxBytes: defaultPDPMaxBytes,
		RegoTimeout: defaultRegoTimeout,
		MaxArgBytes: defaultMaxArgBytes,
	}
}

// newRequest builds a tool call. Arguments are the string-encoded JSON that MCP
// clients actually send.
func newRequest(name string, args map[string]any) mcp.CallToolRequest {
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args
	return req
}

// resultText pulls the first text block out of a tool result.
func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil {
		t.Fatal("nil result")
	}
	if len(res.Content) == 0 {
		t.Fatal("empty result content")
	}
	tc, ok := mcp.AsTextContent(res.Content[0])
	if !ok {
		t.Fatalf("first content block is not text: %T", res.Content[0])
	}
	return tc.Text
}

// structured decodes a successful result's structured content into v. It
// asserts that the text fallback and the structured content agree, because a
// client may read either one and they are produced separately.
func structured[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	var zero T
	if res.IsError {
		t.Fatalf("expected success, got tool error: %s", resultText(t, res))
	}
	if res.StructuredContent == nil {
		t.Fatal("result carries no structured content")
	}

	fromStructured, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("structured content is not encodable: %v", err)
	}
	var out T
	if err := json.Unmarshal(fromStructured, &out); err != nil {
		t.Fatalf("structured content does not fit %T: %v (%s)", zero, err, fromStructured)
	}

	var fromText T
	if err := json.Unmarshal([]byte(resultText(t, res)), &fromText); err != nil {
		t.Fatalf("text fallback is not the same shape as the structured content: %v", err)
	}
	textRoundTrip, err := json.Marshal(fromText)
	if err != nil {
		t.Fatalf("text fallback is not re-encodable: %v", err)
	}
	if !bytes.Equal(textRoundTrip, fromStructured) {
		t.Fatalf("text fallback and structured content disagree:\n text: %s\n  str: %s",
			textRoundTrip, fromStructured)
	}
	return out
}

// requireToolError asserts a tool error whose message contains want.
func requireToolError(t *testing.T, res *mcp.CallToolResult, want string) string {
	t.Helper()
	if !res.IsError {
		t.Fatalf("expected a tool error, got success: %s", resultText(t, res))
	}
	msg := resultText(t, res)
	if want != "" && !strings.Contains(msg, want) {
		t.Fatalf("error message %q does not mention %q", msg, want)
	}
	return msg
}

// requireNoToolError asserts the handler succeeded.
func requireNoToolError(t *testing.T, res *mcp.CallToolResult) {
	t.Helper()
	if res.IsError {
		t.Fatalf("expected success, got tool error: %s", resultText(t, res))
	}
}

// --- fake PDPs -------------------------------------------------------------

// capturedRequest records what a fake PDP received.
type capturedRequest struct {
	Method    string
	Path      string
	Auth      string
	RequestID string
	Accept    string
	Body      []byte
}

// fakePDP serves handler and records the last request it saw.
func fakePDP(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *capturedRequest) {
	t.Helper()
	got := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		if r.Body != nil {
			buf := make([]byte, 1<<16)
			n, _ := r.Body.Read(buf)
			body = buf[:n]
		}
		*got = capturedRequest{
			Method:    r.Method,
			Path:      r.URL.Path,
			Auth:      r.Header.Get("Authorization"),
			RequestID: r.Header.Get("X-Request-ID"),
			Accept:    r.Header.Get("Accept"),
			Body:      body,
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

// decisionPDP answers every evaluation with the given decision.
func decisionPDP(t *testing.T, decision bool) (*httptest.Server, *capturedRequest) {
	t.Helper()
	return fakePDP(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"decision": decision})
	})
}

// jsonPDP answers every request with the given body, encoded.
func jsonPDP(t *testing.T, body any) (*httptest.Server, *capturedRequest) {
	t.Helper()
	return fakePDP(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, body)
	})
}

// rawPDP answers with a status and a literal body.
func rawPDP(t *testing.T, status int, body string) (*httptest.Server, *capturedRequest) {
	t.Helper()
	return fakePDP(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// clientFor returns a PDP client whose configured endpoint is srvURL + path.
func clientFor(srvURL, path string) (*config, *pdpClient) {
	cfg := testConfig()
	cfg.PDPURL = srvURL + path
	return cfg, newPDPClient(cfg)
}

// shortTimeoutConfig is for tests that need a bound to actually be hit.
func shortTimeoutConfig(d time.Duration) *config {
	cfg := testConfig()
	cfg.PDPTimeout = d
	cfg.RegoTimeout = d
	return cfg
}

// validSubject, validAction and validResource are AuthZEN-conformant entities,
// used wherever a test is about something other than entity validation.
const (
	validSubject  = `{"type":"user","id":"alice"}`
	validAction   = `{"name":"read"}`
	validResource = `{"type":"document","id":"doc-1"}`
)

// evaluateArgs returns a complete, valid argument set for authzen_evaluate,
// with overrides applied.
func evaluateArgs(overrides map[string]any) map[string]any {
	args := map[string]any{
		"subject":  validSubject,
		"action":   validAction,
		"resource": validResource,
	}
	for k, v := range overrides {
		args[k] = v
	}
	return args
}

// metadataPDP serves a PDP Metadata document whose policy_decision_point is the
// PDP root it is actually reached at (the server origin plus prefix), merged
// with extra members.
func metadataPDP(t *testing.T, prefix string, extra map[string]any) (*httptest.Server, *capturedRequest) {
	t.Helper()
	return fakePDP(t, func(w http.ResponseWriter, r *http.Request) {
		root := "http://" + r.Host + prefix
		doc := map[string]any{
			"policy_decision_point":      root,
			"access_evaluation_endpoint": root + pathEvaluation,
		}
		for k, v := range extra {
			doc[k] = v
		}
		writeJSON(w, doc)
	})
}
