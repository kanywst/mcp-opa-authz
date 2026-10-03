package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Every tool the documentation and the instructions promise must actually be
// registered. A rename here is otherwise only caught by a human reading a diff.
func TestNewServer_RegistersEveryTool(t *testing.T) {
	tools := newServer(testConfig()).ListTools()

	want := []string{
		"evaluate_policy",
		"authzen_evaluate",
		"authzen_evaluate_batch",
		"authzen_discover",
	}
	for _, name := range want {
		if _, ok := tools[name]; !ok {
			t.Errorf("tool %q is not registered", name)
		}
	}
	if len(tools) != len(want) {
		t.Errorf("registered %d tools, want %d: %v", len(tools), len(want), tools)
	}
}

// Annotations are how a client decides what it may run without asking. Getting
// readOnly wrong on an authorization tool is how a client learns to auto-approve
// something it should not.
func TestNewServer_ToolAnnotations(t *testing.T) {
	tools := newServer(testConfig()).ListTools()

	// evaluate_policy contacts nothing; the authzen_* tools contact a PDP.
	openWorld := map[string]bool{
		"evaluate_policy":        false,
		"authzen_evaluate":       true,
		"authzen_evaluate_batch": true,
		"authzen_discover":       true,
	}

	for name, wantOpen := range openWorld {
		st, ok := tools[name]
		if !ok {
			t.Fatalf("tool %q is not registered", name)
		}
		a := st.Tool.Annotations
		if a.ReadOnlyHint == nil || !*a.ReadOnlyHint {
			t.Errorf("%s: readOnlyHint should be true; none of these tools change state", name)
		}
		if a.DestructiveHint == nil || *a.DestructiveHint {
			t.Errorf("%s: destructiveHint should be false", name)
		}
		if a.IdempotentHint == nil || !*a.IdempotentHint {
			t.Errorf("%s: idempotentHint should be true", name)
		}
		if a.OpenWorldHint == nil || *a.OpenWorldHint != wantOpen {
			t.Errorf("%s: openWorldHint = %v, want %v", name, a.OpenWorldHint, wantOpen)
		}
		if a.Title == "" {
			t.Errorf("%s: no human-readable title", name)
		}
	}
}

// A declared output schema that does not describe the value handlers actually
// return is worse than no schema: a client validating against it rejects a
// correct answer.
func TestNewServer_OutputSchemasMatchResults(t *testing.T) {
	tools := newServer(testConfig()).ListTools()

	for name, sample := range map[string]any{
		"evaluate_policy":        evaluateResult{},
		"authzen_evaluate":       evaluateOutput{},
		"authzen_evaluate_batch": batchOutput{},
		"authzen_discover":       discoverOutput{},
	} {
		st, ok := tools[name]
		if !ok {
			t.Fatalf("tool %q is not registered", name)
		}
		if st.Tool.OutputSchema.Type == "" {
			t.Errorf("%s declares no output schema", name)
			continue
		}
		if st.Tool.OutputSchema.Type != "object" {
			t.Errorf("%s: output schema type = %q, want object", name, st.Tool.OutputSchema.Type)
		}

		// The declared properties have to exist on the value the handler
		// returns, or the two drifted apart.
		encoded, err := json.Marshal(sample)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var fields map[string]any
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for prop := range st.Tool.OutputSchema.Properties {
			if _, ok := fields[prop]; !ok {
				// omitempty fields are absent from a zero value; only flag a
				// property with no corresponding struct tag at all.
				if !strings.Contains(string(encoded), prop) && !isOmitEmpty(sample, prop) {
					t.Errorf("%s: output schema declares %q, which the result type does not carry", name, prop)
				}
			}
		}
	}
}

// isOmitEmpty reports whether v has a JSON field named prop at all, regardless
// of whether the zero value encodes it.
func isOmitEmpty(v any, prop string) bool {
	encoded, err := json.Marshal(v)
	if err != nil {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal(encoded, &m); err != nil {
		return false
	}
	_, present := m[prop]
	return !present
}

// The instructions are what a model reads before choosing between two tools
// that answer the same question at different layers.
func TestInstructions_NameEveryTool(t *testing.T) {
	for _, name := range []string{
		"evaluate_policy", "authzen_evaluate", "authzen_evaluate_batch", "authzen_discover",
	} {
		if !strings.Contains(instructions, name) {
			t.Errorf("the server instructions do not mention %q", name)
		}
	}
}

func TestUsage_DocumentsEveryEnvironmentVariable(t *testing.T) {
	for _, name := range []string{
		envPDPURL, envPDPToken, envPDPTimeout, envPDPMaxBytes,
		envRegoTimeout, envMaxArgBytes, envAllowNetBuilt,
	} {
		if !strings.Contains(usage, name) {
			t.Errorf("--help does not document %s", name)
		}
	}
}

func TestRun_Flags(t *testing.T) {
	cases := []struct {
		args     []string
		wantCode int
		wantOut  string
	}{
		{[]string{"--version"}, 0, "mcp-opa-authz"},
		{[]string{"-v"}, 0, "mcp-opa-authz"},
		{[]string{"version"}, 0, "mcp-opa-authz"},
		{[]string{"--help"}, 0, "Usage:"},
		{[]string{"-h"}, 0, "Tools exposed:"},
		{[]string{"help"}, 0, envPDPURL},
		{[]string{"--nonsense"}, 2, "unknown argument"},
	}

	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			out, errOut, code := runCapturing(tc.args)
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d", code, tc.wantCode)
			}
			combined := out + errOut
			if !strings.Contains(combined, tc.wantOut) {
				t.Fatalf("output %q does not contain %q", combined, tc.wantOut)
			}
		})
	}
}

// runCapturing runs the CLI with stdout and stderr captured.
func runCapturing(args []string) (stdout, stderr string, code int) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func TestResolveVersion(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = "v1.2.3"
	if got := resolveVersion(); got != "v1.2.3" {
		t.Fatalf("resolveVersion = %q, want the linker-stamped value", got)
	}

	// Under `go test` the build info main version is "(devel)" or empty, so the
	// fallback must not produce something worse than "dev".
	version = "dev"
	if got := resolveVersion(); got == "" || got == "(devel)" {
		t.Fatalf("resolveVersion = %q", got)
	}
}

// mcp.CallToolResult is what every handler returns; this pins the two
// invariants the handlers rely on.
func TestToolErrorf(t *testing.T) {
	res := toolErrorf("something went %s", "wrong")
	if !res.IsError {
		t.Fatal("toolErrorf did not produce an error result")
	}
	tc, ok := mcp.AsTextContent(res.Content[0])
	if !ok || tc.Text != "something went wrong" {
		t.Fatalf("content = %#v", res.Content[0])
	}
}

// The declared outputSchema has to accept what the handler actually returns.
// Comparing property names is not enough: json.RawMessage reflects as []byte,
// and a schema of byte arrays has the right names and rejects every PDP
// context. Each result here carries the pass-through members filled in.
func TestNewServer_OutputSchemasAcceptRealResults(t *testing.T) {
	pdp := newPassThroughPDP(t)
	cfg := testConfig()
	cfg.PDPURL = pdp.URL + pathEvaluation
	tools := newServer(cfg).ListTools()
	client := newPDPClient(cfg)
	ctx := context.Background()

	results := map[string]*mcp.CallToolResult{}
	var err error
	if results["evaluate_policy"], err = evaluatePolicy(ctx, newRequest("evaluate_policy", map[string]any{
		"rego":       "package p\n\nallow if input.user == \"alice\"\n\nobj := {\"a\": [1, 2]}",
		"query":      "data.p",
		"input_json": `{"user":"alice"}`,
	}), cfg); err != nil {
		t.Fatal(err)
	}
	if results["authzen_evaluate"], err = authzenEvaluate(ctx, newRequest("authzen_evaluate", evaluateArgs(nil)), client); err != nil {
		t.Fatal(err)
	}
	if results["authzen_evaluate_batch"], err = authzenEvaluateBatch(ctx, newRequest("authzen_evaluate_batch", evaluateArgs(map[string]any{
		"evaluations": `[{},{}]`,
	})), client); err != nil {
		t.Fatal(err)
	}
	if results["authzen_discover"], err = authzenDiscover(ctx, newRequest("authzen_discover", nil), client); err != nil {
		t.Fatal(err)
	}

	for name, res := range results {
		t.Run(name, func(t *testing.T) {
			requireNoToolError(t, res)
			validateAgainstOutputSchema(t, tools[name].Tool, res.StructuredContent)
		})
	}
}

// newPassThroughPDP answers every AuthZEN endpoint with the optional members
// that this server passes through untouched, so that they reach the schema.
func newPassThroughPDP(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := fakePDP(t, func(w http.ResponseWriter, r *http.Request) {
		ctx := map[string]any{"reason": "policy-7", "obligations": []any{"log"}}
		switch r.URL.Path {
		case pathEvaluation:
			writeJSON(w, map[string]any{"decision": true, "context": ctx})
		case pathEvaluations:
			writeJSON(w, map[string]any{"evaluations": []any{
				map[string]any{"decision": true, "context": ctx},
				map[string]any{"decision": false},
			}})
		case pathMetadata:
			writeJSON(w, map[string]any{
				"policy_decision_point":        "https://pdp.example.com",
				"access_evaluation_endpoint":   "https://pdp.example.com" + pathEvaluation,
				"capabilities":                 []any{"urn:example:cap"},
				"supported_evaluation_options": map[string]any{"evaluations_semantic": []any{"execute_all"}},
			})
		default:
			http.NotFound(w, r)
		}
	})
	return srv
}

func validateAgainstOutputSchema(t *testing.T, tool mcp.Tool, value any) {
	t.Helper()
	schemaJSON, err := json.Marshal(tool.OutputSchema)
	if err != nil {
		t.Fatal(err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", schemaDoc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("schema.json")
	if err != nil {
		t.Fatalf("advertised output schema does not compile: %v\n%s", err, schemaJSON)
	}

	// Validate the value as a client would see it: decoded from the wire.
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("%s: a real result fails the advertised outputSchema: %v\nresult: %s", tool.Name, err, encoded)
	}
}
