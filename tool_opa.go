package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/print"
)

// Bounds on the text a policy can put into the tool result. A trace of a
// non-trivial policy runs to thousands of lines, and print() is under the
// policy's own control; past a couple of hundred lines either one stops being
// an explanation and starts being a way to fill a context window.
const (
	maxTraceLines     = 200
	maxPrintLines     = 200
	maxPrintLineBytes = 1024
	// maxTraceEvents bounds what is *collected*, not just what is returned.
	// One evaluation event is not one output line — PrettyTrace filters some
	// and wraps others — so the event budget is deliberately looser than the
	// line budget, and the line cap still applies afterwards.
	maxTraceEvents = 4 * maxTraceLines
	// maxResultBytes bounds the query result itself. A policy can produce an
	// arbitrarily large document within the evaluation budget regardless of how
	// small its input was — `x := numbers.range(1, 10000000)` is one line — and
	// the result is the one field returned on every call.
	maxResultBytes = 256 << 10 // 256 KiB
)

// evaluateResult is the structured result of evaluate_policy.
//
// The bare OPA ResultSet is a poor answer to give a model. An undefined
// document comes back as `[]`, which reads as "false" to anything that is not
// already fluent in Rego — and "the policy did not allow" and "the policy has
// no opinion" are different findings. Decision and Defined say which happened
// in the first two fields.
type evaluateResult struct {
	// Defined reports whether the query produced any result at all.
	Defined bool `json:"defined"`
	// Value is the single expression value when the query produced exactly one
	// result with exactly one expression — the shape of `data.pkg.allow` and of
	// nearly every authorization query. Null otherwise, and null when the value
	// is too large to return; read ResultSet or ResultSetOmitted instead.
	Value any `json:"value"`
	// ResultSet is OPA's own result, unmodified — unless it encoded to more
	// than maxResultBytes, in which case it is omitted and ResultSetOmitted
	// says so. Defined and Value still answer the question that was asked.
	ResultSet rego.ResultSet `json:"result_set"`
	// ResultSetOmitted reports that the result was too large to return.
	ResultSetOmitted bool `json:"result_set_omitted,omitempty"`
	// Printed collects output from print() calls in the policy, in evaluation
	// order, bounded by maxPrintLines and maxPrintLineBytes.
	Printed []string `json:"printed,omitempty"`
	// PrintedTruncated reports that print() output was cut, either because a
	// line was too long or because there were too many of them.
	PrintedTruncated bool `json:"printed_truncated,omitempty"`
	// Trace is a pretty-printed evaluation trace, present only when the caller
	// asked for one.
	Trace []string `json:"trace,omitempty"`
	// TraceTruncated reports that Trace was cut at maxTraceLines.
	TraceTruncated bool `json:"trace_truncated,omitempty"`
}

func registerOPATool(s *server.MCPServer, cfg *config) {
	s.AddTool(
		mcp.NewTool("evaluate_policy",
			mcp.WithDescription(
				"Evaluate a Rego policy module against an input document and optional "+
					"data namespace. Runs in-process via OPA; no external service is "+
					"contacted, and the built-ins that could contact one are disabled. "+
					"Use this to author or debug a policy whose source you have. "+
					"Returns the decision, whether the query was defined at all, the raw "+
					"OPA result set, and any print() output."),
			mcp.WithTitleAnnotation("Evaluate a Rego policy"),
			// The tool computes; it does not change anything, here or anywhere
			// else, and the same arguments always give the same answer.
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(false),
			withOutputSchema[evaluateResult](),
			mcp.WithString("rego",
				mcp.Required(),
				mcp.Description("Rego source for the policy module. Must include a "+
					"`package` declaration. Rego v1 syntax by default: rule bodies need "+
					"`if`, and multi-value rules need `contains`."),
			),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Rego query to evaluate, e.g. `data.example.allow` or "+
					"`data.example.violations[_]`."),
			),
			mcp.WithString("input_json",
				mcp.Description("JSON-encoded input document — the `input` variable "+
					"inside the policy."),
			),
			mcp.WithString("data_json",
				mcp.Description("JSON-encoded base document seeding the `data` "+
					"namespace, for policies that read reference data."),
			),
			mcp.WithString("rego_version",
				mcp.Description("Rego syntax version: `v1` (default) or `v0` for "+
					"pre-OPA-1.0 policies written without `if`/`contains`."),
				mcp.Enum("v1", "v0"),
			),
			mcp.WithBoolean("trace",
				mcp.Description("Return a pretty-printed evaluation trace. Use this to "+
					"find out why a rule did not fire; it is verbose, so leave it off "+
					"until a result is surprising."),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return evaluatePolicy(ctx, req, cfg)
		},
	)
}

func evaluatePolicy(ctx context.Context, req mcp.CallToolRequest, cfg *config) (*mcp.CallToolResult, error) {
	regoSrc, err := requiredString(req, "rego", cfg.MaxArgBytes)
	if err != nil {
		return toolErrorf("%v", err), nil
	}
	query, err := requiredString(req, "query", cfg.MaxArgBytes)
	if err != nil {
		return toolErrorf("%v", err), nil
	}

	var regoVersion ast.RegoVersion
	switch v := req.GetString("rego_version", "v1"); v {
	case "v1", "":
		regoVersion = ast.RegoV1
	case "v0":
		regoVersion = ast.RegoV0
	default:
		return toolErrorf("rego_version must be %q or %q, got %q", "v1", "v0", v), nil
	}

	var input any
	if _, err := optionalJSON(req, "input_json", cfg.MaxArgBytes, &input); err != nil {
		return toolErrorf("%v", err), nil
	}

	printer := &printCollector{}
	options := []func(*rego.Rego){
		rego.Query(query),
		rego.Module("policy.rego", regoSrc),
		rego.SetRegoVersion(regoVersion),
		// Without a capability set OPA compiles against everything it can do,
		// including the built-ins that leave the process. See
		// opa_capabilities.go.
		rego.Capabilities(cfg.capabilities()),
		// A policy under development is full of print(). Discarding it and then
		// asking a model to work out why a rule did not fire is needless.
		rego.EnablePrintStatements(true),
		rego.PrintHook(printer),
		// Default OPA behaviour is for a failing built-in to make its
		// expression undefined, which surfaces as "the policy denied" rather
		// than "the policy is broken". For a debugging tool that distinction is
		// the whole point.
		rego.StrictBuiltinErrors(true),
	}

	// `data` is an object at the root; anything else cannot seed the store.
	var data map[string]any
	if ok, err := optionalJSON(req, "data_json", cfg.MaxArgBytes, &data); err != nil {
		return toolErrorf("%v", err), nil
	} else if ok {
		if data == nil {
			return toolErrorf("argument %q must be a JSON object", "data_json"), nil
		}
		options = append(options, rego.Store(inmem.NewFromObject(data)))
	}

	// The tracer attaches to the evaluation, not to the prepared query: a
	// prepared query is compiled once and evaluated with per-call options, and
	// passing the tracer to rego.New here would silently collect nothing.
	var evalOptions []rego.EvalOption
	var tracer *boundedTracer
	if req.GetBool("trace", false) {
		tracer = &boundedTracer{}
		evalOptions = append(evalOptions, rego.EvalQueryTracer(tracer))
	}

	// Nothing bounds how long a Rego evaluation runs, and the source came from
	// the model. Without a deadline one bad comprehension over a large
	// data_json wedges the server for the life of the session, with no way for
	// the client to recover short of killing the subprocess.
	evalCtx, cancel := context.WithTimeout(ctx, cfg.RegoTimeout)
	defer cancel()

	prepared, err := rego.New(options...).PrepareForEval(evalCtx)
	if err != nil {
		return toolErrorf("rego compile error: %v%s", err, sandboxHint(err, cfg)), nil
	}

	rs, err := prepared.Eval(evalCtx, append(evalOptions, rego.EvalInput(input))...)
	if err != nil {
		if errors.Is(evalCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return toolErrorf(
				"rego evaluation exceeded the %s limit (raise %s if the policy is "+
					"legitimately this expensive)", cfg.RegoTimeout, envRegoTimeout), nil
		}
		return toolErrorf("rego eval error: %v", err), nil
	}

	printed, printTruncated := printer.lines()
	out := evaluateResult{
		Defined:          len(rs) > 0,
		Printed:          printed,
		PrintedTruncated: printTruncated,
	}

	// Defined is computed above and always reported: whether the query had an
	// answer is knowable even when the answer is too big to hand back.
	if encodesWithin(rs, maxResultBytes) {
		out.ResultSet = rs
		out.Value = singleValue(rs)
	} else {
		out.ResultSetOmitted = true
		if v := singleValue(rs); encodesWithin(v, maxResultBytes) {
			// A single huge binding inside an otherwise large result set is
			// still worth returning on its own.
			out.Value = v
		}
	}
	if tracer != nil {
		out.Trace, out.TraceTruncated = formatTrace(tracer.events, tracer.dropped > 0)
	}

	text, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return toolErrorf("failed to encode result: %v", err), nil
	}
	return mcp.NewToolResultStructured(out, string(text)), nil
}

// encodesWithin reports whether v encodes to at most limit bytes. It measures by
// streaming into a counting sink rather than by marshalling and taking len, so
// asking the question does not itself allocate the answer.
func encodesWithin(v any, limit int) bool {
	w := &countingWriter{limit: limit}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return false
	}
	return !w.exceeded
}

// countingWriter discards what it is given and reports whether the total went
// over limit. It keeps accepting writes after that: json.Encoder has no way to
// stop early, and returning an error would only replace one allocation with a
// less legible failure.
type countingWriter struct {
	n        int
	limit    int
	exceeded bool
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	if w.n > w.limit {
		w.exceeded = true
	}
	return len(p), nil
}

// singleValue returns the value of the one expression in the one result, when
// that is the shape of the result set. Returns nil otherwise, which is also
// what a result set holding a literal null returns — callers that need to tell
// those apart have ResultSet.
func singleValue(rs rego.ResultSet) any {
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return nil
	}
	return rs[0].Expressions[0].Value
}

// sandboxHint turns "undefined function http.send" into an answer. The compile
// error is otherwise indistinguishable from a typo, and a model will happily
// spend a turn or two re-spelling the built-in it is not allowed to call.
func sandboxHint(err error, cfg *config) string {
	if cfg.AllowNetworkBuiltins {
		return ""
	}
	msg := err.Error()
	for _, name := range sandboxedBuiltins {
		if strings.Contains(msg, name) {
			return fmt.Sprintf(
				"\n\nnote: %s is disabled in this sandbox because a policy evaluated here "+
					"is model-supplied and runs inside the MCP server process. Set %s=true "+
					"to re-enable it, understanding that the policy can then reach the "+
					"network from wherever this server runs.", name, envAllowNetBuilt)
		}
	}
	return ""
}

// boundedTracer collects evaluation events up to maxTraceEvents and then stops.
//
// topdown.BufferTracer keeps every event for the whole evaluation, bounded only
// by RegoTimeout — and rendering happened over the full buffer before the line
// cap was applied, so the cap bounded what was returned and not what was
// allocated. The policy being traced is model-supplied, so the collection is
// what needs the bound.
//
// OPA may evaluate concurrently, so the tracer has to be safe to call from more
// than one goroutine.
type boundedTracer struct {
	mu      sync.Mutex
	events  []*topdown.Event
	dropped int
}

func (t *boundedTracer) Enabled() bool { return true }

func (t *boundedTracer) Config() topdown.TraceConfig {
	return topdown.TraceConfig{PlugLocalVars: true}
}

func (t *boundedTracer) TraceEvent(evt topdown.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.events) >= maxTraceEvents {
		t.dropped++
		return
	}
	t.events = append(t.events, &evt)
}

// formatTrace renders collected events, capped by line count and line length.
// dropped reports that collection itself stopped early.
func formatTrace(events []*topdown.Event, dropped bool) ([]string, bool) {
	if len(events) == 0 {
		return nil, dropped
	}
	var buf bytes.Buffer
	topdown.PrettyTraceWithLocation(&buf, events)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	truncated := dropped
	if len(lines) > maxTraceLines {
		lines = lines[:maxTraceLines]
		truncated = true
	}
	// A single trace line carries plugged local variable bindings, which are
	// values the policy — and through input_json, the caller — chose.
	for i, l := range lines {
		if len(l) > maxPrintLineBytes {
			lines[i] = l[:maxPrintLineBytes] + "… (truncated)"
			truncated = true
		}
	}
	return lines, truncated
}

// printCollector captures print() output. OPA may evaluate concurrently, so the
// hook has to be safe to call from more than one goroutine.
//
// It is bounded for the same reason the trace and the PDP response body are.
// The policy is model-supplied and runs in-process for as long as RegoTimeout
// allows, which is a lot of iterations when nothing does I/O:
//
//	every i in numbers.range(1, 1000000) { print(i) }
//
// Unbounded, that is both a way to grow this process without limit and a way to
// fill the model's context with text the policy chose. The cap is on the count
// and on each line, and collection stops at the cap rather than continuing to
// allocate for output that will be discarded.
type printCollector struct {
	mu        sync.Mutex
	out       []string
	dropped   int
	truncated bool
}

func (p *printCollector) Print(_ print.Context, msg string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.out) >= maxPrintLines {
		p.dropped++
		return nil
	}
	if len(msg) > maxPrintLineBytes {
		msg = msg[:maxPrintLineBytes] + "… (truncated)"
		p.truncated = true
	}
	p.out = append(p.out, msg)
	return nil
}

// lines returns the captured output and whether anything was cut, either
// because a line was too long or because there were too many of them.
func (p *printCollector) lines() ([]string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out, p.truncated || p.dropped > 0
}
