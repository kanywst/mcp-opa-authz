package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidatePDPURL(t *testing.T) {
	valid := []string{
		"http://localhost:8181/access/v1/evaluation",
		"https://pdp.example.com/access/v1/evaluation",
		"https://pdp.example.com:8443/pdp/access/v1/evaluation",
	}
	for _, raw := range valid {
		if err := validatePDPURL(raw); err != nil {
			t.Errorf("validatePDPURL(%q) = %v, want nil", raw, err)
		}
	}

	// Each of these is something a model can produce, and each would send a
	// request somewhere the operator did not configure.
	invalid := map[string]string{
		"file:///etc/passwd":            "scheme",
		"gopher://pdp.example.com/":     "scheme",
		"/access/v1/evaluation":         "scheme",
		"access/v1/evaluation":          "scheme",
		"":                              "scheme",
		"https://":                      "host",
		"http://user:pass@pdp.test/x":   "userinfo",
		"https://user@pdp.example.com/": "userinfo",
	}
	for raw, want := range invalid {
		err := validatePDPURL(raw)
		if err == nil {
			t.Errorf("validatePDPURL(%q) = nil, want an error", raw)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validatePDPURL(%q) = %v, want it to mention %q", raw, err, want)
		}
	}
}

func TestSetAuth(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"s3cret":                 "Bearer s3cret",
		"  s3cret  ":             "Bearer s3cret",
		"Bearer already":         "Bearer already",
		"bearer lowercase":       "bearer lowercase",
		"Basic dXNlcjpwYXNz":     "Basic dXNlcjpwYXNz",
		"DPoP tok":               "DPoP tok",
		"opaque token with dots": "Bearer opaque token with dots",
	}

	for token, want := range cases {
		t.Run(token, func(t *testing.T) {
			cfg := testConfig()
			cfg.PDPToken = token
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://pdp.example.com/", http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			newPDPClient(cfg).setAuth(req)
			if got := req.Header.Get("Authorization"); got != want {
				t.Fatalf("Authorization = %q, want %q", got, want)
			}
		})
	}
}

func TestPostJSON_SetsSpecHeaders(t *testing.T) {
	pdp, got := decisionPDP(t, true)
	cfg, _ := clientFor(pdp.URL, pathEvaluation)
	cfg.PDPToken = "s3cret"
	client := newPDPClient(cfg)

	var out evaluationResponse
	id, err := client.postJSON(context.Background(), cfg.PDPURL, evaluationRequest{}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestID == "" {
		t.Fatal("X-Request-ID was not sent; the specification recommends it and it is the only way to correlate a call with a PDP log")
	}
	if got.RequestID != id {
		t.Fatalf("reported request id %q does not match the header sent %q", id, got.RequestID)
	}
	if got.Accept != "application/json" {
		t.Fatalf("Accept = %q", got.Accept)
	}
	if got.Auth != "Bearer s3cret" {
		t.Fatalf("Authorization = %q", got.Auth)
	}
}

func TestNewRequestID_IsUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := newRequestID()
		if id == "" {
			t.Fatal("empty request id")
		}
		if seen[id] {
			t.Fatalf("duplicate request id %q", id)
		}
		seen[id] = true
	}
}

// Following a redirect would send the Authorization header to a host the
// operator never configured, and take the decision from an origin nobody chose.
func TestDo_RefusesRedirects(t *testing.T) {
	target, _ := decisionPDP(t, true)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+pathEvaluation, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	_, client := clientFor(redirector.URL, pathEvaluation)

	var out evaluationResponse
	_, err := client.postJSON(context.Background(), redirector.URL+pathEvaluation, evaluationRequest{}, &out)
	if err == nil {
		t.Fatal("expected the redirect to be refused")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("error = %v, want it to name the redirect", err)
	}
}

func TestDo_StatusHandling(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusBadRequest, "HTTP 400"},
		{http.StatusUnauthorized, "authenticate to the PDP"},
		{http.StatusForbidden, "not permitted to query the PDP"},
		{http.StatusNotFound, pathEvaluation},
		{http.StatusInternalServerError, "HTTP 500"},
		{http.StatusNoContent, "HTTP 204"},
	}

	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			pdp, _ := rawPDP(t, tc.status, `{"error":"nope"}`)
			cfg, client := clientFor(pdp.URL, pathEvaluation)

			var out evaluationResponse
			_, err := client.postJSON(context.Background(), cfg.PDPURL, evaluationRequest{}, &out)
			if err == nil {
				t.Fatalf("status %d was accepted; only 200 carries a decision", tc.status)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A megabyte of HTML in an error message is a megabyte of the model's context
// spent on an error message.
func TestDo_TruncatesErrorBodies(t *testing.T) {
	pdp, _ := rawPDP(t, http.StatusInternalServerError, strings.Repeat("A", 10_000))
	cfg, client := clientFor(pdp.URL, pathEvaluation)

	var out evaluationResponse
	_, err := client.postJSON(context.Background(), cfg.PDPURL, evaluationRequest{}, &out)
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > 2000 {
		t.Fatalf("error message is %d bytes; response bodies must be truncated", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncation was not signalled: %.200s", err.Error())
	}
}

func TestDo_BoundsResponseSize(t *testing.T) {
	// Stream far more than the cap; the read must stop rather than buffer it.
	pdp, _ := fakePDP(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := strings.Repeat("x", 4096)
		for range 64 {
			_, _ = w.Write([]byte(chunk))
		}
	})
	cfg, _ := clientFor(pdp.URL, pathEvaluation)
	cfg.PDPMaxBytes = 1024
	client := newPDPClient(cfg)

	var out evaluationResponse
	_, err := client.postJSON(context.Background(), cfg.PDPURL, evaluationRequest{}, &out)
	if err == nil {
		t.Fatal("expected the truncated body to fail decoding")
	}
	if !strings.Contains(err.Error(), "not valid AuthZEN JSON") {
		t.Fatalf("error = %v", err)
	}
}

func TestDo_HonoursTimeout(t *testing.T) {
	pdp, _ := fakePDP(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		writeJSON(w, map[string]any{"decision": true})
	})

	cfg := shortTimeoutConfig(50 * time.Millisecond)
	cfg.PDPURL = pdp.URL + pathEvaluation
	client := newPDPClient(cfg)

	start := time.Now()
	var out evaluationResponse
	_, err := client.postJSON(context.Background(), cfg.PDPURL, evaluationRequest{}, &out)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("took %s; the client timeout did not apply", elapsed)
	}
}

func TestDo_HonoursCallerContext(t *testing.T) {
	pdp, _ := fakePDP(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		writeJSON(w, map[string]any{"decision": true})
	})
	cfg, client := clientFor(pdp.URL, pathEvaluation)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var out evaluationResponse
	if _, err := client.postJSON(ctx, cfg.PDPURL, evaluationRequest{}, &out); err == nil {
		t.Fatal("expected the caller's cancellation to abort the request")
	}
}

func TestResolveEndpoint(t *testing.T) {
	cfg := testConfig()
	cfg.PDPURL = "https://configured.example.com" + pathEvaluation
	client := newPDPClient(cfg)

	got, err := client.resolveEndpoint("")
	if err != nil {
		t.Fatal(err)
	}
	if got != cfg.PDPURL {
		t.Fatalf("resolveEndpoint(\"\") = %q, want the configured URL", got)
	}

	if got, err = client.resolveEndpoint("https://override.example.com/x"); err != nil {
		t.Fatal(err)
	} else if got != "https://override.example.com/x" {
		t.Fatalf("override not honoured: %q", got)
	}

	if _, err := client.resolveEndpoint("file:///etc/passwd"); err == nil {
		t.Fatal("an invalid override must be rejected, not silently replaced by the default")
	}

	empty := newPDPClient(testConfig())
	if _, err := empty.resolveEndpoint(""); err == nil {
		t.Fatal("expected an error when nothing is configured")
	}
}

func TestRootOf(t *testing.T) {
	cases := map[string]string{
		"https://pdp.example.com" + pathEvaluation:        "https://pdp.example.com",
		"https://pdp.example.com" + pathEvaluations:       "https://pdp.example.com",
		"https://pdp.example.com" + pathMetadata:          "https://pdp.example.com",
		"https://pdp.example.com/pdp" + pathEvaluation:    "https://pdp.example.com/pdp",
		"https://pdp.example.com" + pathSearchSubject:     "https://pdp.example.com",
		"https://pdp.example.com" + pathMetadata + "/t1":  "https://pdp.example.com/t1",
		"https://pdp.example.com/pdp" + pathSearchAction:  "https://pdp.example.com/pdp",
		"https://pdp.example.com":                         "https://pdp.example.com",
		"https://pdp.example.com/":                        "https://pdp.example.com",
		"http://localhost:8181" + pathEvaluation + "?x=1": "http://localhost:8181",
		"https://pdp.example.com/custom/evaluate":         "https://pdp.example.com/custom/evaluate",
	}
	for in, want := range cases {
		got, err := rootOf(in)
		if err != nil {
			t.Errorf("rootOf(%q) = %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("rootOf(%q) = %q, want %q", in, got, want)
		}
	}

	if _, err := rootOf("file:///x"); err == nil {
		t.Error("rootOf must reject a URL validatePDPURL would reject")
	}
}

func TestResolveFromRoot(t *testing.T) {
	cases := map[string]string{
		"https://pdp.example.com":      "https://pdp.example.com" + pathEvaluations,
		"https://pdp.example.com/":     "https://pdp.example.com" + pathEvaluations,
		"https://pdp.example.com/pdp":  "https://pdp.example.com/pdp" + pathEvaluations,
		"https://pdp.example.com/pdp/": "https://pdp.example.com/pdp" + pathEvaluations,
	}
	for root, want := range cases {
		got, err := resolveFromRoot(root, pathEvaluations)
		if err != nil {
			t.Errorf("resolveFromRoot(%q) = %v", root, err)
			continue
		}
		if got != want {
			t.Errorf("resolveFromRoot(%q) = %q, want %q", root, got, want)
		}
	}
}

func TestBatchEndpointFrom(t *testing.T) {
	got, err := batchEndpointFrom("https://pdp.example.com" + pathEvaluation)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://pdp.example.com"+pathEvaluations {
		t.Fatalf("batchEndpointFrom = %q", got)
	}

	if _, err := batchEndpointFrom(""); err == nil {
		t.Fatal("expected an error with nothing configured")
	}
}

func TestSnippet(t *testing.T) {
	if got := snippet(nil); got != "(empty body)" {
		t.Fatalf("snippet(nil) = %q", got)
	}
	if got := snippet([]byte("  \n ")); got != "(empty body)" {
		t.Fatalf("snippet(whitespace) = %q", got)
	}
	long := snippet([]byte(strings.Repeat("x", 5000)))
	if !strings.HasSuffix(long, "… (truncated)") {
		t.Fatalf("long body was not truncated: %.60s", long)
	}
	if got := snippet([]byte("short")); got != "short" {
		t.Fatalf("snippet(short) = %q", got)
	}
}

func TestMetadataURLs(t *testing.T) {
	cases := map[string][]string{
		"https://pdp.example.com":        {"https://pdp.example.com" + pathMetadata},
		"https://pdp.example.com/":       {"https://pdp.example.com" + pathMetadata},
		"https://gw.example.com/tenant1": {"https://gw.example.com" + pathMetadata + "/tenant1", "https://gw.example.com/tenant1" + pathMetadata},
	}
	for root, want := range cases {
		got, err := metadataURLs(root)
		if err != nil || strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("metadataURLs(%q) = %v, %v; want %v", root, got, err, want)
		}
	}
	if _, err := metadataURLs("ftp://x"); err == nil {
		t.Error("metadataURLs must validate the root")
	}
}
