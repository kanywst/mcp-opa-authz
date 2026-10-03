package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Wire types for the OpenID AuthZEN Authorization API 1.0 (Final,
// https://openid.net/specs/authorization-api-1_0.html). Member names here are
// normative — a misspelling still round-trips through encoding/json and still
// produces a decision, just not the one the policy meant, so they are the
// single most valuable thing in this file to keep exact.

// Default endpoint paths from the specification, relative to the PDP root.
const (
	pathEvaluation  = "/access/v1/evaluation"  // §Access Evaluation
	pathEvaluations = "/access/v1/evaluations" // §Access Evaluations (batch)
	pathMetadata    = "/.well-known/authzen-configuration"

	pathSearchSubject  = "/access/v1/search/subject"  // §Subject Search
	pathSearchResource = "/access/v1/search/resource" // §Resource Search
	pathSearchAction   = "/access/v1/search/action"   // §Action Search
)

// evaluationRequest is the Access Evaluation request body.
type evaluationRequest struct {
	Subject  json.RawMessage `json:"subject"`
	Action   json.RawMessage `json:"action"`
	Resource json.RawMessage `json:"resource"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// evaluationResponse is the Access Evaluation response body.
//
// Decision is a *bool, not a bool, and the difference is the whole point: the
// specification makes the member REQUIRED, so a body without it is a PDP
// failure. Decoded into a plain bool it would arrive as false and be reported
// as a deny — a PDP that answered nothing would look like a PDP that said no.
type evaluationResponse struct {
	Decision *bool           `json:"decision"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// evaluationsRequest is the batch (Access Evaluations) request body. The
// top-level Subject/Action/Resource/Context are defaults that each entry in
// Evaluations may override.
type evaluationsRequest struct {
	Subject     json.RawMessage    `json:"subject,omitempty"`
	Action      json.RawMessage    `json:"action,omitempty"`
	Resource    json.RawMessage    `json:"resource,omitempty"`
	Context     json.RawMessage    `json:"context,omitempty"`
	Evaluations []json.RawMessage  `json:"evaluations"`
	Options     *evaluationsOption `json:"options,omitempty"`
}

type evaluationsOption struct {
	Semantic string `json:"evaluations_semantic,omitempty"`
}

// Values for evaluations_semantic.
const (
	semanticExecuteAll        = "execute_all"
	semanticDenyOnFirstDeny   = "deny_on_first_deny"
	semanticPermitOnFirstPerm = "permit_on_first_permit"
)

// evaluationsResponse is the batch response body.
type evaluationsResponse struct {
	Evaluations []evaluationResponse `json:"evaluations"`
}

// searchRequest is the body shared by the three Search APIs. Action is absent
// from an Action Search request, which is why it alone is omitempty among the
// entities.
type searchRequest struct {
	Subject  json.RawMessage    `json:"subject"`
	Action   json.RawMessage    `json:"action,omitempty"`
	Resource json.RawMessage    `json:"resource"`
	Context  json.RawMessage    `json:"context,omitempty"`
	Page     *searchPageRequest `json:"page,omitempty"`
}

type searchPageRequest struct {
	Token string `json:"token,omitempty"`
	Limit *int   `json:"limit,omitempty"`
}

// searchResponse is the Search API response body. Results is REQUIRED; like a
// missing decision, a body without it is a PDP that did not answer, and must
// not be reported as "nothing is permitted".
type searchResponse struct {
	Page    *searchPageResponse `json:"page,omitempty"`
	Context json.RawMessage     `json:"context,omitempty"`
	Results []json.RawMessage   `json:"results"`
}

// searchPageResponse is a response's page object. NextToken is a *string for
// the same reason Decision is a *bool: the member is REQUIRED whenever a page
// object is present, and an empty string is the one value that means "this
// was the last page".
//
// Total is a json.Number so that a PDP sending 102.0, or a count past int
// range, still gets its results through: the member is OPTIONAL and only
// informational, and failing the whole response over it would trade a correct
// answer for a tidy one. The equally optional count is not decoded at all.
type searchPageResponse struct {
	NextToken *string     `json:"next_token"`
	Total     json.Number `json:"total,omitempty"`
}

// pdpMetadata is the PDP Metadata document served at pathMetadata.
type pdpMetadata struct {
	PolicyDecisionPoint        string          `json:"policy_decision_point"`
	AccessEvaluationEndpoint   string          `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint  string          `json:"access_evaluations_endpoint,omitempty"`
	SearchSubjectEndpoint      string          `json:"search_subject_endpoint,omitempty"`
	SearchResourceEndpoint     string          `json:"search_resource_endpoint,omitempty"`
	SearchActionEndpoint       string          `json:"search_action_endpoint,omitempty"`
	Capabilities               json.RawMessage `json:"capabilities,omitempty"`
	SignedMetadata             string          `json:"signed_metadata,omitempty"`
	SupportedEvaluationOptions json.RawMessage `json:"supported_evaluation_options,omitempty"`
}

// errPDP is a failure to obtain a decision, as distinct from a decision of
// false. Every path that cannot produce a decision produces one of these.
type errPDP struct {
	msg string
}

func (e *errPDP) Error() string { return e.msg }

func pdpErrorf(format string, a ...any) error { return &errPDP{msg: fmt.Sprintf(format, a...)} }

// pdpClient talks to one PDP. It holds no per-request state, so a single
// instance is shared by every tool.
type pdpClient struct {
	http *http.Client
	cfg  *config

	// metadata caches each PDP root's metadata document for the search tool,
	// so that resolving an endpoint does not add a round trip to every call.
	mu       sync.Mutex
	metadata map[string]metadataEntry
	now      func() time.Time
}

// metadataCacheTTL bounds how long a PDP's advertised endpoints are trusted
// before they are fetched again. Endpoints move rarely; a PDP restarted with a
// new layout is picked up within this window.
const metadataCacheTTL = 5 * time.Minute

type metadataEntry struct {
	meta    *pdpMetadata // nil: the PDP has no usable metadata document
	fetched time.Time
}

func newPDPClient(cfg *config) *pdpClient {
	return &pdpClient{
		http: &http.Client{
			Timeout: cfg.PDPTimeout,
			// A PDP endpoint does not redirect. Following one would send the
			// Authorization header somewhere the operator never configured,
			// and re-point a decision at a host chosen by whoever controls the
			// original. Refusing is both safer and a clearer error than a
			// decision from an unexpected origin.
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return fmt.Errorf("PDP redirected to %s; AuthZEN endpoints are expected to answer directly", req.URL.Redacted())
			},
		},
		cfg:      cfg,
		metadata: map[string]metadataEntry{},
		now:      time.Now,
	}
}

// resolveEndpoint picks the endpoint for a call: the model-supplied override if
// present, otherwise the configured default. Both are validated.
func (c *pdpClient) resolveEndpoint(override string) (string, error) {
	raw := override
	if raw == "" {
		raw = c.cfg.PDPURL
	}
	if raw == "" {
		return "", pdpErrorf("no PDP endpoint: set %s in the MCP server environment, or pass pdp_url", envPDPURL)
	}
	if err := validatePDPURL(raw); err != nil {
		return "", err
	}
	return raw, nil
}

// validatePDPURL constrains where a tool call can send a request. The value may
// come from the model, so "it parsed" is not enough.
func validatePDPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return pdpErrorf("invalid pdp_url: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return pdpErrorf("invalid pdp_url: scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return pdpErrorf("invalid pdp_url: must be an absolute URL with a host")
	}
	// Credentials in the URL would be sent to the host in the URL, which is
	// not necessarily the host the operator configured a token for, and would
	// then appear in every error message that echoes the endpoint back.
	if u.User != nil {
		return pdpErrorf("invalid pdp_url: userinfo (user:password@) is not accepted; use %s", envPDPToken)
	}
	return nil
}

// postJSON sends body to endpoint and decodes the JSON response into out.
// requestID is the X-Request-ID correlating this call in the PDP's logs; the
// value the PDP echoed back is returned.
func (c *pdpClient) postJSON(ctx context.Context, endpoint string, body, out any) (requestID string, err error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", pdpErrorf("failed to encode request: %v", err)
	}

	requestID = newRequestID()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return requestID, pdpErrorf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// RECOMMENDED by the specification, and the only thing that lets somebody
	// reading PDP logs find the call an agent made.
	req.Header.Set("X-Request-ID", requestID)
	c.setAuth(req)

	raw, err := c.do(req)
	if err != nil {
		return requestID, err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return requestID, pdpErrorf("PDP response is not valid AuthZEN JSON: %v (body: %s)", err, snippet(raw))
	}
	return requestID, nil
}

// getJSON fetches endpoint and decodes the JSON response into out.
func (c *pdpClient) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return pdpErrorf("failed to build request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Request-ID", newRequestID())
	c.setAuth(req)

	raw, err := c.do(req)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return pdpErrorf("response is not valid JSON: %v (body: %s)", err, snippet(raw))
	}
	return nil
}

// do performs the request and returns the body, bounded and status-checked.
func (c *pdpClient) do(req *http.Request) ([]byte, error) {
	res, err := c.http.Do(req)
	if err != nil {
		// A redirect refusal arrives wrapped in *url.Error; unwrap so the
		// reason is the message rather than a Go type name.
		var uerr *url.Error
		if errors.As(err, &uerr) && uerr.Err != nil {
			return nil, pdpErrorf("PDP request to %s failed: %v", req.URL.Redacted(), uerr.Err)
		}
		return nil, pdpErrorf("PDP request to %s failed: %v", req.URL.Redacted(), err)
	}
	defer func() { _ = res.Body.Close() }()

	// AuthZEN responses are a few hundred bytes. The cap is here so a
	// misbehaving or hostile endpoint cannot stream this process out of memory.
	raw, err := io.ReadAll(io.LimitReader(res.Body, c.cfg.PDPMaxBytes))
	if err != nil {
		return nil, pdpErrorf("failed to read PDP response: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, pdpErrorf("PDP returned HTTP %d: %s%s",
			res.StatusCode, snippet(raw), statusHint(res.StatusCode))
	}
	return raw, nil
}

func (c *pdpClient) setAuth(req *http.Request) {
	token := strings.TrimSpace(c.cfg.PDPToken)
	if token == "" {
		return
	}
	// A value that already names its scheme is passed through: operators
	// configure "Basic ..." for PDPs behind basic auth, and re-prefixing it
	// with Bearer would break them.
	if !hasAuthScheme(token) {
		token = "Bearer " + token
	}
	req.Header.Set("Authorization", token)
}

// hasAuthScheme reports whether the token already carries an HTTP
// authentication scheme. Scheme names are case-insensitive per RFC 9110.
func hasAuthScheme(token string) bool {
	scheme, _, found := strings.Cut(token, " ")
	if !found {
		return false
	}
	switch strings.ToLower(scheme) {
	case "bearer", "basic", "dpop":
		return true
	}
	return false
}

// statusHint explains the AuthZEN-specific meaning of a status code. A 401 in
// particular is the one most likely to be misread: it says this server failed
// to authenticate to the PDP, never that the subject was denied.
func statusHint(code int) string {
	switch code {
	case http.StatusUnauthorized:
		return fmt.Sprintf("\n\nnote: 401 means this MCP server failed to authenticate to the PDP, not that the subject was denied. Check %s.", envPDPToken)
	case http.StatusForbidden:
		return fmt.Sprintf("\n\nnote: 403 means this MCP server is not permitted to query the PDP, not that the subject was denied. Check %s.", envPDPToken)
	case http.StatusNotFound:
		return fmt.Sprintf("\n\nnote: 404 usually means the URL is a PDP root rather than an endpoint. The AuthZEN default paths are %s and %s; authzen_discover resolves them from a PDP root.", pathEvaluation, pathEvaluations)
	default:
		return ""
	}
}

// snippet bounds untrusted response text before it reaches the model's context.
// The read limit is a megabyte; an error message quoting a megabyte of HTML is
// not a better error message.
func snippet(b []byte) string {
	const maxLen = 512
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "(empty body)"
	}
	if len(s) > maxLen {
		return s[:maxLen] + "… (truncated)"
	}
	return s
}

// newRequestID returns a value for X-Request-ID.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on any supported platform; if it somehow
		// does, a correlation ID is not worth failing an authorization call
		// over.
		return "mcp-opa-authz"
	}
	return hex.EncodeToString(b[:])
}

// resolveFromRoot joins a PDP root URL and a default endpoint path. It is
// deliberately conservative about the root's own path so that a PDP mounted
// under a prefix (https://gw.example.com/pdp) resolves correctly.
func resolveFromRoot(root, path string) (string, error) {
	if err := validatePDPURL(root); err != nil {
		return "", err
	}
	u, err := url.Parse(root)
	if err != nil {
		return "", pdpErrorf("invalid PDP root: %v", err)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// rootOf strips a known AuthZEN endpoint path off a configured URL, so a server
// configured only with an evaluation endpoint can still be asked for its
// metadata. Returns the origin when the path is not one this package knows.
func rootOf(endpoint string) (string, error) {
	if err := validatePDPURL(endpoint); err != nil {
		return "", err
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", pdpErrorf("invalid PDP URL: %v", err)
	}
	for _, p := range []string{
		pathEvaluations, pathEvaluation, pathMetadata,
		pathSearchSubject, pathSearchResource, pathSearchAction,
	} {
		if strings.HasSuffix(u.Path, p) {
			u.Path = strings.TrimSuffix(u.Path, p)
			break
		}
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// fetchMetadata reads the PDP Metadata document for a PDP root and checks it
// may be used. AuthZEN 1.0 requires `policy_decision_point` to be identical to
// the identifier the well-known URL was built from, and says a document that
// fails that "MUST NOT be used": otherwise a PDP mounted under one name can
// hand out endpoints, and the trust that goes with them, for another.
func (c *pdpClient) fetchMetadata(ctx context.Context, root string) (pdpMetadata, string, error) {
	var meta pdpMetadata
	metadataURL, err := resolveFromRoot(root, pathMetadata)
	if err != nil {
		return meta, "", err
	}
	if err := c.getJSON(ctx, metadataURL, &meta); err != nil {
		return meta, metadataURL, err
	}
	// A trailing slash is the one difference tolerated: it does not name a
	// different PDP, and rootOf never produces one.
	if strings.TrimSuffix(meta.PolicyDecisionPoint, "/") != strings.TrimSuffix(root, "/") {
		return meta, metadataURL, pdpErrorf(
			"metadata at %s names policy_decision_point %q, which is not the PDP it was "+
				"fetched from (%s); AuthZEN 1.0 says such a document MUST NOT be used",
			metadataURL, meta.PolicyDecisionPoint, root)
	}
	return meta, metadataURL, nil
}

// usableMetadata returns root's metadata document if it can be fetched and
// passes fetchMetadata's checks, or nil. Either answer is cached for
// metadataCacheTTL. Failure is not an error here: the specification makes the
// metadata document optional and falls back to the default paths without it.
func (c *pdpClient) usableMetadata(ctx context.Context, root string) *pdpMetadata {
	c.mu.Lock()
	e, ok := c.metadata[root]
	c.mu.Unlock()
	if ok && c.now().Sub(e.fetched) < metadataCacheTTL {
		return e.meta
	}

	var found *pdpMetadata
	if meta, _, err := c.fetchMetadata(ctx, root); err == nil {
		found = &meta
	}
	// A call cancelled by its client says nothing about the PDP.
	if ctx.Err() == nil {
		c.mu.Lock()
		c.metadata[root] = metadataEntry{meta: found, fetched: c.now()}
		c.mu.Unlock()
	}
	return found
}
