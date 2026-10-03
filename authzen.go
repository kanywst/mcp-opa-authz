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
	// status is the HTTP status of the answer this error is about: the
	// status of a non-200 response, 200 for a response whose body could not
	// be used, and 0 when no answer arrived at all (timeout, refused
	// connection). It lets a caller tell "the PDP said no" from "the PDP
	// did not say".
	status int
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
		return &errPDP{
			msg:    fmt.Sprintf("response is not valid JSON: %v (body: %s)", err, snippet(raw)),
			status: http.StatusOK,
		}
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
		return nil, &errPDP{
			msg: fmt.Sprintf("PDP returned HTTP %d: %s%s",
				res.StatusCode, snippet(raw), statusHint(res.StatusCode)),
			status: res.StatusCode,
		}
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
	// The RFC 8615 form of a metadata URL puts the PDP's path after the
	// well-known string.
	if rest, ok := strings.CutPrefix(u.Path, pathMetadata); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
		u.Path = rest
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
	candidates, err := metadataURLs(root)
	if err != nil {
		return meta, "", err
	}
	var metadataURL string
	for _, metadataURL = range candidates {
		meta = pdpMetadata{}
		err = c.getJSON(ctx, metadataURL, &meta)
		if !isStatus(err, http.StatusNotFound) {
			break
		}
	}
	if err != nil {
		return meta, metadataURL, err
	}
	// A trailing slash is the one difference tolerated: it does not name a
	// different PDP, and rootOf never produces one.
	if strings.TrimSuffix(meta.PolicyDecisionPoint, "/") != strings.TrimSuffix(root, "/") {
		return meta, metadataURL, &errPDP{
			msg: fmt.Sprintf(
				"metadata at %s names policy_decision_point %q, which is not the PDP it was "+
					"fetched from (%s); AuthZEN 1.0 says such a document MUST NOT be used",
				metadataURL, snippet([]byte(meta.PolicyDecisionPoint)), root),
			status: http.StatusOK,
		}
	}
	return meta, metadataURL, nil
}

// usableMetadata returns root's metadata document if it can be fetched and
// passes fetchMetadata's checks, or nil. Failure is not an error here: the
// specification makes the metadata document optional and falls back to the
// default paths without it.
//
// Only a definite answer is cached for metadataCacheTTL — a usable document,
// or the PDP saying it has none (404, 410, a body that is not usable
// metadata). A failure that says nothing about the PDP's layout — a timeout, a
// 5xx, a 401 — is not cached, and leaves a previously fetched document in
// use: replacing it with "no metadata" would send searches to the default
// path for the whole TTL, when the specification says the advertised endpoint
// MUST be used.
func (c *pdpClient) usableMetadata(ctx context.Context, root string) *pdpMetadata {
	c.mu.Lock()
	e, ok := c.metadata[root]
	c.mu.Unlock()
	if ok && c.now().Sub(e.fetched) < metadataCacheTTL {
		return e.meta
	}

	meta, _, err := c.fetchMetadata(ctx, root)
	var found *pdpMetadata
	switch {
	case err == nil:
		found = &meta
	case isStatus(err, http.StatusOK), isStatus(err, http.StatusNotFound), isStatus(err, http.StatusGone):
		// The PDP answered, and has no usable document.
	default:
		if ok {
			return e.meta
		}
		return nil
	}
	c.mu.Lock()
	c.metadata[root] = metadataEntry{meta: found, fetched: c.now()}
	c.mu.Unlock()
	return found
}

// metadataURLs lists where a PDP root's metadata document may be, in the order
// to try them. AuthZEN 1.0 §Obtaining PDP Metadata inserts the well-known
// string between the host and the path (RFC 8615), so a PDP at
// https://gw.example.com/pdp publishes
// https://gw.example.com/.well-known/authzen-configuration/pdp. Earlier
// releases appended it instead (…/pdp/.well-known/authzen-configuration); that
// form is tried second, on a 404, so a deployment set up to match them keeps
// working. A root without a path has one location, where both agree.
func metadataURLs(root string) ([]string, error) {
	if err := validatePDPURL(root); err != nil {
		return nil, err
	}
	u, err := url.Parse(root)
	if err != nil {
		return nil, pdpErrorf("invalid PDP root: %v", err)
	}
	path := strings.TrimSuffix(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""

	inserted := *u
	inserted.Path = pathMetadata + path
	if path == "" {
		return []string{inserted.String()}, nil
	}
	appended := *u
	appended.Path = path + pathMetadata
	return []string{inserted.String(), appended.String()}, nil
}

// isStatus reports whether err is a PDP answer with the given HTTP status.
func isStatus(err error, status int) bool {
	var perr *errPDP
	return errors.As(err, &perr) && perr.status == status
}

// Values for the endpoint_source member of a result: where the endpoint the
// call went to came from.
const (
	endpointFromArgument = "pdp_url"  // the tool's pdp_url argument
	endpointFromMetadata = "metadata" // advertised in the PDP's metadata
	endpointFromDefault  = "default"  // the default path under the PDP's root
)

// advertisedOrDefault resolves the endpoint for one AuthZEN API on the
// configured PDP. AuthZEN 1.0 §Transport: the request URL MUST be the endpoint
// the PDP's metadata advertises for that API when there is one, and SHOULD be
// the default path under the PDP's root otherwise.
//
// member names the metadata member, for errors; pick reads it; check, if not
// nil, applies API-specific checks to an advertised value.
func (c *pdpClient) advertisedOrDefault(
	ctx context.Context,
	member, defaultPath string,
	pick func(*pdpMetadata) string,
	check func(endpoint string) error,
) (endpoint, source string, err error) {
	if c.cfg.PDPURL == "" {
		return "", "", pdpErrorf("no PDP endpoint: set %s in the MCP server environment, or pass pdp_url", envPDPURL)
	}
	root, err := rootOf(c.cfg.PDPURL)
	if err != nil {
		return "", "", err
	}
	if meta := c.usableMetadata(ctx, root); meta != nil {
		if advertised := pick(meta); advertised != "" {
			err := checkAdvertisedEndpoint(advertised, root)
			if err == nil && check != nil {
				err = check(advertised)
			}
			if err != nil {
				// The value is PDP-controlled, and the reason may quote it in
				// full (url.Parse does), so both are bounded before they
				// reach the model.
				return "", "", fmt.Errorf("the PDP metadata advertises %s %s, which cannot be used: %s",
					member, snippet([]byte(advertised)), snippet([]byte(err.Error())))
			}
			return advertised, endpointFromMetadata, nil
		}
	}
	endpoint, err = resolveFromRoot(root, defaultPath)
	return endpoint, endpointFromDefault, err
}

// checkAdvertisedEndpoint holds an endpoint taken from PDP metadata to the
// PDP's own origin. The configured token is sent with every call, and the
// metadata document is whatever the PDP's host served at the well-known path
// — often a gateway or a static file rather than the PDP. An endpoint on
// another host, or plain http under an https PDP, would carry the token
// somewhere the operator never configured it for. A deliberate cross-origin
// endpoint can still be used by passing it as pdp_url.
func checkAdvertisedEndpoint(endpoint, root string) error {
	if err := validatePDPURL(endpoint); err != nil {
		return err
	}
	e, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	r, err := url.Parse(root)
	if err != nil {
		return err
	}
	if !strings.EqualFold(e.Scheme, r.Scheme) || !strings.EqualFold(e.Host, r.Host) {
		return fmt.Errorf("it is not on the PDP's origin %s://%s, and the PDP token is not "+
			"sent to another origin; pass it as pdp_url to use it deliberately", r.Scheme, r.Host)
	}
	return nil
}
