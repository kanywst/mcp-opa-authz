package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Kinds of search, one per AuthZEN Search API.
const (
	searchSubject  = "subject"
	searchResource = "resource"
	searchAction   = "action"
)

// searchPaths maps a kind of search to its default endpoint path.
var searchPaths = map[string]string{
	searchSubject:  pathSearchSubject,
	searchResource: pathSearchResource,
	searchAction:   pathSearchAction,
}

// searchOutput is the structured result of authzen_search.
type searchOutput struct {
	// Search is the kind of entity that was searched for.
	Search string `json:"search"`
	// Results are the entities the PDP reports as permitted, passed through
	// unmodified. Empty means the PDP answered and nothing is permitted.
	Results []json.RawMessage `json:"results"`
	// HasMore reports that the PDP returned a page of a larger result set.
	HasMore bool `json:"has_more"`
	// NextPageToken is passed back as page_token, with every other argument
	// unchanged, to fetch the next page. Empty when HasMore is false.
	NextPageToken string `json:"next_page_token,omitempty"`
	// Total is the PDP's count of all matching results, when it reports one.
	Total   *int            `json:"total,omitempty"`
	Context json.RawMessage `json:"context,omitempty"`
	// PDPURL and RequestID trace the answer to a PDP call, as for the
	// evaluation tools.
	PDPURL    string `json:"pdp_url"`
	RequestID string `json:"request_id"`
	// EndpointSource says where PDPURL came from: "pdp_url" (the argument),
	// "metadata" (the PDP's advertised search endpoint) or "default" (the
	// specification's default path under the configured PDP's root).
	EndpointSource string `json:"endpoint_source"`
}

// Values for searchOutput.EndpointSource.
const (
	endpointFromArgument = "pdp_url"
	endpointFromMetadata = "metadata"
	endpointFromDefault  = "default"
)

func registerSearchTool(s *server.MCPServer, client *pdpClient) {
	s.AddTool(
		mcp.NewTool("authzen_search",
			mcp.WithDescription(
				"Ask an OpenID AuthZEN 1.0 PDP which entities are permitted, rather than "+
					"whether one is (the Search APIs). `search` picks the question: "+
					"\"subject\" — who may perform the action on the resource; "+
					"\"resource\" — which resources of a type the subject may act on; "+
					"\"action\" — what the subject may do to the resource. The entity "+
					"being searched for carries only its `type`; the action search takes "+
					"no `action` at all. Use authzen_evaluate_batch instead when the "+
					"candidates are already known."),
			mcp.WithTitleAnnotation("Ask an AuthZEN PDP what is permitted"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(true),
			withOutputSchema[searchOutput](),
			mcp.WithString("search",
				mcp.Required(),
				mcp.Description("Which entity to search for: subject, resource or action."),
				mcp.Enum(searchSubject, searchResource, searchAction),
			),
			mcp.WithString("subject",
				mcp.Required(),
				mcp.Description(`JSON subject. For a subject search, only "type" `+
					`(e.g. {"type":"user"}); otherwise "type" and "id" are required.`),
			),
			mcp.WithString("action",
				mcp.Description(`JSON action with "name", e.g. {"name":"read"}. Required for `+
					`subject and resource searches; must be omitted for an action search.`),
			),
			mcp.WithString("resource",
				mcp.Required(),
				mcp.Description(`JSON resource. For a resource search, only "type" `+
					`(e.g. {"type":"document"}); otherwise "type" and "id" are required.`),
			),
			mcp.WithString("context",
				mcp.Description("Optional JSON object of runtime context the policy may read."),
			),
			mcp.WithString("page_token",
				mcp.Description("next_page_token from a previous authzen_search result, to "+
					"fetch the next page. Every other argument must be unchanged from "+
					"that call; AuthZEN lets the PDP reject a changed query."),
			),
			mcp.WithNumber("page_limit",
				mcp.Description("Maximum number of results the PDP should return in one page. "+
					"A PDP without pagination support may ignore it."),
				mcp.Min(0),
			),
			mcp.WithString("pdp_url",
				mcp.Description("Override the endpoint for this call. Must point at the Search "+
					"endpoint for the chosen kind. Defaults to the endpoint the configured "+
					"PDP advertises in its metadata, or the specification's default path "+
					"under the root of "+envPDPURL+" when it advertises none."),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return authzenSearch(ctx, req, client)
		},
	)
}

func authzenSearch(ctx context.Context, req mcp.CallToolRequest, client *pdpClient) (*mcp.CallToolResult, error) {
	kind := req.GetString("search", "")
	path, ok := searchPaths[kind]
	if !ok {
		return toolErrorf("search must be one of %q, %q, %q; got %q",
			searchSubject, searchResource, searchAction, kind), nil
	}

	endpoint, source := req.GetString("pdp_url", ""), endpointFromArgument
	if endpoint == "" {
		var err error
		if endpoint, source, err = resolveSearchEndpoint(ctx, client, kind, path); err != nil {
			return toolErrorf("%v", err), nil
		}
	}
	// An advertised endpoint is validated like a model-supplied one: the
	// metadata document is whatever the PDP's host served.
	if err := validatePDPURL(endpoint); err != nil {
		return toolErrorf("%v", err), nil
	}
	if err := checkSearchEndpoint(endpoint, kind); err != nil {
		return toolErrorf("%v", err), nil
	}

	body, err := readSearchArgs(req, client.cfg, kind)
	if err != nil {
		return toolErrorf("%v", err), nil
	}

	var decoded searchResponse
	requestID, err := client.postJSON(ctx, endpoint, body, &decoded)
	if err != nil {
		return toolErrorf("%v", err), nil
	}
	if decoded.Results == nil {
		return toolErrorf(
			"PDP response has no `results` member, which AuthZEN 1.0 requires. Treating "+
				"this as a failure rather than as \"nothing is permitted\"; endpoint %s, "+
				"request id %s.", endpoint, requestID), nil
	}
	if err := validateSearchResults(decoded.Results, kind, body); err != nil {
		return toolErrorf("%v; endpoint %s, request id %s.", err, endpoint, requestID), nil
	}

	out := searchOutput{
		Search:         kind,
		Results:        decoded.Results,
		Context:        decoded.Context,
		PDPURL:         endpoint,
		RequestID:      requestID,
		EndpointSource: source,
	}
	if p := decoded.Page; p != nil {
		// The specification's own example response carries a page with only
		// count and total. Neither says whether this is the last page, and
		// reporting a partial list as complete is the search equivalent of
		// reporting a missing decision as a deny.
		if p.NextToken == nil {
			return toolErrorf(
				"PDP response has a `page` object without `next_token`, which AuthZEN 1.0 "+
					"requires whenever `page` is present; `count` and `total` alone do not say "+
					"whether these results are complete, so none are reported. Endpoint %s, "+
					"request id %s.", endpoint, requestID), nil
		}
		out.NextPageToken = *p.NextToken
		out.HasMore = *p.NextToken != ""
		if n, err := p.Total.Int64(); err == nil && n >= 0 && n <= math.MaxInt32 {
			total := int(n)
			out.Total = &total
		}
	}
	return structuredResult(out)
}

// readSearchArgs reads and validates the arguments for one kind of search.
//
// Which members are required depends on the kind: the entity being searched for
// carries only a type, and an action search has no action. Checking that here
// names the mistake; a PDP would otherwise answer a subject search that carries
// a subject id by ignoring it, as the specification requires, and the model
// would read the answer as being about that one subject.
func readSearchArgs(req mcp.CallToolRequest, cfg *config, kind string) (searchRequest, error) {
	var out searchRequest
	var err error

	if out.Subject, err = jsonObjectArg(req, "subject", cfg.MaxArgBytes, true); err != nil {
		return out, err
	}
	if out.Resource, err = jsonObjectArg(req, "resource", cfg.MaxArgBytes, true); err != nil {
		return out, err
	}
	if out.Action, err = jsonObjectArg(req, "action", cfg.MaxArgBytes, kind != searchAction); err != nil {
		return out, err
	}
	if out.Context, err = jsonObjectArg(req, "context", cfg.MaxArgBytes, false); err != nil {
		return out, err
	}

	switch kind {
	case searchSubject:
		if err := requireMembers(out.Subject, "argument subject", "type"); err != nil {
			return out, err
		}
		if err := forbidMember(out.Subject, "argument subject", "id", kind); err != nil {
			return out, err
		}
		if err := requireMembers(out.Resource, "argument resource", "type", "id"); err != nil {
			return out, err
		}
	case searchResource:
		if err := requireMembers(out.Subject, "argument subject", "type", "id"); err != nil {
			return out, err
		}
		if err := requireMembers(out.Resource, "argument resource", "type"); err != nil {
			return out, err
		}
		if err := forbidMember(out.Resource, "argument resource", "id", kind); err != nil {
			return out, err
		}
	case searchAction:
		if len(out.Action) > 0 {
			return out, fmt.Errorf("an action search takes no %q argument: the actions are what is being searched for", "action")
		}
		if err := requireMembers(out.Subject, "argument subject", "type", "id"); err != nil {
			return out, err
		}
		if err := requireMembers(out.Resource, "argument resource", "type", "id"); err != nil {
			return out, err
		}
	}
	if err := requireMembers(out.Action, "argument action", "name"); err != nil {
		return out, err
	}

	token := req.GetString("page_token", "")
	if len(token) > cfg.MaxArgBytes {
		return out, fmt.Errorf("argument %q is %d bytes, over the %d byte limit", "page_token", len(token), cfg.MaxArgBytes)
	}
	limit, err := optionalNonNegativeInt(req, "page_limit")
	if err != nil {
		return out, err
	}
	if token != "" || limit != nil {
		out.Page = &searchPageRequest{Token: token, Limit: limit}
	}
	return out, nil
}

// resolveSearchEndpoint finds the endpoint for one kind of search on the
// configured PDP. AuthZEN 1.0 §Transport: the request URL MUST be the endpoint
// the PDP's metadata advertises for that API when there is one, and SHOULD be
// the default path under the PDP's root otherwise.
func resolveSearchEndpoint(ctx context.Context, client *pdpClient, kind, path string) (endpoint, source string, err error) {
	if client.cfg.PDPURL == "" {
		return "", "", pdpErrorf("no PDP endpoint: set %s in the MCP server environment, or pass pdp_url", envPDPURL)
	}
	root, err := rootOf(client.cfg.PDPURL)
	if err != nil {
		return "", "", err
	}
	if meta := client.usableMetadata(ctx, root); meta != nil {
		advertised := map[string]string{
			searchSubject:  meta.SearchSubjectEndpoint,
			searchResource: meta.SearchResourceEndpoint,
			searchAction:   meta.SearchActionEndpoint,
		}[kind]
		if advertised != "" {
			if err := checkAdvertisedEndpoint(advertised, root, kind); err != nil {
				return "", "", fmt.Errorf("the PDP metadata advertises search_%s_endpoint %s, "+
					"which cannot be used: %w", kind, advertised, err)
			}
			return advertised, endpointFromMetadata, nil
		}
	}
	endpoint, err = resolveFromRoot(root, path)
	return endpoint, endpointFromDefault, err
}

// checkAdvertisedEndpoint holds an endpoint taken from PDP metadata to the
// PDP's own origin. The configured token is sent with every search, and the
// metadata document is whatever the PDP's host served at the well-known path
// — often a gateway or a static file rather than the PDP. An endpoint on
// another host, or plain http under an https PDP, would carry the token
// somewhere the operator never configured it for. A deliberate cross-origin
// endpoint can still be used by passing it as pdp_url.
func checkAdvertisedEndpoint(endpoint, root, kind string) error {
	if err := validatePDPURL(endpoint); err != nil {
		return err
	}
	if err := checkSearchEndpoint(endpoint, kind); err != nil {
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

// checkSearchEndpoint rejects a pdp_url that names the default path of a
// different kind of search. A subject search posted to the resource endpoint
// is a well-formed request to the wrong API, and the answer would be read as
// the answer to the question that was asked.
func checkSearchEndpoint(endpoint, kind string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return pdpErrorf("invalid pdp_url: %v", err)
	}
	for other, path := range searchPaths {
		if other != kind && strings.HasSuffix(strings.TrimSuffix(u.Path, "/"), path) {
			return fmt.Errorf("pdp_url %s is the %s search endpoint, but search is %q",
				u.Redacted(), other, kind)
		}
	}
	return nil
}

// forbidMember rejects a member the specification says the PDP must ignore.
func forbidMember(raw json.RawMessage, what, member, kind string) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%s is not a JSON object: %w", what, err)
	}
	if _, ok := obj[member]; ok {
		return fmt.Errorf("%s has %q, but a %s search is for every %s of that type; "+
			"AuthZEN 1.0 has the PDP ignore it, so drop it", what, member, kind, kind)
	}
	return nil
}

// validateSearchResults checks that every result is an entity of the kind that
// was searched for. The specification requires it; a PDP that returns something
// else has answered a different question, and passing that through would put an
// entity of the wrong type in front of the model as "permitted".
func validateSearchResults(results []json.RawMessage, kind string, body searchRequest) error {
	var wantType string
	switch kind {
	case searchSubject:
		wantType = memberString(body.Subject, "type")
	case searchResource:
		wantType = memberString(body.Resource, "type")
	}
	for i, raw := range results {
		what := fmt.Sprintf("results[%d] in the PDP response", i)
		if _, err := asJSONObject(raw); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		if kind == searchAction {
			if err := requireMembers(raw, what, "name"); err != nil {
				return err
			}
			continue
		}
		if err := requireMembers(raw, what, "type", "id"); err != nil {
			return err
		}
		if got := memberString(raw, "type"); got != wantType {
			return fmt.Errorf("%s has type %q, but the search was for type %q", what, got, wantType)
		}
	}
	return nil
}

// memberString returns obj[member] when it is a string, or "".
func memberString(raw json.RawMessage, member string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(obj[member], &s); err != nil {
		return ""
	}
	return s
}
