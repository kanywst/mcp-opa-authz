package main

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/mark3labs/mcp-go/mcp"
)

// Every tool argument that carries structure arrives as a JSON *string*, not as
// a nested object: MCP clients vary in how faithfully they round-trip nested
// objects through a tool schema, and a string is the one shape all of them
// agree on. The cost is that this file exists.

// toolErrorf builds the error result a handler returns to the model. Handlers
// return (result, nil) for user-facing failures — a non-nil error would surface
// as a transport fault and the model would never see the message.
func toolErrorf(format string, a ...any) *mcp.CallToolResult {
	return mcp.NewToolResultError(fmt.Sprintf(format, a...))
}

// requiredString reads a non-empty string argument.
func requiredString(req mcp.CallToolRequest, name string, maxBytes int) (string, error) {
	s := req.GetString(name, "")
	if s == "" {
		return "", fmt.Errorf("missing required argument %q", name)
	}
	if len(s) > maxBytes {
		return "", fmt.Errorf("argument %q is %d bytes, over the %d byte limit", name, len(s), maxBytes)
	}
	return s, nil
}

// optionalJSON decodes an optional JSON-string argument into v. A missing or
// empty argument leaves v untouched and reports false.
func optionalJSON(req mcp.CallToolRequest, name string, maxBytes int, v any) (bool, error) {
	s := req.GetString(name, "")
	if s == "" {
		return false, nil
	}
	if len(s) > maxBytes {
		return false, fmt.Errorf("argument %q is %d bytes, over the %d byte limit", name, len(s), maxBytes)
	}
	if err := json.Unmarshal([]byte(s), v); err != nil {
		return false, fmt.Errorf("argument %q is not valid JSON: %w", name, err)
	}
	return true, nil
}

// jsonObjectArg reads an argument that must decode to a JSON *object*, and
// returns it still encoded. Keeping the raw bytes matters: an AuthZEN entity may
// carry arbitrary `properties`, and a decode/re-encode round trip through
// map[string]any would reorder members and turn integers into floats before the
// PDP — and any policy keyed on them — ever sees the request.
func jsonObjectArg(req mcp.CallToolRequest, name string, maxBytes int, required bool) (json.RawMessage, error) {
	s := req.GetString(name, "")
	if s == "" {
		if required {
			return nil, fmt.Errorf("missing required argument %q", name)
		}
		return nil, nil
	}
	if len(s) > maxBytes {
		return nil, fmt.Errorf("argument %q is %d bytes, over the %d byte limit", name, len(s), maxBytes)
	}
	raw, err := asJSONObject([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("argument %q: %w", name, err)
	}
	return raw, nil
}

// asJSONObject validates that b is a JSON object and returns it unchanged.
func asJSONObject(b []byte) (json.RawMessage, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, fmt.Errorf("must be a JSON object, got %s", jsonKind(v))
	}
	return json.RawMessage(b), nil
}

// jsonKind names the JSON type of a decoded value, for error messages.
func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case float64:
		return "a number"
	case string:
		return "a string"
	case []any:
		return "an array"
	default:
		return "a non-object value"
	}
}

// optionalNonNegativeInt reads an optional integer argument. A client may send
// the number as a JSON number or as a string; either way a fractional or
// negative value is an error rather than something silently truncated, since
// the value is passed on to a PDP as-is.
func optionalNonNegativeInt(req mcp.CallToolRequest, name string) (*int, error) {
	raw, ok := req.GetArguments()[name]
	if !ok || raw == nil {
		return nil, nil
	}
	var f float64
	switch v := raw.(type) {
	case float64:
		f = v
	case int:
		f = float64(v)
	case string:
		if v == "" {
			return nil, nil
		}
		if err := json.Unmarshal([]byte(v), &f); err != nil {
			return nil, fmt.Errorf("argument %q must be an integer, got %q", name, v)
		}
	default:
		return nil, fmt.Errorf("argument %q must be an integer, got %s", name, jsonKind(raw))
	}
	if f < 0 || f != math.Trunc(f) {
		return nil, fmt.Errorf("argument %q must be a non-negative integer, got %v", name, f)
	}
	if f > math.MaxInt32 {
		return nil, fmt.Errorf("argument %q is over the maximum of %d", name, math.MaxInt32)
	}
	n := int(f)
	return &n, nil
}
