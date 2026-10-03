package main

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/mark3labs/mcp-go/mcp"
)

// withOutputSchema is mcp.WithOutputSchema with one correction: json.RawMessage
// is advertised as "any JSON value" instead of as what reflection sees, a
// []byte — an array of integers 0–255. Every json.RawMessage in a result type
// is a PDP's context or metadata member passed through verbatim, so under the
// inferred schema a client that validates structuredContent against the
// declared outputSchema, as the MCP specification says it SHOULD, rejects a
// correct answer whenever the PDP sends one.
func withOutputSchema[T any]() mcp.ToolOption {
	schema, err := jsonschema.For[T](&jsonschema.ForOptions{
		TypeSchemas: map[reflect.Type]*jsonschema.Schema{
			reflect.TypeFor[json.RawMessage](): {},
		},
	})
	if err != nil {
		// The result types are fixed at compile time; this is a programming
		// error, and every test that builds the server would hit it.
		panic(fmt.Sprintf("output schema for %T: %v", *new(T), err))
	}
	encoded, err := json.Marshal(schema)
	if err != nil {
		panic(fmt.Sprintf("output schema for %T: %v", *new(T), err))
	}
	return func(t *mcp.Tool) {
		if err := json.Unmarshal(encoded, &t.OutputSchema); err != nil {
			panic(fmt.Sprintf("output schema for %T: %v", *new(T), err))
		}
		// As mcp.WithOutputSchema does: the specification requires an object,
		// and properties stay sorted by name.
		t.OutputSchema.Type = "object"
		t.OutputSchema.PropertyOrder = nil
	}
}
