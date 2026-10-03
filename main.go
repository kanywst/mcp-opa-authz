// mcp-opa-authz is a Model Context Protocol (MCP) server that lets an agent get
// an authorization answer from real policy code instead of from its own guess.
//
// It exposes the same question at two layers:
//
//	evaluate_policy         Evaluate a Rego module in-process, via OPA.
//	authzen_evaluate        Ask a remote OpenID AuthZEN 1.0 PDP for a decision.
//	authzen_evaluate_batch  Ask that PDP for many decisions in one round trip.
//	authzen_search          Ask that PDP which subjects, resources or actions
//	                        are permitted.
//	authzen_discover        Read a PDP's AuthZEN metadata document.
//
// Use evaluate_policy while authoring or debugging a policy whose source you
// have; use the authzen_* tools when the decision has to come from the PDP that
// actually governs the system.
//
// It is designed to be launched as a subprocess by an MCP client (Claude Code,
// Cursor, and anything else speaking MCP over stdio).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/mark3labs/mcp-go/server"
)

// version is set at build time by goreleaser (-X main.version). Builds made by
// `go install` leave it at its default and fall back to module build info.
var version = "dev"

const usage = `mcp-opa-authz — MCP server exposing OPA/Rego evaluation and an OpenID AuthZEN 1.0 PDP.

Usage:
  mcp-opa-authz             Run as an MCP stdio server (default).
  mcp-opa-authz --version   Print version.
  mcp-opa-authz --help      Print this message.

Tools exposed:
  evaluate_policy         Evaluate a Rego module against an input document,
                          in-process. No external service is contacted.
  authzen_evaluate        Ask an AuthZEN 1.0 PDP for one decision.
  authzen_evaluate_batch  Ask an AuthZEN 1.0 PDP for many decisions at once.
  authzen_search          Ask an AuthZEN 1.0 PDP which subjects, resources or
                          actions are permitted.
  authzen_discover        Read a PDP's /.well-known/authzen-configuration.

Configuration (environment):
  AUTHZEN_PDP_URL                 Default Access Evaluation endpoint, e.g.
                                  http://localhost:8181/access/v1/evaluation
  AUTHZEN_PDP_TOKEN               Authorization header value. A value with no
                                  scheme is sent as "Bearer <token>".
  AUTHZEN_PDP_TIMEOUT             Per-request timeout (default 10s).
  AUTHZEN_PDP_MAX_RESPONSE_BYTES  Response read limit (default 1048576).
  MCP_OPA_EVAL_TIMEOUT            Rego evaluation timeout (default 5s).
  MCP_MAX_ARG_BYTES               Per-argument size limit (default 1048576).
  MCP_OPA_ALLOW_NETWORK_BUILTINS  Re-enable http.send, net.lookup_ip_addr and
                                  opa.runtime inside evaluated policies. Off by
                                  default: policies evaluated here come from a
                                  model and run inside this process.

Configure with an MCP client (Claude Code):
  claude mcp add opa-authz --env AUTHZEN_PDP_URL=http://localhost:8181/access/v1/evaluation -- mcp-opa-authz

Documentation: https://github.com/kanywst/mcp-opa-authz`

func main() {
	if code := run(os.Args[1:], os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}

// run holds everything main does, so that it is reachable from a test. It
// returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "--version", "-v", "version":
			_, _ = fmt.Fprintf(stdout, "mcp-opa-authz %s\n", resolveVersion())
			return 0
		case "--help", "-h", "help":
			_, _ = fmt.Fprintln(stdout, usage)
			return 0
		default:
			_, _ = fmt.Fprintf(stderr, "mcp-opa-authz: unknown argument %q\n\n%s\n", args[0], usage)
			return 2
		}
	}

	// Configuration is validated before the transport opens. A malformed
	// timeout should stop the server with a message an operator can read in the
	// client's log, not become a surprise halfway through a session.
	cfg, err := loadConfig(osGetenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-opa-authz: %v\n", err)
		return 1
	}

	s := newServer(cfg)

	if err := server.ServeStdio(s); err != nil {
		// The client closing stdin, or SIGINT/SIGTERM, is how this server is
		// meant to end. ServeStdio reports the cancellation as an error;
		// exiting non-zero on it would make every clean shutdown look like a
		// crash in the client's logs.
		if errors.Is(err, context.Canceled) {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "mcp-opa-authz: %v\n", err)
		return 1
	}
	return 0
}

// newServer builds the MCP server with every tool registered.
func newServer(cfg *config) *server.MCPServer {
	s := server.NewMCPServer(
		"mcp-opa-authz",
		resolveVersion(),
		server.WithToolCapabilities(false),
		// A panic in a tool handler would otherwise take down the transport and
		// with it the client's whole session. OPA evaluates model-supplied
		// source; that is not a place to bet on nothing ever panicking.
		server.WithRecovery(),
		server.WithInstructions(instructions),
	)

	client := newPDPClient(cfg)
	registerOPATool(s, cfg)
	registerAuthZENTools(s, client)

	return s
}

// instructions tell the model which tool answers which question. Without them
// the two layers look interchangeable, and the usual failure is reaching for a
// PDP when the policy source is right there in the conversation.
const instructions = `Authorization answers from real policy code.

Pick the tool by where the authoritative answer lives:

- evaluate_policy — you have the Rego source. Authoring, debugging, "what would
  this policy say". Runs in-process; nothing external is contacted.
- authzen_evaluate — the answer must come from the PDP that governs the running
  system. Do not paste a policy and evaluate it locally as a substitute for
  this; a local evaluation is a guess about production.
- authzen_evaluate_batch — the same question over a list. Filtering resources a
  subject may see, or checking several actions at once, in one round trip.
- authzen_search — "who may", "which resources may", "what may": the PDP lists
  the permitted subjects, resources or actions. Use it when the candidates are
  not known; when they are, authzen_evaluate_batch checks them directly.
- authzen_discover — a PDP's URL is known but its endpoints are not, or whether
  it offers the search endpoints.

A decision of false is a deny, and is a successful call. A tool error means no
decision was obtained; never report one as the other. Likewise an empty search
result means nothing is permitted; a tool error means the PDP did not answer.`

// resolveVersion prefers the linker-stamped version, and falls back to the
// module version recorded by the Go toolchain so that `go install`ed builds
// report something better than "dev".
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return version
	}
	return info.Main.Version
}
