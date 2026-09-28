#!/usr/bin/env bash
# End-to-end smoke test for mcp-opa-authz.
#
# The unit tests call the handlers directly. This drives the real binary over a
# real stdio MCP session, which is the only thing that exercises tool
# registration, the JSON-RPC framing, and the wiring between them — the parts
# that break when a dependency is upgraded and no Go test notices.
#
# It:
#   1. Starts a fake AuthZEN PDP on a free port that answers both the single
#      and the batch evaluation endpoints and serves a metadata document.
#   2. Runs initialize → tools/list → four tools/call over stdio.
#   3. Asserts every tool answered with the result shape it advertises.
#
# Run it before tagging a release, and after upgrading mcp-go or OPA.
#
# Exit codes:
#   0  every tool answered correctly
#   1  a tool answered incorrectly
#   2  protocol or setup failure

set -euo pipefail

BIN="${1:-./mcp-opa-authz}"
if [[ ! -x "$BIN" ]]; then
    echo "build first: make build" >&2
    exit 2
fi

for tool in jq python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "smoke: $tool is required" >&2; exit 2; }
done

PORT="${SMOKE_PDP_PORT:-18181}"
PDP_LOG=$(mktemp)
# shellcheck disable=SC2329 # registered as EXIT trap below
cleanup() {
    if [[ -n "${PDP_PID:-}" ]] && kill -0 "$PDP_PID" 2>/dev/null; then
        kill "$PDP_PID" 2>/dev/null || true
    fi
    rm -f "$PDP_LOG"
}
trap cleanup EXIT

python3 - "$PORT" >"$PDP_LOG" 2>&1 <<'PY' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = "http://127.0.0.1:%s" % sys.argv[1]


class FakePDP(BaseHTTPRequestHandler):
    def _send(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Echo the correlation id back, as the specification recommends.
        rid = self.headers.get("X-Request-ID")
        if rid:
            self.send_header("X-Request-ID", rid)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/.well-known/authzen-configuration":
            self.send_error(404)
            return
        self._send({
            "policy_decision_point": ROOT,
            "access_evaluation_endpoint": ROOT + "/access/v1/evaluation",
            "access_evaluations_endpoint": ROOT + "/access/v1/evaluations",
        })

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/access/v1/evaluations":
            # Alice may read, may not delete: a per-entry answer, so a wrong
            # zip between requests and decisions shows up as a failed assert.
            out = []
            for ev in payload.get("evaluations", []):
                action = ev.get("action") or payload.get("action") or {}
                out.append({"decision": action.get("name") == "read"})
            self._send({"evaluations": out})
        elif self.path == "/access/v1/evaluation":
            self._send({"decision": True, "context": {"reason": "smoke"}})
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1])), FakePDP).serve_forever()
PY
PDP_PID=$!
disown "$PDP_PID" 2>/dev/null || true

# Wait for the fake PDP to be listening (pure-bash TCP probe).
for _ in {1..50}; do
    (echo >"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
    sleep 0.1
done

read -r -d '' REGO <<'EOF' || true
package smoke

default allow := false

allow if {
	print("evaluating", input.user)
	input.user == "alice"
}
EOF

# mcp_session <responses> <message>... — run one stdio session and print what
# the server wrote. stdin is held open until <responses> lines have come back:
# the server cancels in-flight requests when its input closes, so a bare
# `printf | "$BIN"` would race every tool call that does I/O against EOF.
mcp_session() {
    local want=$1 out
    shift
    out=$(mktemp)
    # shellcheck disable=SC2094 # polling the server's output while it is written is the point
    {
        printf '%s\n' "$@"
        for _ in {1..100}; do
            (( $(wc -l <"$out") >= want )) && break
            sleep 0.1
        done
    } | "$BIN" >"$out"
    cat "$out"
    rm -f "$out"
}

AUTHZEN_PDP_URL="http://127.0.0.1:${PORT}/access/v1/evaluation"
export AUTHZEN_PDP_URL
OUT=$(mcp_session 6 \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    "$(jq -nc --arg r "$REGO" '{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"evaluate_policy",arguments:{rego:$r,query:"data.smoke.allow",input_json:"{\"user\":\"alice\"}"}}}')" \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"authzen_evaluate","arguments":{"subject":"{\"type\":\"user\",\"id\":\"alice\"}","resource":"{\"type\":\"doc\",\"id\":\"d1\"}","action":"{\"name\":\"read\"}"}}}' \
    '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"authzen_evaluate_batch","arguments":{"subject":"{\"type\":\"user\",\"id\":\"alice\"}","resource":"{\"type\":\"doc\",\"id\":\"d1\"}","evaluations":"[{\"action\":{\"name\":\"read\"}},{\"action\":{\"name\":\"delete\"}}]"}}}' \
    '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"authzen_discover","arguments":{}}}')

# result_of <id> — the tool result payload for a request id, decoded from the
# text content block. A tool error has no valid JSON there, which fails loudly.
result_of() {
    printf '%s\n' "$OUT" | jq -r --argjson id "$1" 'select(.id == $id) | .result.content[0].text'
}

fail() {
    echo "✗ smoke: $1"
    printf '%s\n' "$OUT"
    exit "${2:-2}"
}

# --- tools/list ---
TOOLS=$(printf '%s\n' "$OUT" | jq -r 'select(.id == 2) | .result.tools[].name' | sort | tr '\n' ' ')
for want in authzen_discover authzen_evaluate authzen_evaluate_batch evaluate_policy; do
    [[ "$TOOLS" == *"$want"* ]] || fail "tools/list is missing $want (got: $TOOLS)"
done
echo "✓ smoke: tools/list advertises all four tools"

# --- evaluate_policy ---
POLICY=$(result_of 3)
ALLOW=$(jq -r '.value // empty' <<<"$POLICY" 2>/dev/null) || fail "evaluate_policy returned no decodable result"
DEFINED=$(jq -r '.defined // empty' <<<"$POLICY")
PRINTED=$(jq -r '.printed[0] // empty' <<<"$POLICY")
case "$ALLOW" in
    true) ;;
    false) fail "evaluate_policy value=false (expected true)" 1 ;;
    *)     fail "evaluate_policy produced no value field" ;;
esac
[[ "$DEFINED" == "true" ]] || fail "evaluate_policy did not report the query as defined" 1
[[ "$PRINTED" == *"evaluating"* ]] || fail "evaluate_policy dropped print() output" 1
echo "✓ smoke: evaluate_policy value=true, defined, print() captured"

# The sandbox is the security property this server promises; assert it end to
# end and not only in the unit tests.
SANDBOX=$(mcp_session 2 \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"evaluate_policy","arguments":{"rego":"package smoke\n\nallow if http.send({\"method\":\"GET\",\"url\":\"http://127.0.0.1/\"}).status_code == 200","query":"data.smoke.allow"}}}')
if ! printf '%s\n' "$SANDBOX" | jq -e 'select(.id == 2) | .result.isError == true' >/dev/null; then
    echo "✗ smoke: http.send was NOT rejected; the policy sandbox is not in effect"
    printf '%s\n' "$SANDBOX"
    exit 1
fi
echo "✓ smoke: http.send rejected inside evaluate_policy"

# --- authzen_evaluate ---
SINGLE=$(result_of 4)
DECISION=$(jq -r '.decision // empty' <<<"$SINGLE" 2>/dev/null) || fail "authzen_evaluate returned no decodable result"
REQID=$(jq -r '.request_id // empty' <<<"$SINGLE")
case "$DECISION" in
    true) ;;
    false) fail "authzen_evaluate decision=false (fake PDP returned true)" 1 ;;
    *)     fail "authzen_evaluate produced no decision field" ;;
esac
[[ -n "$REQID" ]] || fail "authzen_evaluate reported no X-Request-ID" 1
echo "✓ smoke: authzen_evaluate decision=true, correlated by request id"

# --- authzen_evaluate_batch ---
BATCH=$(result_of 5)
READ=$(jq -r '.decisions[0].decision // empty' <<<"$BATCH" 2>/dev/null) || fail "authzen_evaluate_batch returned no decodable result"
DELETE=$(jq -r '.decisions[1].decision' <<<"$BATCH")
COUNT=$(jq -r '.decisions | length' <<<"$BATCH")
[[ "$COUNT" == "2" ]] || fail "authzen_evaluate_batch returned $COUNT decisions, expected 2" 1
[[ "$READ" == "true" && "$DELETE" == "false" ]] || fail "authzen_evaluate_batch decisions are misaligned (read=$READ delete=$DELETE)" 1
echo "✓ smoke: authzen_evaluate_batch returned 2 aligned decisions"

# --- authzen_discover ---
DISCOVER=$(result_of 6)
ENDPOINT=$(jq -r '.metadata.access_evaluation_endpoint // empty' <<<"$DISCOVER" 2>/dev/null) || fail "authzen_discover returned no decodable result"
[[ -n "$ENDPOINT" ]] || fail "authzen_discover found no access_evaluation_endpoint" 1
echo "✓ smoke: authzen_discover resolved $ENDPOINT"

echo "✓ smoke: all checks passed"
