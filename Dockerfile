# A container image exists for two reasons: MCP clients that launch servers as
# `docker run`, and the OCI listing in the official MCP registry, which is the
# only distribution channel the registry accepts for a Go binary.
#
# Releases are built by goreleaser, which supplies the binary and skips this
# builder stage. Building this file directly compiles from source, so that
# `docker build .` on a checkout produces the same server.

FROM golang:1.27-alpine AS build
WORKDIR /src

# Dependencies are their own layer: source changes far more often than go.sum.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/mcp-opa-authz .

# The server speaks JSON-RPC on stdio and makes outbound HTTPS calls to a PDP.
# It needs a CA bundle and nothing else — no shell, no package manager, and no
# writable filesystem worth attacking.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="mcp-opa-authz" \
      org.opencontainers.image.description="MCP server exposing OPA/Rego evaluation and an OpenID AuthZEN 1.0 PDP" \
      org.opencontainers.image.source="https://github.com/kanywst/mcp-opa-authz" \
      org.opencontainers.image.licenses="MIT"

# The MCP registry will not list an image that does not name the server it
# belongs to. The value must match `name` in server.json exactly — it is how the
# registry proves the io.github.kanywst namespace owns this image, the same job
# npm's `mcpName` does for a package.
LABEL io.modelcontextprotocol.server.name="io.github.kanywst/mcp-opa-authz"

COPY --from=build /out/mcp-opa-authz /usr/local/bin/mcp-opa-authz

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mcp-opa-authz"]
