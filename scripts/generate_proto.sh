#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PROTO_DIR="$ROOT_DIR/proto"
OUT_DIR="$ROOT_DIR"
TOOLS_DIR="$ROOT_DIR/.cache/tools"
TOOL_WORK_DIR="$ROOT_DIR/.cache/protoc-gen-go-tool"
GO_BUILD_CACHE_DIR="$ROOT_DIR/.cache/go-build"

mkdir -p "$TOOLS_DIR" "$TOOL_WORK_DIR" "$GO_BUILD_CACHE_DIR"

(
  cd "$ROOT_DIR"
  GOSUMDB=off GOCACHE="$GO_BUILD_CACHE_DIR" go mod download google.golang.org/protobuf >/dev/null
)

PROTOBUF_MODULE_DIR="$(cd "$ROOT_DIR" && GOSUMDB=off GOCACHE="$GO_BUILD_CACHE_DIR" go list -m -f '{{.Dir}}' google.golang.org/protobuf)"
[ -n "$PROTOBUF_MODULE_DIR" ] || {
  echo "Failed to resolve google.golang.org/protobuf module directory" >&2
  exit 1
}

cat > "$TOOL_WORK_DIR/go.mod" <<EOF
module vkturn-proto-tool

go 1.25.5

require google.golang.org/protobuf v1.36.10

replace google.golang.org/protobuf => $PROTOBUF_MODULE_DIR
EOF

(
  cd "$TOOL_WORK_DIR"
  GOCACHE="$GO_BUILD_CACHE_DIR" go build -o "$TOOLS_DIR/protoc-gen-go" google.golang.org/protobuf/cmd/protoc-gen-go
)

PATH="$TOOLS_DIR:$PATH" protoc \
  --proto_path="$ROOT_DIR" \
  --go_out="$OUT_DIR" \
  --go_opt=module=github.com/cacggghp/vk-turn-proxy \
  "$PROTO_DIR/session.proto"
