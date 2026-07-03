//go:build !wbstream

package main

import "errors"

// wb-stream (LiveKit) support is compiled out by default: it pulls livekit and
// its transitive github.com/wlynxg/anet, whose //go:linkname usage fails to link
// on some targets (notably GOOS=android). The full implementation lives in
// wb_stream_mode.go behind the "wbstream" build tag. Selecting a wb-stream mode
// without that tag is a clear error rather than a silent no-op.

var errWbStreamDisabled = errors.New("wb-stream support is disabled in this build (rebuild with -tags wbstream)")

func runWbStreamClient(clientOptions) error { return errWbStreamDisabled }

func runRoomExchangeMode(clientOptions) error { return errWbStreamDisabled }
