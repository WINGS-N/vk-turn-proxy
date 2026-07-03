//go:build !wbstream

package main

import (
	"net"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// wb-stream (LiveKit) support is compiled out by default: it pulls livekit and
// its transitive github.com/wlynxg/anet, whose //go:linkname usage fails to link
// on some targets (notably GOOS=android). The full implementation lives in
// wb_stream_mode.go behind the "wbstream" build tag; this stub keeps the server
// building and turns the room-exchange sink into a no-op when the tag is off.

type wbStreamSessionPool struct{}

func newWbStreamSessionPool(string) *wbStreamSessionPool { return &wbStreamSessionPool{} }

func (*wbStreamSessionPool) SetServerDisplayName(string) {}

func (*wbStreamSessionPool) PreJoin(string, string) error { return nil }

func (*wbStreamSessionPool) HandleExchange(*sessionproto.RoomDataExchange, net.Addr) {}

func (*wbStreamSessionPool) Close() {}
