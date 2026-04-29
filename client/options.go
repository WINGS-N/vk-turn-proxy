package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/cacggghp/vk-turn-proxy/internal/cliutil"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

type clientOptions struct {
	host                           string
	port                           string
	listen                         string
	vklink                         string
	vklinkSecondary                string
	yalink                         string
	peerAddr                       string
	n                              int
	transport                      string
	vlessMode                      bool
	udp                            bool
	direct                         bool
	manualCaptcha                  bool
	captchaSolver                  string
	tcpFlavor                      string
	credsGroupSize                 int
	protectSock                    string
	protoFingerprint               string
	sessionMode                    string
	sessionID                      string
	adaptivePoolMin                int
	adaptivePoolMax                int
	adaptivePoolStreamsPerIdentity int

	wbStreamRoomID      string
	wbStreamDisplayName string
	wbStreamE2ESecret   string

	roomExchangeMode        bool
	roomExchangeRoomID      string
	roomExchangeDisplayName string
	roomExchangeE2EEnabled  bool
	roomExchangeE2ESecret   string
}

func newClientFlagSet(program string, output io.Writer) (*flag.FlagSet, *clientOptions) {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	fs.SetOutput(output)

	opts := &clientOptions{}
	fs.StringVar(&opts.host, "turn", "", "override TURN server ip")
	fs.StringVar(&opts.port, "port", "", "override TURN port")
	fs.StringVar(&opts.listen, "listen", "127.0.0.1:9000", "listen on ip:port")
	fs.StringVar(&opts.vklink, "vk-link", "", "VK calls invite link(s); accepts multiple comma-separated \"https://vk.com/call/join/...\" entries (priority order)")
	fs.StringVar(&opts.vklinkSecondary, "vk-link-secondary", "", "fallback VK link used when all primary -vk-link entries are in cooldown")
	fs.StringVar(&opts.yalink, "yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	fs.StringVar(&opts.peerAddr, "peer", "", "peer server address (host:port)")
	fs.IntVar(&opts.n, "n", 0, "connections to TURN (default 10 for VK, 1 for Yandex)")
	fs.StringVar(&opts.transport, "transport", "datagram", "transport mode: datagram|tcp")
	fs.BoolVar(&opts.vlessMode, "vless", false, "deprecated alias for -transport=tcp")
	fs.BoolVar(&opts.udp, "udp", false, "connect to TURN with UDP")
	fs.BoolVar(&opts.direct, "no-dtls", false, "connect without obfuscation. DO NOT USE")
	fs.BoolVar(&opts.manualCaptcha, "manual-captcha", false, "skip automatic captcha solving and use manual captcha flow immediately")
	fs.StringVar(&opts.captchaSolver, "captcha-solver", "v2", "auto captcha solver implementation: v1|v2 (v2 = improved, v1 = legacy fallback)")
	fs.StringVar(&opts.tcpFlavor, "tcp-flavor", "auto", "TCP transport flavor override: auto|direct|legacy (auto = negotiate; direct = smux over DTLS; legacy = KCP+smux)")
	fs.IntVar(&opts.credsGroupSize, "creds-group-size", 12, "workers per TURN identity (smaller = more identities, less per-identity rate limit; larger = fewer auth calls)")
	fs.StringVar(&opts.protectSock, "protect-sock", "", "unix socket used for VpnService.protect fd bridge")
	fs.StringVar(&opts.protoFingerprint, "proto-fp", "", "deprecated; ignored")
	fs.StringVar(&opts.sessionMode, "session-mode", string(sessionproto.ModeMainline), "TURN session mode: mainline|mu|auto")
	fs.StringVar(&opts.sessionID, "session-id", "", "override session ID (hex, 32 chars) for mu mode")
	fs.IntVar(&opts.adaptivePoolMin, "adaptive-pool-min", 1, "minimum TURN identity pool size for mu/v1")
	fs.IntVar(&opts.adaptivePoolMax, "adaptive-pool-max", 0, "maximum TURN identity pool size for mu/v1 (default: stream count)")
	fs.IntVar(&opts.adaptivePoolStreamsPerIdentity, "adaptive-pool-streams-per-id", defaultAdaptivePoolStreamsPerIdentity, "target concurrent streams per TURN identity for mu/v1")
	fs.StringVar(&opts.wbStreamRoomID, "wb-stream-room-id", "", `LiveKit room ID; "any" creates a fresh one. When set, runs WB Stream tunnel mode.`)
	fs.StringVar(&opts.wbStreamDisplayName, "wb-stream-display-name", "vk-turn-proxy-client", "display name shown in the LiveKit room when -wb-stream-room-id is set")
	fs.StringVar(&opts.wbStreamE2ESecret, "wb-stream-e2e-secret", "", "optional base64-encoded chacha20-poly1305 key for E2E over DataPacket")
	fs.BoolVar(&opts.roomExchangeMode, "room-exchange-mode", false, "send a single CLIENT_HELLO_TYPE_ROOM_EXCHANGE to -peer over DTLS and exit (used to deliver wb-stream room metadata via VK TURN handshake)")
	fs.StringVar(&opts.roomExchangeRoomID, "room-exchange-room-id", "", "WB Stream room ID delivered through CLIENT_HELLO_TYPE_ROOM_EXCHANGE")
	fs.StringVar(&opts.roomExchangeDisplayName, "room-exchange-display-name", "", "display name delivered alongside the room id in the room-exchange handshake")
	fs.BoolVar(&opts.roomExchangeE2EEnabled, "room-exchange-e2e-enabled", false, "advertise that wb-stream traffic will be E2E-encrypted")
	fs.StringVar(&opts.roomExchangeE2ESecret, "room-exchange-e2e-secret", "", "optional base64-encoded E2E secret to share with the server")
	fs.Usage = func() {
		cliutil.Fprintf(fs.Output(), "Usage:\n  %s -peer <host:port> -vk-link <link> [flags]\n  %s -peer <host:port> -yandex-link <link> [flags]\n\n", program, program)
		cliutil.Fprintln(fs.Output(), "Examples:")
		cliutil.Fprintf(fs.Output(), "  %s -listen 127.0.0.1:9000 -peer 203.0.113.10:56000 -vk-link https://vk.com/call/join/...\n", program)
		cliutil.Fprintf(fs.Output(), "  %s -udp -turn 5.255.211.241 -peer 203.0.113.10:56000 -yandex-link https://telemost.yandex.ru/j/... -listen 127.0.0.1:9000\n\n", program)
		cliutil.Fprintln(fs.Output(), "Flags:")
		fs.PrintDefaults()
	}

	return fs, opts
}

func parseClientOptions(args []string, program string, stdout, stderr io.Writer) (clientOptions, int) {
	return cliutil.Parse(args, program, stdout, stderr, newClientFlagSet, func(opts *clientOptions) error {
		opts.vklink = strings.TrimSpace(opts.vklink)
		opts.vklinkSecondary = strings.TrimSpace(opts.vklinkSecondary)
		opts.yalink = strings.TrimSpace(opts.yalink)
		opts.peerAddr = strings.TrimSpace(opts.peerAddr)
		opts.captchaSolver = strings.ToLower(strings.TrimSpace(opts.captchaSolver))
		if opts.captchaSolver != "v1" && opts.captchaSolver != "v2" {
			opts.captchaSolver = "v2"
		}
		opts.tcpFlavor = strings.ToLower(strings.TrimSpace(opts.tcpFlavor))
		if opts.tcpFlavor != "direct" && opts.tcpFlavor != "legacy" {
			opts.tcpFlavor = "auto"
		}
		if opts.credsGroupSize < 1 {
			opts.credsGroupSize = 1
		}

		opts.wbStreamRoomID = strings.TrimSpace(opts.wbStreamRoomID)
		opts.wbStreamDisplayName = strings.TrimSpace(opts.wbStreamDisplayName)
		opts.wbStreamE2ESecret = strings.TrimSpace(opts.wbStreamE2ESecret)
		opts.roomExchangeRoomID = strings.TrimSpace(opts.roomExchangeRoomID)
		opts.roomExchangeDisplayName = strings.TrimSpace(opts.roomExchangeDisplayName)
		opts.roomExchangeE2ESecret = strings.TrimSpace(opts.roomExchangeE2ESecret)

		if opts.roomExchangeMode {
			if opts.peerAddr == "" {
				return fmt.Errorf("-peer is required for -room-exchange-mode")
			}
			if opts.roomExchangeRoomID == "" {
				return fmt.Errorf("-room-exchange-room-id is required for -room-exchange-mode")
			}
			return nil
		}
		if opts.wbStreamRoomID != "" {
			return nil
		}

		if opts.peerAddr == "" {
			return fmt.Errorf("-peer is required")
		}
		linkCount := 0
		for _, link := range []string{opts.vklink, opts.yalink} {
			if link != "" {
				linkCount++
			}
		}
		if linkCount != 1 {
			return fmt.Errorf("exactly one of -vk-link or -yandex-link is required")
		}
		return nil
	})
}
