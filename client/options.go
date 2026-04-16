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
	yalink                         string
	peerAddr                       string
	n                              int
	transport                      string
	vlessMode                      bool
	udp                            bool
	direct                         bool
	manualCaptcha                  bool
	protectSock                    string
	protoFingerprint               string
	sessionMode                    string
	sessionID                      string
	adaptivePoolMin                int
	adaptivePoolMax                int
	adaptivePoolStreamsPerIdentity int
}

func newClientFlagSet(program string, output io.Writer) (*flag.FlagSet, *clientOptions) {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	fs.SetOutput(output)

	opts := &clientOptions{}
	fs.StringVar(&opts.host, "turn", "", "override TURN server ip")
	fs.StringVar(&opts.port, "port", "", "override TURN port")
	fs.StringVar(&opts.listen, "listen", "127.0.0.1:9000", "listen on ip:port")
	fs.StringVar(&opts.vklink, "vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	fs.StringVar(&opts.yalink, "yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	fs.StringVar(&opts.peerAddr, "peer", "", "peer server address (host:port)")
	fs.IntVar(&opts.n, "n", 0, "connections to TURN (default 10 for VK, 1 for Yandex)")
	fs.StringVar(&opts.transport, "transport", "datagram", "transport mode: datagram|tcp")
	fs.BoolVar(&opts.vlessMode, "vless", false, "deprecated alias for -transport=tcp")
	fs.BoolVar(&opts.udp, "udp", false, "connect to TURN with UDP")
	fs.BoolVar(&opts.direct, "no-dtls", false, "connect without obfuscation. DO NOT USE")
	fs.BoolVar(&opts.manualCaptcha, "manual-captcha", false, "skip automatic captcha solving and use manual captcha flow immediately")
	fs.StringVar(&opts.protectSock, "protect-sock", "", "unix socket used for VpnService.protect fd bridge")
	fs.StringVar(&opts.protoFingerprint, "proto-fp", "", "deprecated; ignored")
	fs.StringVar(&opts.sessionMode, "session-mode", string(sessionproto.ModeMainline), "TURN session mode: mainline|mu|auto")
	fs.StringVar(&opts.sessionID, "session-id", "", "override session ID (hex, 32 chars) for mu mode")
	fs.IntVar(&opts.adaptivePoolMin, "adaptive-pool-min", 1, "minimum TURN identity pool size for mu/v1")
	fs.IntVar(&opts.adaptivePoolMax, "adaptive-pool-max", 0, "maximum TURN identity pool size for mu/v1 (default: stream count)")
	fs.IntVar(&opts.adaptivePoolStreamsPerIdentity, "adaptive-pool-streams-per-id", defaultAdaptivePoolStreamsPerIdentity, "target concurrent streams per TURN identity for mu/v1")
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
		opts.yalink = strings.TrimSpace(opts.yalink)
		opts.peerAddr = strings.TrimSpace(opts.peerAddr)

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
