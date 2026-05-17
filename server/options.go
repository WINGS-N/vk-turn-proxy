package main

import (
	"flag"
	"io"
	"strings"

	"github.com/cacggghp/vk-turn-proxy/internal/cliutil"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

type serverOptions struct {
	listen      string
	connect     string
	udpConnect  string
	tcpConnect  string
	vlessMode   bool
	sessionMode string
	tuiMode     string

	wbStreamRoomID      string
	wbStreamDisplayName string
	wbStreamE2ESecret   string

	wrapMode   string // off|on
	wrapCipher string // aes-ctr|chacha20-xor
	wrapKeyHex string // 64-char hex (32 bytes)
}

func newServerFlagSet(program string, output io.Writer) (*flag.FlagSet, *serverOptions) {
	fs := flag.NewFlagSet(program, flag.ContinueOnError)
	fs.SetOutput(output)

	opts := &serverOptions{}
	fs.StringVar(&opts.listen, "listen", "0.0.0.0:56000", "listen on ip:port")
	fs.StringVar(&opts.connect, "connect", "", "deprecated alias for -udp-connect (or -tcp-connect when -vless is set)")
	fs.StringVar(&opts.udpConnect, "udp-connect", "", "UDP backend for datagram transport")
	fs.StringVar(&opts.tcpConnect, "tcp-connect", "", "TCP backend for tcp transport")
	fs.BoolVar(&opts.vlessMode, "vless", false, "deprecated alias: treat legacy -connect as -tcp-connect")
	fs.StringVar(&opts.sessionMode, "session-mode", string(sessionproto.ModeAuto), "TURN session mode: mainline|mu|auto")
	fs.StringVar(&opts.tuiMode, "tui", "auto", "server TUI mode: auto|on|off")
	fs.StringVar(&opts.wbStreamRoomID, "wb-stream-room-id", "", "join the given LiveKit room and forward DataPacket frames instead of the TURN data plane")
	fs.StringVar(&opts.wbStreamDisplayName, "wb-stream-display-name", "", "display name the server uses when joining a LiveKit room (empty = random VK-style name per room)")
	fs.StringVar(&opts.wbStreamE2ESecret, "wb-stream-e2e-secret", "", "optional base64-encoded 32-byte AES-256 key for E2E over DataPacket")
	fs.StringVar(&opts.wrapMode, "wrap-mode", "off", "WRAP per-packet obfuscation mode: off|on")
	fs.StringVar(&opts.wrapCipher, "wrap-cipher", "aes-ctr", "WRAP cipher: aes-ctr|chacha20-xor")
	fs.StringVar(&opts.wrapKeyHex, "wrap-key", "", "WRAP key (64-char hex, 32 bytes); required when -wrap-mode=on")
	fs.Usage = func() {
		cliutil.Fprintf(fs.Output(), "Usage:\n  %s -connect <ip:port> [flags]\n  %s -udp-connect <ip:port> [flags]\n  %s -wb-stream-room-id <id> -udp-connect <ip:port> [flags]\n\n", program, program, program)
		cliutil.Fprintln(fs.Output(), "Examples:")
		cliutil.Fprintf(fs.Output(), "  %s -connect 127.0.0.1:51820\n", program)
		cliutil.Fprintf(fs.Output(), "  %s -listen 0.0.0.0:56000 -tcp-connect 127.0.0.1:443 -vless\n", program)
		cliutil.Fprintf(fs.Output(), "  %s -wb-stream-room-id ABC123 -udp-connect 127.0.0.1:51820\n\n", program)
		cliutil.Fprintln(fs.Output(), "Flags:")
		fs.PrintDefaults()
	}

	return fs, opts
}

func parseServerOptions(args []string, program string, stdout, stderr io.Writer) (serverOptions, int) {
	return cliutil.Parse(args, program, stdout, stderr, newServerFlagSet, func(opts *serverOptions) error {
		opts.connect = strings.TrimSpace(opts.connect)
		opts.udpConnect = strings.TrimSpace(opts.udpConnect)
		opts.tcpConnect = strings.TrimSpace(opts.tcpConnect)
		opts.wbStreamRoomID = strings.TrimSpace(opts.wbStreamRoomID)
		opts.wbStreamDisplayName = strings.TrimSpace(opts.wbStreamDisplayName)
		opts.wbStreamE2ESecret = strings.TrimSpace(opts.wbStreamE2ESecret)
		opts.wrapMode = strings.ToLower(strings.TrimSpace(opts.wrapMode))
		switch opts.wrapMode {
		case "on", "off":
		default:
			opts.wrapMode = "off"
		}
		opts.wrapCipher = strings.ToLower(strings.TrimSpace(opts.wrapCipher))
		switch opts.wrapCipher {
		case "aes-ctr", "chacha20-xor":
		default:
			opts.wrapCipher = "aes-ctr"
		}
		opts.wrapKeyHex = strings.TrimSpace(opts.wrapKeyHex)

		if opts.wbStreamRoomID != "" {
			if opts.udpConnect == "" && opts.connect == "" {
				return errMissingBackendForWbStream
			}
			return nil
		}
		_, err := resolveServerBackends(opts.connect, opts.udpConnect, opts.tcpConnect, opts.vlessMode)
		return err
	})
}

var errMissingBackendForWbStream = wbStreamError("-wb-stream-room-id requires -udp-connect (or -connect)")

type wbStreamError string

func (e wbStreamError) Error() string { return string(e) }
