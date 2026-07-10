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

	wrapMode             string // off|on — honor client-proposed WRAP at all
	wrapCipher           string // any|srtp-aes-gcm|srtp-chacha20-poly1305 — accepted cipher(s)
	wrapKeyHex           string // optional preset key; takes precedence over client proposal
	wrapAcceptClientKeys bool   // default true; in-band key transmission opt-out

	grpcListen   string // ip:port for the panel-facing Relay management API (empty = disabled)
	grpcToken    string // bearer token the panel must present on the Relay API
	grpcCert     string // TLS certificate file for the Relay API (empty = plaintext)
	grpcKey      string // TLS private key file for the Relay API
	wgTunnelCIDR string // tunnel address pool, e.g. 10.66.66.0/24
	wgInterface  string // tunnel interface name reported by the Relay API
	wgApply      bool   // program peers onto a live kernel WireGuard interface (needs root)
	wgListenPort int    // WireGuard interface listen port
	wgAddress    string // WireGuard interface address (CIDR), e.g. 10.66.66.1/24
	wgKeyFile    string // path to persist the WG server key (empty = ephemeral)

	panelGRPC     string // panel Provisioning gRPC endpoint for DTLS PROVISION (empty = disabled)
	panelCAPin    string // panel CA SPKI pin (sha256/<base64>) for a self-signed panel; empty uses system trust
	panelInsecure bool   // dial the panel over plaintext h2c (trusted local network only)
	nodeID        string // this node's id as registered in the panel
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
	fs.StringVar(&opts.wrapMode, "wrap-mode", "on", "Accept client-proposed WRAP SRTP-mimicry: off|on")
	fs.StringVar(&opts.wrapCipher, "wrap-cipher", "any", "Accepted WRAP cipher(s): any|srtp-aes-gcm|srtp-chacha20-poly1305")
	fs.StringVar(&opts.wrapKeyHex, "wrap-key", "", "Optional fixed WRAP key (64-char hex, 32 bytes); takes precedence over client proposal when set")
	fs.BoolVar(&opts.wrapAcceptClientKeys, "wrap-accept-client-keys", true, "Accept wrap_key_proposal from client SessionHello when no -wrap-key is preset (default true)")
	fs.StringVar(&opts.grpcListen, "grpc-listen", "", "ip:port for the panel-facing Relay management API (empty disables it)")
	fs.StringVar(&opts.grpcToken, "grpc-token", "", "bearer token the panel must present on the Relay management API")
	fs.StringVar(&opts.grpcCert, "grpc-cert", "", "TLS certificate file for the Relay management API (empty serves plaintext)")
	fs.StringVar(&opts.grpcKey, "grpc-key", "", "TLS private key file for the Relay management API")
	fs.StringVar(&opts.wgTunnelCIDR, "wg-tunnel-cidr", "10.66.66.0/24", "tunnel address pool for managed peers")
	fs.StringVar(&opts.wgInterface, "wg-interface", "wg-wingsv", "tunnel interface name reported by the Relay API")
	fs.BoolVar(&opts.wgApply, "wg-apply", false, "program peers onto a live kernel WireGuard interface (requires root)")
	fs.IntVar(&opts.wgListenPort, "wg-listen-port", 51820, "WireGuard interface listen port")
	fs.StringVar(&opts.wgAddress, "wg-address", "10.66.66.1/24", "WireGuard interface address (CIDR)")
	fs.StringVar(&opts.wgKeyFile, "wg-key-file", "", "path to persist the WireGuard server key so its public key is stable across restarts (empty = regenerated each start)")
	fs.StringVar(&opts.panelGRPC, "panel-grpc", "", "panel Provisioning gRPC endpoint enabling the DTLS PROVISION path")
	fs.StringVar(&opts.panelCAPin, "panel-ca-pin", "", "panel CA SPKI pin (sha256/<base64>) for a self-signed panel; empty verifies the panel via system trust")
	fs.BoolVar(&opts.panelInsecure, "panel-insecure", false, "dial the panel over plaintext h2c instead of TLS (trusted local network only)")
	fs.StringVar(&opts.nodeID, "node-id", "", "this node's id as registered in the panel")
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
	args = mergeConfigFile(args)
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
		case "any", "srtp-aes-gcm", "srtp-chacha20-poly1305":
		default:
			opts.wrapCipher = "any"
		}
		opts.wrapKeyHex = strings.TrimSpace(opts.wrapKeyHex)

		// One node credential wires both directions: grpc-token authenticates the
		// panel's inbound management calls (AES-GCM transport) and doubles as the
		// bearer on the node's outbound provisioning calls, which the panel verifies
		// against the same value. There is no separate panel-token.
		opts.grpcToken = strings.TrimSpace(opts.grpcToken)

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
