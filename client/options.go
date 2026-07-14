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
	host               string
	port               string
	listen             string
	vklink             string
	vklinkSecondary    string
	yalink             string
	peerAddr           string
	n                  int
	transport          string
	vlessMode          bool
	udp                bool
	direct             bool
	manualCaptcha      bool
	captchaSolver      string
	vkAuth             string
	vkSessionFile      string
	vkCookieFilePoll   bool
	appGRPCSocket      string
	appGRPCToken       string
	appGRPCPeerUID     int
	appGRPCPeerContext string
	tcpFlavor          string
	credsGroupSize     int
	protectSock        string
	protoFingerprint   string
	browserFP          string
	sessionMode        string
	sessionID          string

	wbStreamRoomID             string
	wbStreamRoomIDs            string
	wbStreamDisplayName        string
	wbStreamE2ESecret          string
	wbStreamMultiIdentityCount int

	dnsMode string
	userDns string

	roomExchangeMode        bool
	roomExchangeRoomID      string
	roomExchangeRoomIDs     string
	roomExchangeDisplayName string
	roomExchangeE2EEnabled  bool
	roomExchangeE2ESecret   string

	wrapMode    string // off|preferred|required
	wrapCipher  string // srtp-aes-gcm|srtp-chacha20-poly1305
	wrapKeyHex  string // 64-char hex (32 bytes); empty + mode!=off generates fresh key
	wrapSendKey bool   // in-band key delivery (default true)
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
	fs.StringVar(&opts.captchaSolver, "captcha-solver", "v2", "captcha handling: bypass|v2|v1 (bypass = VK Calls captcha-free path via api.vk.me, legacy solver as fallback; v2 = improved solver; v1 = legacy solver)")
	fs.StringVar(&opts.vkAuth, "vk-auth", "anonymous", "VK auth mode: anonymous|account (account = relay emits PROXY_EVENT vk_account_auth_required with the VK join URL; the host app opens it in a WebView, signs in, intercepts the VK turn_server creds, and sends them back on a vk_account_creds stdin line; vk_account_auth_complete/_failed signal the outcome)")
	fs.StringVar(&opts.tcpFlavor, "tcp-flavor", "auto", "TCP transport flavor override: auto|direct|legacy (auto = negotiate; direct = smux over DTLS; legacy = KCP+smux)")
	fs.IntVar(&opts.credsGroupSize, "creds-group-size", 12, "workers per TURN identity (smaller = more identities, less per-identity rate limit; larger = fewer auth calls)")
	fs.StringVar(&opts.protectSock, "protect-sock", "", "unix socket used for VpnService.protect fd bridge")
	fs.StringVar(&opts.vkSessionFile, "vk-session-file", "", "path to persist VK session cookies across relay restarts (account mode)")
	fs.BoolVar(&opts.vkCookieFilePoll, "vk-cookie-file-poll", false, "poll vk-session-file for live cookie updates written by the host app (root/no-stdin path where the vk_account_creds stdin line cannot be delivered)")
	fs.StringVar(&opts.appGRPCSocket, "app-grpc-socket", "", "serve the local AppControl gRPC IPC on this unix socket path (app-private dir); empty disables it")
	fs.StringVar(&opts.appGRPCToken, "app-grpc-token", "", "shared bearer token the host app must present on the AppControl IPC")
	fs.IntVar(&opts.appGRPCPeerUID, "app-grpc-peer-uid", -1, "uid the AppControl socket must accept and be owned by; -1 uses this process's own uid (root/kernel-WG path passes the host app uid so the app can connect to the root-launched relay)")
	fs.StringVar(&opts.appGRPCPeerContext, "app-grpc-peer-context", "", "SELinux file context to relabel the AppControl socket to (root/kernel-WG path passes the host app's app_data_file context so untrusted_app can connect); empty leaves the socket label unchanged")
	fs.StringVar(&opts.protoFingerprint, "proto-fp", "", "deprecated; ignored")
	fs.StringVar(&opts.browserFP, "browser-fp", "safari", "browser fingerprint family for HTTP+TLS impersonation: auto|chrome|edge|safari|firefox (default safari; auto = random per session)")
	fs.StringVar(&opts.sessionMode, "session-mode", string(sessionproto.ModeMainline), "TURN session mode: mainline|mu|auto")
	fs.StringVar(&opts.sessionID, "session-id", "", "override session ID (hex, 32 chars) for mu mode")
	fs.StringVar(&opts.wbStreamRoomID, "wb-stream-room-id", "", `LiveKit room ID; "any" creates a fresh one. When set, runs WB Stream tunnel mode.`)
	fs.StringVar(&opts.wbStreamRoomIDs, "wb-stream-room-ids", "", `comma-separated LiveKit room IDs ("any" entries create fresh rooms); takes precedence over -wb-stream-room-id, opens N rooms in parallel and round-robins outbound frames`)
	fs.StringVar(&opts.wbStreamDisplayName, "wb-stream-display-name", "", "display name for the LiveKit room when -wb-stream-room-id is set (empty = random VK-style name per session)")
	fs.StringVar(&opts.wbStreamE2ESecret, "wb-stream-e2e-secret", "", "optional base64-encoded 32-byte AES-256 key for E2E over DataPacket")
	fs.IntVar(&opts.wbStreamMultiIdentityCount, "wb-stream-multi-identity-count", 1, "number of LiveKit identities to join the same room with (1-16; round-robin send across identities for higher upload throughput)")
	fs.StringVar(&opts.dnsMode, "dns", "auto", "DNS resolution mode: auto|udp|doh (auto = probe UDP/53, sticky-fallback to DoH on total failure)")
	fs.StringVar(&opts.userDns, "user-dns", "", "comma/newline-separated user DNS resolvers prepended to the built-in list. Formats: https://host/dns-query (DoH), udp://ip[:port] or bare ip[:port] (plain UDP/53)")
	fs.BoolVar(&opts.roomExchangeMode, "room-exchange-mode", false, "send a single CLIENT_HELLO_TYPE_ROOM_EXCHANGE to -peer over DTLS and exit (used to deliver wb-stream room metadata via VK TURN handshake)")
	fs.StringVar(&opts.roomExchangeRoomID, "room-exchange-room-id", "", "WB Stream room ID delivered through CLIENT_HELLO_TYPE_ROOM_EXCHANGE")
	fs.StringVar(&opts.roomExchangeRoomIDs, "room-exchange-room-ids", "", "comma-separated WB Stream room IDs for multi-room exchange (takes precedence over -room-exchange-room-id)")
	fs.StringVar(&opts.roomExchangeDisplayName, "room-exchange-display-name", "", "display name delivered alongside the room id in the room-exchange handshake")
	fs.BoolVar(&opts.roomExchangeE2EEnabled, "room-exchange-e2e-enabled", false, "advertise that wb-stream traffic will be E2E-encrypted")
	fs.StringVar(&opts.roomExchangeE2ESecret, "room-exchange-e2e-secret", "", "optional base64-encoded E2E secret to share with the server")
	fs.StringVar(&opts.wrapMode, "wrap-mode", "off", "WRAP SRTP-mimicry mode: off|preferred|required")
	fs.StringVar(&opts.wrapCipher, "wrap-cipher", "srtp-aes-gcm", "WRAP AEAD: srtp-aes-gcm|srtp-chacha20-poly1305")
	fs.StringVar(&opts.wrapKeyHex, "wrap-key", "", "WRAP key (64-char hex, 32 bytes); empty + mode!=off generates a fresh key")
	fs.BoolVar(&opts.wrapSendKey, "wrap-send-key", true, "Send wrap_key_proposal in mu/v1 SessionHello (default true). Disable to require the server to use its own preset key.")
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
		if opts.captchaSolver != "v1" && opts.captchaSolver != "v2" && opts.captchaSolver != "bypass" {
			opts.captchaSolver = "v2"
		}
		opts.vkAuth = strings.ToLower(strings.TrimSpace(opts.vkAuth))
		if opts.vkAuth != "account" {
			opts.vkAuth = "anonymous"
		}
		opts.tcpFlavor = strings.ToLower(strings.TrimSpace(opts.tcpFlavor))
		if opts.tcpFlavor != "direct" && opts.tcpFlavor != "legacy" {
			opts.tcpFlavor = "auto"
		}
		if opts.credsGroupSize < 1 {
			opts.credsGroupSize = 1
		}
		opts.wrapMode = strings.ToLower(strings.TrimSpace(opts.wrapMode))
		switch opts.wrapMode {
		case "off", "preferred", "required":
		default:
			opts.wrapMode = "off"
		}
		opts.wrapCipher = strings.ToLower(strings.TrimSpace(opts.wrapCipher))
		switch opts.wrapCipher {
		case "srtp-aes-gcm", "srtp-chacha20-poly1305":
		default:
			opts.wrapCipher = "srtp-aes-gcm"
		}
		opts.wrapKeyHex = strings.TrimSpace(opts.wrapKeyHex)

		opts.wbStreamRoomID = strings.TrimSpace(opts.wbStreamRoomID)
		opts.wbStreamRoomIDs = strings.TrimSpace(opts.wbStreamRoomIDs)
		opts.wbStreamDisplayName = strings.TrimSpace(opts.wbStreamDisplayName)
		opts.wbStreamE2ESecret = strings.TrimSpace(opts.wbStreamE2ESecret)
		opts.dnsMode = strings.ToLower(strings.TrimSpace(opts.dnsMode))
		switch opts.dnsMode {
		case DNSModeUDP, DNSModeDoH, DNSModeAuto:
		default:
			opts.dnsMode = DNSModeAuto
		}
		opts.browserFP = strings.ToLower(strings.TrimSpace(opts.browserFP))
		switch opts.browserFP {
		case FamilyChrome, FamilyEdge, FamilySafari, FamilyFirefox, FamilyAuto:
		default:
			opts.browserFP = FamilyAuto
		}
		opts.roomExchangeRoomID = strings.TrimSpace(opts.roomExchangeRoomID)
		opts.roomExchangeRoomIDs = strings.TrimSpace(opts.roomExchangeRoomIDs)
		opts.roomExchangeDisplayName = strings.TrimSpace(opts.roomExchangeDisplayName)
		opts.roomExchangeE2ESecret = strings.TrimSpace(opts.roomExchangeE2ESecret)

		if opts.roomExchangeMode {
			if opts.peerAddr == "" {
				return fmt.Errorf("-peer is required for -room-exchange-mode")
			}
			if opts.roomExchangeRoomID == "" && opts.roomExchangeRoomIDs == "" {
				return fmt.Errorf("-room-exchange-room-id or -room-exchange-room-ids is required for -room-exchange-mode")
			}
			return nil
		}
		if opts.wbStreamRoomID != "" || opts.wbStreamRoomIDs != "" {
			return nil
		}

		// gRPC-config mode: the host app launches the relay with only the AppControl
		// socket and delivers -peer/-vk-link/... over the Configure RPC, so skip the
		// flag-required checks here (main() blocks for Configure before booting).
		if opts.appGRPCSocket != "" && opts.peerAddr == "" && opts.vklink == "" && opts.yalink == "" {
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
