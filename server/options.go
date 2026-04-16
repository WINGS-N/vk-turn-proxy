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
	fs.Usage = func() {
		cliutil.Fprintf(fs.Output(), "Usage:\n  %s -connect <ip:port> [flags]\n  %s -udp-connect <ip:port> [flags]\n\n", program, program)
		cliutil.Fprintln(fs.Output(), "Examples:")
		cliutil.Fprintf(fs.Output(), "  %s -connect 127.0.0.1:51820\n", program)
		cliutil.Fprintf(fs.Output(), "  %s -listen 0.0.0.0:56000 -tcp-connect 127.0.0.1:443 -vless\n\n", program)
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

		_, err := resolveServerBackends(opts.connect, opts.udpConnect, opts.tcpConnect, opts.vlessMode)
		return err
	})
}
