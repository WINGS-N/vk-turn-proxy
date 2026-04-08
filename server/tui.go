package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

const (
	tuiLogBufferSize = 120
	tuiRenderEvery   = time.Second
)

type streamMetrics struct {
	Key             string
	Protocol        string
	Version         uint32
	Remote          string
	ClientIP        string
	SessionID       string
	StreamID        byte
	RxBytes         uint64
	TxBytes         uint64
	LastRx          uint64
	LastTx          uint64
	RxRate          uint64
	TxRate          uint64
	StartedAt       time.Time
	LastHeartbeatAt time.Time
}

type clientMetrics struct {
	ClientIP      string
	ActiveStreams int
	RxBytes       uint64
	TxBytes       uint64
	LastRx        uint64
	LastTx        uint64
	RxRate        uint64
	TxRate        uint64
}

type serverTUI struct {
	listen      string
	connectAddr string
	mode        string
	enabled     bool
	colors      bool
	startedAt   time.Time

	streamSeq atomic.Uint64
	stopCh    chan struct{}
	doneCh    chan struct{}

	mu            sync.Mutex
	streams       map[string]*streamMetrics
	clients       map[string]*clientMetrics
	sessions      map[string]struct{}
	serverRxBytes uint64
	serverTxBytes uint64
	lastServerRx  uint64
	lastServerTx  uint64
	serverRxRate  uint64
	serverTxRate  uint64
	logLines      []string
}

func newServerTUI(listen, connectAddr, mode, renderMode string) *serverTUI {
	tui := &serverTUI{
		listen:      listen,
		connectAddr: connectAddr,
		mode:        mode,
		enabled:     shouldEnableTUI(renderMode),
		colors:      shouldEnableTUI(renderMode),
		startedAt:   time.Now(),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		streams:     make(map[string]*streamMetrics),
		clients:     make(map[string]*clientMetrics),
		sessions:    make(map[string]struct{}),
		logLines:    make([]string, 0, tuiLogBufferSize),
	}
	if tui.enabled {
		go tui.renderLoop()
	}
	return tui
}

func shouldEnableTUI(renderMode string) bool {
	switch strings.ToLower(strings.TrimSpace(renderMode)) {
	case "on", "true", "1":
		return isInteractiveTerminal()
	case "off", "false", "0":
		return false
	default:
		return isInteractiveTerminal()
	}
}

func isInteractiveTerminal() bool {
	term := strings.TrimSpace(os.Getenv("TERM"))
	if term == "" || strings.EqualFold(term, "dumb") {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func (t *serverTUI) Close() {
	if t == nil {
		return
	}
	if t.enabled {
		close(t.stopCh)
		<-t.doneCh
		return
	}
	close(t.doneCh)
}

func (t *serverTUI) logWriter() io.Writer {
	return &serverLogWriter{tui: t, fallback: os.Stdout}
}

func (t *serverTUI) nextStreamKey(prefix string) string {
	id := t.streamSeq.Add(1)
	return fmt.Sprintf("%s-%d", prefix, id)
}

func (t *serverTUI) registerSession(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	t.sessions[id] = struct{}{}
	t.mu.Unlock()
}

func (t *serverTUI) unregisterSession(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	delete(t.sessions, id)
	t.mu.Unlock()
}

func (t *serverTUI) registerStream(key, protocol string, version uint32, remote, clientIP, sessionID string, streamID byte) {
	if t == nil || key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.streams[key] = &streamMetrics{
		Key:       key,
		Protocol:  protocol,
		Version:   version,
		Remote:    remote,
		ClientIP:  clientIP,
		SessionID: sessionID,
		StreamID:  streamID,
		StartedAt: time.Now(),
	}
	client := t.clients[clientIP]
	if client == nil {
		client = &clientMetrics{ClientIP: clientIP}
		t.clients[clientIP] = client
	}
	client.ActiveStreams++
}

func (t *serverTUI) unregisterStream(key string) {
	if t == nil || key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	stream := t.streams[key]
	if stream == nil {
		return
	}
	client := t.clients[stream.ClientIP]
	if client != nil {
		client.ActiveStreams--
		if client.ActiveStreams <= 0 && client.RxBytes == 0 && client.TxBytes == 0 {
			delete(t.clients, stream.ClientIP)
		}
	}
	delete(t.streams, key)
}

func (t *serverTUI) addStreamRx(key, clientIP string, n int) {
	t.addStreamBytes(key, clientIP, n, true)
}

func (t *serverTUI) addStreamTx(key, clientIP string, n int) {
	t.addStreamBytes(key, clientIP, n, false)
}

func (t *serverTUI) noteStreamHeartbeat(key string) {
	if t == nil || key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if stream := t.streams[key]; stream != nil {
		stream.LastHeartbeatAt = time.Now()
	}
}

func (t *serverTUI) addStreamBytes(key, clientIP string, n int, rx bool) {
	if t == nil || n <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	bytesN := uint64(n)
	if rx {
		t.serverRxBytes += bytesN
	} else {
		t.serverTxBytes += bytesN
	}
	if key != "" {
		if stream := t.streams[key]; stream != nil {
			if rx {
				stream.RxBytes += bytesN
			} else {
				stream.TxBytes += bytesN
			}
			if clientIP == "" {
				clientIP = stream.ClientIP
			}
		}
	}
	if clientIP != "" {
		client := t.clients[clientIP]
		if client == nil {
			client = &clientMetrics{ClientIP: clientIP}
			t.clients[clientIP] = client
		}
		if rx {
			client.RxBytes += bytesN
		} else {
			client.TxBytes += bytesN
		}
	}
}

func (t *serverTUI) appendLog(line string) {
	if t == nil {
		return
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.logLines) >= tuiLogBufferSize {
		copy(t.logLines, t.logLines[1:])
		t.logLines[len(t.logLines)-1] = line
		return
	}
	t.logLines = append(t.logLines, line)
}

func (t *serverTUI) renderLoop() {
	ticker := time.NewTicker(tuiRenderEvery)
	defer ticker.Stop()
	_, _ = fmt.Fprint(os.Stdout, "\x1b[?25l")
	defer func() {
		_, _ = fmt.Fprint(os.Stdout, "\x1b[?25h\x1b[0m\n")
		close(t.doneCh)
	}()
	for {
		t.render()
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
		}
	}
}

func (t *serverTUI) render() {
	t.mu.Lock()
	t.updateRatesLocked()
	streams := make([]streamMetrics, 0, len(t.streams))
	for _, stream := range t.streams {
		streams = append(streams, *stream)
	}
	clients := make([]clientMetrics, 0, len(t.clients))
	for _, client := range t.clients {
		clients = append(clients, *client)
	}
	logs := append([]string(nil), t.logLines...)
	serverRx := t.serverRxBytes
	serverTx := t.serverTxBytes
	serverRxRate := t.serverRxRate
	serverTxRate := t.serverTxRate
	sessionCount := len(t.sessions)
	t.mu.Unlock()

	sort.Slice(streams, func(i, j int) bool {
		if streams[i].RxRate+streams[i].TxRate == streams[j].RxRate+streams[j].TxRate {
			return streams[i].StartedAt.After(streams[j].StartedAt)
		}
		return streams[i].RxRate+streams[i].TxRate > streams[j].RxRate+streams[j].TxRate
	})
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].RxRate+clients[i].TxRate == clients[j].RxRate+clients[j].TxRate {
			return clients[i].ClientIP < clients[j].ClientIP
		}
		return clients[i].RxRate+clients[i].TxRate > clients[j].RxRate+clients[j].TxRate
	})

	var b strings.Builder
	b.WriteString("\x1b[2J\x1b[H")
	b.WriteString(t.colorize("WINGS V VK TURN PROXY SERVER", ansiCyanBold))
	b.WriteString("  ")
	b.WriteString(t.colorize(fmt.Sprintf("%s -> %s", t.listen, t.connectAddr), ansiWhite))
	b.WriteString("  ")
	b.WriteString(t.colorize(fmt.Sprintf("mode=%s", t.mode), ansiBlue))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf(
		"uptime=%s  sessions=%d  active_streams=%d  clients=%d  rx=%s/s  tx=%s/s  total_rx=%s  total_tx=%s\n\n",
		time.Since(t.startedAt).Round(time.Second),
		sessionCount,
		len(streams),
		len(clients),
		humanRate(serverRxRate),
		humanRate(serverTxRate),
		humanBytes(serverRx),
		humanBytes(serverTx),
	))

	b.WriteString(t.colorize("STREAMS", ansiGreenBold))
	b.WriteString("\n")
	b.WriteString(renderStreamsTable(t, streams))
	b.WriteString("\n")

	b.WriteString(t.colorize("CLIENTS", ansiYellowBold))
	b.WriteString("\n")
	b.WriteString(renderClientsTable(t, clients))
	b.WriteString("\n")

	b.WriteString(t.colorize("LOGS", ansiMagentaBold))
	b.WriteString("\n")
	start := 0
	if len(logs) > 14 {
		start = len(logs) - 14
	}
	for _, line := range logs[start:] {
		b.WriteString(colorizeLogLine(t, line))
		b.WriteString("\n")
	}

	_, _ = fmt.Fprint(os.Stdout, b.String())
}

func (t *serverTUI) updateRatesLocked() {
	t.serverRxRate = t.serverRxBytes - t.lastServerRx
	t.serverTxRate = t.serverTxBytes - t.lastServerTx
	t.lastServerRx = t.serverRxBytes
	t.lastServerTx = t.serverTxBytes
	for _, stream := range t.streams {
		stream.RxRate = stream.RxBytes - stream.LastRx
		stream.TxRate = stream.TxBytes - stream.LastTx
		stream.LastRx = stream.RxBytes
		stream.LastTx = stream.TxBytes
	}
	for _, client := range t.clients {
		client.RxRate = client.RxBytes - client.LastRx
		client.TxRate = client.TxBytes - client.LastTx
		client.LastRx = client.RxBytes
		client.LastTx = client.TxBytes
	}
}

type serverLogWriter struct {
	tui      *serverTUI
	fallback io.Writer
}

func (w *serverLogWriter) Write(p []byte) (int, error) {
	if w.tui == nil {
		return w.fallback.Write(p)
	}
	lines := bytes.Split(p, []byte{'\n'})
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		w.tui.appendLog(string(line))
	}
	if !w.tui.enabled {
		return w.fallback.Write(p)
	}
	return len(p), nil
}

func clientIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

func humanBytes(v uint64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%dB", v)
	}
	div, exp := uint64(unit), 0
	for n := v / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(v)/float64(div), "KMGTPE"[exp])
}

func humanRate(v uint64) string {
	return humanBytes(v)
}

func trimMiddle(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	left := (max - 1) / 2
	right := max - left - 1
	return s[:left] + "…" + s[len(s)-right:]
}

func renderStreamsTable(t *serverTUI, streams []streamMetrics) string {
	if len(streams) == 0 {
		return t.colorize("no active streams\n", ansiDim)
	}
	tw := table.NewWriter()
	tw.SetStyle(table.StyleRounded)
	tw.AppendHeader(table.Row{"Protocol", "Remote", "Client", "Session", "SID", "HB", "RX/s", "TX/s", "RX Total", "TX Total"})
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, WidthMax: 14},
		{Number: 2, WidthMax: 22},
		{Number: 3, WidthMax: 15},
		{Number: 4, WidthMax: 20},
		{Number: 5, WidthMax: 4, Align: text.AlignRight},
		{Number: 6, WidthMax: 6, Align: text.AlignRight},
		{Number: 7, WidthMax: 10, Align: text.AlignRight},
		{Number: 8, WidthMax: 10, Align: text.AlignRight},
		{Number: 9, WidthMax: 11, Align: text.AlignRight},
		{Number: 10, WidthMax: 11, Align: text.AlignRight},
	})
	for i, stream := range streams {
		if i >= 10 {
			break
		}
		tw.AppendRow(table.Row{
			trimMiddle(stream.Protocol, 14),
			trimMiddle(stream.Remote, 22),
			trimMiddle(stream.ClientIP, 15),
			trimMiddle(stream.SessionID, 20),
			stream.StreamID,
			heartbeatAgeLabel(stream.LastHeartbeatAt),
			colorRate(t, stream.RxRate),
			colorRate(t, stream.TxRate),
			humanBytes(stream.RxBytes),
			humanBytes(stream.TxBytes),
		})
	}
	return tw.Render() + "\n"
}

func heartbeatAgeLabel(lastHeartbeatAt time.Time) string {
	if lastHeartbeatAt.IsZero() {
		return "—"
	}
	age := time.Since(lastHeartbeatAt).Round(time.Second)
	if age < time.Second {
		return "now"
	}
	return age.String()
}

func renderClientsTable(t *serverTUI, clients []clientMetrics) string {
	if len(clients) == 0 {
		return t.colorize("no active clients\n", ansiDim)
	}
	tw := table.NewWriter()
	tw.SetStyle(table.StyleRounded)
	tw.AppendHeader(table.Row{"Client", "Active", "RX/s", "TX/s", "RX Total", "TX Total"})
	tw.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, WidthMax: 18},
		{Number: 2, WidthMax: 6, Align: text.AlignRight},
		{Number: 3, WidthMax: 10, Align: text.AlignRight},
		{Number: 4, WidthMax: 10, Align: text.AlignRight},
		{Number: 5, WidthMax: 11, Align: text.AlignRight},
		{Number: 6, WidthMax: 11, Align: text.AlignRight},
	})
	for i, client := range clients {
		if i >= 10 {
			break
		}
		tw.AppendRow(table.Row{
			trimMiddle(client.ClientIP, 18),
			client.ActiveStreams,
			colorRate(t, client.RxRate),
			colorRate(t, client.TxRate),
			humanBytes(client.RxBytes),
			humanBytes(client.TxBytes),
		})
	}
	return tw.Render() + "\n"
}

const (
	ansiReset       = "\x1b[0m"
	ansiDim         = "\x1b[2m"
	ansiWhite       = "\x1b[97m"
	ansiBlue        = "\x1b[94m"
	ansiCyanBold    = "\x1b[1;96m"
	ansiGreenBold   = "\x1b[1;92m"
	ansiYellowBold  = "\x1b[1;93m"
	ansiMagentaBold = "\x1b[1;95m"
	ansiRed         = "\x1b[91m"
	ansiYellow      = "\x1b[93m"
	ansiGreen       = "\x1b[92m"
)

func (t *serverTUI) colorize(s, code string) string {
	if t == nil || !t.colors {
		return s
	}
	return code + s + ansiReset
}

func colorizeLogLine(t *serverTUI, line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "error"), strings.Contains(lower, "failed"), strings.Contains(lower, "reject"):
		return t.colorize(line, ansiRed)
	case strings.Contains(lower, "listening"), strings.Contains(lower, "accepted"), strings.Contains(lower, "mux_supported=true"):
		return t.colorize(line, ansiGreen)
	case strings.Contains(lower, "probe"), strings.Contains(lower, "mainline"), strings.Contains(lower, "mux"):
		return t.colorize(line, ansiYellow)
	default:
		return line
	}
}

func colorRate(t *serverTUI, v uint64) string {
	value := humanRate(v)
	if t == nil || !t.colors {
		return value
	}
	switch {
	case v >= 5*1024*1024:
		return text.Colors{text.FgHiGreen}.Sprint(value)
	case v >= 512*1024:
		return text.Colors{text.FgHiYellow}.Sprint(value)
	default:
		return text.Colors{text.FgHiBlue}.Sprint(value)
	}
}
