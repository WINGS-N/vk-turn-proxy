package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// configFilePath is where the server looks for its optional config file. Override
// with the WINGS_VKTP_CONFIG env var.
const configFilePath = "/etc/wings/vktp/config.toml"

// mergeConfigFile folds an optional on-disk config file under the command-line
// flags: file values seed each flag, then any flag passed on the command line
// overrides it (flag parsing keeps the last occurrence). Precedence is therefore
// flags > file > built-in default. The file is a flat KEY = value TOML subset
// whose KEY names are the flag names (e.g. panel-grpc, node-id, listen); nested
// tables and arrays are not supported.
func mergeConfigFile(args []string) []string {
	vals := loadConfigFile()
	if len(vals) == 0 {
		return args
	}
	// A throwaway flag set just to enumerate valid flag names, so a typo in the
	// file is ignored rather than crashing the parse with an unknown flag.
	fs, _ := newServerFlagSet("config-probe", io.Discard)
	var pre []string
	fs.VisitAll(func(f *flag.Flag) {
		if v, ok := vals[f.Name]; ok {
			pre = append(pre, "-"+f.Name+"="+v)
		}
	})
	if len(pre) == 0 {
		return args
	}
	return append(pre, args...)
}

// migrateFlagsToConfig writes the effective startup flags to the config file on
// first run so an operator can later drop the flags from the unit and rely on the
// file. It never overwrites an existing file (that file is authoritative), and it
// logs the one-time migration. Failures are logged and ignored - a read-only
// filesystem must not stop the relay from starting.
func migrateFlagsToConfig(lines []string) {
	path := strings.TrimSpace(os.Getenv("WINGS_VKTP_CONFIG"))
	if path == "" {
		path = configFilePath
	}
	if _, err := os.Stat(path); err == nil {
		return // already present; the file wins, nothing to migrate
	} else if !os.IsNotExist(err) {
		return
	}
	if len(lines) == 0 {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("config: cannot create %s: %v", filepath.Dir(path), err)
		return
	}
	body := "# Auto-generated from startup flags on first run. Edit freely; these\n" +
		"# values are used when the matching command-line flags are absent.\n" +
		strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		log.Printf("config: cannot write %s: %v", path, err)
		return
	}
	log.Printf("config: migrated startup flags to %s (you can drop them from the unit and edit the file)", path)
}

// serverOptionsToConfigLines renders the meaningful startup options as config
// file lines (flag-name keys), skipping empty/false values so the generated file
// captures only what the operator actually configured.
// serverOptionsToConfigLines renders every server option as a config line. An
// option carrying a meaningful (non-default) value is written active; one left at
// its default is written COMMENTED with that default, so the generated file is a
// complete, self-documenting template an operator can uncomment and edit. loadConfigFile
// ignores the commented lines, so they never affect the running config.
func serverOptionsToConfigLines(o serverOptions) []string {
	str := func(key, value, def string) string {
		value = strings.TrimSpace(value)
		if value != "" && value != def {
			return fmt.Sprintf("%s = %q", key, value)
		}
		return fmt.Sprintf("# %s = %q", key, def)
	}
	boolean := func(key string, value, def bool) string {
		if value != def {
			return fmt.Sprintf("%s = %t", key, value)
		}
		return fmt.Sprintf("# %s = %t", key, def)
	}
	integer := func(key string, value, def int) string {
		if value != 0 && value != def {
			return fmt.Sprintf("%s = %d", key, value)
		}
		return fmt.Sprintf("# %s = %d", key, def)
	}
	return []string{
		str("listen", o.listen, "0.0.0.0:56000"),
		str("udp-connect", o.udpConnect, ""),
		str("tcp-connect", o.tcpConnect, ""),
		str("session-mode", o.sessionMode, "auto"),
		str("tui", o.tuiMode, "auto"),
		str("wrap-mode", o.wrapMode, "on"),
		str("wrap-cipher", o.wrapCipher, "any"),
		str("wrap-key", o.wrapKeyHex, ""),
		boolean("wrap-accept-client-keys", o.wrapAcceptClientKeys, true),
		str("grpc-listen", o.grpcListen, ""),
		str("grpc-token", o.grpcToken, ""),
		str("grpc-cert", o.grpcCert, ""),
		str("grpc-key", o.grpcKey, ""),
		str("panel-grpc", o.panelGRPC, ""),
		str("node-id", o.nodeID, ""),
		str("panel-ca-pin", o.panelCAPin, ""),
		boolean("panel-insecure", o.panelInsecure, false),
		str("wg-interface", o.wgInterface, "wg-wingsv"),
		str("wg-tunnel-cidr", o.wgTunnelCIDR, "10.66.66.0/24"),
		str("wg-address", o.wgAddress, "10.66.66.1/24"),
		boolean("wg-apply", o.wgApply, false),
		integer("wg-listen-port", o.wgListenPort, 51820),
	}
}

func loadConfigFile() map[string]string {
	path := strings.TrimSpace(os.Getenv("WINGS_VKTP_CONFIG"))
	if path == "" {
		path = configFilePath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if key == "" {
			continue
		}
		out[key] = unquoteConfigValue(strings.TrimSpace(line[eq+1:]))
	}
	return out
}

// unquoteConfigValue strips surrounding quotes from a quoted value, or drops a
// trailing inline comment from a bare value.
func unquoteConfigValue(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
			return v[1 : 1+end]
		}
	}
	if hash := strings.IndexByte(v, '#'); hash >= 0 {
		v = v[:hash]
	}
	return strings.TrimSpace(v)
}
