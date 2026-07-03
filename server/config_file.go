package main

import (
	"flag"
	"io"
	"os"
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
