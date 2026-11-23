// Package config reads the server's configuration file: flat `key = "value"`
// lines, a small subset of TOML read by its own parser so no TOML library is
// needed. Blank lines and lines starting with # are ignored, and a # after
// the closing quote starts a comment. Values are double-quoted and hold no
// backslash, double quote or control character. An unknown key, a key set
// twice or any other line is an error that names its line.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/donaldsteele/telltale/internal/store"
	"github.com/donaldsteele/telltale/internal/visit"
)

// DefaultDataDir is where the database, the TLS key and the package cache
// live when data_dir is not set.
const DefaultDataDir = "/var/lib/telltale"

// maxFileSize bounds the configuration file.
const maxFileSize = 64 << 10

// Config is the server's configuration.
type Config struct {
	// Listen is the address and port the web UI listens on (listen). It is
	// required and has no default: the UI is never put on every interface
	// by accident. A wildcard address (0.0.0.0, ::) also needs the
	// --allow-all-interfaces flag (AllInterfaces).
	Listen string
	// ServerAddr is the literal IP address machines see the server connect
	// from (server_addr); it goes into the enrolment snippets and every
	// scan. When it is not set it is Listen's address, which must then be
	// a literal, specific IP.
	ServerAddr string
	// DataDir holds the database, the TLS certificate and key and the
	// package cache (data_dir; DefaultDataDir when not set).
	DataDir string
	// BinDir holds the collector binaries copied to machines (bin_dir;
	// next to the running executable when not set).
	BinDir string
	// Unlock opens the store. KeyFile comes from key_file; without one the
	// command fills in Passphrase.
	Unlock store.Unlock
}

// keys lists every key the file may set.
var keys = map[string]bool{"listen": true, "server_addr": true, "data_dir": true, "bin_dir": true, "key_file": true}

// Load reads and checks the file at path; errors name the file and line.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse reads and checks a configuration.
func Parse(r io.Reader) (*Config, error) {
	vals, err := parseLines(io.LimitReader(r, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	c := &Config{
		Listen:     vals["listen"].value,
		ServerAddr: vals["server_addr"].value,
		DataDir:    vals["data_dir"].value,
		BinDir:     vals["bin_dir"].value,
		Unlock:     store.Unlock{KeyFile: vals["key_file"].value},
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}
	if err := c.check(vals); err != nil {
		return nil, err
	}
	return c, nil
}

type setting struct {
	value string
	line  int
}

func parseLines(r io.Reader) (map[string]setting, error) {
	vals := map[string]setting{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), maxFileSize+1)
	n, size := 0, 0
	for sc.Scan() {
		n++
		size += len(sc.Bytes()) + 1
		if size > maxFileSize {
			return nil, fmt.Errorf("the file is larger than %d bytes", maxFileSize)
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if !keys[key] {
			return nil, fmt.Errorf("line %d: unknown key %q", n, key)
		}
		if prev, ok := vals[key]; ok {
			return nil, fmt.Errorf("line %d: %q is set twice (first on line %d)", n, key, prev.line)
		}
		vals[key] = setting{value, n}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("line %d: too long", n+1)
		}
		return nil, err
	}
	return vals, nil
}

// parseLine reads `key = "value"` with an optional # comment after it.
func parseLine(line string) (key, value string, err error) {
	k, rest, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", errors.New(`not a line of the form key = "value"`)
	}
	key = strings.TrimSpace(k)
	if key == "" || strings.IndexFunc(key, func(r rune) bool { return !(r == '_' || r >= 'a' && r <= 'z') }) >= 0 {
		return "", "", fmt.Errorf(`not a line of the form key = "value" (key %q)`, key)
	}
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, `"`) {
		return "", "", fmt.Errorf("the value of %s must be in double quotes", key)
	}
	end := strings.IndexByte(rest[1:], '"')
	if end < 0 {
		return "", "", fmt.Errorf("the value of %s has no closing quote", key)
	}
	value = rest[1 : 1+end]
	after := strings.TrimSpace(rest[2+end:])
	if after != "" && !strings.HasPrefix(after, "#") {
		return "", "", fmt.Errorf("unexpected text after the value of %s", key)
	}
	if strings.ContainsRune(value, '\\') {
		return "", "", fmt.Errorf("the value of %s holds a backslash, which this file does not allow", key)
	}
	if strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) >= 0 {
		return "", "", fmt.Errorf("the value of %s holds a control character", key)
	}
	return key, value, nil
}

// check validates the values and fills in ServerAddr.
func (c *Config) check(vals map[string]setting) error {
	at := func(key string) string {
		if s, ok := vals[key]; ok {
			return "line " + strconv.Itoa(s.line) + ": "
		}
		return ""
	}
	listen, err := parseListen(c.Listen)
	if err != nil {
		return fmt.Errorf("%s%w", at("listen"), err)
	}
	c.Listen = listen.String()
	switch {
	case c.ServerAddr != "":
		a, err := visit.CheckServerAddr(c.ServerAddr)
		if err != nil {
			return fmt.Errorf("%sserver_addr: %w", at("server_addr"), err)
		}
		c.ServerAddr = a.String()
	case listen.Addr().IsUnspecified():
		return fmt.Errorf("%sserver_addr is required when listen is %s: give the IP address the machines see the server connect from", at("listen"), c.Listen)
	default:
		a, err := visit.CheckServerAddr(listen.Addr().String())
		if err != nil {
			return fmt.Errorf("%sserver_addr: %w", at("listen"), err)
		}
		c.ServerAddr = a.String()
	}
	for _, d := range []struct{ key, val string }{{"data_dir", c.DataDir}, {"bin_dir", c.BinDir}, {"key_file", c.Unlock.KeyFile}} {
		if d.val != "" && !filepath.IsAbs(d.val) {
			return fmt.Errorf("%s%s must be an absolute path, not %q", at(d.key), d.key, d.val)
		}
	}
	return nil
}

// parseListen accepts a literal IP address and a port: a host name could
// resolve to anything, and an empty host is every interface.
func parseListen(s string) (netip.AddrPort, error) {
	if s == "" {
		return netip.AddrPort{}, errors.New(`listen is required: the LAN address and port for the web UI, for example listen = "192.168.1.10:8443"`)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("listen %q is not an address and port, for example 192.168.1.10:8443: %v", s, err)
	}
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("listen %q: the address must be a literal IP address without a zone (no host name, not empty)", s)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("listen %q: the port must be a number from 0 to 65535", s)
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(p)), nil
}

// AllInterfaces reports whether Listen is a wildcard address (0.0.0.0 or
// ::), which puts the UI on every interface.
func (c *Config) AllInterfaces() bool {
	ap, err := netip.ParseAddrPort(c.Listen)
	return err == nil && ap.Addr().IsUnspecified()
}
