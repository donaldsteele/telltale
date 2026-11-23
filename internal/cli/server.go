//go:build !collector

package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/donaldsteele/telltale/internal/alerts"
	"github.com/donaldsteele/telltale/internal/config"
	"github.com/donaldsteele/telltale/internal/escape"
	"github.com/donaldsteele/telltale/internal/server"
	"github.com/donaldsteele/telltale/internal/store"
	"github.com/donaldsteele/telltale/internal/visit"
)

const serverUsage = `usage: telltale server --config FILE [--allow-all-interfaces]

Runs the telltale server: it visits the enrolled machines on their schedules,
judges what it collects, keeps their snapshots and reports, and serves the web
UI over HTTPS at the configuration's listen address.

The database is unlocked with key_file from the configuration, or with a
passphrase from TELLTALE_PASSPHRASE, from systemd's credential "passphrase"
($CREDENTIALS_DIRECTORY/passphrase, see LoadCredential=), or from a prompt.

Flags:
  --config FILE            the configuration file (see deploy/telltale.toml.example)
  --allow-all-interfaces   allow listen = "0.0.0.0:..." or "[::]:...", which puts
                           the web UI on every interface of this machine`

// Files in the data directory.
const (
	dbFile       = "telltale.db"
	pkgCacheDir  = "pkgcache"
	credentialID = "passphrase"
)

func init() {
	Register(Command{Name: "server", Summary: "run the telltale server", Run: runServer})
}

func runServer(ctx *Context) int {
	fail := func(err error) int {
		fmt.Fprintf(ctx.Stderr, "telltale server: %s\n", escape.Terminal(err.Error()))
		return ExitUsage
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgPath := fs.String("config", "", "")
	allowAll := fs.Bool("allow-all-interfaces", false, "")
	if err := fs.Parse(ctx.Args); err != nil || *cfgPath == "" || fs.NArg() > 0 {
		if err != nil && !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(ctx.Stderr, "telltale server: %s\n", escape.Terminal(err.Error()))
		}
		fmt.Fprintln(ctx.Stderr, serverUsage)
		return ExitUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(ctx.Stderr, "telltale server: warning: %s\n", escape.Terminal(w))
	}
	if cfg.AllInterfaces() && !*allowAll {
		return fail(fmt.Errorf("listen = %q puts the web UI on every interface of this machine; give its LAN address instead, or pass --allow-all-interfaces if that is what you want", cfg.Listen))
	}
	if err := prepareDataDir(cfg.DataDir, ctx.Stderr); err != nil {
		return fail(err)
	}
	dbPath := filepath.Join(cfg.DataDir, dbFile)
	unlock := cfg.Unlock
	if unlock.KeyFile == "" {
		_, statErr := os.Stat(dbPath)
		p, err := serverPassphrase(ctx, errors.Is(statErr, os.ErrNotExist))
		if err != nil {
			return fail(err)
		}
		unlock.Passphrase = p
	}
	st, err := store.Open(dbPath, unlock)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	return serve(ctx, cfg, st)
}

// serve runs the server on an open store until SIGINT or SIGTERM.
func serve(ctx *Context, cfg *config.Config, st *store.Store) int {
	fail := func(err error) int {
		fmt.Fprintf(ctx.Stderr, "telltale server: %s\n", escape.Terminal(err.Error()))
		return ExitUsage
	}
	logger := log.New(ctx.Stderr, "", log.LstdFlags)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fail(err)
	}
	defer ln.Close()
	bound, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		return fail(err)
	}
	bound = netip.AddrPortFrom(bound.Addr().Unmap().WithZone(""), bound.Port())
	cert, certFP, err := server.LoadOrCreateCert(cfg.DataDir, certIPs(bound.Addr(), cfg.ServerAddr))
	if err != nil {
		return fail(err)
	}
	signer, _, err := visit.ServerKey(st)
	if err != nil {
		return fail(err)
	}
	var setupCode string
	if first, err := server.NeedsSetup(st); err != nil {
		return fail(err)
	} else if first {
		setupCode = newSetupCode()
	}

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Alerts go to bubbles once the owner pairs in the web UI; until then
	// the sink sends nothing.
	bub := &alerts.Bubbles{Store: st, Log: logger, Context: runCtx}
	if cfg.MaxCollectionBytes > 0 {
		if err := visit.SetMaxCollection(cfg.MaxCollectionBytes); err != nil {
			return fail(err)
		}
	}
	core := &server.Core{
		Store:      st,
		Bins:       visit.Binaries{Dir: cfg.BinDir, Log: logger},
		CacheDir:   filepath.Join(cfg.DataDir, pkgCacheDir),
		ServerAddr: cfg.ServerAddr,
		Alerts:     bub,
		Log:        logger,
	}
	ui, err := server.NewUI(server.UIOptions{
		Core:            core,
		Store:           st,
		Listen:          bound.String(),
		ServerAddr:      cfg.ServerAddr,
		CertFingerprint: certFP,
		SetupCode:       setupCode,
		Context:         runCtx,
		Log:             logger,
		Bubbles:         bub,
	})
	if err != nil {
		return fail(err)
	}
	srv := &http.Server{
		Handler:           ui,
		TLSConfig:         server.TLSConfig(cert),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          logger,
	}

	out := ctx.Stdout
	fmt.Fprintf(out, "telltale server: web UI at https://%s/\n", bound)
	fmt.Fprintf(out, "telltale server: HTTPS certificate SHA-256 fingerprint (compare it with what your browser shows):\n  %s\n", certFP)
	fmt.Fprintf(out, "telltale server: SSH key fingerprint %s; machines see this server as %s\n", ssh.FingerprintSHA256(signer.PublicKey()), cfg.ServerAddr)
	if setupCode != "" {
		fmt.Fprintf(out, "telltale server: first run: open https://%s/setup and enter this one-time setup code to set the admin password:\n  %s\n", bound, setupCode)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		core.Run(runCtx)
	}()
	// Alerts bubbles could not take are sent again every five minutes and
	// after every visit, until the server stops.
	go func() {
		defer wg.Done()
		bub.Run(runCtx)
	}()
	served := make(chan error, 1)
	go func() { served <- srv.ServeTLS(ln, "", "") }()
	code := 0
	select {
	case <-runCtx.Done():
		fmt.Fprintln(out, "telltale server: stopping")
	case err := <-served:
		logger.Printf("telltale server: the web UI stopped: %v", err)
		code = ExitUsage
	}
	stop()
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shut)
	wg.Wait()
	ui.Wait()
	// A pairing request still waiting for the chat admin ends with runCtx.
	bub.Wait()
	return code
}

// certIPs are the addresses the self-signed certificate names: the listen
// address, or for a wildcard one the loopback addresses, and the address
// machines see the server from.
func certIPs(listen netip.Addr, serverAddr string) []net.IP {
	var ips []net.IP
	add := func(a netip.Addr) {
		ip := net.IP(a.AsSlice())
		for _, x := range ips {
			if x.Equal(ip) {
				return
			}
		}
		ips = append(ips, ip)
	}
	if listen.IsUnspecified() {
		add(netip.MustParseAddr("127.0.0.1"))
		add(netip.IPv6Loopback())
	} else {
		add(listen)
	}
	if a, err := netip.ParseAddr(serverAddr); err == nil {
		add(a.Unmap())
	}
	return ips
}

// newSetupCode is the one-time first-run code: 100 random bits in base32,
// in groups of five.
func newSetupCode() string {
	t := rand.Text()[:20]
	return t[0:5] + "-" + t[5:10] + "-" + t[10:15] + "-" + t[15:20]
}

// prepareDataDir makes the data directory 0700, creating it when missing.
// A symbolic link in its place is refused.
func prepareDataDir(dir string, stderr io.Writer) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("the data directory %s is not a directory (a symbolic link is not followed)", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("the data directory %s is open to other users and could not be made 0700: %w", dir, err)
		}
		fmt.Fprintf(stderr, "telltale server: made the data directory %s private (0700)\n", dir)
	}
	return nil
}

// serverPassphrase returns the store's passphrase: from TELLTALE_PASSPHRASE,
// from systemd's credential file, or from a prompt on the terminal with
// echo off (twice when confirm is set, for a new database). It never reads
// a passphrase from a pipe.
func serverPassphrase(ctx *Context, confirm bool) (string, error) {
	if p := os.Getenv(passphraseEnv); p != "" {
		return p, nil
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		p, err := readCredential(filepath.Join(dir, credentialID))
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	f, ok := termFile(ctx.Stdin)
	if !ok {
		return "", errors.New("no passphrase: set " + passphraseEnv + ", give systemd LoadCredential=" + credentialID + ":FILE, set key_file in the configuration, or run from a terminal")
	}
	p, err := readHidden(f, "Server passphrase: ", ctx.Stderr)
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", errors.New("empty passphrase")
	}
	if confirm {
		q, err := readHidden(f, "New database: repeat the passphrase: ", ctx.Stderr)
		if err != nil {
			return "", err
		}
		if p != q {
			return "", errors.New("the passphrases do not match")
		}
	}
	return p, nil
}

// readCredential reads a small credential file, without its final newline.
func readCredential(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", err
	}
	if len(b) > 4096 {
		return "", fmt.Errorf("the credential %s is larger than 4 KiB", p)
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if s == "" {
		return "", fmt.Errorf("the credential %s is empty", p)
	}
	return s, nil
}
