package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const passphraseEnv = "TELLTALE_PASSPHRASE"

var errNoTerminal = errors.New("no terminal to ask for a passphrase on; set " + passphraseEnv + " or run from a terminal")

// termFile returns the stdin file when it is a terminal.
func termFile(r io.Reader) (*os.File, bool) {
	f, ok := r.(*os.File)
	if !ok {
		return nil, false
	}
	if _, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS); err != nil {
		return nil, false
	}
	return f, true
}

// readHidden reads one line from the terminal with echo off, restoring the
// terminal on return and on interrupt.
func readHidden(f *os.File, prompt string, stderr io.Writer) (string, error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", err
	}
	noEcho := *old
	noEcho.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &noEcho); err != nil {
		return "", err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			unix.IoctlSetTermios(fd, unix.TCSETS, old)
			fmt.Fprintln(stderr)
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		close(done)
		signal.Stop(sig)
		unix.IoctlSetTermios(fd, unix.TCSETS, old)
		fmt.Fprintln(stderr)
	}()
	fmt.Fprint(stderr, prompt)
	var b strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if n == 1 {
			if buf[0] == '\n' || buf[0] == '\r' {
				return b.String(), nil
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			if err == io.EOF && b.Len() > 0 {
				return b.String(), nil
			}
			return "", err
		}
	}
}

// getPassphrase returns the passphrase from the environment, or prompts on
// the terminal (twice when confirm is set). Never reads from a pipe.
func getPassphrase(ctx *Context, confirm bool) (string, error) {
	if p := os.Getenv(passphraseEnv); p != "" {
		return p, nil
	}
	f, ok := termFile(ctx.Stdin)
	if !ok {
		return "", errNoTerminal
	}
	p, err := readHidden(f, "Snapshot passphrase: ", ctx.Stderr)
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", errors.New("empty passphrase; use --no-encrypt for an unencrypted snapshot")
	}
	if confirm {
		q, err := readHidden(f, "Repeat passphrase: ", ctx.Stderr)
		if err != nil {
			return "", err
		}
		if p != q {
			return "", errors.New("passphrases do not match")
		}
	}
	return p, nil
}
