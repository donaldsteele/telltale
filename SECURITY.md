# Security

telltale is a security tool, and its server holds a key that is root on
every machine it watches, so a flaw in it matters. Thank you for reporting
one.

## Reporting a vulnerability

Please report it privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Only the maintainer
sees the report, and the fix can be discussed and prepared there before
anything is public.

Please do not open a public issue for a vulnerability.

A useful report says which version and which mode (carry mode, the server,
`telltale mcp`), what an attacker needs (a user account on a monitored
machine, root on it, access to the server's network, an MCP token), and how
to reproduce it.

## What counts

Among the things that are in scope:

- a way for a monitored machine, even one where the attacker is root, to
  make telltale report less than it should, crash, hang, or run anything on
  the server or on your terminal;
- a way into the server, its web UI, its API or its database, or to its SSH
  key;
- a way for text from a machine to steer an AI assistant through
  `telltale mcp` beyond reading;
- a secret from a machine (a password hash, a private key, a token) ending
  up in a snapshot, a report or an alert;
- a fix command that does something other than what it says.

The limits described in the README are known: in particular, a kernel-level
rootkit can hide from any check that runs on the machine.

## Verifying a release

Every file of a release is listed in its `SHA256SUMS`, and has a signed
build provenance attestation made by the release workflow: it binds the
file's hash to this repository, the workflow and the tagged commit it was
built from. To check a download before you trust it:

```
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify telltale_0.1.1_linux_amd64.tar.gz --repo donaldsteele/telltale
```

`gh attestation verify` needs the [GitHub CLI](https://cli.github.com/). A
file that fails either check did not come from this project's release
workflow: do not run it, and please report it.

The tarballs are also reproducible: `scripts/build.sh` at the same commit,
with the same Go toolchain, gives the same bytes.

## Supported versions

Fixes go into the latest release.
