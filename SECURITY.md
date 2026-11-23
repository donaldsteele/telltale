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

## Supported versions

Fixes go into the latest release.
