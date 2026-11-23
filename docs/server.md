# The telltale server

The server keeps each machine's snapshot and history, visits the machines on
a schedule, judges what it collects, and shows the results in a web UI. It
can send alerts to a bubbles chat and answer an AI assistant over MCP.

A visit works like this: the server logs in to the machine as root over SSH
with its own key, finds a root-owned temporary directory where programs may
run (`/run`, then `/var/tmp`, `/root`, `/tmp`), copies the collector there,
runs it, reads the collection back, and removes the directory. The collector
is the only thing a visit writes. The snapshot never goes to the machine,
and all judging happens on the server.

## Run it on a machine of its own

The server holds an SSH key that is root on every machine you enrol, and the
history of what is wrong with each of them. It is the most valuable target
on your network, so give it a small machine of its own (a small virtual
machine or a single-board computer with 2 GB of memory will do):

- nothing else runs on it, and nobody else has an account on it;
- it is kept up to date (unattended upgrades);
- its own SSH login is key-only, and only from where you administer it;
- the web UI listens on its LAN address, never on every interface, and a
  firewall lets only your own computers reach that port;
- its disk is encrypted if it can be stolen.

Up to four visits run at once. A visit to a large machine can hold a few
hundred megabytes while it reads and judges the collection, so give the
server that memory, and disk for the package cache (it grows
with the number of distinct package versions on your machines).

The server itself runs as an unprivileged user under a systemd unit that
locks down nearly everything it does not need (see below).

## Install

With the package (amd64 or arm64):

```
sudo apt install ./telltale_0.1.0-1_amd64.deb
```

It installs:

| Path | What it is |
|------|------------|
| `/usr/bin/telltale` | The full build, which runs the server |
| `/usr/lib/telltale/telltale-linux-amd64`, `-arm64` | The collector build, which the server copies to machines of each architecture |
| `/lib/systemd/system/telltale.service` | The unit |
| `/etc/telltale/telltale.toml.example` | An example configuration |

It creates the `telltale` system account and makes `/etc/telltale` readable
by it, and starts nothing: the server needs a configuration and a
passphrase first. Removing the package stops and disables the service;
purging it keeps the data directory and the account, because the database
holds your snapshots.

Without the package, the full tarball's binary works the same way: put the
collectors from the carry tarballs (renamed to `telltale-linux-amd64` and
`telltale-linux-arm64`) next to it or in a directory named by `bin_dir`, and
follow the steps at the top of the unit file in `deploy/systemd/`.

## Configure

```
sudo install -m 0640 -o root -g telltale /etc/telltale/telltale.toml.example /etc/telltale/telltale.toml
sudoedit /etc/telltale/telltale.toml
```

One setting per line, `key = "value"`:

| Setting | What it is |
|---------|------------|
| `listen` | Required. The web UI's address and port, a literal IP: this machine's LAN address, for example `192.168.1.10:8443`. `0.0.0.0:8443` or `[::]:8443` puts it on every interface and also needs `--allow-all-interfaces`. |
| `server_addr` | The IP address the monitored machines see the server connect from. It goes into the two snippets each machine gets, so it must be one literal address, never a name or a range. When it is not set, it is the address in `listen`, which then must not be a wildcard or loopback address. Set it when the machines see another address (the server has several, or sits behind NAT). |
| `data_dir` | Where the database, the HTTPS certificate and key and the package cache live. Default `/var/lib/telltale`. |
| `bin_dir` | Where the collectors are. By default they are looked for next to the binary and then in `../lib/telltale` beside it, which is where the package puts them. |
| `key_file` | An age key file that unlocks the database instead of a passphrase, for restarts with nobody there. See [the passphrase](#the-passphrase-or-a-key-file). |

## The passphrase, or a key file

Snapshots, reports, exceptions, the server's SSH key and the alert queue are
encrypted in the database with a key that is unlocked at start, from either:

- **a passphrase** (the default). The unit has systemd read
  `/etc/telltale/passphrase` as root and hand it to the service as a
  credential (`LoadCredential=passphrase:...`), so the `telltale` account
  never needs to read the file itself:

  ```
  sudo install -m 0600 /dev/null /etc/telltale/passphrase
  sudoedit /etc/telltale/passphrase
  ```

  Without systemd the passphrase comes from `TELLTALE_PASSPHRASE` or a
  prompt.

- **a key file** (`key_file` in the configuration), created on the first
  start. The server then restarts without anyone typing anything, but anyone
  who can read the key file can read the database. Under the unit only
  `/var/lib/telltale` is writable, so keep it there (as the example does),
  and clear the credential, which is then not needed, with `sudo systemctl
  edit telltale`:

  ```
  [Service]
  LoadCredential=
  ```

Keep the passphrase (or a copy of the key file) somewhere safe away from the
server: without it the database cannot be opened.

Not everything is encrypted: machine names, their addresses and pinned host
keys, the settings and the audit log are stored as they are.

## Start it and set the admin password

```
sudo systemctl enable --now telltale
sudo journalctl -u telltale
```

The log shows the HTTPS certificate's fingerprint, the server's SSH key
fingerprint, the address machines will see it connect from, and, on the
first start, a **one-time setup code**.

Open `https://<listen address>/`. The certificate is self-signed: check that
the fingerprint your browser shows matches the one in the log before you
trust it. The first page asks for the setup code and a new admin password
(at least 12 characters). The code proves that the person setting the
password is the one who started the server, so nobody else on the network
can claim it first.

Use the IP address from `listen` in the address bar: in this version the UI
answers only to that address, not to a host name. Any current browser works;
Safari older than 16.4 cannot submit the forms.

## Enrol a machine

1. **Enrol** (in the menu): a name and the address the server reaches the
   machine on over SSH (with the port if it is not 22).
2. The server connects and shows the machine's SSH host key fingerprint.
   **Compare it** with what the machine itself says, on its own console, not
   over the network:

   ```
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

   If they match, confirm. The server pins that key and refuses any other on
   every visit; if they do not match, stop, because something between the
   server and the machine may be posing as it.
3. **Add the two snippets** the server shows to the machine (next section),
   then check sshd's configuration and reload it:

   ```
   sudo sshd -t && sudo systemctl reload ssh
   ```

4. **Check now.** The first visit has no snapshot, so it shows what the
   package verification, the checklist and the suspicious-on-any-machine
   checks find. Look at every finding. When you believe the machine has not
   been tampered with, press **This machine is believed clean: take the
   snapshot**. From then on every visit is compared with that snapshot.

### The two snippets, and why

The server needs root on the machine, but root login over SSH should stay
off. So root login stays off for everyone, except with the server's key
from the server's address:

```
# appended to /root/.ssh/authorized_keys
from="192.168.1.10" ssh-ed25519 AAAA... telltale-server

# appended to the end of /etc/ssh/sshd_config
Match Address 192.168.1.10
    PermitRootLogin prohibit-password
```

- The global `PermitRootLogin no` stays as it is.
- `from="..."` makes the key work only from the server's address, even if
  the key leaked.
- The `Match Address` block lets root log in **with a key only**, and only
  from that address. A `Match` block applies to everything after it, which
  is why it goes at the end of the file.
- Every visit expects exactly this key line and this block, and the
  checklist judges the effective sshd configuration, so "root may log in by
  key from the telltale server only" passes. Any other root key, a broader
  `Match` block or root login turned on for anyone else is a finding, and no
  fix command ever touches the server's own entries.

Two other designs were rejected. A separate account with a password-free
sudo rule would need a rule that allows anything (the collector's path
changes on every visit), which is root for anyone who gets that account and
is itself a classic backdoor. A forced-command wrapper would have to be
installed on the machine, and forced commands are among the things telltale
reports.

The server's SSH key fingerprint and its full `authorized_keys` line are on
the settings page, so you can audit each machine's
`/root/.ssh/authorized_keys` against them.

## Visits, changes and exceptions

- **Schedule**: every hour, day (the default for new machines) or week, or
  only when you press **Check now**; set per machine.
- **Changes you made on purpose** (a new service, a configuration you
  edited): on the machine page, review the changes since the snapshot and
  accept them, one by one or all at once after seeing them all. The snapshot
  rolls forward. Changes that a confirmed package update explains roll
  forward by themselves.
- **Exceptions**: a finding you mean to keep (a setting you leave as it is,
  a module you built) can be accepted as an exception. It stays accepted
  only while its value stays exactly the same.
- **A visit that fails** is recorded; after three failures in a row the
  machine's report says so. A temporary directory a broken connection left
  behind is removed on the next visit.
- **The audit log** records every visit, enrolment, snapshot, accepted
  change and exception, every login and every settings change. Nothing in it
  can be changed or removed from the UI.

The UI keeps you logged in for up to 12 hours of inactivity and 7 days in
all; a restart of the server logs everyone out.

## Third-party repository keys

Packages from third-party APT repositories are verified only with a key
bound to the repository (see [how-it-works.md](how-it-works.md)). On the
settings page you can add one: the repository's address as the machines'
APT sources give it, and the vendor's public key. The key then vouches only
for that address and the addresses under it, never for another repository
and never for the official archives. Fetch it from the vendor's own HTTPS
site and compare its fingerprint with one they publish somewhere else;
never copy it from a machine you are checking.

## Alerts through bubbles

Settings > **Connect to bubbles**: give the bubbles server's address, compare
the fingerprint telltale shows with the one your chat admin reads in bubbles
under Admin > Overview, and your chat admin approves telltale with the code
it shows and picks a channel.

An alert goes out when a visit finds new tampering or a new backdoor sign
(the default) or any new finding (an option), and a resolved alert when it
is gone. An alert holds the finding, the machine and at most the one changed
line, redacted, never file contents. If bubbles cannot be reached, alerts
wait in an encrypted queue (the most serious are kept when it is full) and
are sent later.

## AI assistants (MCP)

Settings > **MCP access tokens** makes a token for an assistant. On the
computer where the assistant runs, save it in a file only you can read
(`install -m 600 /dev/null ~/.telltale-token`, then paste it in), and add
this to the assistant's MCP configuration as a stdio server:

```
telltale mcp --server https://192.168.1.10:8443 --token-file /home/you/.telltale-token --fingerprint SHA256:...
```

`telltale mcp` comes with the full build. It talks only to a server with
exactly that certificate fingerprint, and refuses a token file others can
read. The tools are `list_machines`, `latest_report`, `explain_finding`,
`compare_reports` and `check_now` (at most one visit a minute per machine).
They cannot take a snapshot, accept changes or add exceptions, and the
assistant is told that text from machines is data, not instructions, and
never to run fix commands. Revoke a token on the same page.

## Back up the data directory

Everything the server knows is in its data directory (`/var/lib/telltale`):

| File | What it is |
|------|------------|
| `telltale.db` (with `-wal` and `-shm` while it runs) | The database: machines, snapshots, reports, exceptions, settings, the audit log, the server's SSH key |
| `tls.crt`, `tls.key` | The HTTPS certificate and key (keep them, or the fingerprint changes) |
| `pkgcache/` | Downloaded packages and file hashes; it can be left out, it fills again |
| `data.key` | Only with `key_file` set there |

Stop the server while you copy, so the database is consistent:

```
sudo systemctl stop telltale
sudo tar -C /var/lib -czf telltale-backup.tar.gz --exclude telltale/pkgcache telltale
sudo systemctl start telltale
```

The backup holds the server's SSH key, encrypted with the database key. With
a passphrase, the backup is useless without it; with a key file inside the
data directory, the backup includes the key file, so whoever has the backup
can read everything in it and log in to your machines as root. Store it
accordingly, and keep a copy of the key file or the passphrase separately so
the backup can be restored.

To restore: install the package, stop the service, put the directory back
(owned by `telltale`, mode 0700), restore the configuration and the
passphrase file, and start it.

## The systemd unit

`deploy/systemd/telltale.service` (installed as
`/lib/systemd/system/telltale.service`) runs `telltale server --config
/etc/telltale/telltale.toml` as the `telltale` user, with:

- `LoadCredential=passphrase:/etc/telltale/passphrase`: the passphrase
  handed over as a credential;
- `StateDirectory=telltale` with mode 0700: the data directory, private to
  the service, and the only writable place (`ProtectSystem=strict`,
  `ProtectHome=yes`, `PrivateTmp=yes`);
- no capabilities at all, `NoNewPrivileges`, no new namespaces, only IP and
  local sockets, a system call filter, and the kernel, clock, devices and
  other processes out of reach.

To change it, use `sudo systemctl edit telltale` rather than editing the
file, so a package upgrade keeps your change.
