package redact

import (
	"strings"
	"testing"
)

// Every pattern the documentation lists: the secret is gone, what tells a
// reader which setting or command it was stays, and a second pass changes
// nothing.
func TestRedactPatterns(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		secrets    []string // must not survive
		keep       []string // must survive
	}{
		{"JSON key", `{"user": "bob", "password": "hunter2", "port": 5432}`, []string{"hunter2"}, []string{`"user": "bob"`, `"password": `, `"port": 5432`}},
		{"JSON key, no spaces", `{"password":"hunter2","db":"app"}`, []string{"hunter2"}, []string{`"password":`, `"db":"app"`}},
		{"JSON value with an escaped quote", `{"password": "hun\"ter2", "db": "app"}`, []string{"hun", "ter2"}, []string{`"db": "app"`}},
		{"YAML single-quoted key", `'token': 'abc123'`, []string{"abc123"}, []string{`'token': `}},
		{"YAML double-quoted key", `"api_key": abc123`, []string{"abc123"}, []string{`"api_key": `}},
		{"Python dict", `conf = {'secret': 'abc123', 'debug': True}`, []string{"abc123"}, []string{`'secret': `, `'debug': True`}},
		{"quoted value then more text that belongs to it", `password='it''s secret'`, []string{"it", "s secret"}, []string{"password="}},
		{"URL password with an @", `mirror = https://deploy:p@ss@w0rd@repo.example.com/apt`, []string{"deploy", "p@ss", "w0rd"}, []string{"https://", "@repo.example.com/apt"}},
		{"URL password, port after the host", `amqp://app:hunter2@mq.example.com:5672/vhost`, []string{"hunter2"}, []string{"@mq.example.com:5672/vhost"}},
		{"curl -u", `curl -u admin:hunter2 https://api.example.com/v1`, []string{"admin:", "hunter2"}, []string{"curl -u ", " https://api.example.com/v1"}},
		{"curl -u quoted", `0 3 * * * root curl -s -u "admin:hunter 2" https://x.example/`, []string{"hunter 2", "admin"}, []string{"curl -s -u ", " https://x.example/"}},
		{"--user user:pass", `wget --user ci:hunter2 https://x.example/f`, []string{"hunter2"}, []string{"wget --user ", " https://x.example/f"}},
		{"--user=user:pass", `ExecStart=/usr/bin/sync --user=ci:hunter2 --quiet`, []string{"hunter2"}, []string{"--user=", " --quiet"}},
		{"Authorization: Bearer", `curl -H "Authorization: Bearer eyJhbGciOi.abc.def" https://api.example.com`, []string{"eyJhbGciOi"}, []string{`"Authorization: Bearer `, ` https://api.example.com`}},
		{"Authorization: Basic", `Authorization: Basic YWRtaW46aHVudGVyMg==`, []string{"YWRtaW46"}, []string{"Authorization: Basic "}},
		{"Authorization with a bare value", `proxy_set_header Authorization abc123secret;`, nil, []string{"proxy_set_header"}},
		{"Authorization, no scheme", `authorization: abc123secret`, []string{"abc123secret"}, []string{"authorization: "}},
		{"Proxy-Authorization", `Proxy-Authorization: Basic Zm9vOmJhcg==`, []string{"Zm9vOmJhcg"}, []string{"Proxy-Authorization: Basic "}},
		{"--password x", `ExecStart=/usr/bin/backup --host db --password hunter2 --all`, []string{"hunter2"}, []string{"--host db --password ", " --all"}},
		{"--password=x", `backup --password=hunter2 --all`, []string{"hunter2"}, []string{"--password=", " --all"}},
		{"--password 'x y'", `backup --password 'hunter 2' --all`, []string{"hunter 2"}, []string{"--password ", " --all"}},
		{"--token x", `gh auth login --with-token --token ghp_abc123`, []string{"ghp_abc123"}, []string{"--with-token --token "}},
		{"sshpass -p", `sshpass -p hunter2 ssh -p 2222 backup@host`, []string{"hunter2"}, []string{"sshpass -p ", " ssh -p 2222 backup@host"}},
		{"sshpass -pX", `sshpass -phunter2 scp -P 2222 f host:`, []string{"hunter2"}, []string{"sshpass -p", " scp -P 2222 f host:"}},
		{"mysql -pX", `mysql -u root -phunter2 app < dump.sql`, []string{"hunter2"}, []string{"mysql -u root -p", " app < dump.sql"}},
		{"mysqldump -pX", `0 2 * * * root mysqldump -uroot -p'hunter 2' --all-databases | gzip > /backup/all.gz`, []string{"hunter 2"}, []string{"mysqldump -uroot -p", " --all-databases | gzip > /backup/all.gz"}},
		{"mariadb -pX", `mariadb -h db -phunter2`, []string{"hunter2"}, []string{"mariadb -h db -p"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, n := Line(testKey, tc.line)
			for _, s := range tc.secrets {
				if strings.Contains(got, s) {
					t.Errorf("%q survived in %q", s, got)
				}
			}
			for _, k := range tc.keep {
				if !strings.Contains(got, k) {
					t.Errorf("%q lost in %q", k, got)
				}
			}
			if len(tc.secrets) > 0 && (n == 0 || !digestRe.MatchString(got)) {
				t.Errorf("n = %d, no digest in %q", n, got)
			}
			again, m := Line(testKey, got)
			if again != got || m != 0 {
				t.Errorf("a second pass changed %q into %q (n = %d)", got, again, m)
			}
		})
	}
}

// Lines that only look like the patterns stay as they are.
func TestRedactPatternsLeaveOrdinaryLines(t *testing.T) {
	for _, line := range []string{
		"# ask for the password at the console",
		"password requisite pam_pwquality.so retry=3",
		"PasswordAuthentication no",
		"PermitRootLogin prohibit-password",
		"ssh -p 22 backup@host uptime",
		"scp -P 2222 -p file host:/srv/",
		"rsync -a -e 'ssh -p 2222' /srv/ host:/srv/",
		"mysql -p",
		"mysql -p -u root app",
		"mysqldump --port=3307 -u backup app",
		"mysql -P 3307 -u backup app",
		"cp -p /etc/hosts /root/",
		"mkdir -p /var/lib/mysql-files",
		"sudo -u www-data php artisan schedule:run",
		"crontab -u backup -l",
		"rsync -u host:/srv/a /srv/b",
		"runuser --user backup -- /usr/local/bin/job",
		"https://example.com:8443/path@v2",
		"git clone git@github.com:org/repo.git",
		"curl -u admin https://api.example.com/",
		"backup --password-file /etc/backup/pw --all",
		"docker login --password-stdin registry.example.com",
		"AuthorizedKeysFile .ssh/authorized_keys",
		"auth required pam_unix.so",
	} {
		if got, n := Line(testKey, line); got != line || n != 0 {
			t.Errorf("Line(%q) = %q, n = %d; want unchanged", line, got, n)
		}
	}
}
