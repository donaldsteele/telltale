package pkgverify

import (
	"context"
	"testing"
)

// A conffile that equals the signed package's default gets a verdict of its
// own; a path only the machine's dpkg status calls a conffile gets none.
func TestVerifyConffileDefaultVerdict(t *testing.T) {
	f := toolFixture(t)
	const planted = "/etc/cron.d/zz"
	disk := toolDisk(map[string]string{planted: "* * * * * root /tmp/.x\n"})
	pk := toolPackage()
	pk.Files = append(pk.Files, planted, "/root/.ssh/authorized_keys")
	pk.Conffiles[planted] = md5hex("* * * * * root /tmp/.x\n")
	pk.Conffiles["/root/.ssh/authorized_keys"] = md5hex("key\n")
	disk["/root/.ssh/authorized_keys"] = "key\n"
	c := collectionOf(disk, pk)

	opt := f.opts()
	opt.OnlyPaths = map[string]bool{"/etc/tool.conf": true, "/etc/init.d/tool": true, planted: true, "/root/.ssh/authorized_keys": true}
	res := Verify(context.Background(), c, opt)
	wantPaths(t, "ConffileDefaults", res.ConffileDefaults, "/etc/init.d/tool", "/etc/tool.conf")
	for _, v := range res.ConffileDefaults {
		if v.Kind != KindConffileDefault || v.Package != "tool" || v.Version != "1.0-1" || v.Expected != v.Actual || v.Actual == "" || v.Source != SourceArchive {
			t.Errorf("verdict %+v", v)
		}
	}
	for _, list := range [][]FileVerdict{res.Verified, res.ConffileDefaults} {
		for _, p := range []string{planted, "/root/.ssh/authorized_keys"} {
			if _, ok := find(list, p); ok {
				t.Errorf("%s, which the signed package does not ship, got a positive verdict", p)
			}
		}
	}
	wantPaths(t, "Verified", res.Verified)

	// Edited away from the default: a diff, no positive verdict.
	c = collectionOf(toolDisk(map[string]string{"/etc/tool.conf": "edited\n"}), toolPackage())
	res = Verify(context.Background(), c, opt)
	wantPaths(t, "ConffileDefaults", res.ConffileDefaults, "/etc/init.d/tool")
	if len(res.Conffiles) != 1 || res.Conffiles[0].Path != "/etc/tool.conf" {
		t.Errorf("Conffiles = %+v", res.Conffiles)
	}
}
