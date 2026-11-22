package procnet

import "testing"

func TestParse(t *testing.T) {
	data := "  sl  local_address rem_address   st\n" +
		"   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 1234 1 0\n" +
		"   1: garbage\n"
	rows := Parse(data)
	if len(rows) != 1 {
		t.Fatalf("%d rows", len(rows))
	}
	r := rows[0]
	if r.Local != "127.0.0.1:53" || r.LocalPort != 53 || r.Inode != 1234 || !r.RemoteZero || !r.Listening("tcp") {
		t.Errorf("%+v", r)
	}
	if States[r.State] != "LISTEN" {
		t.Errorf("state %q", r.State)
	}
}
