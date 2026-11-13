package main

import "testing"

func TestListenPortBindsAtStartAndIsNeverReappliedAtCommit(t *testing.T) {
	staged, commit := stages("private_key=aa\nlisten_port=31820\nreplace_peers=true\npublic_key=bb\nendpoint=127.0.0.1:51821\npersistent_keepalive_interval=25\n")
	if staged != "private_key=aa\nlisten_port=31820\nreplace_peers=true\npublic_key=bb\n" {
		t.Fatalf("start applied %q", staged)
	}
	// Reapplying listen_port would reopen the sockets after Android protected them.
	if commit != "private_key=aa\nreplace_peers=true\npublic_key=bb\nendpoint=127.0.0.1:51821\npersistent_keepalive_interval=25\n" {
		t.Fatalf("commit applied %q", commit)
	}
}
