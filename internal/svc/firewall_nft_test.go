package svc

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestNftFilters(t *testing.T) {
	orig := readFile
	t.Cleanup(func() { readFile = orig })

	cases := []struct {
		name string
		conf string
		err  error
		want bool
	}{
		{name: "debian skeleton accepts everything", conf: `#!/usr/sbin/nft -f
flush ruleset
table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}`, want: false},
		{name: "drop policy filters", conf: `table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
	}
}`, want: true},
		{name: "explicit drop rule filters", conf: `table inet filter {
	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 22 drop
	}
}`, want: true},
		{name: "reject rule filters", conf: "chain input { tcp dport 25 reject }", want: true},
		{name: "the word drop in a comment does not count", conf: `chain input {
	# we used to drop this
	policy accept;
}`, want: false},
		{name: "unreadable config is assumed to filter", err: os.ErrNotExist, want: true},
		{name: "included rulesets may filter", conf: "flush ruleset\ninclude \"/etc/nftables.d/*.nft\"\n", want: true},
		{name: "a rule ending in a semicolon filters", conf: `table inet filter {
	chain input {
		type filter hook input priority 0; policy accept;
		ct state invalid drop;
	}
}`, want: true},
		{name: "drop before a closing brace", conf: "chain input { tcp dport 25 drop}", want: true},
		{name: "drop in a verdict map", conf: "chain input { tcp dport vmap { 22 : drop, 80 : accept } }", want: true},
		{name: "the word include in a comment does not count", conf: "# include nothing\nchain input { policy accept; }", want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			readFile = func(string) ([]byte, error) {
				if c.err != nil {
					return nil, c.err
				}
				return []byte(c.conf), nil
			}
			if got := nftFilters(); got != c.want {
				t.Fatalf("nftFilters() = %v, want %v", got, c.want)
			}
		})
	}
	readFile = func(string) ([]byte, error) { return nil, errors.New("boom") }
	if !nftFilters() {
		t.Fatal("a read error must be treated as filtering")
	}
}

// nft lives in /usr/sbin, which is not on a normal user's PATH on Debian:
// nftables is still detected there, and only there.
func TestDetectNftablesInSbin(t *testing.T) {
	oldRead, oldStat := readFile, statPath
	t.Cleanup(func() { readFile, statPath = oldRead, oldStat })
	readFile = func(p string) ([]byte, error) {
		if p == "/etc/nftables.conf" {
			return []byte("table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n }\n}\n"), nil
		}
		return nil, os.ErrNotExist
	}
	h, fr := testHost(t, "linux", 1000)
	h.LookPath = func(n string) (string, error) {
		if n == "systemctl" {
			return "/usr/bin/systemctl", nil
		}
		return "", errors.New("not found")
	}
	fr.resp["systemctl is-active nftables"] = fakeResp{out: "active\n"}
	sbin := true
	statPath = func(p string) (os.FileInfo, error) {
		if sbin && p == "/usr/sbin/nft" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	fws := DetectFirewalls(context.Background(), h)
	if len(fws) != 1 || fws[0].Kind != FirewallNftables || !fws[0].Active {
		t.Fatalf("nft only in /usr/sbin: %+v", fws)
	}
	sbin = false
	if fws := DetectFirewalls(context.Background(), h); len(fws) != 0 {
		t.Fatalf("no nft anywhere: %+v", fws)
	}
}
