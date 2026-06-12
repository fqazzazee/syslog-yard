package netfeeds

import (
	"testing"
)

func TestParseSpamhausDrop(t *testing.T) {
	body := []byte(`{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"2.56.192.0/22","sblid":"SBL459831","rir":"ripencc"}
{"type":"summary","timestamp":1718000000,"size":2}`)
	ps, err := parseSpamhausDrop(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].String() != "1.10.16.0/20" {
		t.Errorf("prefixes = %v", ps)
	}
}

func TestParseFeodo(t *testing.T) {
	body := []byte(`[{"ip_address":"103.85.95.4","port":443,"status":"online","malware":"Pikabot"},
	{"ip_address":"45.155.249.99","port":8080,"status":"offline","malware":"QakBot"}]`)
	ps, err := parseFeodo(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].String() != "103.85.95.4/32" {
		t.Errorf("prefixes = %v", ps)
	}
}

func TestParsePlainIPs(t *testing.T) {
	ps, err := parsePlainIPs([]byte("# comment\n185.220.101.34\n\n199.249.230.87\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[1].String() != "199.249.230.87/32" {
		t.Errorf("prefixes = %v", ps)
	}
}

func TestParseO365(t *testing.T) {
	body := []byte(`[{"id":1,"serviceArea":"Exchange","ips":["13.107.6.152/31","2603:1006::/40"],"urls":["outlook.office.com"]},
	{"id":2,"serviceArea":"SharePoint","ips":["13.107.6.152/31","13.107.136.0/22"]}]`)
	ps, err := parseO365(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 { // duplicate 13.107.6.152/31 collapsed
		t.Errorf("prefixes = %v", ps)
	}
}

func TestParseCIDRList(t *testing.T) {
	ps, err := parseCIDRList([]string{"10.8.0.0/16", " 192.0.2.7 ", "", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 3 || ps[1].String() != "192.0.2.7/32" || ps[2].String() != "2001:db8::1/128" {
		t.Errorf("prefixes = %v", ps)
	}
	if _, err := parseCIDRList([]string{"not-an-ip"}); err == nil {
		t.Error("expected error for junk input")
	}
}

func TestDefaultConfigEnablesBuiltins(t *testing.T) {
	c := DefaultConfig()
	for _, f := range builtins {
		if !c.Feeds[f.ID] {
			t.Errorf("feed %s not enabled by default", f.ID)
		}
	}
}
