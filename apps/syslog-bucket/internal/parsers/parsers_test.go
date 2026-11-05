package parsers

import (
	"encoding/json"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// The records below are what syslog-ng hands the bucket for real hose
// preset lines sent through a valve forward (host/app/message as in the
// JSON record), so they carry syslog-ng's own split of headerless lines.

func structured(t *testing.T, e *store.Entry) map[string]string {
	t.Helper()
	m := map[string]string{}
	if len(e.Structured) > 0 {
		if err := json.Unmarshal(e.Structured, &m); err != nil {
			t.Fatalf("structured: %v", err)
		}
	}
	return m
}

func TestFortiGate(t *testing.T) {
	cases := []struct {
		msg, logid, typ, subtype string
	}{
		{`time=10:06:28 devname="fortinet-45" devid="FGT60FTK2009012345" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root" policyid=31 sessionid=599424 srcip=172.21.136.81 srcport=64991 dstip=23.111.231.225 dstport=443 proto=6 service="HTTPS" hostname="bet-win-now.example.com" action="blocked" cat=46 catdesc="Gambling"`,
			"0316013056", "utm", "webfilter"},
		{`time=10:06:28 devname="fortinet-45" devid="FGT60FTK2009012345" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.232.137 srcport=7140 srcintf="internal" srcintfrole="lan" dstip=151.108.77.50 dstport=123 dstintf="wan1" dstintfrole="wan" sessionid=599427 proto=6 action="accept" policyid=30 policytype="policy" service="NTP" trandisp="snat" transip=91.204.146.238 transport=51999 appcat="unscanned" duration=288 sentbyte=684524 rcvdbyte=2879411 sentpkt=112 rcvdpkt=657`,
			"0000000013", "traffic", "forward"},
		{`time=10:06:28 devname="fortinet-45" devid="FGT60FTK2009012345" logid="0211008192" type="utm" subtype="virus" eventtype="infected" level="high" vd="root" severity="high" srcip=172.24.48.1 dstip=162.222.211.77 sessionid=599428 srcintf="internal" dstintf="wan1" proto=6 service="HTTP" action="blocked" filename="driver_pack.zip" virus="EICAR_TEST_FILE" url="http://cdn-fastpatch.example.com/dl" profile="default" user="" msg="File is infected."`,
			"0211008192", "utm", "virus"},
	}
	for _, c := range cases {
		e := store.Entry{Host: "172.18.0.2", AppName: "date=2026-11-05", Msg: c.msg,
			Structured: json.RawMessage(`{"pid":"-"}`)}
		Default().Apply(&e)
		if e.AppName != "fortigate" {
			t.Errorf("app = %q, want fortigate", e.AppName)
		}
		if e.Host != "fortinet-45" {
			t.Errorf("host = %q, want the devname", e.Host)
		}
		if e.Msg != "date=2026-11-05 "+c.msg {
			t.Errorf("date token not restored to the message: %q", e.Msg)
		}
		s := structured(t, &e)
		for k, want := range map[string]string{
			"date": "2026-11-05", "time": "10:06:28", "devname": "fortinet-45",
			"devid": "FGT60FTK2009012345", "logid": c.logid, "type": c.typ,
			"subtype": c.subtype, "vd": "root", "pid": "-",
		} {
			if s[k] != want {
				t.Errorf("structured[%s] = %q, want %q", k, s[k], want)
			}
		}
	}
}

// A FortiGate line straight to the bucket (no valve) splits the same way.
func TestFortiGateUnquotedDevid(t *testing.T) {
	e := store.Entry{Host: "10.0.0.1", AppName: "date=2026-11-05",
		Msg: `time=10:06:28 devname=edge-fw devid=FWF61E0000000001 logid=0100032001 type=event subtype=system`}
	Default().Apply(&e)
	if e.AppName != "fortigate" || e.Host != "edge-fw" {
		t.Errorf("got app %q host %q", e.AppName, e.Host)
	}
}

func TestSonicWall(t *testing.T) {
	e := store.Entry{Host: "172.18.0.2", AppName: "id=firewall",
		Msg: `sn=18B1690729A8 time="2026-11-05 10:06:28 UTC" fw=151.223.97.212 pri=6 c=1024 m=537 msg="Connection Closed" app=177 n=982129 src=172.25.111.200:55967:X0 dst=185.109.4.134:443:X1 proto=tcp/https sent=370888 rcvd=839383`}
	Default().Apply(&e)
	if e.AppName != "sonicwall" {
		t.Errorf("app = %q", e.AppName)
	}
	if e.Host != "172.18.0.2" {
		t.Errorf("host changed to %q; SonicWall logs name no device", e.Host)
	}
	s := structured(t, &e)
	if s["id"] != "firewall" || s["sn"] != "18B1690729A8" || s["m"] != "537" || s["msg"] != "Connection Closed" {
		t.Errorf("structured = %v", s)
	}
}

func TestPANOS(t *testing.T) {
	for _, c := range []struct{ msg, typ, subtype string }{
		{`10:06:28,007251000123456,TRAFFIC,deny,2561,2026/11/05 10:06:28,151.223.97.212,192.168.112.76,0.0.0.0,0.0.0.0,deny-inbound,,,not-applicable,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Log-Forwarding,2026/11/05 10:06:28,351930,1,64197,23,0,0,0x0,tcp,deny,0,0,0,1,2026/11/05 10:06:28,0,any`,
			"TRAFFIC", "deny"},
		{`10:06:28,007251000123456,THREAT,vulnerability,2561,2026/11/05 10:06:28,64.26.195.185,192.168.17.231,0.0.0.0,0.0.0.0,alert-inbound,,,ssl,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Log-Forwarding,2026/11/05 10:06:28,351935,1,60046,443,0,0,0x80004000,tcp,reset-both,"Suspicious DNS Query",46069,critical,client-to-server`,
			"THREAT", "vulnerability"},
	} {
		e := store.Entry{Host: "paloalto-45", AppName: "1,2026/11/05", Msg: c.msg}
		Default().Apply(&e)
		if e.AppName != "panos" || e.Host != "paloalto-45" {
			t.Errorf("got app %q host %q", e.AppName, e.Host)
		}
		if e.Msg != "1,2026/11/05 "+c.msg {
			t.Errorf("record head not restored: %q", e.Msg)
		}
		s := structured(t, &e)
		if s["serial"] != "007251000123456" || s["type"] != c.typ || s["subtype"] != c.subtype || s["receive_time"] != "2026/11/05 10:06:28" {
			t.Errorf("structured = %v", s)
		}
	}
}

// Well-formed program names stay as syslog-ng parsed them.
func TestProgramKept(t *testing.T) {
	for _, c := range []struct{ app, msg string }{
		{"sudo", "jsmith : TTY=pts/3 ; PWD=/home/mlopez ; USER=root ; COMMAND=/usr/bin/dnf update -y"},
		{"system,info,account", "user admin logged in from 172.17.165.245 via web"}, // MikroTik topics
		{"%ASA-6-302014", "Teardown TCP connection 334751 for outside:162.97.165.245/443"},
		{"RT_FLOW", `[junos@2636.1.1.1.2.129 reason="idle Timeout" source-address="172.17.165.245"] session closed`},
		{"filterlog", "40,,,1000000117,em1,match,pass,out,4,0x0,,118,358,0,DF,6,tcp"},
	} {
		e := store.Entry{Host: "h", AppName: c.app, Msg: c.msg}
		Default().Apply(&e)
		if e.AppName != c.app || e.Msg != c.msg || e.Host != "h" {
			t.Errorf("%s: got app %q host %q msg %q", c.app, e.AppName, e.Host, e.Msg)
		}
	}
	// Juniper structured data, folded into the message by syslog-ng, is
	// picked up by the generic parser.
	e := store.Entry{AppName: "RT_FLOW", Msg: `[junos@2636.1.1.1.2.129 reason="idle Timeout" source-address="172.17.165.245"] session closed`}
	Default().Apply(&e)
	if s := structured(t, &e); s["source-address"] != "172.17.165.245" || s["reason"] != "idle Timeout" {
		t.Errorf("junos structured data not extracted: %v", s)
	}
}

// Any other headerless key=value device gets its first pair back.
func TestRepairGenericKV(t *testing.T) {
	e := store.Entry{Host: "10.1.1.1", AppName: "device=ups-3", Msg: "event=on_battery load=41"}
	Default().Apply(&e)
	if e.AppName != "" || e.Msg != "device=ups-3 event=on_battery load=41" {
		t.Errorf("got app %q msg %q", e.AppName, e.Msg)
	}
	if s := structured(t, &e); s["device"] != "ups-3" || s["load"] != "41" {
		t.Errorf("structured = %v", s)
	}
}
