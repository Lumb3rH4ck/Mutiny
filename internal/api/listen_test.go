package api

import (
	"net"
	"reflect"
	"testing"
)

func cidrAddr(t *testing.T, c string) net.Addr {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(c)
	if err != nil {
		t.Fatalf("bad cidr %q: %v", c, err)
	}
	return &net.IPNet{IP: ip, Mask: ipnet.Mask}
}

func TestListenAddrsLoopbackOnly(t *testing.T) {
	got := listenAddrs("127.0.0.1", 3030, false, false, func() ([]ifaceInfo, error) {
		return nil, nil
	})
	want := []string{"127.0.0.1:3030"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loopback-only = %v, want %v", got, want)
	}
}

func TestListenAddrsLANAndTailscale(t *testing.T) {
	get := func() ([]ifaceInfo, error) {
		return []ifaceInfo{
			{name: "wlo1", flags: net.FlagUp, addrs: []net.Addr{cidrAddr(t, "192.168.68.114/24")}},
			{name: "tailscale0", flags: net.FlagUp, addrs: []net.Addr{cidrAddr(t, "100.100.100.5/32")}},
			// tunnel + virtual interfaces must never receive the bind
			{name: "surfshark_wg", flags: net.FlagUp, addrs: []net.Addr{cidrAddr(t, "10.14.0.2/32")}},
			{name: "docker0", flags: net.FlagUp, addrs: []net.Addr{cidrAddr(t, "172.17.0.1/16")}},
			{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []net.Addr{cidrAddr(t, "127.0.0.1/8")}},
		}, nil
	}
	got := listenAddrs("127.0.0.1", 3030, true, true, get)
	want := []string{"100.100.100.5:3030", "127.0.0.1:3030", "192.168.68.114:3030"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("addrs = %v, want %v", got, want)
	}
}

func TestListenAddrsTailscaleOnly(t *testing.T) {
	get := func() ([]ifaceInfo, error) {
		return []ifaceInfo{
			{name: "wlo1", flags: net.FlagUp, addrs: []net.Addr{cidrAddr(t, "192.168.68.114/24")}},
			{name: "tailscale0", flags: net.FlagUp, addrs: []net.Addr{cidrAddr(t, "100.100.100.5/32")}},
		}, nil
	}
	got := listenAddrs("127.0.0.1", 3030, false, true, get)
	want := []string{"100.100.100.5:3030", "127.0.0.1:3030"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("addrs = %v, want %v", got, want)
	}
}

func TestListenAddrsWildcardCoversEverything(t *testing.T) {
	// A wildcard admin host alone binds every interface the toggles would add.
	got := listenAddrs("0.0.0.0", 3030, true, true, nil)
	want := []string{"0.0.0.0:3030"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wildcard = %v, want %v", got, want)
	}
}

func TestClassifyInterface(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want string
	}{
		{"wlo1", "192.168.68.114", "lan"},
		{"eth0", "10.1.2.3", "lan"},
		{"tailscale0", "100.100.100.5", "ts"},
		{"utun100", "100.90.90.9", "ts"}, // CGNAT fallback catches tunnel names too
		{"surfshark_wg", "10.14.0.2", ""},
		{"docker0", "172.17.0.1", ""},
		{"veth1234", "172.18.0.2", ""},
		{"br-abc", "172.19.0.1", ""},
		{"wlo1", "8.8.8.8", ""},       // public address: not bound as "internal"
		{"lo", "127.0.0.1", ""},       // loopback handled elsewhere, never classified
		{"eno2", "169.254.1.1", ""},   // link-local, not global unicast
	}
	for _, c := range cases {
		if got := classifyInterface(c.name, net.ParseIP(c.ip)); got != c.want {
			t.Fatalf("classifyInterface(%q, %q) = %q, want %q", c.name, c.ip, got, c.want)
		}
	}
}