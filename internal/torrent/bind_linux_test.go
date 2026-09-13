//go:build linux

package torrent

import (
	"net"
	"testing"
)

// TestVPNBindResolverUsable rejects loopback-only interfaces but resolves a
// real unicast address on an up interface.
func TestVPNBindResolverUsable(t *testing.T) {
	if _, _, err := vpnBindResolver("lo"); err == nil {
		t.Fatalf("loopback-only interface should be rejected as unusable, got no error")
	}

	var iface string
	ifs, _ := net.Interfaces()
	for _, ni := range ifs {
		if ni.Flags&net.FlagUp == 0 {
			continue
		}
		if _, _, err := vpnBindResolver(ni.Name); err == nil {
			iface = ni.Name
			break
		}
	}
	if iface == "" {
		t.Skip("no up interface with a usable unicast address; nothing to assert")
	}
	v4, v6, err := vpnBindResolver(iface)
	if err != nil {
		t.Fatalf("vpnBindResolver(%q): %v", iface, err)
	}
	if v4 == nil && v6 == nil {
		t.Fatalf("vpnBindResolver(%q) resolved to nothing", iface)
	}
}

// TestVPNBindResolverMissing fails closed for an interface that doesn't exist.
func TestVPNBindResolverMissing(t *testing.T) {
	if _, _, err := vpnBindResolver("definitely-not-an-interface-mutiny-test"); err == nil {
		t.Fatal("missing interface should error (fail closed), got nil")
	}
}

// TestVPNListenHostAddr pins the listen host to the right family's address.
func TestVPNListenHostAddr(t *testing.T) {
	v4 := net.ParseIP("10.8.0.2")
	v6 := net.ParseIP("fd00::2")
	if got := vpnListenHostAddr("tcp4", v4, v6); got != "10.8.0.2" {
		t.Fatalf("tcp4 -> %q, want 10.8.0.2", got)
	}
	if got := vpnListenHostAddr("udp6", v4, v6); got != "fd00::2" {
		t.Fatalf("udp6 -> %q, want fd00::2", got)
	}
}

// TestVPNBindDialerNetwork checks the two injected dialers advertise the right
// address families so DialFirst routes outbound TCP to them.
func TestVPNBindDialerNetwork(t *testing.T) {
	for _, n := range []string{"tcp4", "tcp6"} {
		d := vpnBindDialer{network: n, iface: "wg0"}
		if got := d.DialerNetwork(); got != n {
			t.Fatalf("DialerNetwork() = %q, want %q", got, n)
		}
	}
}
