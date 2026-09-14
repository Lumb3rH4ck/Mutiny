//go:build windows

package torrent

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// vpnBindDialer dials an outgoing peer connection. On Windows there is no
// SO_BINDTODEVICE equivalent, so this is a plain dialer — VPN interface pinning
// is not implemented. The user can configure Windows routing or use a
// kill-switch at the VPN application level.
type vpnBindDialer struct {
	network string
	iface   string
}

func (d vpnBindDialer) DialerNetwork() string { return d.network }

func (d vpnBindDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, d.network, addr)
}

// vpnBindResolver picks the tunnel interface's unicast IPv4 and IPv6 addresses.
// A family the tunnel has no address for returns nil, letting the caller
// disable that family wholesale so it can never leak over the physical NIC.
func vpnBindResolver(iface string) (v4, v6 net.IP, err error) {
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("vpn bind interface %q: %w", iface, err)
	}
	addrs, err := ni.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("vpn bind interface %q addrs: %w", iface, err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP
		if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			if v4 == nil {
				v4 = ip4
			}
			continue
		}
		if ip.IsLinkLocalUnicast() {
			continue
		}
		if v6 == nil {
			v6 = ip
		}
	}
	if v4 == nil && v6 == nil {
		return nil, nil, fmt.Errorf("vpn bind interface %q has no usable addresses", iface)
	}
	return v4, v6, nil
}

// vpnListenHostAddr maps an anacrolix listen network ("tcp4"/"udp6"/...) to the
// tunnel interface's address so every listener is pinned to the tunnel.
func vpnListenHostAddr(network string, v4, v6 net.IP) string {
	if strings.HasSuffix(network, "6") {
		return v6.String()
	}
	return v4.String()
}
