//go:build linux

package torrent

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// soBindToDevice is SO_BINDTODEVICE (Linux). Pinning a socket to a device
// forces all its traffic to leave (and arrive) on that interface: when the VPN
// tunnel dies the socket errors with ENODEV instead of silently failing over to
// the physical NIC — the fix for the gap between "VPN dropped" and "VPN monitor
// pauses everything".
const soBindToDevice = 25

// vpnBindDialer dials an outgoing peer connection with its socket pinned to the
// VPN tunnel device (SO_BINDTODEVICE), so a dead or broken tunnel can never
// route the connection over the physical interface.
type vpnBindDialer struct {
	network string // "tcp4" or "tcp6"
	iface   string
}

func (d vpnBindDialer) DialerNetwork() string { return d.network }

func (d vpnBindDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, soBindToDevice, d.iface)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return dialer.DialContext(ctx, d.network, addr)
}

// vpnBindResolver picks the tunnel interface's unicast IPv4 and IPv6 addresses.
// A family the tunnel has no address for returns nil, letting the caller
// disable that family wholesale so it can never leak over the physical NIC
// (IPv6 in particular tends to bypass tunnel routing).
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
// tunnel interface's address so every listener — inbound connections, the uTP
// socket and the shared DHT socket — is pinned to the tunnel.
func vpnListenHostAddr(network string, v4, v6 net.IP) string {
	if strings.HasSuffix(network, "6") {
		return v6.String()
	}
	return v4.String()
}
