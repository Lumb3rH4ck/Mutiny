package api

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// ifaceInfo is the interface data the bind resolution needs; a plain struct so
// tests can synthesize networks without the syscall-backed net.Interface.Addrs.
type ifaceInfo struct {
	name  string
	flags net.Flags
	addrs []net.Addr
}

// currentIfaces enumerates the host interfaces, converting to ifaceInfo for the
// address resolution.
func currentIfaces() ([]ifaceInfo, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]ifaceInfo, 0, len(ifs))
	for _, i := range ifs {
		as, err := i.Addrs()
		if err != nil {
			continue
		}
		out = append(out, ifaceInfo{name: i.Name, flags: i.Flags, addrs: as})
	}
	return out, nil
}

// listenAddrs resolves the addresses the API + web UI bind to.
//
// The loopback/admin address (default 127.0.0.1, from config `host`) is always
// included. With lan enabled, each of the host's private LAN addresses is added;
// with ts enabled (Tailscale), the tailnet interface addresses are added.
// Virtual/tunnel interfaces (docker, veth, bridge, wg, tun, ...) are never
// exposed — a hostile sample or container must not reach the management UI.
func listenAddrs(host string, port int, lan, ts bool, get func() ([]ifaceInfo, error)) []string {
	addrs := map[string]struct{}{}
	add := func(ip string) {
		addrs[net.JoinHostPort(ip, strconv.Itoa(port))] = struct{}{}
	}

	// A wildcard host already covers every interface — explicit toggles are
	// redundant and would race the wildcard socket for the same port on Linux.
	if host == "0.0.0.0" || host == "::" {
		add(host)
		return sortedKeys(addrs)
	}
	add(host)

	if !lan && !ts {
		return sortedKeys(addrs)
	}

	ifs, err := get()
	if err != nil {
		return sortedKeys(addrs)
	}

	for _, ifce := range ifs {
		if ifce.flags&net.FlagUp == 0 || ifce.flags&net.FlagLoopback != 0 {
			continue
		}
		for _, a := range ifce.addrs {
			ip := ipv4(a)
			if ip == nil {
				continue
			}
			switch classifyInterface(ifce.name, ip) {
			case "lan":
				if lan {
					add(ip.String())
				}
			case "ts":
				if ts {
					add(ip.String())
				}
			}
		}
	}
	return sortedKeys(addrs)
}

// ipv4 returns the IPv4 form of an interface address, or nil.
func ipv4(a net.Addr) net.IP {
	var ip net.IP
	switch v := a.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return nil
	}
	return ip.To4()
}

// classifyInterface buckets an interface address for the serving toggles:
// "lan" for the host's private LAN addresses, "ts" for the tailnet, "" for
// anything that must not receive a management listener.
func classifyInterface(name string, ip net.IP) string {
	if ip.IsLoopback() || !ip.IsGlobalUnicast() {
		return ""
	}
	switch {
	case strings.HasPrefix(name, "tailscale"):
		return "ts"
	case ipInRange(ip, "100.64.0.0/10"):
		// Tailscale's default CGNAT range, matched by address as a fallback so
		// a differently-named tailnet interface still binds.
		return "ts"
	}
	if isVirtual(name) {
		return ""
	}
	if isPrivateIP(ip) {
		return "lan"
	}
	return ""
}

// isVirtual reports whether an interface name marks a virtual/tunnel device
// that must never receive the management UI bind (containers, bridges,
// wireguard/openvpn tunnels, taps).
func isVirtual(name string) bool {
	for _, p := range []string{"docker", "veth", "br-", "virbr", "wg", "tun", "utun", "tap", "zt", "ovs", "vmnet"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return strings.Contains(name, "wg")
}

// isPrivateIP reports whether ip is in an RFC1918 private range (10/8, 172.16/12,
// 192.168/16).
func isPrivateIP(ip net.IP) bool {
	return ipInRange(ip, "10.0.0.0/8") || ipInRange(ip, "172.16.0.0/12") || ipInRange(ip, "192.168.0.0/16")
}

// ipInRange reports whether ip falls inside the given CIDR.
func ipInRange(ip net.IP, cidr string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}

// sortedKeys returns map keys in a stable order so bind order (and logs) are
// deterministic.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// describeListenAddrs renders the bind list for the startup log line.
func describeListenAddrs(addrs []string) string {
	if len(addrs) == 1 {
		return "http://" + addrs[0]
	}
	var b strings.Builder
	for i, a := range addrs {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "http://%s", a)
	}
	return b.String()
}