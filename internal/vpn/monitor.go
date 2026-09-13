package vpn

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type VPNStatus struct {
	Connected   bool   `json:"connected"`
	Interface   string `json:"interface"`
	IPAddress   string `json:"ip_address"`
	LastChecked string `json:"last_checked"`
	Reason      string `json:"reason,omitempty"`
}

type PanicFunc func()

// minFailuresToPanic is how many consecutive check cycles the tunnel must fail
// its live traffic probe before it is declared down. A single transient echo
// blip must not park every download, but two missed cycles in a row (outside
// the interface being genuinely down, which panics immediately) is a dead
// tunnel, not noise.
const minFailuresToPanic = 2

type Monitor struct {
	interfaceName string
	checkInterval time.Duration
	ipCheckURL    string
	panicEnabled  bool

	mu                  sync.RWMutex
	status              VPNStatus
	onPanic             PanicFunc
	onRecover           PanicFunc
	panicked            bool
	lastIP              string
	consecutiveFailures int

	// test hooks: default to the real checks; overridden by tests to exercise
	// the panic threshold without touching the network.
	interfaceUp   func() bool
	livenessProbe func() string
}

func NewMonitor(interfaceName, ipCheckURL string, checkInterval time.Duration, panicEnabled bool) *Monitor {
	m := &Monitor{
		interfaceName: interfaceName,
		checkInterval: checkInterval,
		ipCheckURL:    ipCheckURL,
		panicEnabled:  panicEnabled,
		status: VPNStatus{
			Interface: interfaceName,
		},
	}
	m.interfaceUp = m.checkInterface
	m.livenessProbe = m.getExternalIP
	return m
}

func (m *Monitor) SetPanicFunc(fn PanicFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPanic = fn
}

func (m *Monitor) SetRecoverFunc(fn PanicFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onRecover = fn
}

// SetPanicEnabled flips the panic guard live (used by the TUI settings).
// evaluate() reads panicEnabled under the same lock, so the swap is atomic.
func (m *Monitor) SetPanicEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.panicEnabled = enabled
}

func (m *Monitor) Status() VPNStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Monitor) IsPanicked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.panicked
}

func (m *Monitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	m.check()
	m.updateStatus()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check()
			m.updateStatus()
		}
	}
}

func (m *Monitor) check() {
	// An interface that is physically gone is a hard, immediate disconnect.
	ifaceUp := m.interfaceUp()
	if !ifaceUp {
		m.mu.Lock()
		m.consecutiveFailures++
		m.mu.Unlock()
		m.update(false, "", "interface "+m.interfaceName+" is down")
		return
	}

	// The interface is administratively up, but that only proves the tunnel
	// exists — not that it actually carries traffic. A WireGuard device can stay
	// up while its endpoint is unreachable (or the physical uplink is gone),
	// which would silently fail over to the physical NIC. Probe liveness through
	// the tunnel: if the echo services are unreachable the tunnel is dead even
	// though the interface looks healthy.
	ip := m.livenessProbe()
	if ip != "" {
		m.mu.Lock()
		m.consecutiveFailures = 0
		m.mu.Unlock()
		m.update(true, ip, "")
		return
	}

	m.mu.Lock()
	m.consecutiveFailures++
	suspect := m.consecutiveFailures < minFailuresToPanic
	m.mu.Unlock()
	if suspect {
		// First missed probe: keep going for one more cycle so a single blip
		// doesn't pause every download.
		m.update(true, ip, "tunnel reachability probe failed, re-checking")
		return
	}
	m.update(false, ip, "tunnel up but not carrying traffic")
}

func (m *Monitor) update(connected bool, ip, reason string) {
	m.mu.Lock()
	m.status.Connected = connected
	m.status.IPAddress = ip
	m.status.Reason = reason
	m.status.LastChecked = time.Now().Format(time.RFC3339)
	m.lastIP = ip
	m.mu.Unlock()

	m.evaluate(connected)
}

// evaluate engages panic mode whenever the VPN is down (including at startup)
// and clears it automatically once the VPN is back up.
func (m *Monitor) evaluate(connected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !connected && m.panicEnabled && !m.panicked {
		m.panicked = true
		if m.onPanic != nil {
			log.Printf("VPN DOWN — panic mode engaged")
			go m.onPanic()
		}
	} else if connected && m.panicked {
		m.panicked = false
		if m.onRecover != nil {
			log.Printf("VPN UP — panic mode cleared")
			go m.onRecover()
		}
	}
}

func (m *Monitor) checkInterface() bool {
	iface, err := net.InterfaceByName(m.interfaceName)
	if err != nil {
		return false
	}
	return iface.Flags&net.FlagUp != 0
}

func (m *Monitor) getExternalIP() string {
	// The configured probe first (the operator's choice of echo service),
	// then the standard fallbacks.
	services := []string{
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://ipinfo.io/ip",
	}
	if m.ipCheckURL != "" {
		services = append([]string{m.ipCheckURL}, services...)
	}

	for _, url := range services {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			continue
		}

		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()

		ip := strings.TrimSpace(string(buf[:n]))
		// Validate: should be a valid IP, not HTML
		if len(ip) > 46 || strings.Contains(ip, "<") {
			continue
		}
		// Basic IP validation
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func (m *Monitor) updateStatus() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	log.Printf("VPN status: connected=%v ip=%s interface=%s reason=%s", m.status.Connected, m.status.IPAddress, m.status.Interface, m.status.Reason)
}

func (m *Monitor) ManualPanic() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.panicked {
		m.panicked = true
		if m.onPanic != nil {
			go m.onPanic()
		}
	}
}
