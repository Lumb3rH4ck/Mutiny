package vpn

import (
	"testing"
	"time"
)

func waitFor(t *testing.T, name string, ch chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected %s callback to fire", name)
	}
}

func TestPanicEngagesWhenVPNDownAtStartup(t *testing.T) {
	m := &Monitor{panicEnabled: true, checkInterval: time.Second}
	panicked := make(chan struct{})
	m.SetPanicFunc(func() { close(panicked) })

	m.evaluate(false)

	if !m.IsPanicked() {
		t.Fatal("expected panic mode engaged while VPN is down")
	}
	waitFor(t, "onPanic", panicked)
}

func TestPanicDoesNotEngageWhenVPNUp(t *testing.T) {
	m := &Monitor{panicEnabled: true, checkInterval: time.Second}
	m.evaluate(true)
	if m.IsPanicked() {
		t.Fatal("expected no panic while VPN is up")
	}
}

func TestPanicClearsWhenVPNReturns(t *testing.T) {
	m := &Monitor{panicEnabled: true, checkInterval: time.Second}
	recovered := make(chan struct{})
	m.SetRecoverFunc(func() { close(recovered) })

	m.evaluate(false)
	if !m.IsPanicked() {
		t.Fatal("precondition: panic not engaged")
	}

	m.evaluate(true)
	if m.IsPanicked() {
		t.Fatal("expected panic to clear once VPN is back up")
	}
	waitFor(t, "onRecover", recovered)
}

func TestPanicDoesNotEngageWhenDisabled(t *testing.T) {
	m := &Monitor{panicEnabled: false, checkInterval: time.Second}
	m.evaluate(false)
	if m.IsPanicked() {
		t.Fatal("expected no panic when panic_enabled is false")
	}
}

func TestPanicPersistsWhileVPNStillDown(t *testing.T) {
	m := &Monitor{panicEnabled: true, checkInterval: time.Second}
	panicked := make(chan struct{})
	m.SetPanicFunc(func() { panicked <- struct{}{} })

	m.evaluate(false)
	waitFor(t, "onPanic (first)", panicked)

	m.evaluate(false)
	select {
	case <-panicked:
		t.Fatal("expected onPanic to fire only once while VPN stays down")
	case <-time.After(50 * time.Millisecond):
	}
	if !m.IsPanicked() {
		t.Fatal("expected panic to stay engaged")
	}
}

// TestTunnelDeadButUpPanicsAfterThreshold verifies a tunnel whose interface is
// administratively up but which fails its traffic probe is treated as dead
// (panic) after the consecutive-failure threshold, not on a single transient
// blip.
func TestTunnelDeadButUpPanicsAfterThreshold(t *testing.T) {
	m := NewMonitor("wg0", "", time.Second, true)
	m.interfaceUp = func() bool { return true }
	m.livenessProbe = func() string { return "" }
	panicked := make(chan struct{})
	m.SetPanicFunc(func() { close(panicked) })

	m.check()
	if m.IsPanicked() {
		t.Fatal("a single probe failure should not yet panic")
	}
	if !m.Status().Connected {
		t.Fatal("a single probe failure should keep status connected")
	}

	m.check()
	if !m.IsPanicked() {
		t.Fatal("dead-but-up tunnel must panic once the threshold is hit")
	}
	waitFor(t, "onPanic", panicked)
}

// TestInterfaceDownPanicsImmediately verifies a genuinely gone interface still
// panics on the first check (no threshold).
func TestInterfaceDownPanicsImmediately(t *testing.T) {
	m := NewMonitor("wg0", "", time.Second, true)
	m.interfaceUp = func() bool { return false }
	m.livenessProbe = func() string { return "" }
	panicked := make(chan struct{})
	m.SetPanicFunc(func() { close(panicked) })

	m.check()
	if !m.IsPanicked() {
		t.Fatal("interface down must panic on the first check")
	}
	waitFor(t, "onPanic", panicked)
	if reason := m.Status().Reason; reason == "" {
		t.Fatal("expected a reason explaining the disconnect")
	}
}

// TestTunnelRecoveryClearsPanicAndResetsThreshold verifies recovery on the
// first live probe, and that the failure counter is reset so a later single
// blip doesn't re-panic immediately.
func TestTunnelRecoveryClearsPanicAndResetsThreshold(t *testing.T) {
	m := NewMonitor("wg0", "", time.Second, true)
	m.interfaceUp = func() bool { return true }
	up := false
	m.livenessProbe = func() string {
		if up {
			return "1.2.3.4"
		}
		return ""
	}

	m.check()
	m.check()
	if !m.IsPanicked() {
		t.Fatal("expected panic after threshold")
	}
	if reason := m.Status().Reason; reason != "tunnel up but not carrying traffic" {
		t.Fatalf("unexpected panic reason: %q", reason)
	}

	up = true
	m.check()
	if m.IsPanicked() {
		t.Fatal("expected panic to clear once the tunnel carries traffic again")
	}

	// One more miss must not re-panic: the counter was reset on recovery.
	up = false
	m.check()
	if m.IsPanicked() {
		t.Fatal("failure counter should reset on recovery — one miss must not re-panic")
	}
}
