// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestMagicsockReceiveFuncECONNABORTED verifies that magicsock recovers from an
// ECONNABORTED error on its UDP receive socket. Without recovery, the receive
// func exits and direct connectivity is lost while DERP remains available.
//
// The test first establishes a direct path between two Ubuntu VMs, then uses
// `ss -K` on one node to inject the error. It waits for health to report the
// stopped receive func and verifies DERP fallback before requiring the direct
// path to recover and the health warning to clear.
//
// Ubuntu is used because the test needs a root shell in the guest to run
// `ss -K`.
func TestMagicsockReceiveFuncECONNABORTED(t *testing.T) {
	env := vmtest.New(t)

	netA := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	netB := env.AddNetwork("2.2.2.2", "192.168.2.1/24", vnet.EasyNAT)

	victim := env.AddNode("victim", netA, vmtest.OS(vmtest.Ubuntu2404))
	peer := env.AddNode("peer", netB, vmtest.OS(vmtest.Ubuntu2404))

	// Declare test-specific steps for the web UI.
	directStep := env.AddStep("Establish healthy direct UDP path")
	abortStep := env.AddStep("Abort victim UDP sockets")
	warningStep := env.AddStep("Observe magicsock receive-func warning")
	derpStep := env.AddStep("Verify DERP fallback")
	recoverStep := env.AddStep("Recover direct UDP path")
	clearWarningStep := env.AddStep("Clear magicsock receive-func warning")

	env.Start()

	// Verify the direct UDP path and receive-func health before injecting the
	// error.
	directStep.Begin()
	if err := env.PingExpect(victim, peer, vmtest.PingRouteDirect, 60*time.Second); err != nil {
		directStep.Fatalf("expected direct connection before break: %v", err)
	}
	if hasReceiveFuncWarning(t, env.Status(victim).Health) {
		directStep.Fatalf("magicsock receive-func warning present before we broke anything")
	}
	directStep.End(nil)

	// `ss -K` is one-shot: Linux's SOCK_DESTROY path reports ECONNABORTED to the
	// blocked receiver and returns. The persistent failure occurs if magicsock's
	// receive func exits in response; `ss` does not keep killing sockets.
	//
	// tailscaled uses an ephemeral UDP port in natlab, so find its current ports
	// before selecting the sockets to kill.
	abortStep.Begin()
	out, err := env.SSHExec(victim, `set -eu
ports=$(ss -H -u -a -n -p | awk '/users:\(\("tailscaled",/ { addr=$4; sub(/^.*:/, "", addr); print addr }' | sort -u)
test -n "$ports"
for port in $ports; do
	ss -K -u -a "sport = :$port"
done`)
	t.Logf("ss -K output: %s", out)
	if err != nil {
		abortStep.Fatalf("ss -K on victim: %v (out=%s)", err, out)
	}
	abortStep.End(nil)

	// Health checks run about once per minute and may need two checks to detect
	// the stopped receive func. The third minute allows for VM scheduling jitter.
	warningStep.Begin()
	if err := tstest.WaitFor(3*time.Minute, func() error {
		if hasReceiveFuncWarning(t, env.Status(victim).Health) {
			return nil
		}
		return errors.New("no receive-func warning yet")
	}); err != nil {
		warningStep.Fatalf("magicsock receive-func warning never appeared after ss -K: %v", err)
	}
	t.Log("observed magicsock receive-func health warning after ss -K")
	warningStep.End(nil)

	// Verify that TCP-based DERP remains available while the direct receive path
	// is unavailable.
	derpStep.Begin()
	if err := env.PingExpect(victim, peer, vmtest.PingRouteDERP, 60*time.Second); err != nil {
		derpStep.Fatalf("expected DERP reachability after UDP sockets aborted: %v", err)
	}
	t.Log("victim still reachable via DERP")
	derpStep.End(nil)

	// Direct connectivity requires the receive func to resume so the victim can
	// receive the return disco pong.
	recoverStep.Begin()
	if err := env.PingExpect(victim, peer, vmtest.PingRouteDirect, 45*time.Second); err != nil {
		recoverStep.Fatalf("direct path did not recover after UDP sockets were aborted: %v", err)
	}
	t.Log("direct path self-healed")
	recoverStep.End(nil)

	// The next health check should clear the warning once receiving resumes.
	clearWarningStep.Begin()
	if err := tstest.WaitFor(3*time.Minute, func() error {
		if hasReceiveFuncWarning(t, env.Status(victim).Health) {
			return errors.New("receive-func warning still present")
		}
		return nil
	}); err != nil {
		clearWarningStep.Fatalf("magicsock receive-func warning did not clear after recovery: %v", err)
	}
	t.Log("receive-func warning cleared after recovery")
	clearWarningStep.End(nil)
}

// hasReceiveFuncWarning reports whether health contains the magicsock
// receive-func warning.
func hasReceiveFuncWarning(t *testing.T, health []string) bool {
	t.Helper()
	for _, h := range health {
		if strings.Contains(h, "MagicSock function") && strings.Contains(h, "is not running") {
			return true
		}
	}
	return false
}
