// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine"
)

// recordingRoundTripper records each control plane request the control client
// makes, then fails it. These tests only check whether the client tried to
// reach control, so they don't need a control server.
type recordingRoundTripper struct {
	attempts chan string
}

func (rt *recordingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	select {
	case rt.attempts <- r.URL.String():
	default:
	}
	return nil, errors.New("recordingRoundTripper: no control server in this test")
}

// authLogWatcher captures control client logs so a test can block until the
// client logs a particular line. Waiting for a line that was already logged
// returns at once.
type authLogWatcher struct {
	mu      sync.Mutex
	lines   []string
	waiters map[string]chan struct{}
}

func (w *authLogWatcher) logf(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, s)
	for substr, ch := range w.waiters {
		if strings.Contains(s, substr) {
			close(ch)
			delete(w.waiters, substr)
		}
	}
}

func (w *authLogWatcher) wait(t *testing.T, substr string, d time.Duration) {
	t.Helper()
	w.mu.Lock()
	for _, l := range w.lines {
		if strings.Contains(l, substr) {
			w.mu.Unlock()
			return
		}
	}
	if w.waiters == nil {
		w.waiters = map[string]chan struct{}{}
	}
	ch := make(chan struct{})
	w.waiters[substr] = ch
	w.mu.Unlock()

	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("timed out after %v waiting for a control client log line containing %q", d, substr)
	}
}

// stoppedBackend is a [LocalBackend] with a real [controlclient.Auto], put in
// the state a macOS client is in right after an app update. It is logged in and
// has a netmap, but it is stopped with WantRunning=false because the user
// disconnected before updating. In that state LocalBackend pauses the control
// client.
type stoppedBackend struct {
	b        *LocalBackend
	attempts chan string
}

// drainAttempts discards any control plane attempts recorded so far.
func (sb *stoppedBackend) drainAttempts() {
	for {
		select {
		case <-sb.attempts:
		default:
			return
		}
	}
}

// awaitAttempt reports whether the control client attempts to reach the control
// plane within d.
func (sb *stoppedBackend) awaitAttempt(d time.Duration) bool {
	select {
	case <-sb.attempts:
		return true
	case <-time.After(d):
		return false
	}
}

func newStoppedBackendWithRealClient(t *testing.T) *stoppedBackend {
	t.Helper()

	logf := tstest.WhileTestRunningLogger(t)
	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	sys.Set(new(testStateStorage))
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(),
		sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(e.Close)
	sys.Set(e)

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(b.Shutdown)

	attempts := make(chan string, 64)
	httpc := &http.Client{Transport: &recordingRoundTripper{attempts: attempts}}
	w := new(authLogWatcher)

	var (
		mu     sync.Mutex
		cc     *controlclient.Auto
		ccOpts controlclient.Options
	)
	b.ForTest().SetControlClientGetter(func(opts controlclient.Options) (controlclient.Client, error) {
		opts.HTTPTestClient = httpc
		opts.NoiseTestClient = httpc
		inner := opts.Logf
		opts.Logf = func(format string, args ...any) {
			w.logf(format, args...)
			if inner != nil {
				inner(format, args...)
			}
		}
		c, err := controlclient.New(opts)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		cc, ccOpts = c, opts
		mu.Unlock()
		return c, nil
	})

	if err := b.Start(ipn.Options{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	mu.Lock()
	gotCC := cc != nil
	mu.Unlock()
	if !gotCC {
		t.Fatal("LocalBackend.Start did not create a control client")
	}

	// Log in and get a netmap, like a client that has already been running.
	// There is no control server, so hand the login result to LocalBackend
	// directly, the way the control client would.
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: true},
	})
	nm := buildNetmapWithPeers(makePeer(1,
		withName("self"),
		withAddresses(netip.MustParsePrefix("100.64.1.1/32")),
		withAllowedIPs(netip.MustParsePrefix("100.64.1.1/32")),
	))
	mu.Lock()
	p := ccOpts.Persist.Clone()
	observer := ccOpts.Observer
	client := cc
	mu.Unlock()
	p.PrivateNodeKey = key.NewNode()
	if u, ok := nm.UserProfiles[nm.SelfNode.User()]; ok {
		p.UserProfile = *u.AsStruct()
	}
	p.NodeID = nm.SelfNode.StableID()
	observer.SetControlClientStatus(client, controlclient.Status{
		NetMap:   nm,
		Persist:  p.View(),
		LoggedIn: true,
	})
	if b.NetMapNoPeers() == nil {
		t.Fatal("fixture: backend has no netmap after simulated login")
	}

	// The user disconnects before updating. LocalBackend pauses the control
	// client because state==Stopped and a netmap is loaded.
	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: false},
	})
	if st := b.State(); st != ipn.Stopped {
		t.Fatalf("fixture: state = %v; want Stopped", st)
	}
	w.wait(t, "setPaused(true)", 10*time.Second)
	w.wait(t, "authRoutine: awaiting unpause", 30*time.Second)

	// The control client is now parked. Discard attempts from before the
	// pause and check that it has gone quiet, so any later attempt comes from
	// what the test does next.
	sb := &stoppedBackend{b: b, attempts: attempts}
	sb.drainAttempts()
	if sb.awaitAttempt(300 * time.Millisecond) {
		t.Fatal("fixture: control client is still contacting control while paused")
	}
	return sb
}

// TestStartLoginInteractiveWhileStoppedReachesControl checks that when a
// stopped backend gets an interactive login request, the control client tries
// to log in.
//
// This is the end-to-end form of a hang seen on the macOS client. After an app
// update the profile was stopped but logged in. When the user pressed Connect,
// the GUI started a reauth flow that POSTed to /localapi/v0/login-interactive
// without setting WantRunning.
//
// LocalBackend pauses the control client whenever state==Stopped and a netmap
// is loaded, per shouldPauseControlClientLocked. StartLoginInteractiveAs then
// calls cc.Login(LoginInteractive) without unpausing it. In
// [controlclient.Auto], Login stores the goal, but authRoutine is parked in
// waitUnpause and never reads it. The login is stranded. The user gets no auth
// URL, no error and no timeout. TestInteractiveLoginWhilePausedIsNotStranded in
// control/controlclient is the unit-level form.
//
// This test uses the real control client instead of mockControl.
// mockControl.Login ignores pause state, so it can't see the bug. The same gap
// hides the bug from TestStateMachine. Its "LoginDifferent" step starts an
// interactive login while Stopped and hand-injects the auth URL, so it passes
// even though the real client would never produce that URL.
//
// LoginDifferent also limits the fix. It requires that an interactive login
// while Stopped reaches cc.Login and leaves the client paused. Returning an
// error from StartLoginInteractive breaks it, and so does unpausing from
// LocalBackend. A fix inside controlclient that lets authRoutine act on an
// interactive login while paused doesn't break it. This test doesn't care where
// the fix lives. It passes if the login reaches control, or if
// StartLoginInteractive tells the caller it can't proceed.
func TestStartLoginInteractiveWhileStoppedReachesControl(t *testing.T) {
	sb := newStoppedBackendWithRealClient(t)

	if err := sb.b.StartLoginInteractive(context.Background()); err != nil {
		// The caller got an error, so the GUI can show it instead of leaving
		// the toggle greyed out forever. The test accepts this so it doesn't
		// dictate the fix, but see the note above about LoginDifferent.
		t.Logf("StartLoginInteractive reported: %v", err)
		return
	}

	if !sb.awaitAttempt(10 * time.Second) {
		t.Fatalf("interactive login was stranded: StartLoginInteractive returned nil, " +
			"but the control client made no attempt to reach control within 10s")
	}
}

// TestStartLoginInteractiveWhileStoppedThenConnect documents how users get out
// of this by accident. Setting WantRunning=true unpauses the control client,
// which then contacts control.
//
// A fix never makes it fail. Once the login stops getting stranded, it skips.
// It shows that the login is stranded, not lost, and keeps the test above
// honest.
func TestStartLoginInteractiveWhileStoppedThenConnect(t *testing.T) {
	sb := newStoppedBackendWithRealClient(t)

	if err := sb.b.StartLoginInteractive(context.Background()); err != nil {
		t.Skipf("backend rejected the interactive login (%v); nothing is stranded", err)
	}
	if sb.awaitAttempt(500 * time.Millisecond) {
		t.Skip("login reached control without connecting; the stranding no longer occurs")
	}

	// What the connect toggle does.
	sb.b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs:          ipn.Prefs{WantRunning: true},
	})

	if !sb.awaitAttempt(10 * time.Second) {
		t.Fatal("control client did not contact control within 10s of connecting")
	}
}
