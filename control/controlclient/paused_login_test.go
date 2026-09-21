// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/hostinfo"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
)

// recordingTransport records each control plane request the client makes, then
// fails it. These tests only check whether the client tried to reach control,
// so they don't need a control server.
type recordingTransport struct {
	attempts chan string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	select {
	case rt.attempts <- r.URL.String():
	default:
	}
	return nil, errors.New("recordingTransport: no control server in this test")
}

// logWatcher captures client logs and lets a test block until the client logs
// a particular line. Waiting for a line that was already logged returns at once.
type logWatcher struct {
	mu      sync.Mutex
	lines   []string
	waiters map[string]chan struct{}
}

func newLogWatcher() *logWatcher {
	return &logWatcher{waiters: map[string]chan struct{}{}}
}

func (w *logWatcher) logf(format string, args ...any) {
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

// wait blocks until the client logs a line containing substr, and fails the
// test if that takes longer than d.
func (w *logWatcher) wait(t *testing.T, substr string, d time.Duration) {
	t.Helper()
	w.mu.Lock()
	for _, l := range w.lines {
		if strings.Contains(l, substr) {
			w.mu.Unlock()
			return
		}
	}
	ch := make(chan struct{})
	w.waiters[substr] = ch
	w.mu.Unlock()

	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("timed out after %v waiting for a log line containing %q; got:\n%s",
			d, substr, w.dump())
	}
}

func (w *logWatcher) dump() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return "\t" + strings.Join(w.lines, "\n\t")
}

// newLoginTestClient returns a started Auto client that cannot reach any real
// network, along with a channel that receives the URL of each control plane
// request it attempts.
func newLoginTestClient(t *testing.T, w *logWatcher) (*Auto, chan string) {
	t.Helper()

	attempts := make(chan string, 8)
	httpc := &http.Client{Transport: &recordingTransport{attempts: attempts}}
	mk := key.NewMachine()

	c, err := New(Options{
		ServerURL: "https://control.invalid",
		Hostinfo:  hostinfo.New(),
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return mk, nil
		},
		HTTPTestClient:  httpc,
		NoiseTestClient: httpc,
		Dialer:          tsdial.NewDialer(netmon.NewStatic()),
		Bus:             eventbustest.NewBus(t),
		Logf:            w.logf,

		SkipStartForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Shutdown)

	c.StartForTest()
	return c, attempts
}

// pause pauses the client the way LocalBackend does when the user disconnects
// and sets WantRunning=false. It returns once authRoutine has parked itself in
// waitUnpause.
//
// It first waits for authRoutine to log that it has no login goal. By then
// authRoutine holds the auth context it is about to block on. Pausing any
// earlier races with it. authRoutine can get past waitUnpause, pick up the
// fresh context that SetPaused installs, and block on a context nobody will
// cancel. It never logs that it is awaiting unpause, and pause times out.
func pause(t *testing.T, c *Auto, w *logWatcher) {
	t.Helper()
	w.wait(t, "authRoutine: loggedIn=false; goal=nil", 15*time.Second)
	c.SetPaused(true)
	w.wait(t, "authRoutine: awaiting unpause", 15*time.Second)
}

// TestInteractiveLoginWhilePausedIsNotStranded checks that Auto acts on an
// interactive login requested while it is paused.
//
// This reproduces a hang seen on the macOS client. After an app update the
// profile was stopped but logged in. WantRunning was false, so LocalBackend had
// called SetPaused(true). When the user pressed Connect, the GUI started a
// reauth flow that POSTed to /localapi/v0/login-interactive without setting
// WantRunning, reaching Auto.Login(LoginInteractive) on a paused client.
//
// Auto.Login stores the goal and cancels the auth and map contexts, but does
// not unpause. authRoutine is blocked in waitUnpause on a channel that only
// SetPaused(false) feeds, so it never reaches the code that reads c.loginGoal.
// The login is stranded. The user gets no auth URL, no error, no status update
// and no timeout. On macOS the connect toggle stays greyed out until something
// else sets WantRunning=true, which unpauses the client as a side effect.
//
// Nothing here is macOS-specific. The CLI doesn't hit it because
// `tailscale login` sets WantRunning, which unpauses the client. Any caller
// that requests an interactive login without also starting the backend will.
//
// With the current Auto.Login, this test fails with a timeout.
func TestInteractiveLoginWhilePausedIsNotStranded(t *testing.T) {
	w := newLogWatcher()
	c, attempts := newLoginTestClient(t, w)
	pause(t, c, w)

	// The GUI's reauth path: interactive login, no change to WantRunning.
	c.Login(LoginInteractive)

	select {
	case <-attempts:
		// authRoutine woke, read the goal, and tried to reach control.
	case <-time.After(10 * time.Second):
		t.Fatalf("interactive login was stranded: no control plane attempt within 10s "+
			"of Login(LoginInteractive) on a paused client.\nclient logs:\n%s", w.dump())
	}
}

// TestInteractiveLoginWhenNotPausedReachesControl is a positive control for the
// test above. It runs the same setup against a client that was never paused,
// where the login should go through.
//
// It passes no matter how Login treats paused clients. If it fails, the test
// setup is broken, and a failure above says nothing about the bug.
func TestInteractiveLoginWhenNotPausedReachesControl(t *testing.T) {
	w := newLogWatcher()
	c, attempts := newLoginTestClient(t, w)

	c.Login(LoginInteractive)

	select {
	case <-attempts:
	case <-time.After(10 * time.Second):
		t.Fatalf("no control plane attempt within 10s of Login(LoginInteractive) "+
			"on a running client.\nclient logs:\n%s", w.dump())
	}
}

// TestLoginWhilePausedRecoversOnUnpause documents how users get out of this by
// accident. authRoutine picks up the stranded goal as soon as something
// unpauses the client. On macOS, that's the connect toggle setting
// WantRunning=true.
//
// It only checks that the client reaches control after being unpaused, so it
// passes both before and after any fix to Login.
func TestLoginWhilePausedRecoversOnUnpause(t *testing.T) {
	w := newLogWatcher()
	c, attempts := newLoginTestClient(t, w)
	pause(t, c, w)

	c.Login(LoginInteractive)

	// What the connect toggle ends up doing.
	c.SetPaused(false)

	select {
	case <-attempts:
	case <-time.After(10 * time.Second):
		t.Fatalf("login goal was not picked up within 10s of unpausing.\nclient logs:\n%s",
			w.dump())
	}
}
