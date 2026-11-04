// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

// Tests for how LocalBackend on Windows reacts when the last LocalAPI client
// disconnects and the same user reconnects shortly afterwards.
//
// Background (field logs, tailscaled 1.104.5, 2026-11-04): after a long
// Modern Standby, the GUI's long-lived IPN bus connection was missing, so
// only short-lived requests arrived. ipnserver calls SetCurrentUser(actor)
// when its active-request count goes 0->1 and SetCurrentUser(nil) on 1->0,
// so every request caused a full Start on the user's profile followed by
// "disconnecting Tailscale" and a full reset. On a ~900-node tailnet each
// cycle rewrote the hosts file and NRPT rules and flushed the DNS cache
// (flushes of up to 45s), for 11-16 minutes at a time. With cheap resets,
// a client of the same user reconnected within 46-432ms of each disconnect.
//
// The tests are in two groups:
//
//   - Expected behavior after a fix (FAIL on current code): a brief gap
//     between requests from the same user must not tear down and restart
//     the backend. The spec used here is a grace period: teardown is deferred
//     after the last client disconnects and cancelled if the same user
//     reconnects within it.
//   - Existing behavior a fix must keep (PASS on current code): long
//     absences still tear down, a different user still gets their own
//     profile immediately, and Unattended Mode still prevents teardown.
//     (The held-connection case is covered end to end in ipnserver.)
//
// Time is controlled with a fake clock, so a fix should schedule deferred
// teardown with b.clock (e.g. b.clock.AfterFunc).

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine"
)

const (
	flapUID       = ipn.WindowsUserID("S-1-5-21-1000000001-1000000002-1000000003-1001")
	otherUID      = ipn.WindowsUserID("S-1-5-21-1000000001-1000000002-1000000003-1002")
	flapCorpLogin = "user@corp.example.com"
	flapHomeLogin = "user@home.example.org"

	// The tests assume a fix's grace period G satisfies
	// minGrace <= G <= maxGrace. Every reconnect is either clearly inside
	// it (quickReconnect, 4x below minGrace) or clearly after it
	// (longAbsence, 2x above maxGrace), never near a timer boundary.
	minGrace = 2 * time.Second
	maxGrace = 30 * time.Second

	// quickReconnect is how soon the same client reconnects after its
	// previous request ended. The largest gap observed in the field with
	// cheap resets was 432ms.
	quickReconnect = 500 * time.Millisecond

	// longAbsence is long enough that the grace period has expired, so the
	// backend must have been torn down.
	longAbsence = 2 * maxGrace
)

func init() {
	if quickReconnect*4 > minGrace || longAbsence < 2*maxGrace {
		panic("windows_client_flap_test: reconnect times too close to grace bounds")
	}
}

const disconnectMsg = "disconnecting Tailscale"

// logCapture is a concurrency-safe [logger.Logf] that records every line.
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCapture) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

// count returns the number of captured lines containing substr.
func (c *logCapture) count(substr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, l := range c.lines {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

// flapEnv is a LocalBackend running as if on Windows with a fake clock and
// two persisted profiles owned by the same OS user: "corp" (the user's
// default) and "home". No client is connected initially.
type flapEnv struct {
	t        *testing.T
	b        *LocalBackend
	clock    *tstest.Clock
	logs     *logCapture
	user     *ipnauth.TestActor
	corp     ipn.LoginProfileView
	home     ipn.LoginProfileView
	ccStarts atomic.Int32 // control clients created; one per backend (re)start
}

func newFlapEnv(t *testing.T, unattended bool) *flapEnv {
	t.Helper()
	envknob.SetenvForTest(t, "TS_DEBUG_FAKE_GOOS", "windows")

	env := &flapEnv{
		t:     t,
		clock: tstest.NewClock(tstest.ClockOpts{Start: time.Date(2026, 11, 4, 14, 17, 32, 0, time.UTC)}),
		logs:  new(logCapture),
		user:  &ipnauth.TestActor{UID: flapUID, Name: `HOST\user`},
	}
	logf := logger.Logf(env.logs.logf)

	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	sys.Set(new(mem.Store))
	e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
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
	b.ForTest().SetClock(env.clock)
	b.ForTest().SetControlClientGetter(func(opts controlclient.Options) (controlclient.Client, error) {
		env.ccStarts.Add(1)
		return newClient(t, opts), nil
	})
	env.b = b

	// Seed two persisted profiles for the same Windows user, the way they
	// exist on disk after logging into two tailnets from the GUI.
	b.mu.Lock()
	pm := b.pm
	pm.SetCurrentUserID(flapUID)
	seed := func(login string, uid tailcfg.UserID, forceDaemon bool) ipn.LoginProfileView {
		pm.SwitchToNewProfileForUser(flapUID)
		p := pm.CurrentPrefs().AsStruct()
		p.WantRunning = true
		p.CorpDNS = true
		p.RouteAll = true
		p.ForceDaemon = forceDaemon
		p.Persist = &persist.Persist{
			UserProfile: tailcfg.UserProfile{ID: uid, LoginName: login},
			NodeID:      tailcfg.StableNodeID("node-" + login),
		}
		if err := pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
			t.Fatalf("SetPrefs(%s): %v", login, err)
		}
		return pm.CurrentProfile()
	}
	env.home = seed(flapHomeLogin, 2, false)
	env.corp = seed(flapCorpLogin, 1, unattended) // seeded last => user's default
	b.mu.Unlock()

	if env.corp.ID() == "" || env.home.ID() == "" || env.corp.ID() == env.home.ID() {
		t.Fatalf("bad seeded profiles: corp=%q home=%q", env.corp.ID(), env.home.ID())
	}

	// No client connected yet (tailscaled just started).
	b.SetCurrentUser(nil)
	return env
}

func (env *flapEnv) currentProfileID() ipn.ProfileID {
	return env.b.CurrentProfile().ID()
}

// connect simulates ipnserver's 0->1 active-request transition for actor.
func (env *flapEnv) connect(actor ipnauth.Actor) { env.b.SetCurrentUser(actor) }

// disconnect simulates ipnserver's 1->0 active-request transition.
func (env *flapEnv) disconnect() { env.b.SetCurrentUser(nil) }

// advance moves the fake clock forward, letting any timers scheduled on
// b.clock fire.
func (env *flapEnv) advance(d time.Duration) { env.clock.Advance(d) }

// counters is a snapshot of the observable cost of backend churn.
type counters struct {
	disconnects int   // "disconnecting Tailscale" log lines (full resets to the empty profile)
	starts      int32 // control clients created (full backend starts)
}

func (env *flapEnv) snapshot() counters {
	return counters{disconnects: env.logs.count(disconnectMsg), starts: env.ccStarts.Load()}
}

func (env *flapEnv) since(base counters) counters {
	now := env.snapshot()
	return counters{disconnects: now.disconnects - base.disconnects, starts: now.starts - base.starts}
}

// waitForProfile polls (in real time) until the current profile ID is want,
// for fixes that tear down asynchronously from a timer callback.
func (env *flapEnv) waitForProfile(want ipn.ProfileID) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if env.currentProfileID() == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return env.currentProfileID() == want
}

// connectedFlapEnv returns an env with the user connected and running on
// corp, i.e. the state just before the GUI's long-lived connection goes away.
func connectedFlapEnv(t *testing.T, unattended bool) *flapEnv {
	t.Helper()
	env := newFlapEnv(t, unattended)
	env.connect(env.user)
	if got := env.currentProfileID(); got != env.corp.ID() {
		t.Fatalf("after connect: profile = %q; want corp %q", got, env.corp.ID())
	}
	return env
}

// ---------------------------------------------------------------------------
// Expected behavior after a fix. These FAIL on current code.
// ---------------------------------------------------------------------------

// TestWindowsQuickReconnectBySameUserKeepsBackend: when the last client
// disconnects and the same user reconnects within quickReconnect, the
// backend must stay on the same profile without a reset or restart.
//
// Current code: one "disconnecting Tailscale" and two control-client
// starts per gap (the teardown to the empty profile, then the restart).
func TestWindowsQuickReconnectBySameUserKeepsBackend(t *testing.T) {
	env := connectedFlapEnv(t, false)
	base := env.snapshot()

	env.disconnect()
	if got := env.currentProfileID(); got != env.corp.ID() {
		t.Errorf("immediately after disconnect: profile = %q; want corp %q (teardown should be deferred)", got, env.corp.ID())
	}
	env.advance(quickReconnect)
	env.connect(env.user)

	if got := env.currentProfileID(); got != env.corp.ID() {
		t.Errorf("after reconnect: profile = %q; want corp %q", got, env.corp.ID())
	}
	if got := env.since(base); got.disconnects != 0 || got.starts != 0 {
		t.Errorf("quick reconnect caused %d resets and %d restarts; want 0 and 0", got.disconnects, got.starts)
	}
}

// TestWindowsPollingWithoutWatcherDoesNotChurn reproduces the field loop:
// with no long-lived connection, the same user's requests arrive one after
// another with short gaps. The backend must not reset or restart at all.
//
// Current code: 10 resets and 20 restarts for 10 requests.
func TestWindowsPollingWithoutWatcherDoesNotChurn(t *testing.T) {
	env := connectedFlapEnv(t, false)
	env.disconnect() // the GUI's long-lived connection goes away
	base := env.snapshot()

	const n = 10
	for i := range n {
		env.advance(quickReconnect)
		env.connect(env.user)
		if got := env.currentProfileID(); got != env.corp.ID() {
			t.Errorf("request %d: profile while connected = %q; want corp %q", i, got, env.corp.ID())
		}
		env.disconnect()
	}
	got := env.since(base)
	t.Logf("%d polled requests %v apart: %d resets, %d restarts", n, quickReconnect, got.disconnects, got.starts)
	if got.disconnects != 0 || got.starts != 0 {
		t.Errorf("polling caused %d resets and %d restarts; want 0 and 0", got.disconnects, got.starts)
	}
}

// TestWindowsPollingAfterDisconnectDoesNotChurn covers the 14:27 part of
// the field logs: during the loop a client set WantRunning=false via
// PATCH /localapi/v0/prefs (most likely the GUI's Disconnect; the logs show
// the request, not who made it), and the loop kept going (~77 cycles in
// ~75s). With a fix, WantRunning=false is kept and polling causes no
// resets or restarts.
func TestWindowsPollingAfterDisconnectDoesNotChurn(t *testing.T) {
	env := connectedFlapEnv(t, false)
	if _, err := env.b.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: false}, WantRunningSet: true}); err != nil {
		t.Fatalf("EditPrefs(WantRunning=false): %v", err)
	}
	env.disconnect()
	base := env.snapshot()

	for range 10 {
		env.advance(quickReconnect)
		env.connect(env.user)
		env.disconnect()
	}
	if got := env.since(base); got.disconnects != 0 || got.starts != 0 {
		t.Errorf("polling after Disconnect caused %d resets and %d restarts; want 0 and 0", got.disconnects, got.starts)
	}
	if env.b.Prefs().WantRunning() {
		t.Errorf("WantRunning = true; want false (WantRunning=false must be kept)")
	}
}

// ---------------------------------------------------------------------------
// Existing behavior a fix must keep. These PASS on current code.
// ---------------------------------------------------------------------------

// TestWindowsLongAbsenceTearsDown: if no client reconnects for longAbsence,
// the backend must end up disconnected ("disconnecting Tailscale" and the
// empty profile), as it does today, just possibly later.
func TestWindowsLongAbsenceTearsDown(t *testing.T) {
	env := connectedFlapEnv(t, false)
	base := env.snapshot()

	env.disconnect()
	env.advance(longAbsence)

	if !env.waitForProfile("") {
		t.Fatalf("%v after the last client disconnected: profile = %q; want empty (disconnected)", longAbsence, env.currentProfileID())
	}
	if got := env.since(base); got.disconnects != 1 {
		t.Errorf("'%s' = %d; want exactly 1", disconnectMsg, got.disconnects)
	}
}

// TestWindowsDifferentUserGetsOwnProfileImmediately: a grace period must
// not let a different Windows user inherit the previous user's profile.
// When another user connects right after the first one disconnects, they
// must get their own profile, not corp.
func TestWindowsDifferentUserGetsOwnProfileImmediately(t *testing.T) {
	env := connectedFlapEnv(t, false)
	other := &ipnauth.TestActor{UID: otherUID, Name: `HOST\other`}

	env.disconnect()
	env.advance(quickReconnect)
	env.connect(other)

	cp := env.b.CurrentProfile()
	if cp.ID() == env.corp.ID() || cp.ID() == env.home.ID() {
		t.Fatalf("other user is on %q (%q); want a profile of their own", cp.ID(), cp.UserProfile().LoginName())
	}
	if got := cp.LocalUserID(); got != otherUID {
		t.Errorf("profile owner = %q; want %q", got, otherUID)
	}
}

// TestWindowsUnattendedModePreventsFlap: with ForceDaemon (Run Unattended),
// a client disconnect keeps the current profile, even when polling.
func TestWindowsUnattendedModePreventsFlap(t *testing.T) {
	env := connectedFlapEnv(t, true)
	base := env.snapshot()

	for i := range 10 {
		env.disconnect()
		env.advance(quickReconnect)
		env.connect(env.user)
		if got := env.currentProfileID(); got != env.corp.ID() {
			t.Fatalf("request %d: profile = %q; want corp %q", i, got, env.corp.ID())
		}
	}
	env.disconnect()
	env.advance(longAbsence)
	if got := env.currentProfileID(); got != env.corp.ID() {
		t.Errorf("after long absence: profile = %q; want corp %q (unattended)", got, env.corp.ID())
	}
	if got := env.since(base); got.disconnects != 0 || got.starts != 0 {
		t.Errorf("got %d resets and %d restarts with unattended mode; want 0 and 0", got.disconnects, got.starts)
	}
}

// TestWindowsReconnectAfterGraceStartsFresh: once the grace period has
// clearly expired and the backend was torn down, the same user's next
// connection must start the backend again on their profile. A fix must not
// leave the backend stuck on the empty profile.
func TestWindowsReconnectAfterGraceStartsFresh(t *testing.T) {
	env := connectedFlapEnv(t, false)

	env.disconnect()
	env.advance(longAbsence)
	if !env.waitForProfile("") {
		t.Fatalf("after %v: profile = %q; want empty (torn down)", longAbsence, env.currentProfileID())
	}
	base := env.snapshot()

	env.connect(env.user)
	if got := env.currentProfileID(); got != env.corp.ID() {
		t.Fatalf("after reconnect: profile = %q; want corp %q", got, env.corp.ID())
	}
	if got := env.since(base); got.starts < 1 {
		t.Errorf("reconnect after teardown: %d restarts; want >= 1", got.starts)
	}
}

// TestWindowsSessionEndDuringGraceTearsDownImmediately: a grace period
// exists to absorb a client's brief reconnect, not to keep a user's tailnet
// up after they leave. If the desktop sessions extension re-resolves the
// profile (e.g. the user's Windows session was closed or locked) while no
// client is connected, the backend must disconnect right away, without
// waiting for the grace period to expire.
func TestWindowsSessionEndDuringGraceTearsDownImmediately(t *testing.T) {
	env := connectedFlapEnv(t, false)

	env.disconnect()                                        // last client goes away; a fix may start a grace period here
	env.advance(quickReconnect)                             // still clearly inside any grace period
	env.b.SwitchToBestProfile(`HOST\user closed session 1`) // what ipn/desktop does on session close

	if got := env.currentProfileID(); got != "" {
		t.Errorf("after session end: profile = %q; want empty immediately (no grace after the user leaves)", got)
	}
}
