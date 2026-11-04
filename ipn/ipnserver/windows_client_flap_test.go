// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnserver_test

// End-to-end guard (through real LocalAPI HTTP requests) for the Windows
// connect/disconnect behavior: while a long-lived request such as the GUI's
// IPN bus watcher is active, short-lived requests from the same user must
// not cause any connect/disconnect transitions or backend teardown.
// See ipn/ipnlocal/windows_client_flap_test.go for the full set of tests,
// including the ones that fail until the post-standby flap is fixed.

import (
	"context"
	"encoding/json"
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
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/lapitest"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logid"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine"
)

type lineCounter struct {
	mu    sync.Mutex
	lines []string
}

func (c *lineCounter) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *lineCounter) count(substr string) int {
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

// flapServer is a LocalAPI test server running as if on Windows, with its
// backend's logs captured and its control-client creations counted.
type flapServer struct {
	*lapitest.Server
	b      *ipnlocal.LocalBackend
	logs   *lineCounter
	starts atomic.Int32 // control clients created (full backend starts)
}

// newFlapServer returns a flapServer. If seedUID is non-empty, the state
// store is pre-populated with one persisted, logged-in profile owned by that
// Windows user and set as their default, as on a real machine where the user
// has already signed in. If clock is non-nil, the backend uses it.
func newFlapServer(t *testing.T, seedUID ipn.WindowsUserID, clock *tstest.Clock) *flapServer {
	t.Helper()
	envknob.SetenvForTest(t, "TS_DEBUG_FAKE_GOOS", "windows")

	fs := &flapServer{logs: new(lineCounter)}
	store := new(mem.Store)
	if seedUID != "" {
		seedProfile(t, store, seedUID)
	}
	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	sys.Set(store)
	e, err := wgengine.NewFakeUserspaceEngine(fs.logs.logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(e.Close)
	sys.Set(e)
	b, err := ipnlocal.NewLocalBackend(fs.logs.logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(b.Shutdown)
	if clock != nil {
		b.ForTest().SetClock(clock)
	}
	b.ForTest().SetControlClientGetter(func(opts controlclient.Options) (controlclient.Client, error) {
		fs.starts.Add(1)
		return lapitest.NewUnreachableControlClient(t, opts)
	})
	fs.b = b
	fs.Server = lapitest.NewServer(t, lapitest.WithBackend(b))
	return fs
}

// seedProfile writes one logged-in profile owned by uid into store.
func seedProfile(t *testing.T, store *mem.Store, uid ipn.WindowsUserID) {
	t.Helper()
	const (
		id    = ipn.ProfileID("c0rp")
		key   = ipn.StateKey("profile-c0rp")
		login = "user@corp.example.com"
	)
	prefs := ipn.NewPrefs()
	prefs.WantRunning = true
	prefs.Persist = &persist.Persist{
		UserProfile: tailcfg.UserProfile{ID: 1, LoginName: login},
		NodeID:      "node-c0rp",
	}
	profiles := map[ipn.ProfileID]*ipn.LoginProfile{id: {
		ID:          id,
		Name:        login,
		Key:         key,
		UserProfile: prefs.Persist.UserProfile,
		NodeID:      prefs.Persist.NodeID,
		LocalUserID: uid,
		ControlURL:  prefs.ControlURL,
	}}
	pj, err := json.Marshal(profiles)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[ipn.StateKey][]byte{
		ipn.KnownProfilesStateKey:          pj,
		key:                                prefs.ToBytes(),
		ipn.CurrentProfileKey(string(uid)): []byte(key),
	} {
		if err := store.WriteState(k, v); err != nil {
			t.Fatal(err)
		}
	}
}

// TestWindowsShortRequestsWithoutWatcherDoNotChurn is the end-to-end
// version of the field loop: the user has a signed-in profile, no
// long-lived IPN bus watcher is open, and short-lived LocalAPI requests
// (here Status calls, as the GUI polls) arrive 500ms apart. Each request
// goes through ipnserver's real active-request accounting, so this checks
// that the request lifecycle itself does not cause resets and restarts.
//
// Expected behavior after a fix; FAILS on current code, where every
// request that ends logs "disconnecting Tailscale" and restarts the backend.
func TestWindowsShortRequestsWithoutWatcherDoNotChurn(t *testing.T) {
	ctx := context.Background()
	const uid = ipn.WindowsUserID("S-1-5-21-1000000001-1000000002-1000000003-1001")
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Date(2026, 11, 4, 20, 17, 32, 0, time.UTC)})
	fs := newFlapServer(t, uid, clock)
	client := fs.ClientFor(&ipnauth.TestActor{UID: uid, Name: `HOST\user`, CID: ipnauth.ClientIDFrom("gui")})

	// First request: the user's profile is selected and the backend starts.
	if _, err := client.Status(ctx); err != nil {
		t.Fatalf("Status #0: %v", err)
	}
	fs.BlockWhileInUse(ctx)
	if fs.logs.count(`switching to profile "user@corp.example.com"`) == 0 {
		t.Fatal("seeded profile was not selected on connect; test setup is broken")
	}
	const corp = ipn.ProfileID("c0rp")
	base := fs.logs.count("disconnecting Tailscale")
	baseStarts := fs.starts.Load()

	const n = 10
	for i := 1; i <= n; i++ {
		clock.Advance(500 * time.Millisecond)
		if _, err := client.Status(ctx); err != nil {
			t.Fatalf("Status #%d: %v", i, err)
		}
		fs.BlockWhileInUse(ctx)
	}

	resets := fs.logs.count("disconnecting Tailscale") - base
	restarts := fs.starts.Load() - baseStarts
	t.Logf("%d Status calls 500ms apart, no watcher: %d resets, %d restarts", n, resets, restarts)
	if resets != 0 || restarts != 0 {
		t.Errorf("short requests caused %d resets and %d restarts; want 0 and 0", resets, restarts)
	}
	if got := fs.b.CurrentProfile().ID(); got != corp {
		t.Errorf("profile between requests = %q; want %q (still within the grace period)", got, corp)
	}
}

// TestWindowsWatcherHeldSuppressesConnectDisconnect shows that while a
// long-lived IPN bus watcher is open, short-lived requests from the same
// user do not trigger any additional connect/disconnect transitions.
func TestWindowsWatcherHeldSuppressesConnectDisconnect(t *testing.T) {
	ctx := context.Background()
	fs := newFlapServer(t, "", nil)
	server, logs := fs.Server, fs.logs
	client := server.ClientWithName(`HOST\user`)

	watcher, cancelWatcher := client.WatchIPNBus(ctx, 0)
	defer cancelWatcher()
	go pumpIPNBus(watcher)
	server.CheckCurrentUser(client.Actor)
	// With no persisted profile, the initial connect itself logs
	// "disconnecting Tailscale" (switch to a new, empty profile); count
	// only what happens after the watcher is established.
	baseDisconnecting := logs.count("disconnecting Tailscale")

	for i := range 10 {
		if _, err := client.Status(ctx); err != nil {
			t.Fatalf("Status #%d: %v", i, err)
		}
		server.CheckCurrentUser(client.Actor)
	}
	if got := logs.count("client connected ("); got != 1 {
		t.Errorf("'client connected' = %d; want 1 (watcher only)", got)
	}
	if got := logs.count("client disconnected ("); got != 0 {
		t.Errorf("'client disconnected' = %d; want 0 while watcher is held", got)
	}
	if got := logs.count("disconnecting Tailscale") - baseDisconnecting; got != 0 {
		t.Errorf("'disconnecting Tailscale' = %d; want 0 while watcher is held", got)
	}
}
