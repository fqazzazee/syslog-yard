package engine

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-hose/internal/preset"
)

// udpSink returns the port of a local UDP listener that discards everything.
func udpSink(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	store, err := preset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func udpJob(name string, port int) JobConfig {
	return JobConfig{
		Name: name, Preset: "linux-host", Host: "127.0.0.1", Port: port,
		Transport: "udp", Rate: 500, Facility: -1,
	}
}

// waitNoRuns fails the test if any generator goroutine is still alive
// after the deadline: that would be a job nobody can stop any more.
func waitNoRuns(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for activeRuns.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d generator goroutine(s) still running", activeRuns.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// listWithin calls List and fails if it does not return promptly (the old
// double-stop panic left j.mu locked and List hung forever).
func listWithin(t *testing.T, mgr *Manager) []JobStatus {
	t.Helper()
	ch := make(chan []JobStatus, 1)
	go func() { ch <- mgr.List() }()
	select {
	case l := <-ch:
		return l
	case <-time.After(2 * time.Second):
		t.Fatal("List hung")
		return nil
	}
}

func TestStopIsIdempotentAndConcurrent(t *testing.T) {
	port := udpSink(t)
	mgr := newTestManager(t)
	st, err := mgr.Create(udpJob("double-stop", port))
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 20; round++ {
		if err := mgr.Start(st.ID); err != nil {
			t.Fatalf("round %d start: %v", round, err)
		}
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Go(func() {
				if i%4 == 0 {
					mgr.StopAll()
					return
				}
				if err := mgr.Stop(st.ID); err != nil {
					t.Errorf("stop: %v", err)
				}
			})
		}
		wg.Wait()
		jobs := listWithin(t, mgr)
		if len(jobs) != 1 || jobs[0].Running {
			t.Fatalf("round %d: job should be stopped: %+v", round, jobs)
		}
	}
	waitNoRuns(t)
}

func TestStopWhileStartingAndStopAfterSelfExit(t *testing.T) {
	port := udpSink(t)
	mgr := newTestManager(t)
	cfg := udpJob("short", port)
	cfg.MaxEvents = 3
	cfg.Rate = 1000
	st, err := mgr.Create(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(st.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for listWithin(t, mgr)[0].Running {
		if time.Now().After(deadline) {
			t.Fatal("job did not exit after maxEvents")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// the run exited on its own; stopping it again must be a no-op
	if err := mgr.Stop(st.ID); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(st.ID); err != nil {
		t.Fatalf("restart after self-exit: %v", err)
	}
	if err := mgr.Stop(st.ID); err != nil {
		t.Fatal(err)
	}
	waitNoRuns(t)
}

// Delete racing Start must never leave a generator running for a job that
// is no longer in the manager.
func TestDeleteRacesStart(t *testing.T) {
	port := udpSink(t)
	mgr := newTestManager(t)
	for i := 0; i < 100; i++ {
		st, err := mgr.Create(udpJob(fmt.Sprintf("race-%d", i), port))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Go(func() { mgr.Start(st.ID) })
		wg.Go(func() { mgr.Delete(st.ID) })
		wg.Wait()
	}
	if n := len(listWithin(t, mgr)); n != 0 {
		t.Fatalf("expected no jobs, got %d", n)
	}
	waitNoRuns(t)
}

// Hammer every lifecycle operation concurrently; run with -race.
func TestLifecycleHammer(t *testing.T) {
	port := udpSink(t)
	mgr := newTestManager(t)

	var idsMu sync.Mutex
	ids := []string{}
	for i := 0; i < 6; i++ {
		st, err := mgr.Create(udpJob(fmt.Sprintf("job-%d", i), port))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, st.ID)
	}
	pick := func(rng *rand.Rand) string {
		idsMu.Lock()
		defer idsMu.Unlock()
		return ids[rng.Intn(len(ids))]
	}

	stop := time.Now().Add(1500 * time.Millisecond)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Go(func() {
			rng := rand.New(rand.NewSource(int64(w)))
			for time.Now().Before(stop) {
				id := pick(rng)
				switch rng.Intn(8) {
				case 0, 1:
					mgr.Start(id)
				case 2, 3:
					if err := mgr.Stop(id); err != nil && err != errJobNotFound {
						t.Errorf("stop: %v", err)
					}
				case 4:
					cfg := udpJob(fmt.Sprintf("upd-%d", rng.Intn(100)), port)
					cfg.Rate = float64(1 + rng.Intn(2000))
					mgr.Update(id, cfg)
				case 5:
					if rng.Intn(4) == 0 {
						mgr.Delete(id)
						if st, err := mgr.Create(udpJob("fresh", port)); err == nil {
							idsMu.Lock()
							ids = append(ids, st.ID)
							idsMu.Unlock()
						}
					}
				case 6:
					listWithin(t, mgr)
				case 7:
					if rng.Intn(10) == 0 {
						mgr.StopAll()
					}
				}
			}
		})
	}
	wg.Wait()

	mgr.StopAll()
	for _, j := range listWithin(t, mgr) {
		if j.Running {
			t.Fatalf("job %s still running after StopAll", j.Name)
		}
	}
	waitNoRuns(t)
}
