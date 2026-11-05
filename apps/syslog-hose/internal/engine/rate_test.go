package engine

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

// simulate drives a pacer + rate shape on a fake clock for dur, waking
// roughly every tick with scheduling noise and the occasional missed tick
// (as a busy run loop sees them), and returns events emitted per second.
func simulate(cfg JobConfig, dur time.Duration, seed int64) []int {
	rng := rand.New(rand.NewSource(seed))
	start := time.Unix(1_700_000_000, 0)
	rs := newRateShape(cfg, rand.New(rand.NewSource(seed)))
	p := newPacer(start)
	perSec := make([]int, int(dur/time.Second))
	for el := time.Duration(0); ; {
		step := tick + time.Duration(rng.Intn(10)-5)*time.Millisecond
		if rng.Intn(20) == 0 {
			step += tick // a missed tick
		}
		el += step
		if el >= dur {
			return perSec
		}
		perSec[int(el/time.Second)] += p.take(start.Add(el), rs.rate(el))
	}
}

func sum(xs []int) int {
	t := 0
	for _, x := range xs {
		t += x
	}
	return t
}

func within(t *testing.T, what string, got, want, tol float64) {
	t.Helper()
	if math.Abs(got-want) > want*tol {
		t.Errorf("%s: got %.0f, want %.0f ±%.0f%%", what, got, want, tol*100)
	}
}

func TestRateSteady(t *testing.T) {
	for _, rate := range []float64{0.5, 3, 200, 5000, 20000, 50000} {
		got := sum(simulate(JobConfig{Rate: rate}, 20*time.Second, 1))
		within(t, "steady total", float64(got), rate*20, 0.02)
	}
}

func TestRateJitterAveragesOut(t *testing.T) {
	got := sum(simulate(JobConfig{Rate: 1000, RateMode: "jitter", JitterPct: 50}, 30*time.Second, 2))
	within(t, "jitter total", float64(got), 30000, 0.05)
}

// A 20k EPS job with a 5x burst must burst at the 50k ceiling (not at
// ~42k with a backlog trickling out afterwards), then fall straight back.
func TestRateBurstClampedNoBacklog(t *testing.T) {
	cfg := JobConfig{Rate: 20000, RateMode: "burst", BurstFactor: 5, BurstEvery: 10, BurstLen: 2}
	per := simulate(cfg, 10*time.Second, 3)
	within(t, "burst total", float64(sum(per)), 2*maxRate+8*20000, 0.02)
	within(t, "first burst second", float64(per[0]), maxRate, 0.04)
	for s, n := range per {
		if float64(n) > maxRate*1.03 {
			t.Errorf("second %d: %d events exceeds the %d EPS ceiling", s, n, maxRate)
		}
		if s >= 3 { // after the burst: straight back to base, no backlog
			within(t, "post-burst second", float64(n), 20000, 0.04)
		}
	}
	if float64(per[2]) > 20000*1.1 {
		t.Errorf("second 2 carries burst backlog: %d", per[2])
	}
}

func TestPacerNoBacklogAfterStall(t *testing.T) {
	start := time.Unix(0, 0)
	p := newPacer(start)
	p.take(start, 1000)
	// the sender blocked for 3s: only ~two ticks' worth may come out now
	n := p.take(start.Add(3*time.Second), 1000)
	if n > 101 {
		t.Fatalf("stall produced a backlog of %d events", n)
	}
	if n < 50 {
		t.Fatalf("stall lost the in-flight tick: %d events", n)
	}
}

// Real clock: the run loop should hold a few thousand EPS within tolerance.
func TestJobRateRealClock(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	port := udpSink(t)
	mgr := newTestManager(t)
	cfg := udpJob("rate", port)
	cfg.Rate = 2000
	st, err := mgr.Create(cfg)
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	if err := mgr.Start(st.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if err := mgr.Stop(st.ID); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(begin).Seconds()
	within(t, "real-clock sent", float64(listWithin(t, mgr)[0].Sent), 2000*elapsed, 0.15)
}
