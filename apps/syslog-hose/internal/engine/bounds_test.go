package engine

import (
	"context"
	"math/rand"
	"testing"
	"time"
)

func TestValidateBoundsJobDurations(t *testing.T) {
	base := JobConfig{Name: "j", Host: "h", Port: 514, Transport: "udp", Rate: 1, RateMode: "burst"}
	for name, mut := range map[string]func(*JobConfig){
		"burstEvery":  func(c *JobConfig) { c.BurstEvery = 1 << 55 },
		"burstLen":    func(c *JobConfig) { c.BurstLen = 1 << 55 },
		"durationSec": func(c *JobConfig) { c.DurationSec = 1 << 55 },
	} {
		cfg := base
		mut(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: oversized value accepted", name)
		}
	}
	ok := base
	ok.BurstEvery, ok.BurstLen, ok.DurationSec = 30*86400, 86400, 365*86400
	if err := ok.Validate(); err != nil {
		t.Errorf("long but sane durations rejected: %v", err)
	}
}

// A jobs.json written before the bounds existed must not crash the run loop.
func TestRateShapeSurvivesPersistedOverflow(t *testing.T) {
	for _, v := range []int{1 << 55, 1 << 62} {
		cfg := JobConfig{Rate: 10, RateMode: "burst", BurstEvery: v, BurstLen: v}
		rs := newRateShape(cfg, rand.New(rand.NewSource(1)))
		if rs.burstEvery <= 0 || rs.burstLen <= 0 {
			t.Fatalf("burst window overflowed: every=%s len=%s", rs.burstEvery, rs.burstLen)
		}
		rs.rate(time.Minute)
	}
}

// Starting a UDP job must not depend on the destination resolving yet.
func TestUDPSenderDoesNotDialUpFront(t *testing.T) {
	s, err := NewSender(context.Background(), "udp", "127.0.0.1", 9, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if u := s.(*udpSender); u.conn != nil {
		t.Fatal("UDP sender dialled before the first send")
	}
}
