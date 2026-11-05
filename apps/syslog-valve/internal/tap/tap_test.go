package tap

import "testing"

func TestPublishAndSubscribe(t *testing.T) {
	tp := New()
	tp.publish("src_1\t2026-01-01T00:00:00Z\thost\tsshd\tfirst\n")
	tp.publish("malformed line") // ignored
	replay, ch, cancel := tp.Subscribe()
	defer cancel()
	if len(replay) != 1 || replay[0].Src != "src_1" || replay[0].Message != "first" {
		t.Fatalf("replay = %+v", replay)
	}
	tp.publish("src_1\t2026-01-01T00:00:01Z\thost\tsshd\tsecond\twith a tab\n")
	ev := <-ch
	if ev.Message != "second\twith a tab" || ev.Seq != 2 {
		t.Fatalf("event = %+v", ev)
	}
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	tp := New()
	_, _, cancel := tp.Subscribe() // never read
	defer cancel()
	// Publishing past the subscriber's buffer must drop, not block.
	for i := 0; i < ringSize+subBuffer; i++ {
		tp.publish("s\tt\th\tp\tm")
	}
	replay, _, c := tp.Subscribe()
	c()
	if len(replay) != ringSize {
		t.Fatalf("replay ring = %d, want %d", len(replay), ringSize)
	}
}
