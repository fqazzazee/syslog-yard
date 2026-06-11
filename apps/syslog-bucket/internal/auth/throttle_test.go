package auth

import (
	"testing"
	"time"
)

func TestThrottleLocksAfterMaxFails(t *testing.T) {
	tr := newThrottle(3, time.Minute)
	const key = "admin"

	for i := 0; i < 2; i++ {
		if ok, _ := tr.allow(key); !ok {
			t.Fatalf("attempt %d should be allowed", i)
		}
		tr.fail(key)
	}
	// Third failure trips the lock.
	if ok, _ := tr.allow(key); !ok {
		t.Fatal("third attempt should still be allowed before its failure")
	}
	tr.fail(key)
	ok, retry := tr.allow(key)
	if ok {
		t.Fatal("account should be locked after max failures")
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("unexpected retry-after: %v", retry)
	}
}

func TestThrottleResetOnSuccess(t *testing.T) {
	tr := newThrottle(3, time.Minute)
	const key = "alice"
	tr.fail(key)
	tr.fail(key)
	tr.reset(key) // a correct password clears the count
	tr.fail(key)
	if ok, _ := tr.allow(key); !ok {
		t.Fatal("reset should have cleared earlier failures")
	}
}

func TestThrottleIsolatesKeys(t *testing.T) {
	tr := newThrottle(2, time.Minute)
	tr.fail("victim")
	tr.fail("victim") // locks "victim"
	if ok, _ := tr.allow("victim"); ok {
		t.Fatal("victim should be locked")
	}
	if ok, _ := tr.allow("bystander"); !ok {
		t.Fatal("an unrelated account must not be affected")
	}
}
