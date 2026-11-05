package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/syslog-yard/syslog-hose/internal/preset"
)

// Concurrent Create/Delete must leave exactly the in-memory job set on disk
// (an out-of-order write used to resurrect deleted jobs).
func TestPersistConcurrentCreateDelete(t *testing.T) {
	dir := t.TempDir()
	store, err := preset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, dir)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Go(func() {
			for i := 0; i < 10; i++ {
				st, err := mgr.Create(udpJob(fmt.Sprintf("w%d-%d", w, i), 5514))
				if err != nil {
					t.Error(err)
					return
				}
				if i%2 == 0 {
					if err := mgr.Delete(st.ID); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
	wg.Wait()

	raw, err := os.ReadFile(filepath.Join(dir, "jobs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []JobConfig
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	var diskIDs, memIDs []string
	for _, c := range onDisk {
		diskIDs = append(diskIDs, c.ID)
	}
	for _, s := range mgr.List() {
		memIDs = append(memIDs, s.ID)
	}
	sort.Strings(diskIDs)
	sort.Strings(memIDs)
	if fmt.Sprint(diskIDs) != fmt.Sprint(memIDs) {
		t.Fatalf("disk has %d jobs, memory %d:\n%v\n%v", len(diskIDs), len(memIDs), diskIDs, memIDs)
	}
	if len(memIDs) != 40 {
		t.Fatalf("expected 40 jobs, got %d", len(memIDs))
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "jobs.json" {
			t.Errorf("leftover file %s", e.Name())
		}
	}
	// and it still loads
	mgr2, err := NewManager(store, dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(mgr2.List()); n != 40 {
		t.Fatalf("reloaded %d jobs", n)
	}
}
