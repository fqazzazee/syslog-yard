package preset

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Store holds built-in presets (embedded) and custom ones (files in dir).
type Store struct {
	mu      sync.RWMutex
	dir     string // custom presets directory, e.g. /data/presets
	presets map[string]*Preset
}

// NewStore loads built-ins and scans dir for custom preset YAMLs.
func NewStore(dir string) (*Store, error) {
	s := &Store{dir: dir, presets: map[string]*Preset{}}
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		raw, err := builtinFS.ReadFile("builtin/" + e.Name())
		if err != nil {
			return nil, err
		}
		p, err := Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("builtin %s: %w", e.Name(), err)
		}
		p.Builtin = true
		s.presets[p.Name] = p
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
		more, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
		for _, f := range append(files, more...) {
			raw, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			p, err := Parse(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "syshose: skipping custom preset %s: %v\n", f, err)
				continue
			}
			s.presets[p.Name] = p
		}
	}
	return s, nil
}

// List returns all presets sorted by vendor then name.
func (s *Store) List() []*Preset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Preset, 0, len(s.presets))
	for _, p := range s.presets {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Get looks a preset up by name.
func (s *Store) Get(name string) (*Preset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.presets[name]
	return p, ok
}

// Save validates and persists a custom preset. Built-in names are shadowable
// only by explicit different name; overwriting a builtin is rejected.
func (s *Store) Save(raw []byte) (*Preset, error) {
	p, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.presets[p.Name]; ok && existing.Builtin {
		return nil, fmt.Errorf("%q is a built-in preset; choose another name", p.Name)
	}
	if s.dir == "" {
		return nil, fmt.Errorf("no data directory configured for custom presets")
	}
	path := filepath.Join(s.dir, sanitize(p.Name)+".yaml")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return nil, err
	}
	s.presets[p.Name] = p
	return p, nil
}

// Delete removes a custom preset (built-ins cannot be deleted).
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.presets[name]
	if !ok {
		return fmt.Errorf("preset %q not found", name)
	}
	if p.Builtin {
		return fmt.Errorf("cannot delete built-in preset %q", name)
	}
	delete(s.presets, name)
	return os.Remove(filepath.Join(s.dir, sanitize(name)+".yaml"))
}

func sanitize(name string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, name)
}
