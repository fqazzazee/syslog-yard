package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/syslog-yard/syslog-bucket/internal/classify"
	"github.com/syslog-yard/syslog-bucket/internal/frameworks"
	"github.com/syslog-yard/syslog-bucket/internal/mitre"
	"github.com/syslog-yard/syslog-bucket/internal/otmap"
	"github.com/syslog-yard/syslog-bucket/internal/rules"
)

// knownTechnique / knownOT / knownClass validate a code against the build's
// catalogs — used for custom frameworks and hand-classification.
func knownTechnique(id string) bool {
	for _, t := range mitre.Get().Techniques {
		if t.ID == id {
			return true
		}
	}
	return false
}

func knownOT(id string) bool {
	for _, a := range otmap.Get().AlertTypes {
		if a.ID == id {
			return true
		}
	}
	return false
}

func knownClass(c string) bool {
	switch c {
	case classify.Firewall, classify.Network, classify.Host, classify.Windows, classify.OT:
		return true
	}
	return false
}

// framework resolves a framework by ID. Built-in catalogs win; site-defined
// custom frameworks (stored in Postgres) are consulted next, so the filter and
// summary paths treat both kinds uniformly.
func (s *server) framework(ctx context.Context, id string) (frameworks.Framework, bool) {
	if f, ok := frameworks.Get(id); ok {
		return f, true
	}
	return s.store.GetCustomFramework(ctx, id)
}

// frameworkCond builds the entry condition for a framework (or one item of it):
// an Any over the mitre techniques / ot codes / device classes it crosswalks to.
// With no itemID, it covers everything the whole framework maps.
func (s *server) frameworkCond(ctx context.Context, fwID, itemID string) (rules.Cond, error) {
	f, ok := s.framework(ctx, fwID)
	if !ok {
		return rules.Cond{}, errors.New("unknown framework")
	}
	var any []rules.Cond
	add := func(mIDs, otIDs, classIDs []string) {
		for _, m := range mIDs {
			any = append(any, rules.Cond{Mitre: m})
		}
		for _, o := range otIDs {
			any = append(any, rules.Cond{OT: o})
		}
		for _, c := range classIDs {
			any = append(any, rules.Cond{Field: "device_class", Op: "eq", Value: c})
		}
	}
	if itemID != "" {
		mIDs, otIDs, classIDs, found := frameworks.ExpandIn(f, itemID)
		if !found {
			return rules.Cond{}, errors.New("unknown framework item")
		}
		add(mIDs, otIDs, classIDs)
	} else {
		for _, it := range f.Items {
			add(it.Mitre, it.OT, it.Class)
		}
	}
	return rules.Cond{Any: any}, nil
}

// getFrameworks returns the built-in catalogs plus any site-defined custom
// frameworks, so the UI lists them together.
func (s *server) getFrameworks(w http.ResponseWriter, r *http.Request) {
	out := append([]frameworks.Framework(nil), frameworks.All()...)
	custom, err := s.store.ListCustomFrameworks(r.Context())
	if err != nil {
		s.internalError(w, "list custom frameworks", err)
		return
	}
	out = append(out, custom...)
	writeJSON(w, map[string]any{"frameworks": out})
}

// validateFrameworkDoc checks a submitted custom framework references only
// known mitre/ot/class codes and real groups — the same integrity the built-in
// catalogs are unit-tested for.
func (s *server) validateFrameworkDoc(f frameworks.Framework) error {
	if len(f.Items) == 0 {
		return errors.New("a framework needs at least one item")
	}
	groups := map[string]bool{}
	for _, g := range f.Groups {
		groups[g.ID] = true
	}
	for _, it := range f.Items {
		if it.Group != "" && !groups[it.Group] {
			return errors.New("item " + it.ID + " references unknown group " + it.Group)
		}
		if len(it.Mitre) == 0 && len(it.OT) == 0 && len(it.Class) == 0 {
			return errors.New("item " + it.ID + " maps to nothing")
		}
		for _, m := range it.Mitre {
			if !knownTechnique(m) {
				return errors.New("unknown technique " + m)
			}
		}
		for _, o := range it.OT {
			if !knownOT(o) {
				return errors.New("unknown OT code " + o)
			}
		}
		for _, c := range it.Class {
			if !knownClass(c) {
				return errors.New("unknown device class " + c)
			}
		}
	}
	return nil
}

func (s *server) createFramework(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var f frameworks.Framework
	if !decodeJSON(w, r, &f) {
		return
	}
	if err := s.validateFrameworkDoc(f); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	created, err := s.store.CreateCustomFramework(r.Context(), f)
	if err != nil {
		s.internalError(w, "create framework", err)
		return
	}
	writeJSON(w, created)
}

func (s *server) updateFramework(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	var f frameworks.Framework
	if !decodeJSON(w, r, &f) {
		return
	}
	if err := s.validateFrameworkDoc(f); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ok, err := s.store.UpdateCustomFramework(r.Context(), id, f)
	if err != nil {
		s.internalError(w, "update framework", err)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f.ID = id
	writeJSON(w, f)
}

func (s *server) deleteFramework(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ok, err := s.store.DeleteCustomFramework(r.Context(), r.PathValue("id"))
	if err != nil {
		s.internalError(w, "delete framework", err)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
