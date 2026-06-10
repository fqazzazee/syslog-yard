// Package preset defines appliance syslog dialects as weighted template packs.
package preset

import (
	"fmt"
	"math/rand"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

// Event is one weighted message template within a preset.
type Event struct {
	Weight   int    `yaml:"weight" json:"weight"`
	Severity int    `yaml:"severity" json:"severity"`
	Appname  string `yaml:"appname,omitempty" json:"appname,omitempty"`
	Template string `yaml:"template" json:"template"`
}

// Preset describes one appliance's syslog dialect.
//
// Format controls how the rendered payload is framed on the wire:
//   - rfc3164: <PRI>Mmm dd hh:mm:ss HOSTNAME APP[PID]: payload
//   - rfc5424: <PRI>1 TIMESTAMP HOSTNAME APP PROCID - - payload
//   - raw:     <PRI>payload (vendors like FortiGate put key=value right after PRI)
type Preset struct {
	Name        string  `yaml:"name" json:"name"`
	Vendor      string  `yaml:"vendor" json:"vendor"`
	Description string  `yaml:"description" json:"description"`
	Format      string  `yaml:"format" json:"format"`
	Facility    int     `yaml:"facility" json:"facility"`
	Appname     string  `yaml:"appname" json:"appname"`
	Hostname    string  `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	Events      []Event `yaml:"events" json:"events"`

	Builtin     bool `yaml:"-" json:"builtin"`
	totalWeight int
	compiled    []*template.Template
}

// Parse unmarshals and validates a preset from YAML, compiling its templates.
func Parse(raw []byte) (*Preset, error) {
	var p Preset
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if err := p.compile(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Preset) compile() error {
	if p.Name == "" {
		return fmt.Errorf("preset is missing 'name'")
	}
	switch p.Format {
	case "rfc3164", "rfc5424", "raw":
	case "":
		p.Format = "rfc3164"
	default:
		return fmt.Errorf("preset %q: format must be rfc3164, rfc5424 or raw", p.Name)
	}
	if p.Facility < 0 || p.Facility > 23 {
		return fmt.Errorf("preset %q: facility must be 0-23", p.Name)
	}
	if len(p.Events) == 0 {
		return fmt.Errorf("preset %q: needs at least one event", p.Name)
	}
	p.totalWeight = 0
	p.compiled = make([]*template.Template, len(p.Events))
	for i := range p.Events {
		ev := &p.Events[i]
		if ev.Weight <= 0 {
			ev.Weight = 1
		}
		if ev.Severity < 0 || ev.Severity > 7 {
			return fmt.Errorf("preset %q event %d: severity must be 0-7", p.Name, i)
		}
		p.totalWeight += ev.Weight
		// FuncMap names must exist at parse time; bind no-op context, the
		// real one is attached per render via Funcs.
		t, err := template.New(fmt.Sprintf("%s/%d", p.Name, i)).
			Funcs(newRenderContext(p, "", rand.New(rand.NewSource(0)), nil).funcs()).
			Parse(ev.Template)
		if err != nil {
			return fmt.Errorf("preset %q event %d: %w", p.Name, i, err)
		}
		p.compiled[i] = t
	}
	return nil
}

// YAML re-serializes the preset definition (without runtime fields).
func (p *Preset) YAML() ([]byte, error) { return yaml.Marshal(p) }

// pick returns a weighted-random event index.
func (p *Preset) pick(rng *rand.Rand) int {
	n := rng.Intn(p.totalWeight)
	for i, ev := range p.Events {
		n -= ev.Weight
		if n < 0 {
			return i
		}
	}
	return len(p.Events) - 1
}

// Renderer produces wire-ready syslog messages for one job using this preset.
type Renderer struct {
	preset   *Preset
	hostname string
	appname  string
	facility int
	format   string
	pid      int
	rng      *rand.Rand
	seqs     map[string]int64
}

// RenderOpts carries per-job overrides applied on top of preset defaults.
type RenderOpts struct {
	Hostname string
	Appname  string
	Facility int // -1 = preset default
	Format   string
	Seed     int64 // 0 = time-seeded
}

// NewRenderer builds a renderer with job-level overrides.
func (p *Preset) NewRenderer(o RenderOpts) *Renderer {
	seed := o.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed))
	host := o.Hostname
	if host == "" {
		host = p.Hostname
	}
	if host == "" {
		host = fmt.Sprintf("%s-%02d", strings.SplitN(p.Name, "-", 2)[0], rng.Intn(99)+1)
	}
	app := o.Appname
	if app == "" {
		app = p.Appname
	}
	if app == "" {
		app = p.Name
	}
	fac := o.Facility
	if fac < 0 || fac > 23 {
		fac = p.Facility
	}
	format := o.Format
	if format != "rfc3164" && format != "rfc5424" && format != "raw" {
		format = p.Format
	}
	return &Renderer{
		preset:   p,
		hostname: host,
		appname:  app,
		facility: fac,
		format:   format,
		pid:      rng.Intn(60000) + 1000,
		rng:      rng,
		seqs:     map[string]int64{},
	}
}

// Render produces one complete syslog message (without trailing newline).
func (r *Renderer) Render() (string, error) {
	i := r.preset.pick(r.rng)
	ev := r.preset.Events[i]
	now := time.Now()

	ctx := newRenderContext(r.preset, r.hostname, r.rng, r.seqs)
	ctx.now = now
	ctx.appname = r.appname
	if ev.Appname != "" {
		ctx.appname = ev.Appname
	}

	var sb strings.Builder
	t, err := r.preset.compiled[i].Clone()
	if err != nil {
		return "", err
	}
	if err := t.Funcs(ctx.funcs()).Execute(&sb, nil); err != nil {
		return "", fmt.Errorf("render %s: %w", r.preset.Name, err)
	}
	payload := strings.ReplaceAll(strings.TrimSpace(sb.String()), "\n", " ")

	pri := r.facility*8 + ev.Severity
	switch r.format {
	case "raw":
		return fmt.Sprintf("<%d>%s", pri, payload), nil
	case "rfc5424":
		return fmt.Sprintf("<%d>1 %s %s %s %d - - %s",
			pri, now.Format("2006-01-02T15:04:05.000000-07:00"),
			r.hostname, ctx.appname, r.pid, payload), nil
	default: // rfc3164
		return fmt.Sprintf("<%d>%s %s %s[%d]: %s",
			pri, now.Format("Jan _2 15:04:05"), r.hostname, ctx.appname, r.pid, payload), nil
	}
}
