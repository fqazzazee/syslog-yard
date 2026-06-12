package rules

import "fmt"

// Action is one ordered rule action. The engine ships tag, set_priority,
// suppress, notify, and the set_mitre/set_ot classification actions that let a
// hand-made detection re-stamp the mapping the automated packs missed.
type Action struct {
	Type      string   `json:"type"` // tag | set_priority | suppress | notify | set_mitre | set_ot
	TagID     int64    `json:"tag_id,omitempty"`
	Priority  int16    `json:"priority,omitempty"`   // 0 none … 3 high
	ChannelID int64    `json:"channel_id,omitempty"` // notify: destination channel
	Mitre     []string `json:"mitre,omitempty"`      // set_mitre: ATT&CK technique IDs to stamp
	OT        []string `json:"ot,omitempty"`         // set_ot: Claroty OT alert codes to stamp
}

func ValidateActions(actions []Action) error {
	if len(actions) == 0 {
		return fmt.Errorf("rule needs at least one action")
	}
	for _, a := range actions {
		switch a.Type {
		case "tag":
			if a.TagID == 0 {
				return fmt.Errorf("tag action needs tag_id")
			}
		case "set_priority":
			if a.Priority < 0 || a.Priority > 3 {
				return fmt.Errorf("priority must be 0-3")
			}
		case "suppress":
		case "notify":
			if a.ChannelID == 0 {
				return fmt.Errorf("notify action needs channel_id")
			}
		case "set_mitre":
			if len(a.Mitre) == 0 {
				return fmt.Errorf("set_mitre action needs at least one technique")
			}
		case "set_ot":
			if len(a.OT) == 0 {
				return fmt.Errorf("set_ot action needs at least one OT code")
			}
		default:
			return fmt.Errorf("unknown action type %q", a.Type)
		}
	}
	return nil
}
