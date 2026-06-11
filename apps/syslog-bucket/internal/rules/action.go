package rules

import "fmt"

// Action is one ordered rule action (PLAN §5). The engine ships tag,
// set_priority, suppress, and notify (S9); assign lands later.
type Action struct {
	Type      string `json:"type"` // "tag" | "set_priority" | "suppress" | "notify"
	TagID     int64  `json:"tag_id,omitempty"`
	Priority  int16  `json:"priority,omitempty"`   // 0 none … 3 high
	ChannelID int64  `json:"channel_id,omitempty"` // notify: destination channel
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
		default:
			return fmt.Errorf("unknown action type %q", a.Type)
		}
	}
	return nil
}
