package rules

import "fmt"

// Action is one ordered rule action (PLAN §5). v1 of the engine ships tag,
// set_priority, and suppress; assign and notify land with M3/M4.
type Action struct {
	Type     string `json:"type"` // "tag" | "set_priority" | "suppress"
	TagID    int64  `json:"tag_id,omitempty"`
	Priority int16  `json:"priority,omitempty"` // 0 none … 3 high
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
		default:
			return fmt.Errorf("unknown action type %q", a.Type)
		}
	}
	return nil
}
