package preset

import (
	"fmt"
	"strings"
	"testing"
)

// A literal "[" must not shrink the bound below the surplus arguments that
// fmt still prints as %!(EXTRA ...).
func TestFormatBoundCountsExtraArgsWithBracket(t *testing.T) {
	args := make([]any, 20)
	for i := range args {
		args[i] = strings.Repeat("x", 1000)
	}
	const format = "[%s"
	if got, want := formatBound(format, args), int64(len(fmt.Sprintf(format, args...))); got < want {
		t.Fatalf("bound %d is below the rendered size %d", got, want)
	}
}
