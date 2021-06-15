package api

import (
	// "fmt"
	"testing"
)

func TestBaseScore(t *testing.T) {
	result := BaseScore("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N")
	if result != 4.1 {
		t.Error()
	}
}