package api

import (
	"fmt"
	"testing"
)

func TestBaseScore(t *testing.T) {
	result := BaseScore("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:F/RL:W/RC:R/CR:M/IR:H/AR:L/MAV:A/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:L/MA:H")
	fmt.Println(result)
	if result != 5.5 {
		t.Error()
	}
}

func TestTemporalScore(t *testing.T) {
	baseScore := BaseScore("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:F/RL:W/RC:R/CR:M/IR:H/AR:L/MAV:A/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:L/MA:H")
	result := TemporalScore("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:F/RL:W/RC:R/CR:M/IR:H/AR:L/MAV:A/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:L/MA:H", baseScore)
	fmt.Println(result)
	if result != 5 {
		t.Error()
	}
}

func TestEnvironmentalScore(t *testing.T) {
	result := EnvironmentalScore("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:F/RL:W/RC:R/CR:M/IR:H/AR:L/MAV:A/MAC:L/MPR:H/MUI:N/MS:C/MC:L/MI:L/MA:H")
	fmt.Println(result)
	if result != 6.1 {
		t.Error()
	}
}

func TestQualitativeSeverity(t *testing.T) {
	var tests = []struct {
		score float64
		severity string
	}{
		{0, "None"},
		{3, "Low"},
		{5, "Medium"},
		{8, "High"},
		{9, "Critical"},
	}

	for _, tt := range tests {
		testName := tt.severity
		t.Run(testName, func(t *testing.T) {
			result := QualitativeSeverity(tt.score)
			if result != tt.severity {
				t.Error()
			}
		})
	}
}