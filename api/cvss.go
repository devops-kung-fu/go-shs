package api

import (
	"fmt"
	"math"
	"regexp"
)

func getMetricValue(key string) float64 {
	metricValue := map[string]float64{
		"AV:N":   0.85,
		"AV:A":   0.62,
		"AV:L":   0.55,
		"AV:P":   0.2,
		"MAV:N":  0.85,
		"MAV:A":  0.62,
		"MAV:L":  0.55,
		"MAV:P":  0.2,
		"AC:L":   0.77,
		"AC:H":   0.44,
		"MAC:L":  0.77,
		"MAC:H":  0.44,
		"PR:N":   0.85,
		"PR:L":   0.62,
		"PR:LC":  0.68,
		"PR:H":   0.27,
		"PR:HC":  0.5,
		"MPR:N":  0.85,
		"MPR:L":  0.62,
		"MPR:LC": 0.68,
		"MPR:H":  0.27,
		"MPR:HC": 0.5,
		"UI:N":   0.85,
		"UI:R":   0.62,
		"MUI:N":  0.85,
		"MUI:R":  0.62,
		"C:H":    0.56,
		"C:L":    0.22,
		"C:N":    0,
		"MC:H":   0.56,
		"MC:L":   0.22,
		"MC:N":   0,
		"I:H":    0.56,
		"I:L":    0.22,
		"I:N":    0,
		"MI:H":   0.56,
		"MI:L":   0.22,
		"MI:N":   0,
		"A:H":    0.56,
		"A:L":    0.22,
		"A:N":    0,
		"MA:H":   0.56,
		"MA:L":   0.22,
		"MA:N":   0,
		"E:X":    1,
		"E:H":    1,
		"E:F":    0.97,
		"E:P":    0.94,
		"E:U":    0.91,
		"RL:X":   1,
		"RL:U":   1,
		"RL:W":   0.97,
		"RL:T":   0.96,
		"RL:O":   0.95,
		"RC:X":   1,
		"RC:C":   1,
		"RC:R":   0.96,
		"RC:U":   0.92,
	}
	value, _ := metricValue[key]
	return value
}

// BaseScore - 
func BaseScore(cvss string) float64 {
	metricSections := regexp.MustCompile(`[A-Z]{1,2}:[A-Z]{1,2}`).FindAllString(cvss, -1)
	s := metricSections[4]
	av := getMetricValue(metricSections[0])
	ac := getMetricValue(metricSections[1])
	var pr float64
	if s == "S:C" && metricSections[2] != "PR:N" {
		pr = getMetricValue(fmt.Sprintf("%sC", metricSections[2]))
	} else {
		pr = getMetricValue(metricSections[2])
	}
	ui := getMetricValue(metricSections[3])
	c := getMetricValue(metricSections[5])
	i := getMetricValue(metricSections[6])
	a := getMetricValue(metricSections[7])
	var iss float64 = 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if s == "S:U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * av * ac * pr * ui
	var base float64 = 0
	if impact <= 0 {
		return base
	}
	if s == "S:U" {
		return math.Ceil((math.Min(impact+exploitability, 10))*10) / 10
	} 
	return math.Ceil(math.Min(1.08*(impact+exploitability), 10)*10) / 10
}

// TemporalScore - 
func TemporalScore(cvss string, baseScore float64) float64 {
	metricSections := regexp.MustCompile(`[A-Z]{1,2}:[A-Z]{1,2}`).FindAllString(cvss, -1)
	e := getMetricValue(metricSections[0])
	rl := getMetricValue(metricSections[1])
	rc := getMetricValue(metricSections[2])
	return math.Ceil((baseScore*e*rl*rc)*10) / 10
}

// EnvironmentalScore -
func EnvironmentalScore(environmentalVector string, temporalVector string) float64 {
	environmentalMetricSections := regexp.MustCompile(`[A-Z]{1,2}:[A-Z]{1,2}`).FindAllString(environmentalVector, -1)
	cr := getMetricValue(environmentalMetricSections[0])
	ir := getMetricValue(environmentalMetricSections[1])
	ar := getMetricValue(environmentalMetricSections[2])
	mav := getMetricValue(environmentalMetricSections[3])
	mac := getMetricValue(environmentalMetricSections[4])
	mpr := getMetricValue(environmentalMetricSections[5])
	mui := getMetricValue(environmentalMetricSections[6])
	ms := environmentalMetricSections[7]
	mc := getMetricValue(environmentalMetricSections[8])
	mi := getMetricValue(environmentalMetricSections[9])
	ma := getMetricValue(environmentalMetricSections[10])
	temporalMetricSections := regexp.MustCompile(`[A-Z]{1,2}:[A-Z]{1,2}`).FindAllString(temporalVector, -1)
	e := getMetricValue(temporalMetricSections[0])
	rl := getMetricValue(temporalMetricSections[1])
	rc := getMetricValue(temporalMetricSections[2])
	miss := math.Min(1-((1-cr-mc)*(1-ir-mi)*(1-ar-ma)), 0.915)
	var modifiedImpact float64
	if ms == "MS:U" {
		modifiedImpact = 6.42 * miss
	} else if ms == "MS:C" {
		modifiedImpact = 7.52*(miss-0.029) - 3.25*math.Pow((miss*0.9731-0.02), 13)
	}
	modifiedExploitability := 8.22 * mav * mac * mpr * mui
	var environmentalScoreValue float64 = 0
	if modifiedImpact <= 0 {
		environmentalScoreValue = 0
	} else {
		if ms == "MS:U" {
			environmentalScoreValue = math.Ceil(((math.Ceil(math.Min((modifiedImpact+modifiedExploitability), 10)*10)/10)*e*rl*rc)*10) / 10
		} else if ms == "MS:C" {
			environmentalScoreValue = math.Ceil(((math.Ceil(math.Min(1.08*(modifiedImpact+modifiedExploitability), 10)*10)/10)*e*rl*rc)*10) / 10
		}
	}
	return environmentalScoreValue
}

// QualitativeSeverity - None, Low, Medium, High
func QualitativeSeverity(score float64) string {
	if score == 0 {
		return "None"
	} else if score > 0 && score < 4 {
		return "Low"
	} else if score >= 4 && score < 7 {
		return "Medium"
	} else if score >= 7 && score < 9 {
		return "High"
	} else {
		return "Critical"
	}
}
