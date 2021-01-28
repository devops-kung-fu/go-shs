package api

import (
	"fmt"
	"math"
	"os"

	"github.com/spiegel-im-spiegel/go-cvss/v3/metric"
)

//CalculateCves Provides an SHS given a collection of cve structure
func (api *API) CalculateCves(cves []Cve) int {
	var vectors []string
	for _, v := range cves {
		vectors = append(vectors, v.Vector)
	}
	return api.CalculateVectors(vectors)
}

//CalculateVectors Provides an SHS given a list of vectors in string format
func (api *API) CalculateVectors(vectors []string) int {
	sumWeight, avg := 0.0, 0.0
	for _, v := range vectors {
		metric, err := metric.NewBase().Decode(v)

		sumWeight += api.severityWeight(metric)

		//TODO: apply additional score adjustments here
		adjustedScore := metric.Score() * api.config.Weights.Compliance.Hipaa //Pretend we are magnifying for HIPAA

		adjustedScore = adjustedScore * api.severityWeight(metric)
		avg += adjustedScore

		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 0
		}
	}
	avg /= sumWeight

	avg *= -100
	avg = avg + 1000
	return int(math.RoundToEven(avg))

}

func (api *API) severityWeight(metric *metric.Base) float64 {
	if metric.Severity().String() == "LOW" {
		return api.config.Weights.Severity.Low
	} else if metric.Severity().String() == "MEDIUM" {
		return api.config.Weights.Severity.Medium
	} else if metric.Severity().String() == "HIGH" {
		return api.config.Weights.Severity.High
	}
	return api.config.Weights.Severity.Max
}
