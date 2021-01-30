package api

//Cve Represents a Common Vulnerability and Exposure entry
type Cve struct {
	ID     string `json:"id"`
	Vector string `json:"vector"`
}

//Config Configuration for the SHS calculator
type Config struct {
	Weights Weights `json:"weights"`
}

//Weights Contains values to either amplify or reduce severity scores
type Weights struct {
	Severity   Severity   `json:"severity"`
	Compliance Compliance `json:"compliance"`
}

//Compliance Weights for different compliance types
type Compliance struct {
	Hipaa   float64 `json:"HIPAA"`
	PCI     float64 `json:"PCI"`
	Hitrust float64 `json:"HITRUST"`
	Soc2    float64 `json:"SOC2"`
	Fedramp float64 `json:"Fedramp"`
}

//Severity Weights for severity levels
type Severity struct {
	Low    float64 `json:"low"`
	Medium float64 `json:"medium"`
	High   float64 `json:"high"`
	Max    float64 `json:"max"`
}
