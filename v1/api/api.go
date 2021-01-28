package api

//API Is a struct holding the properties of an API instance
type API struct {
	name   string
	config Config
}

//NewAPI Returns an instance of the SHS API
func NewAPI(config Config) *API {
	return &API{config: config}
}

//DefaultConfig Returns a default configuration for the API
func DefaultConfig() Config {
	defaultConfig := Config{
		Weights{
			Severity{Low: 0.1, Medium: 0.2, High: 0.3, Max: 0.41},
			Compliance{Hipaa: 1.02},
		},
	}
	return defaultConfig
}
