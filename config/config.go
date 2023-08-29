package config

import "errors"

type Config struct {
	BaseURL string
	APIKey  string

	PolicyName           string
	PolicyOperator       string
	PolicyViolationState string
	PolicyProjects       []string
	PolicyTags           []string
}

var (
	ErrAPIKeyIsRequired     = errors.New("api-key is required")
	ErrPolicyNameIsRequired = errors.New("policy-name is required")
)

func New(baseURL, apiKey, policyName, policyOperator, policyViolationState string, policyProjects, policyTags []string) *Config {
	return &Config{
		BaseURL:              baseURL,
		APIKey:               apiKey,
		PolicyName:           policyName,
		PolicyOperator:       policyOperator,
		PolicyViolationState: policyViolationState,
		PolicyProjects:       policyProjects,
		PolicyTags:           policyTags,
	}
}

func (c *Config) Validate() error {
	if c.APIKey == "" {
		return ErrAPIKeyIsRequired
	}

	if c.PolicyName == "" {
		return ErrPolicyNameIsRequired
	}

	return nil
}
