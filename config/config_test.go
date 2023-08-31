package config

import "testing"

func TestConfig_Validate(t *testing.T) {
	type fields struct {
		BaseURL              string
		APIKey               string
		PolicyName           string
		PolicyOperator       string
		PolicyViolationState string
		PolicyProjects       []string
		PolicyTags           []string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "valid config",
			fields: fields{
				BaseURL:    "https://example.com",
				APIKey:     "api-key",
				PolicyName: "policy-name",
			},
			wantErr: false,
		},
		{
			name: "missing API key",
			fields: fields{
				BaseURL:    "https://example.com",
				APIKey:     "",
				PolicyName: "policy-name",
			},
			wantErr: true,
		},
		{
			name: "missing policy name",
			fields: fields{
				BaseURL:    "https://example.com",
				APIKey:     "api-key",
				PolicyName: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{
				BaseURL:              tt.fields.BaseURL,
				APIKey:               tt.fields.APIKey,
				PolicyName:           tt.fields.PolicyName,
				PolicyOperator:       tt.fields.PolicyOperator,
				PolicyViolationState: tt.fields.PolicyViolationState,
				PolicyProjects:       tt.fields.PolicyProjects,
				PolicyTags:           tt.fields.PolicyTags,
			}
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
