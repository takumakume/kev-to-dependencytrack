package dependencytrack

import (
	"errors"
	"testing"

	dtrack "github.com/DependencyTrack/client-go"
)

func TestIsNotFound(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "policy not found",
			args: args{
				err: ErrPolicyNotFound,
			},
			want: true,
		},
		{
			name: "project not found",
			args: args{
				err: ErrProjectNotFound,
			},
			want: true,
		},
		{
			name: "api error 404",
			args: args{
				err: &dtrack.APIError{
					StatusCode: 404,
				},
			},
			want: true,
		},
		{
			name: "api error not 404",
			args: args{
				err: &dtrack.APIError{
					StatusCode: 500,
				},
			},
			want: false,
		},
		{
			name: "other error",
			args: args{
				err: errors.New("error"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFound(tt.args.err); got != tt.want {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDependencyTrack_NeedsUpdatePolicy(t *testing.T) {
	type args struct {
		current  dtrack.Policy
		desired  dtrack.Policy
		expected bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "same policy",
			args: args{
				current:  dtrack.Policy{Operator: dtrack.PolicyOperatorAll, ViolationState: dtrack.PolicyViolationStateFail},
				desired:  dtrack.Policy{Operator: dtrack.PolicyOperatorAll, ViolationState: dtrack.PolicyViolationStateFail},
				expected: false,
			},
		},
		{
			name: "different operator",
			args: args{
				current:  dtrack.Policy{Operator: dtrack.PolicyOperatorAll, ViolationState: dtrack.PolicyViolationStateFail},
				desired:  dtrack.Policy{Operator: dtrack.PolicyOperatorAny, ViolationState: dtrack.PolicyViolationStateFail},
				expected: true,
			},
		},
		{
			name: "different violation state",
			args: args{
				current:  dtrack.Policy{Operator: dtrack.PolicyOperatorAll, ViolationState: dtrack.PolicyViolationStateFail},
				desired:  dtrack.Policy{Operator: dtrack.PolicyOperatorAll, ViolationState: dtrack.PolicyViolationStateWarn},
				expected: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DependencyTrack{}
			if got := d.NeedsUpdatePolicy(tt.args.current, tt.args.desired); got != tt.args.expected {
				t.Errorf("DependencyTrack.NeedsUpdatePolicy() = %v, expected %v", got, tt.args.expected)
			}
		})
	}
}
