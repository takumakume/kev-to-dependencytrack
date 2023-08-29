package dependencytrack

import (
	"reflect"
	"testing"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
)

func Test_comparePolicyConditions(t *testing.T) {
	type args struct {
		aa []dtrack.PolicyCondition
		bb []dtrack.PolicyCondition
	}
	tests := []struct {
		name        string
		args        args
		wantRemoved []dtrack.PolicyCondition
		wantAdded   []dtrack.PolicyCondition
	}{
		{
			name: "success",
			args: args{
				aa: []dtrack.PolicyCondition{
					{
						UUID:  uuid.MustParse("00000000-0000-0000-0000-000000000001"),
						Value: "CVE-2019-1002100",
					},
					{
						UUID:  uuid.MustParse("00000000-0000-0000-0000-000000000002"),
						Value: "CVE-2019-1002101",
					},
				},
				bb: []dtrack.PolicyCondition{
					{
						Value: "CVE-2019-1002101",
					},
					{
						Value: "CVE-2019-1002102",
					},
				},
			},
			wantRemoved: []dtrack.PolicyCondition{
				{
					UUID:  uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					Value: "CVE-2019-1002100",
				},
			},
			wantAdded: []dtrack.PolicyCondition{
				{
					Value: "CVE-2019-1002102",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRemoved, gotAdded := comparePolicyConditions(tt.args.aa, tt.args.bb)
			if !reflect.DeepEqual(gotRemoved, tt.wantRemoved) {
				t.Errorf("comparePolicyConditions() gotRemoved = %v, want %v", gotRemoved, tt.wantRemoved)
			}
			if !reflect.DeepEqual(gotAdded, tt.wantAdded) {
				t.Errorf("comparePolicyConditions() gotAdded = %v, want %v", gotAdded, tt.wantAdded)
			}
		})
	}
}
