package conversion

import (
	"reflect"
	"testing"

	"github.com/tentacle-conv/internal/model"
)

func TestExtractTactics(t *testing.T) {
	tests := []struct {
		name  string
		mitre []model.Mitre
		want  []string
	}{
		{
			name:  "empty mitre list",
			mitre: []model.Mitre{},
			want:  []string{},
		},
		{
			name: "single mitre entry with tactics",
			mitre: []model.Mitre{
				{Tactics: []string{"Execution", "Persistence"}},
			},
			want: []string{"Execution", "Persistence"},
		},
		{
			name: "multiple mitre entries",
			mitre: []model.Mitre{
				{Tactics: []string{"Execution"}},
				{Tactics: []string{"Persistence", "PrivilegeEscalation"}},
			},
			want: []string{"Execution", "Persistence", "PrivilegeEscalation"},
		},
		{
			name: "mitre entry with empty tactics",
			mitre: []model.Mitre{
				{Tactics: []string{"LateralMovement"}},
				{Tactics: []string{}},
			},
			want: []string{"LateralMovement"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTactics(tt.mitre)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractTactics() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractTechniques(t *testing.T) {
	tests := []struct {
		name  string
		mitre []model.Mitre
		want  []string
	}{
		{
			name:  "empty mitre list",
			mitre: []model.Mitre{},
			want:  []string{},
		},
		{
			name: "single mitre entry with techniques",
			mitre: []model.Mitre{
				{Techniques: []string{"T1059", "T1078"}},
			},
			want: []string{"T1059", "T1078"},
		},
		{
			name: "multiple mitre entries",
			mitre: []model.Mitre{
				{Techniques: []string{"T1098"}},
				{Techniques: []string{"T1078", "T1136"}},
			},
			want: []string{"T1098", "T1078", "T1136"},
		},
		{
			name: "mitre entry with empty techniques",
			mitre: []model.Mitre{
				{Techniques: []string{"T1036"}},
				{Techniques: []string{}},
			},
			want: []string{"T1036"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTechniques(tt.mitre)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractTechniques() = %v, want %v", got, tt.want)
			}
		})
	}
}