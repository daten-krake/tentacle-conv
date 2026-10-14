package model

import (
	"strings"
	"testing"
)

func validAnalytic() Analytic {
	return Analytic{
		Name:           "Rule",
		Severity:       "High",
		Query:          "print 1",
		QueryFrequency: "PT1H",
		QueryPeriod:    "P1D",
	}
}

func TestValidate_OK(t *testing.T) {
	for _, d := range []string{"PT5M", "PT1H", "P1D", "P1DT12H", "PT1H30M", "P14D", "P2W"} {
		a := validAnalytic()
		a.QueryFrequency = d
		if err := a.Validate(); err != nil {
			t.Errorf("duration %q rejected: %v", d, err)
		}
	}
	a := validAnalytic()
	a.ID = "PRI-AAD-07"
	if err := a.Validate(); err != nil {
		t.Errorf("valid id rejected: %v", err)
	}
}

func TestValidate_Errors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Analytic)
		want   string
	}{
		{"missing name", func(a *Analytic) { a.Name = " " }, "name is required"},
		{"missing query", func(a *Analytic) { a.Query = "" }, "query is required"},
		{"missing severity", func(a *Analytic) { a.Severity = "" }, "severity is required"},
		{"bad severity", func(a *Analytic) { a.Severity = "Critical" }, `severity "Critical"`},
		{"lowercase severity", func(a *Analytic) { a.Severity = "high" }, `severity "high"`},
		{"missing frequency", func(a *Analytic) { a.QueryFrequency = "" }, "query_frequency is required"},
		{"bad frequency", func(a *Analytic) { a.QueryFrequency = "1h" }, `query_frequency "1h"`},
		{"bare P", func(a *Analytic) { a.QueryPeriod = "P" }, `query_period "P"`},
		{"missing period", func(a *Analytic) { a.QueryPeriod = "" }, "query_period is required"},
		{"bad id", func(a *Analytic) { a.ID = "a/b" }, `id "a/b"`},
		{"quote in id", func(a *Analytic) { a.ID = "it's" }, `id "it's"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := validAnalytic()
			tt.mutate(&a)
			err := a.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestValidate_ReportsAllProblems(t *testing.T) {
	err := Analytic{}.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"name", "query", "severity", "query_frequency", "query_period"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}
